//! Runner glue (Task 08): everything the `swapkey-cli` binary needs between
//! the built wallet seams and an actual terminal session — the two-party
//! PRE-SWAP NEGOTIATION handshake that assembles a [`SwapContext`], and the
//! TICK→BROADCAST mapping that turns [`SwapApp`]/[`RecoveryDriver`] decisions
//! into chain broadcasts. Lives in the library (not the binary) so the whole
//! loop is unit-testable against `SimChain` + an in-process transport.
//!
//! # Engine boundary (unchanged)
//! The drivers DECIDE; this module BROADCASTS. Nothing here adds curve math or
//! touches the frozen settlement core — it composes `SwapApp`, the ledger, the
//! tx builders, and the `Transport` trait exactly as the integration tests do.
//!
//! # The role↔CSV pre-commitment gap (pre-alpha honesty)
//! The derived role is `f(txid_lower, txid_higher, S)` — unknowable until BOTH
//! escrows confirm — yet each escrow's refund leaf must carry the ROLE-correct
//! CSV (`delta_early` on the SL-funded escrow, `delta_late` on the SH-funded
//! one), which `SwapEngine::verify_swept_escrow_csv` enforces before any
//! partial is released. Two independent parties therefore CANNOT pre-commit
//! the correct CSVs; the proper pre-commitment scheme is the deferred external
//! cryptographer stop-gate. This runner uses the honest interim convention:
//! the canonically-SMALLER session pubkey (party A, the first funder) funds at
//! `delta_early` (presumed SL) and the larger (party B) at `delta_late`
//! (presumed SH). When the derived role agrees with the presumption the swap
//! settles; when it disagrees the CSV-binding guard refuses the exchange and
//! the swap exits through its pre-armed refund — forward-or-refund holds
//! either way, and no partial is ever released against a wrong-CSV escrow.
//! Expect ~half of pre-alpha attempts to route to refund by design.
//!
//! # Session keys
//! The session keypair is EPHEMERAL (supplied by the caller, generated fresh
//! per swap): both alternative exits are fully signed at negotiate time (the
//! pre-armed refund rides in the store record; the completion is co-signed in
//! Phase A and pays a wallet-derived `SwapDestination` key), so losing the
//! session scalar after the swap strands nothing.

use std::path::Path;

use bitcoin::{OutPoint, ScriptBuf, Txid};
use sha2::{Digest, Sha256};

use crate::chain::AuthoritativeChainView;
use crate::crypto::adaptor::AdaptorSecret;
use crate::crypto::ValidatedPoint;
use crate::settlement::params::Params;
use crate::settlement::refund::confirm_watchtower_handoff;
use crate::settlement::state_machine::{canonical_internal_key, swap_session_id, Role, Transport};
use crate::tx::escrow::Escrow;
use crate::tx::setup::{build_setup, pre_encumbrance_spk};
use crate::tx::txbuild::{build_completion, finalize_key_spend, SpendTx};
use crate::wallet::app::{AppTick, BackstopRun, SwapApp};
use crate::wallet::config::Network;
use crate::wallet::engine::{SwapContext, SwapEngine};
use crate::wallet::keys::{KeyPurpose, KeySource};
use crate::wallet::ledger::WalletClock;
use crate::wallet::orchestrator::AbortAction;
use crate::wallet::recovery_driver::{RecoveryDriver, RecoveryTick};
use crate::wallet::store::SwapPhase;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Handshake wire format (pre-session, BEFORE the Task-05 envelope: the session
// id the envelope binds to is derived FROM this exchange).
// ---------------------------------------------------------------------------

/// Version byte of the pre-swap negotiation handshake. Bumped on any change
/// to the frame layout below.
pub const HANDSHAKE_VERSION: u8 = 0x01;

const KIND_HELLO: u8 = 0x01;
const KIND_OFFER: u8 = 0x02;

/// Hard cap on the exchanged destination scriptPubKey (P2TR is 34 bytes;
/// headroom for future output types without admitting unbounded garbage).
const MAX_DEST_SPK: usize = 64;

const HELLO_LEN: usize = 2 + 1 + 32 + 33; // ver kind net digest pubkey
const OFFER_FIXED: usize = 2 + 32 + 4 + 2; // ver kind txid vout spk_len

fn network_byte(network: Network) -> u8 {
    match network {
        Network::Regtest => 0,
        Network::Testnet => 1,
    }
}

/// Domain-separated digest over every manifest parameter that shapes the
/// cross-party transactions. Any mismatch (different manifest versions, a
/// tampered peer) must abort BEFORE anything funds: mismatched params mean
/// mismatched sighashes, which Phase A would only discover after both Setups
/// are on the wire.
fn params_digest(network: Network, p: &Params) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"newkey-cli-handshake-params-v1");
    h.update([network_byte(network)]);
    for v in [
        p.tier_d_sats,
        p.delta_fee_sats,
        p.anchor_sats,
        p.setup_fee_sats,
        p.cpfp_reserve_sats,
    ] {
        h.update(v.to_le_bytes());
    }
    for v in [
        p.delta_early,
        p.margin,
        p.delta_buffer,
        p.claim_confirm_allowance,
        p.cofunding_window,
        p.onboarding_delay_hours.0,
        p.onboarding_delay_hours.1,
    ] {
        h.update(v.to_le_bytes());
    }
    h.finalize().into()
}

fn encode_hello(network: Network, digest: &[u8; 32], pubkey: &[u8; 33]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HELLO_LEN);
    v.push(HANDSHAKE_VERSION);
    v.push(KIND_HELLO);
    v.push(network_byte(network));
    v.extend_from_slice(digest);
    v.extend_from_slice(pubkey);
    v
}

fn decode_hello(bytes: &[u8], network: Network, digest: &[u8; 32]) -> Result<[u8; 33]> {
    if bytes.len() != HELLO_LEN {
        return Err(Error::Validation("handshake: hello frame has the wrong length"));
    }
    if bytes[0] != HANDSHAKE_VERSION {
        return Err(Error::Validation("handshake: peer speaks a different handshake version"));
    }
    if bytes[1] != KIND_HELLO {
        return Err(Error::Validation("handshake: expected a hello frame"));
    }
    if bytes[2] != network_byte(network) {
        return Err(Error::Validation("handshake: peer is on a different network"));
    }
    if &bytes[3..35] != digest {
        return Err(Error::Validation(
            "handshake: peer runs different signed params (manifest mismatch)",
        ));
    }
    let mut pk = [0u8; 33];
    pk.copy_from_slice(&bytes[35..68]);
    Ok(pk)
}

fn encode_offer(escrow_op: OutPoint, dest_spk: &ScriptBuf) -> Result<Vec<u8>> {
    let spk = dest_spk.as_bytes();
    if spk.is_empty() || spk.len() > MAX_DEST_SPK {
        return Err(Error::Validation("handshake: destination spk length out of bounds"));
    }
    let mut v = Vec::with_capacity(OFFER_FIXED + spk.len());
    v.push(HANDSHAKE_VERSION);
    v.push(KIND_OFFER);
    v.extend_from_slice(escrow_op.txid.as_ref());
    v.extend_from_slice(&escrow_op.vout.to_le_bytes());
    v.extend_from_slice(&(spk.len() as u16).to_le_bytes());
    v.extend_from_slice(spk);
    Ok(v)
}

fn decode_offer(bytes: &[u8]) -> Result<(OutPoint, ScriptBuf)> {
    if bytes.len() < OFFER_FIXED {
        return Err(Error::Validation("handshake: offer frame truncated"));
    }
    if bytes[0] != HANDSHAKE_VERSION {
        return Err(Error::Validation("handshake: peer speaks a different handshake version"));
    }
    if bytes[1] != KIND_OFFER {
        return Err(Error::Validation("handshake: expected an offer frame"));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&bytes[2..34]);
    let vout = u32::from_le_bytes(bytes[34..38].try_into().expect("4 bytes"));
    let spk_len = u16::from_le_bytes(bytes[38..40].try_into().expect("2 bytes")) as usize;
    if spk_len == 0 || spk_len > MAX_DEST_SPK {
        return Err(Error::Validation("handshake: destination spk length out of bounds"));
    }
    if bytes.len() != OFFER_FIXED + spk_len {
        return Err(Error::Validation("handshake: offer frame has the wrong length"));
    }
    let spk = ScriptBuf::from_bytes(bytes[OFFER_FIXED..].to_vec());
    let op = OutPoint::new(Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(txid)), vout);
    Ok((op, spk))
}

// ---------------------------------------------------------------------------
// Negotiation
// ---------------------------------------------------------------------------

/// The broadcast material a [`SwapApp`] run needs from its caller — the txs
/// only the caller holds under the engine boundary. `comp_sh`/`comp_sl` are
/// the two co-signed completion TEMPLATES; which one is OURS is decided by the
/// derived role (read from the persisted record at the `Completed` tick).
#[derive(Clone)]
pub struct SwapArtifacts {
    pub session_id: [u8; 32],
    /// Our fully-signed Setup (spends our leased pre-encumbrance coin).
    pub setup_tx: Vec<u8>,
    /// Completion of the presumed-SH leg (spends party A's escrow, pays B).
    pub comp_sh: SpendTx,
    /// Completion of the presumed-SL leg (spends party B's escrow, pays A).
    pub comp_sl: SpendTx,
    /// Our fully-signed pre-armed refund, as armed at negotiate time. A copy
    /// also rides in the store record; THIS copy exists so a crash inside the
    /// setup-broadcast→record-persist window still leaves a broadcastable
    /// exit on disk (Fable review, HIGH).
    pub refund_tx: Vec<u8>,
    /// The `SwapDestination` key index our settlement output pays — needed to
    /// register the received coin in the ledger once an exit confirms.
    pub dest_key_index: u32,
    /// Our destination scriptPubKey (both our completion leg and our refund
    /// pay it) — the output-recognition anchor for registration.
    pub dest_spk: ScriptBuf,
}

/// Mutable per-run state the caller threads through [`swap_step`]: whether
/// our Setup went on the wire (the fund-exposure marker the binary's failure
/// handling keys on), and whether the early-record persist is still owed
/// (a store fault after the broadcast — retried on every subsequent step;
/// the [`SwapApp`] flag is already set, so the tick is never re-issued).
#[derive(Default)]
pub struct SwapRunState {
    pub setup_on_wire: bool,
    record_confirm_pending: bool,
}

impl SwapRunState {
    pub fn new() -> SwapRunState {
        SwapRunState::default()
    }
    /// True while the early `Funding` record persist is still owed to the
    /// store (ALARM state: the swap is funded but not yet durable).
    pub fn record_pending(&self) -> bool {
        self.record_confirm_pending
    }
}

/// Everything `negotiate_swap` hands the caller: the assembled context for
/// [`SwapApp::begin`] plus the broadcast artifacts for the run loop.
pub struct NegotiatedSwap {
    pub ctx: SwapContext,
    pub artifacts: SwapArtifacts,
}

/// Run the two-party pre-swap negotiation over `peer` and assemble the
/// [`SwapContext`] + [`SwapArtifacts`] for one swap.
///
/// Sequence (symmetric on both sides; both send, then receive):
/// 1. `hello` — handshake version, network, params digest, session pubkey.
///    Any mismatch aborts before a coin is leased.
/// 2. Locally: derive the session id + canonical internal key, apply the
///    CSV convention (module docs), LEASE one pre-encumbrance coin under the
///    session id, build our signed Setup (⇒ our escrow outpoint), and issue a
///    fresh `SwapDestination` key.
/// 3. `offer` — escrow outpoint + destination spk, exchanged.
/// 4. Locally: build both completion templates + both parties' taproot
///    commitments, arm OUR pre-armed refund, and assemble the context.
///
/// The lease is intentionally NOT rolled back on a late failure: no record
/// exists yet, so the next `SwapEngine::open`'s lease reconcile releases the
/// coin (the same heal the early-record crash story relies on). Within a
/// still-running process the coin stays leased until restart — pre-alpha.
///
/// `session_seckey` is the caller-generated ephemeral session key (see the
/// module docs). The transport is NOT consumed — wrap it into a
/// [`PeerSession`](crate::settlement::state_machine::PeerSession) with the
/// returned `artifacts.session_id` for [`SwapApp::begin`].
pub fn negotiate_swap(
    peer: &mut dyn Transport,
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    clock: &dyn WalletClock,
    network: Network,
    data_dir: &Path,
    session_seckey: secp::Scalar,
) -> Result<NegotiatedSwap> {
    let params = engine.manifest().current().params().clone();
    params.validate()?;
    let digest = params_digest(network, &params);

    // --- 1. hello ---------------------------------------------------------
    let our_point = session_seckey * secp::G;
    let our_pk_bytes = our_point.serialize();
    peer.send(&encode_hello(network, &digest, &our_pk_bytes))?;
    let their_pk_bytes = decode_hello(&peer.recv()?, network, &digest)?;
    // Requirement 2: validate on receipt. Also rejects the identity trap of a
    // peer echoing our own key (equal keys break role derivation and KeyAgg).
    let their_pubkey = ValidatedPoint::from_bytes(&their_pk_bytes)?;
    if their_pk_bytes == our_pk_bytes {
        return Err(Error::Validation("handshake: peer echoed our own session pubkey"));
    }
    let their_point = secp::Point::from_slice(&their_pk_bytes)
        .map_err(|_| Error::Validation("handshake: peer session pubkey is not a valid point"))?;

    let sid = swap_session_id(our_point, their_point)?;
    let internal = canonical_internal_key(our_point, their_point)?;

    // --- 2. CSV convention + our side's material ---------------------------
    let delta_late = u32::try_from(params.delta_late())
        .map_err(|_| Error::Deadline("delta_late exceeds the CSV height field"))?;
    let we_are_a = our_pk_bytes < their_pk_bytes;
    let (my_csv, their_csv) = if we_are_a {
        (params.delta_early, delta_late)
    } else {
        (delta_late, params.delta_early)
    };
    let my_escrow = Escrow::new(&internal, &our_point, my_csv)?;
    let their_escrow = Escrow::new(&internal, &their_point, their_csv)?;

    let coin = engine
        .ledger_mut()
        .lease_pre_encumbrance(params.pre_encumbrance_sats(), clock, chain.tip_height(), sid)?
        .ok_or(Error::Validation(
            "no mature pre-encumbrance coin to fund the swap — onboard a deposit first",
        ))?;
    let funder_sk = engine.keys().derive_seckey(coin.key_purpose, coin.key_index)?;
    let (setup_tx, my_escrow_op) = build_setup(
        coin.outpoint,
        coin.amount_sats,
        params.escrow_amount_sats(),
        params.anchor_sats,
        &my_escrow,
        &funder_sk,
    )?;
    let (dest_key_index, my_dest) = engine.issue_swap_destination()?;

    // --- 3. offer -----------------------------------------------------------
    peer.send(&encode_offer(my_escrow_op, &my_dest)?)?;
    let (their_escrow_op, their_dest) = decode_offer(&peer.recv()?)?;
    if their_escrow_op == my_escrow_op {
        return Err(Error::Validation("handshake: peer echoed our own escrow outpoint"));
    }

    // --- 4. completions, refund, context ------------------------------------
    // Canonical A/B mapping (A = smaller session pubkey = presumed SL).
    let (escrow_a, op_a, dest_a, escrow_b, op_b, dest_b) = if we_are_a {
        (&my_escrow, my_escrow_op, my_dest.clone(), &their_escrow, their_escrow_op, their_dest.clone())
    } else {
        (&their_escrow, their_escrow_op, their_dest.clone(), &my_escrow, my_escrow_op, my_dest.clone())
    };
    let escrow_amount = params.escrow_amount_sats();
    // Comp→SH spends the SL-funded (A's) escrow and pays SH (B); Comp→SL
    // spends the SH-funded (B's) escrow and pays SL (A).
    let comp_sh =
        build_completion(escrow_a, op_a, escrow_amount, dest_b, params.tier_d_sats, params.anchor_sats)?;
    let comp_sl =
        build_completion(escrow_b, op_b, escrow_amount, dest_a, params.tier_d_sats, params.anchor_sats)?;

    // Our pre-armed refund reclaims OUR escrow to our own fresh destination.
    // The arm-time maturity is a PREDICTION from the current tip; the tower
    // fires on the chain-derived maturity once the escrow's funding height is
    // observable (WatchtowerDriver::effective_maturity).
    let pre_armed_refund = crate::settlement::refund::PreArmedRefund::arm(
        &my_escrow,
        my_escrow_op,
        escrow_amount,
        &session_seckey,
        my_dest.clone(),
        params.tier_d_sats,
        params.anchor_sats,
        chain.tip_height(),
    )?;
    let watchtower_receipt =
        confirm_watchtower_handoff(&pre_armed_refund, pre_armed_refund.fingerprint())?;

    // Presumed SH (party B) generates the adaptor secret; presumed SL carries
    // none. On a convention-mismatching role flip the CSV-binding guard
    // refuses the exchange BEFORE the adaptor secret would be consumed.
    let adaptor_secret = if we_are_a { None } else { Some(AdaptorSecret::generate()?.0) };

    let lease_dir = data_dir.join("leases");
    std::fs::create_dir_all(&lease_dir)
        .map_err(|_| Error::Abort("could not create the nonce-lease directory"))?;

    let ctx = SwapContext {
        our_seckey: session_seckey,
        their_pubkey,
        our_escrow_op: my_escrow_op,
        their_escrow_op,
        // The reveal (Comp→SH) lands on the SL-funded escrow = A's, both sides.
        reveal_escrow_op: op_a,
        escrow_amount,
        msg_comp_sh: comp_sh.sighash,
        msg_comp_sl: comp_sl.sighash,
        pre_armed_refund,
        adaptor_secret,
        taproot_root_comp_sh: escrow_a.merkle_root(),
        taproot_root_comp_sl: escrow_b.merkle_root(),
        taproot_output_comp_sh: escrow_a.output_key_xonly(),
        taproot_output_comp_sl: escrow_b.output_key_xonly(),
        lease_dir,
        // Convention (wallet::runtime data-dir layout): possession records
        // live flat in the data dir as <sid>.possession.
        possession_store: data_dir.to_path_buf(),
        watchtower_receipt,
        funding_coin: coin.outpoint,
    };

    let artifacts = SwapArtifacts {
        session_id: sid,
        setup_tx,
        comp_sh,
        comp_sl,
        refund_tx: ctx.pre_armed_refund.tx_bytes().to_vec(),
        dest_key_index,
        dest_spk: my_dest,
    };
    // Sidecar the templates (see `persist_artifacts`): the record persists
    // only the 64-byte final SIGNATURE, so a cold `recover` needs these to
    // rebuild the broadcastable claim/completion — and the refund copy must
    // be durable BEFORE the Setup can ever broadcast (fund-exposure order).
    persist_artifacts(data_dir, &artifacts)?;

    Ok(NegotiatedSwap { ctx, artifacts })
}

// ---------------------------------------------------------------------------
// Artifacts sidecar
// ---------------------------------------------------------------------------

const ARTIFACTS_MAGIC: &[u8; 8] = b"SKART01\0";

/// Persist a swap's broadcast templates as `<sid>.artifacts` in the data dir.
///
/// WHY: the sealed store deliberately persists only the 64-byte final
/// signature (`SwapRecord::completion_tx` — the spender-attribution
/// artifact); the broadcastable completion is template + signature, and the
/// engine boundary leaves template custody with the caller. Without this
/// sidecar a crashed SL could re-derive its claim SIGNATURE from the
/// possession record but have no tx to put it in.
///
/// CONTENT IS PUBLIC-ONLY: unsigned tx templates + sighashes + our signed
/// refund/Setup + destination metadata — everything the chain reveals once
/// the swap settles; no key material. Stored PLAINTEXT (pre-alpha: the
/// templates do leak intended swap linkage a bit earlier than the chain
/// would if the data dir is exfiltrated mid-swap).
pub fn persist_artifacts(data_dir: &Path, artifacts: &SwapArtifacts) -> Result<()> {
    let mut v = Vec::new();
    v.extend_from_slice(ARTIFACTS_MAGIC);
    for bytes in [
        artifacts.setup_tx.clone(),
        bitcoin::consensus::encode::serialize(&artifacts.comp_sh.tx),
        bitcoin::consensus::encode::serialize(&artifacts.comp_sl.tx),
        artifacts.refund_tx.clone(),
        artifacts.dest_spk.as_bytes().to_vec(),
    ] {
        v.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        v.extend_from_slice(&bytes);
    }
    v.extend_from_slice(&artifacts.comp_sh.sighash);
    v.extend_from_slice(&artifacts.comp_sl.sighash);
    v.extend_from_slice(&artifacts.dest_key_index.to_le_bytes());

    let path = artifacts_path(data_dir, &artifacts.session_id);
    let tmp = path.with_extension("artifacts.tmp");
    std::fs::write(&tmp, &v).map_err(|_| Error::Abort("could not write the artifacts sidecar"))?;
    std::fs::rename(&tmp, &path)
        .map_err(|_| Error::Abort("could not commit the artifacts sidecar"))
}

/// Load a swap's `<sid>.artifacts` sidecar. `Ok(None)` when absent (a swap
/// begun by something other than this runner); malformed bytes are an `Err`.
pub fn load_artifacts(data_dir: &Path, sid: &[u8; 32]) -> Result<Option<SwapArtifacts>> {
    let path = artifacts_path(data_dir, sid);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Abort("artifacts sidecar unreadable")),
    };
    if bytes.len() < ARTIFACTS_MAGIC.len() || &bytes[..ARTIFACTS_MAGIC.len()] != ARTIFACTS_MAGIC {
        return Err(Error::Validation("artifacts sidecar malformed"));
    }
    let mut at = ARTIFACTS_MAGIC.len();
    let mut take = |bytes: &[u8]| -> Result<Vec<u8>> {
        let len_end = at.checked_add(4).ok_or(Error::Validation("artifacts sidecar malformed"))?;
        if bytes.len() < len_end {
            return Err(Error::Validation("artifacts sidecar malformed"));
        }
        let len =
            u32::from_le_bytes(bytes[at..len_end].try_into().expect("4 bytes")) as usize;
        let end =
            len_end.checked_add(len).ok_or(Error::Validation("artifacts sidecar malformed"))?;
        if bytes.len() < end {
            return Err(Error::Validation("artifacts sidecar malformed"));
        }
        at = end;
        Ok(bytes[len_end..end].to_vec())
    };
    let setup_tx = take(&bytes)?;
    let comp_sh_bytes = take(&bytes)?;
    let comp_sl_bytes = take(&bytes)?;
    let refund_tx = take(&bytes)?;
    let dest_spk = take(&bytes)?;
    if bytes.len() != at + 64 + 4 {
        return Err(Error::Validation("artifacts sidecar malformed"));
    }
    let mut sighash_sh = [0u8; 32];
    sighash_sh.copy_from_slice(&bytes[at..at + 32]);
    let mut sighash_sl = [0u8; 32];
    sighash_sl.copy_from_slice(&bytes[at + 32..at + 64]);
    let dest_key_index =
        u32::from_le_bytes(bytes[at + 64..at + 68].try_into().expect("4 bytes"));
    let decode = |b: &[u8]| -> Result<bitcoin::Transaction> {
        bitcoin::consensus::encode::deserialize(b)
            .map_err(|_| Error::Validation("artifacts sidecar malformed"))
    };
    Ok(Some(SwapArtifacts {
        session_id: *sid,
        setup_tx,
        comp_sh: SpendTx { tx: decode(&comp_sh_bytes)?, sighash: sighash_sh },
        comp_sl: SpendTx { tx: decode(&comp_sl_bytes)?, sighash: sighash_sl },
        refund_tx,
        dest_key_index,
        dest_spk: ScriptBuf::from_bytes(dest_spk),
    }))
}

fn artifacts_path(data_dir: &Path, sid: &[u8; 32]) -> std::path::PathBuf {
    data_dir.join(format!("{}.artifacts", hex32(sid)))
}

// ---------------------------------------------------------------------------
// Run loop: tick → broadcast
// ---------------------------------------------------------------------------

/// Caller knobs for the run loop.
pub struct RunOptions {
    /// Target feerate handed to the congestion backstop's CPFP sizing.
    pub target_feerate_sat_vb: u64,
    /// Decide but never broadcast (and never mutate the ledger through the
    /// backstop executor). Useful for observing what the drivers WOULD do.
    pub dry_run: bool,
    /// Operator observation that an ALREADY-RELAYED pre-armed refund pays
    /// below the current confirmation floor (the one refund stall the tower
    /// cannot detect internally). Auto-detection needs real node feerate
    /// reads — a Task-10 item; until then this is the CLI's
    /// `--assume-congested` escape hatch.
    pub refund_congested: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions { target_feerate_sat_vb: 2, dry_run: false, refund_congested: false }
    }
}

/// Terminal outcome of one swap run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapOutcome {
    /// OUR leg settled; the finalized completion is on the wire (its txid).
    Completed { completion_txid: Txid },
    /// The swap routed to its pre-armed refund exit. Keep driving
    /// [`refund_babysit_step`] (plus [`backstop_step`]) until the record
    /// reaches `Refunded`/`Completed`.
    Refunding { reason: &'static str },
    /// Clean abort — nothing was ever locked.
    Aborted { reason: &'static str },
}

/// One `poll` advanced: keep going, or a terminal was reached.
#[derive(Debug)]
pub enum SwapStepOutcome {
    /// Non-terminal; the tick is surfaced for logging/cadence decisions.
    Continue(AppTick),
    Done(SwapOutcome),
}

/// Advance the swap one poll and PERFORM the broadcast the tick demands (the
/// engine-boundary half the drivers leave to the caller):
///
/// * `BroadcastSetup` → broadcast our signed Setup (idempotent), then confirm
///   via [`SwapApp::setup_broadcast`] so the early `Funding` record persists.
/// * `Completed` → finalize OUR completion (the record's `completion_tx` when
///   persisted, else the role-matching template + returned signature) and
///   broadcast it.
/// * `Refunding` / `Aborted` → surfaced as terminals; the refund babysit loop
///   owns everything after `Refunding`.
/// * `Wait` / `AwaitingVerification` / `AwaitingReveal` → `Continue`.
///
/// With `dry_run` every broadcast is skipped (and `setup_broadcast` is NOT
/// called — the confirm must never precede a real broadcast), so a dry run
/// cannot advance past the funding phase; it observes decisions only.
///
/// FUND-EXPOSURE ERROR DISCIPLINE (Fable review, HIGH): once our Setup is on
/// the wire, a store fault in the early-record persist must NEVER abort the
/// run — [`SwapApp::setup_broadcast`] is documented retryable, so the persist
/// is retried here (and, via `state.record_pending`, on every later step)
/// while the live ctx/backstop keeps guarding the refund. The caller should
/// key its own hard-error handling on `state.setup_on_wire`: after that
/// point, degrade to a backstop guard loop instead of exiting.
pub fn swap_step(
    app: &mut SwapApp,
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    artifacts: &SwapArtifacts,
    state: &mut SwapRunState,
    opts: &RunOptions,
    log: &mut dyn FnMut(String),
) -> Result<SwapStepOutcome> {
    // Owed early-record persist from a prior step's store fault: retry until
    // the store heals (idempotent; the app's broadcast flag is already set).
    if state.record_confirm_pending {
        match app.setup_broadcast(engine, &artifacts.setup_tx) {
            Ok(()) => {
                state.record_confirm_pending = false;
                log("early Funding record persisted (store healed)".into());
            }
            Err(e) => log(format!(
                "ALARM: early Funding record STILL not persisted ({e}); the funded escrow \
                 is guarded only by this live process until the store heals"
            )),
        }
    }
    let tick = app.poll(engine, chain)?;
    match tick {
        AppTick::Wait | AppTick::AwaitingVerification | AppTick::AwaitingReveal => {
            Ok(SwapStepOutcome::Continue(tick))
        }
        AppTick::BroadcastSetup => {
            if opts.dry_run {
                log("dry-run: would broadcast our Setup".into());
                return Ok(SwapStepOutcome::Continue(tick));
            }
            let txid = chain.broadcast(&artifacts.setup_tx)?;
            state.setup_on_wire = true;
            log(format!("setup broadcast: {txid}"));
            // The crash-exposure window is OPEN. A store Err here is
            // retryable by contract — never propagated past the broadcast.
            let mut persisted = false;
            for _ in 0..3 {
                match app.setup_broadcast(engine, &artifacts.setup_tx) {
                    Ok(()) => {
                        persisted = true;
                        break;
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
                }
            }
            if !persisted {
                state.record_confirm_pending = true;
                log(
                    "ALARM: our Setup is on the wire but the early Funding record could not \
                     be persisted; retrying every step — do NOT kill this process until it \
                     heals (the refund guard is otherwise in-memory only; the signed refund \
                     also sits in the .artifacts sidecar)"
                        .into(),
                );
            }
            Ok(SwapStepOutcome::Continue(tick))
        }
        AppTick::Completed { our_final_sig } => {
            // The record's `completion_tx` holds the 64-byte FINAL SIGNATURE
            // (the spender-attribution artifact), not broadcastable bytes —
            // the full tx is template + signature (the engine boundary keeps
            // tx custody with the caller).
            let rec = engine
                .store()
                .get(&artifacts.session_id)?
                .ok_or(Error::Ordering("completed swap has no persisted record"))?;
            let template = match rec.role {
                Role::SecretHolder => artifacts.comp_sh.clone(),
                Role::SecretLearner => artifacts.comp_sl.clone(),
            };
            let bytes = finalize_key_spend(template, our_final_sig);
            let txid = txid_of(&bytes)?;
            if opts.dry_run {
                log(format!("dry-run: would broadcast our completion {txid}"));
            } else {
                // A transient broadcast failure must not abort the run with
                // the record already terminal — the completion babysit loop
                // re-drives the (idempotent) broadcast until it CONFIRMS.
                match chain.broadcast(&bytes) {
                    Ok(_) => log(format!("completion broadcast: {txid}")),
                    Err(e) => log(format!(
                        "ALARM: completion broadcast failed ({e}); the completion babysit \
                         will re-drive it — do not stop before it confirms"
                    )),
                }
            }
            Ok(SwapStepOutcome::Done(SwapOutcome::Completed { completion_txid: txid }))
        }
        AppTick::Refunding(reason) => Ok(SwapStepOutcome::Done(SwapOutcome::Refunding { reason })),
        AppTick::Aborted(reason) => Ok(SwapStepOutcome::Done(SwapOutcome::Aborted { reason })),
    }
}

/// One congestion/dead-device backstop pass, EXECUTED (autonomous refund
/// bumps; completion bumps stay decision-only here — the dead-device consent
/// policy). Run on its own cadence alongside `swap_step`, and keep running it
/// after a `Refunding` terminal until the refund confirms.
///
/// Skipped entirely under `dry_run`: even the pure DECISION path fires the
/// matured dead-device refund through the tower (by design — the owner may be
/// offline), which a dry run must not do.
pub fn backstop_step(
    app: &SwapApp,
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    opts: &RunOptions,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    if opts.dry_run {
        log("dry-run: backstop pass skipped (a tick can fire the dead-device refund)".into());
        return Ok(());
    }
    match app.backstop_execute(
        engine,
        chain,
        opts.target_feerate_sat_vb,
        opts.refund_congested,
        None,
        None,
    )? {
        BackstopRun::Decided(tick) => log(format!("backstop: {tick:?}")),
        BackstopRun::Executed { decision, outcome } => {
            log(format!("backstop executed: {decision:?} -> {outcome:?}"))
        }
    }
    Ok(())
}

/// Drive one persisted swap's crash-recovery/refund continuation a single
/// step: re-enter the record ([`RecoveryDriver::reenter_one`]), perform the
/// broadcast its tick demands, and report the terminal phase once reached
/// (`Refunded` / `Completed`), else `None` — call again as the chain advances.
///
/// This is both the post-`Refunding` babysit loop of a live run and the
/// building block the `recover` command applies to every scanned record.
pub fn refund_babysit_step(
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    sid: &[u8; 32],
    opts: &RunOptions,
    log: &mut dyn FnMut(String),
) -> Result<Option<SwapPhase>> {
    let rec = engine
        .store()
        .get(sid)?
        .ok_or(Error::Ordering("refunding swap has no persisted record"))?;
    if matches!(rec.phase, SwapPhase::Refunded | SwapPhase::Completed) {
        return Ok(Some(rec.phase));
    }
    let tick = RecoveryDriver::reenter_one(engine.store(), &rec, chain)?;
    // The `Refunded` terminal-advance arm registers the reclaimed settlement
    // output itself, so babysat and cold-recovered refunds are tracked alike.
    apply_recovery_tick(engine, chain, data_dir, sid, &tick, opts, log)?;
    Ok(engine
        .store()
        .get(sid)?
        .map(|r| r.phase)
        .filter(|p| matches!(p, SwapPhase::Refunded | SwapPhase::Completed)))
}

/// Drive OUR broadcast completion to its CONFIRMED terminal — the
/// forward-half twin of [`refund_babysit_step`] (Fable review: the record is
/// persisted `Completed` BEFORE any broadcast confirms, so "completed" from
/// [`swap_step`] means on-the-wire, not settled). Each step re-enters the
/// persisted record: an evicted/unbroadcast completion surfaces as
/// `Rebroadcast { confirmed: false }` and is re-driven; `confirmed: true` (or
/// a `Settled` re-validation) ends the babysit, after which the received
/// output is registered in the ledger. Returns `Some(())` once confirmed.
pub fn completion_babysit_step(
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    sid: &[u8; 32],
    opts: &RunOptions,
    log: &mut dyn FnMut(String),
) -> Result<Option<()>> {
    let rec = engine
        .store()
        .get(sid)?
        .ok_or(Error::Ordering("completed swap has no persisted record"))?;
    let tick = RecoveryDriver::reenter_one(engine.store(), &rec, chain)?;
    match &tick {
        RecoveryTick::Settled | RecoveryTick::Rebroadcast { confirmed: true, .. } => {
            if !opts.dry_run {
                if let (Some(sig), Some(artifacts)) =
                    (completion_sig(&rec), load_artifacts(data_dir, sid)?)
                {
                    let template = match rec.role {
                        Role::SecretHolder => artifacts.comp_sh.clone(),
                        Role::SecretLearner => artifacts.comp_sl.clone(),
                    };
                    let bytes = finalize_key_spend(template, sig);
                    register_settlement_output(engine, chain, data_dir, sid, &bytes, log);
                }
            }
            Ok(Some(()))
        }
        _ => {
            apply_recovery_tick(engine, chain, data_dir, sid, &tick, opts, log)?;
            Ok(None)
        }
    }
}

/// The record's persisted 64-byte final signature, if present and well-sized.
fn completion_sig(rec: &crate::wallet::store::SwapRecord) -> Option<[u8; 64]> {
    rec.completion_tx.as_deref().and_then(|b| <[u8; 64]>::try_from(b).ok())
}

/// The record's signed pre-armed refund bytes (for output registration).
fn rec_refund_bytes(engine: &SwapEngine, sid: &[u8; 32]) -> Result<Vec<u8>> {
    Ok(engine
        .store()
        .get(sid)?
        .and_then(|r| r.pre_armed_refund.map(|p| p.tx_bytes().to_vec()))
        .unwrap_or_default())
}

/// Register the settlement output a confirmed exit tx pays to OUR
/// `SwapDestination` key ([`Ledger::record_swapped_output`]) — without this
/// the wallet never tracks the coin it just received/reclaimed. Best-effort:
/// already-tracked and missing-sidecar cases log and return (the coin is
/// still recoverable by key derivation), never failing the babysit terminal.
/// `deposit_linked` is `false`: this runner never executes a consent-linked
/// completion bump (dead-device policy passes `consent = None`).
fn register_settlement_output(
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    sid: &[u8; 32],
    exit_tx_bytes: &[u8],
    log: &mut dyn FnMut(String),
) {
    let sid_hex = hex32(sid);
    let Ok(Some(artifacts)) = load_artifacts(data_dir, sid) else {
        log(format!(
            "{sid_hex}: no artifacts sidecar — received output NOT registered in the \
             ledger (recover it by SwapDestination key derivation)"
        ));
        return;
    };
    let Ok(tx) = bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(exit_tx_bytes)
    else {
        return;
    };
    let txid = tx.compute_txid();
    let Some((vout, out)) = tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey == artifacts.dest_spk)
    else {
        return; // not our exit tx shape — nothing to register
    };
    let outpoint = OutPoint::new(txid, vout as u32);
    let height = chain.funding_height(outpoint).unwrap_or_else(|| chain.tip_height());
    // An Err here is the already-tracked case (an earlier pass registered
    // it) — benign, so only the success is reported.
    if engine
        .ledger_mut()
        .record_swapped_output(outpoint, out.value.to_sat(), artifacts.dest_key_index, height, false)
        .is_ok()
    {
        log(format!(
            "{sid_hex}: settlement output {txid}:{vout} registered ({} sats)",
            out.value.to_sat()
        ));
    }
}

/// Perform the broadcast/record-advance a [`RecoveryTick`] asks of its caller
/// (the engine-boundary half of recovery). Everything is derived from the
/// PERSISTED record — no live context needed:
///
/// * refund decisions broadcast the record's pre-armed refund bytes;
/// * `RebroadcastSetup` re-submits the persisted Setup (idempotent);
/// * `Extract`/`Rebroadcast` rebuild the broadcastable completion from the
///   tick's 64-byte signature + the `<sid>.artifacts` template sidecar in
///   `data_dir` (the record persists only the signature);
/// * a `Refunded` decision advances the record to its terminal phase;
/// * `RewritePending` and driver-reported damage are surfaced as ALARMS via
///   `log` — never silently dropped.
pub fn apply_recovery_tick(
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    sid: &[u8; 32],
    tick: &RecoveryTick,
    opts: &RunOptions,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let sid_hex = hex32(sid);
    match tick {
        RecoveryTick::Settled => {
            log(format!("{sid_hex}: settled — nothing to drive"));
            Ok(())
        }
        RecoveryTick::RewritePending => {
            log(format!(
                "{sid_hex}: ALARM — non-resumable Signing record still awaiting its \
                 abort rewrite; re-open the wallet to retry"
            ));
            Ok(())
        }
        RecoveryTick::Funding { refund } => match refund {
            Some(action) => apply_abort_action(engine, chain, data_dir, sid, *action, opts, log),
            None => {
                log(format!("{sid_hex}: funding-phase record, nothing locked yet"));
                Ok(())
            }
        },
        RecoveryTick::Refund(action) => {
            apply_abort_action(engine, chain, data_dir, sid, *action, opts, log)
        }
        RecoveryTick::RebroadcastSetup { setup_tx } => {
            if opts.dry_run {
                log(format!("{sid_hex}: dry-run — would re-submit the persisted Setup"));
                return Ok(());
            }
            let txid = chain.broadcast(setup_tx)?;
            log(format!("{sid_hex}: re-submitted the persisted Setup ({txid})"));
            Ok(())
        }
        RecoveryTick::Extract { final_sig, fallback } => match final_sig {
            Some(sig) => broadcast_recovered_completion(engine, chain, data_dir, sid, *sig, opts, log),
            None => apply_abort_action(engine, chain, data_dir, sid, *fallback, opts, log),
        },
        RecoveryTick::Rebroadcast { final_sig, confirmed } => {
            if *confirmed {
                log(format!("{sid_hex}: completion confirmed — record advanced to Completed"));
                Ok(())
            } else {
                broadcast_recovered_completion(engine, chain, data_dir, sid, *final_sig, opts, log)
            }
        }
    }
}

/// The caller side of an [`AbortAction`] decision on a persisted record.
fn apply_abort_action(
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    sid: &[u8; 32],
    action: AbortAction,
    opts: &RunOptions,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let sid_hex = hex32(sid);
    match action {
        AbortAction::Wait => {
            log(format!("{sid_hex}: refund not yet actionable (immature, no completion)"));
            Ok(())
        }
        AbortAction::BroadcastRefund => {
            let rec = engine
                .store()
                .get(sid)?
                .ok_or(Error::Ordering("refund decision on a vanished record"))?;
            let refund = rec
                .pre_armed_refund
                .as_ref()
                .ok_or(Error::Ordering("refund decision on a record with no pre-armed refund"))?;
            if opts.dry_run {
                log(format!("{sid_hex}: dry-run — would broadcast the pre-armed refund"));
                return Ok(());
            }
            match chain.broadcast(refund.tx_bytes()) {
                Ok(txid) => log(format!("{sid_hex}: pre-armed refund broadcast ({txid})")),
                // The driver's maturity gate is the ARM-TIME prediction
                // (`predicted_S + csv` — armed before the escrow funded); the
                // chain enforces the REAL funding-relative CSV. A too-early
                // refusal is "not yet", not a failure — the next pass retries
                // (the same chain-derived-maturity discipline the watchtower
                // applies internally via `effective_maturity`).
                Err(Error::Deadline(_)) => log(format!(
                    "{sid_hex}: refund not yet accepted (CSV immature at the node); retrying next pass"
                )),
                Err(e) => return Err(e),
            }
            Ok(())
        }
        AbortAction::TakeTheSwap => {
            // SL's executable arm surfaces as Extract (handled there); for SH
            // a winning counterparty completion means our leg already resolved.
            log(format!("{sid_hex}: a counterparty completion is winning — not refunding"));
            Ok(())
        }
        AbortAction::Refunded => {
            if opts.dry_run {
                log(format!("{sid_hex}: dry-run — refund confirmed; would advance the record"));
                return Ok(());
            }
            advance_to_refunded(engine, sid)?;
            log(format!("{sid_hex}: refund confirmed on chain — record advanced to Refunded"));
            // The confirmed refund pays our own SwapDestination key: register
            // the reclaimed coin HERE (the terminal-advance site), so a
            // COLD-RECOVERED refund is ledger-tracked too — not only one
            // babysat by a live swap process (Fable review, HIGH).
            let refund_bytes = rec_refund_bytes(engine, sid)?;
            register_settlement_output(engine, chain, data_dir, sid, &refund_bytes, log);
            Ok(())
        }
        AbortAction::Completed => {
            log(format!("{sid_hex}: a completion confirmed against our escrow — swap resolved"));
            Ok(())
        }
    }
}

/// Rebuild + broadcast the recovered completion: the record/tick carry only
/// the 64-byte final SIGNATURE (rule 3 persists it `Completing`-first); the
/// unsigned template comes from the `<sid>.artifacts` sidecar. A missing
/// sidecar (a swap begun outside this runner) is a LOUD alarm, not an `Err` —
/// the scan must keep driving the other swaps, and the signature stays
/// re-derivable on every future pass.
fn broadcast_recovered_completion(
    engine: &SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    sid: &[u8; 32],
    final_sig: [u8; 64],
    opts: &RunOptions,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let sid_hex = hex32(sid);
    let Some(artifacts) = load_artifacts(data_dir, sid)? else {
        log(format!(
            "{sid_hex}: ALARM — recovered a finalized completion signature but no \
             {sid_hex}.artifacts template sidecar exists in the data dir; the claim \
             cannot be broadcast from here (restore the sidecar or finalize externally)"
        ));
        return Ok(());
    };
    let rec = engine
        .store()
        .get(sid)?
        .ok_or(Error::Ordering("completion rebroadcast on a vanished record"))?;
    let template = match rec.role {
        Role::SecretHolder => artifacts.comp_sh,
        Role::SecretLearner => artifacts.comp_sl,
    };
    let bytes = finalize_key_spend(template, final_sig);
    let txid = txid_of(&bytes)?;
    if opts.dry_run {
        log(format!("{sid_hex}: dry-run — would (re)broadcast our completion {txid}"));
        return Ok(());
    }
    chain.broadcast(&bytes)?;
    log(format!("{sid_hex}: completion (re)broadcast ({txid})"));
    Ok(())
}

/// Advance a record whose refund the chain confirmed to its `Refunded`
/// terminal, honoring the store's transition table (`Funding` records pass
/// through `AbortRefund` first — the same route the live app takes).
fn advance_to_refunded(engine: &SwapEngine, sid: &[u8; 32]) -> Result<()> {
    let Some(mut rec) = engine.store().get(sid)? else {
        return Ok(());
    };
    if rec.phase == SwapPhase::Funding {
        rec.phase = SwapPhase::AbortRefund;
        engine.store().put(&rec)?;
    }
    if rec.phase == SwapPhase::AbortRefund {
        rec.phase = SwapPhase::Refunded;
        engine.store().put(&rec)?;
    }
    Ok(())
}

/// The scriptPubKey the wallet derives for `(purpose, index)` — the SAME
/// single-key P2TR construction `Ledger::issue_key` uses for every issued
/// address. Exposed for the binary's deposit-address recognition scan
/// (`onboard` matches the chain-reported funding spk back to its key index).
pub fn derived_spk(keys: &dyn KeySource, purpose: KeyPurpose, index: u32) -> Result<ScriptBuf> {
    pre_encumbrance_spk(keys.derive_xonly(purpose, index)?)
}

fn txid_of(tx_bytes: &[u8]) -> Result<Txid> {
    let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(tx_bytes)
        .map_err(|_| Error::Validation("persisted tx bytes do not decode"))?;
    Ok(tx.compute_txid())
}

/// Lowercase hex of a 32-byte id (session ids in logs/filenames).
pub fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}
