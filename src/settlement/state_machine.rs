//! Settlement state machine — the operational envelope (v3.14 §Operational State
//! Machine), rendered as TYPESTATES so illegal transitions don't compile.
//!
//! Phases advance by CONSUMING the prior state and returning the next, so you
//! cannot, e.g., broadcast a completion before the possession gate has produced
//! its witness. Each transition maps any failure to `Error::Abort`, which
//! `refund::run` turns into the completion-supersedes refund subroutine.
//! Typestate fields are PRIVATE: a `Possessing` cannot be forged with an
//! arbitrary `s_height` or unvalidated `Params` — the only way to hold one is
//! to have come through the transitions.
//!
//! Discovery is STUBBED (Requirement 5): a `PeerSession` (authenticated Tor
//! channel to the counterparty) is passed IN. This module never does matching,
//! overlay, or store-and-forward.
//!
//! GATES the external cryptographer must confirm are enforced here:
//!   G1 POSSESSION — `PossessionWitness` can only be built inside
//!      `Funded::run_adaptor_exchange`, after the assembled `CompletePreSig` for
//!      Comp->SH passes adaptor verification; the SL enabling partial is sent
//!      ONLY by `release_enabling_partial`, which demands that witness.
//!   G2 DEADLINE   — `broadcast_completion` refuses without runway + a
//!      `WatchtowerReceipt` bound to the already-armed `PreArmedRefund`. The
//!      evidence is a witness type, not a caller-supplied bool.

use crate::crypto::adaptor::{AdaptorPoint, AdaptorSecret, CompletePreSig};
use crate::crypto::{ValidatedFinalSig, ValidatedPoint};
use crate::settlement::params::Params;
use crate::settlement::refund::{PreArmedRefund, WatchtowerReceipt};
use crate::signing::{
    aggregate_nonces, assemble_complete_presig, commit_and_reveal, nonce_commitment,
    verify_partial, RevealedNonces, SigningSession, SingleSignerLease,
};
use crate::wire::{parse_message, serialize_message, Message};
use crate::{Error, Result};
use musig2::KeyAggContext;
use secp::{Point, Scalar};
use std::rc::Rc;

/// Byte-level duplex channel to the counterparty. The (stubbed) discovery layer
/// provides the real authenticated Tor stream; tests provide an in-memory pair.
/// RECEIVING goes through `wire::parse_message`, so everything that enters the
/// state machine has passed the validation gate — a Transport cannot bypass it.
pub trait Transport {
    fn send(&mut self, bytes: &[u8]) -> Result<()>;
    fn recv(&mut self) -> Result<Vec<u8>>;
}

/// Opaque handle to the authenticated peer channel. Provided by the (stubbed)
/// discovery layer; here constructed manually (tests, hand-fed testnet drive).
pub struct PeerSession {
    swap_session_id: [u8; 32],
    transport: Box<dyn Transport>,
}

impl PeerSession {
    pub fn new(swap_session_id: [u8; 32], transport: Box<dyn Transport>) -> Self {
        PeerSession { swap_session_id, transport }
    }

    pub fn swap_session_id(&self) -> &[u8; 32] {
        &self.swap_session_id
    }

    fn send_msg(&mut self, m: &Message) -> Result<()> {
        self.transport.send(&serialize_message(m))
    }

    /// Every received byte string passes the validation gate here.
    fn recv_msg(&mut self) -> Result<Message> {
        let bytes = self.transport.recv()?;
        parse_message(&bytes)
    }
}

/// Role, derived from confirmed funding (v3.13). Not known until Funded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { SecretHolder, SecretLearner }

// ----- Typestate phases -----------------------------------------------------

/// Phase 3–4: escrows constructed, refunds pre-agreed, funding in flight.
pub struct Funding {
    params: Params,
    peer: PeerSession,
}

/// Phase 4 complete: both escrows confirmed (dual-source, self-verifying), role
/// derived from txids + S. Holds the confirmation height S.
pub struct Funded {
    params: Params,
    peer: PeerSession,
    role: Role,
    s_height: u32,
    /// Confirmation height of the escrow WE sweep (the counterparty-funded
    /// escrow). SL's claim deadline is anchored HERE, not to S: bitcoin's
    /// relative CSV on the SH-funded escrow matures from that escrow's own
    /// funding height, so anchoring to S would over-grant under co-funding skew.
    sweep_escrow_height: u32,
}

/// Role-specific settlement material produced by the exchange. Encodes the
/// v3.11 lesson at the type level: SL's ability to complete its OWN leg is a
/// `CompletePreSig` it must actually hold, not an assumption.
enum RoleState {
    /// SH holds t itself (it minted it) and completes Comp->SH with it.
    SecretHolder { t: AdaptorSecret },
    /// SL holds the complete pre-signature for its own leg, completable once
    /// t is extracted from SH's broadcast. Boxed: much larger than the SH arm.
    SecretLearner { presig_comp_sl: Box<CompletePreSig> },
}

/// Phase 5 complete: we hold what we need to EXTRACT or COMPLETE — i.e. the
/// possession gate G1 is satisfied. Fields private: not forgeable, not
/// tamperable; the deadline math below always runs against the params that
/// were validated on the way in.
pub struct Possessing {
    params: Params,
    role: Role,
    s_height: u32,
    /// Confirmation height of the escrow we sweep — SL's claim deadline anchor
    /// (see `Funded::sweep_escrow_height`).
    sweep_escrow_height: u32,
    presig_comp_sh: CompletePreSig, // verified (G1)
    t_point: AdaptorPoint,
    pre_armed_refund: PreArmedRefund, // exists BEFORE any broadcast (G2)
    role_state: RoleState,
}

/// Witness that G1 holds FOR ONE SPECIFIC SWAP. Non-constructible except
/// inside `Funded::run_adaptor_exchange`, after the Comp->SH complete
/// pre-signature verified; minted exactly ONCE per exchange and consumed by
/// `release_enabling_partial` — it never escapes this module. The witness is
/// BOUND to the swap and the extraction message: a witness earned in one swap
/// cannot release anything in another (fields are module-private).
pub struct PossessionWitness {
    swap_session_id: [u8; 32],
    #[allow(dead_code)] // binding recorded for audit; release checks swap id
    msg_comp_sh: [u8; 32],
}

/// Everything the exchange needs from the caller. Secrets stay in fields the
/// caller constructs; the exchange derives pubkeys and contexts itself.
pub struct ExchangeInputs {
    /// Our MuSig2 secret key for the 2-of-2.
    pub our_seckey: Scalar,
    /// Counterparty pubkey (validated on receipt during setup).
    pub their_pubkey: ValidatedPoint,
    /// Sighash of the Comp->SH completion (tx layer provides the real one).
    pub msg_comp_sh: [u8; 32],
    /// Sighash of the Comp->SL completion.
    pub msg_comp_sl: [u8; 32],
    /// Pre-armed refund — must exist BEFORE anything is released (G2 setup).
    pub pre_armed_refund: PreArmedRefund,
    /// SH: the adaptor secret it minted (`AdaptorSecret::generate`). SL: None.
    pub adaptor_secret: Option<AdaptorSecret>,
    /// Lease directory override (tests / alternate stores). None = default.
    pub lease_dir: Option<std::path::PathBuf>,
    /// Durable directory for the G1 possession record. REQUIRED for SL: the
    /// complete pre-signatures MUST be persisted before the enabling partial
    /// is released — after release, refund is no longer a safe sink and
    /// extraction (which needs this material) is the only path, including
    /// across a crash/restart. Ignored for SH (its crash is refund-safe).
    pub possession_store: Option<std::path::PathBuf>,
    /// Tapscript merkle root of the escrow Comp->SH spends (SL-funded escrow),
    /// if this is a real taproot swap. `Some` => the Comp->SH session signs
    /// under the taproot-tweaked key so the signature is valid for the funded
    /// OUTPUT key. `None` => untweaked (crypto-core unit-test path). Both
    /// parties MUST agree on the same roots (they fund the same escrows).
    pub taproot_root_comp_sh: Option<[u8; 32]>,
    /// Tapscript merkle root of the escrow Comp->SL spends (SH-funded escrow).
    pub taproot_root_comp_sl: Option<[u8; 32]>,
    /// Expected 32-byte x-only OUTPUT key of the escrow Comp->SH spends. When
    /// `Some` (alongside the matching root), the exchange PROVES the taproot-
    /// tweaked signing key equals the funded output key before producing any
    /// partial — a mis-specified root then aborts instead of yielding a
    /// silently-unspendable completion. `None` skips the check (untweaked path).
    pub taproot_output_comp_sh: Option<[u8; 32]>,
    /// Expected x-only output key of the escrow Comp->SL spends.
    pub taproot_output_comp_sl: Option<[u8; 32]>,
}

/// Apply a taproot tweak to a base context if a merkle root is supplied, else
/// clone unchanged. The two completions spend DIFFERENT escrows (different CSV,
/// hence different merkle roots), so each leg gets its own tweaked context.
///
/// When `expected_output` is supplied, the tweaked aggregate x-only key MUST
/// equal it — this is the funded-key == signed-key guard (`escrow::
/// taproot_tweaked_keyagg`), wired into the production exchange so a wrong
/// merkle root cannot produce completions that verify against each other yet
/// are unspendable against the on-chain UTXO.
fn tweak_ctx(
    base: &KeyAggContext,
    root: Option<[u8; 32]>,
    expected_output: Option<[u8; 32]>,
) -> Result<KeyAggContext> {
    match root {
        Some(r) => {
            let tweaked = base
                .clone()
                .with_taproot_tweak(&r)
                .map_err(|_| Error::Validation("taproot tweak (exchange)"))?;
            if let Some(exp) = expected_output {
                let got = tweaked.aggregated_pubkey::<Point>().serialize_xonly();
                if got != exp {
                    return Err(Error::Verification(
                        "taproot tweak: signing key does not match the funded output key",
                    ));
                }
            }
            Ok(tweaked)
        }
        None => Ok(base.clone()),
    }
}

/// Canonical 2-of-2 key aggregation: BIP327 key aggregation is order-DEPENDENT,
/// so both parties MUST derive the same ordering. Rule: sort the two compressed
/// encodings lexicographically. (Any taproot tweak is applied by the tx layer
/// before sessions begin — see `SigningSession::begin` docs.)
fn canonical_key_agg(ours: Point, theirs: Point) -> Result<KeyAggContext> {
    let (a, b) = (ours.serialize(), theirs.serialize());
    if a == b {
        return Err(Error::Validation("both parties presented the same pubkey"));
    }
    let keys = if a < b { [ours, theirs] } else { [theirs, ours] };
    KeyAggContext::new(keys).map_err(|_| Error::Validation("key aggregation failed"))
}

fn expect_nonce_commitment(m: Message) -> Result<[u8; 32]> {
    match m {
        Message::NonceCommitment(h) => Ok(h),
        _ => Err(Error::Ordering("expected NonceCommitment message")),
    }
}

fn expect_nonces(m: Message) -> Result<(crate::crypto::ValidatedPubNonce, crate::crypto::ValidatedPubNonce)> {
    match m {
        Message::Nonces { comp_sh, comp_sl } => Ok((comp_sh, comp_sl)),
        _ => Err(Error::Ordering("expected Nonces message")),
    }
}

fn expect_adaptor_point(m: Message) -> Result<AdaptorPoint> {
    match m {
        Message::AdaptorPointMsg(t) => Ok(t),
        _ => Err(Error::Ordering("expected AdaptorPoint message")),
    }
}

fn expect_sh_partials(m: Message) -> Result<(crate::crypto::ValidatedPartial, crate::crypto::ValidatedPartial)> {
    match m {
        Message::ShPartials { comp_sh, comp_sl } => Ok((comp_sh, comp_sl)),
        _ => Err(Error::Ordering("expected ShPartials message")),
    }
}

fn expect_sl_enabling(m: Message) -> Result<crate::crypto::ValidatedPartial> {
    match m {
        Message::SlEnablingPartial(p) => Ok(p),
        _ => Err(Error::Ordering("expected SlEnablingPartial message")),
    }
}

/// The ONLY function that puts SL's enabling partial on the wire, and it
/// demands the possession witness (G1). The witness is consumed (one release)
/// and must be bound to THIS peer's swap — a stale witness from another swap
/// is rejected, so G1 cannot be replayed across swaps.
fn release_enabling_partial(
    witness: PossessionWitness,
    peer: &mut PeerSession,
    enabling_partial: crate::crypto::ValidatedPartial,
) -> Result<()> {
    if witness.swap_session_id != peer.swap_session_id {
        return Err(Error::Ordering("possession witness is bound to a different swap"));
    }
    peer.send_msg(&Message::SlEnablingPartial(enabling_partial))
}

impl Funding {
    pub fn new(params: Params, peer: PeerSession) -> Self {
        Funding { params, peer }
    }

    /// Confirm both escrows against the chain view, enforce the co-funding
    /// window, compute S, and derive the role (v3.14 Phase 4). Both funding
    /// outpoints are supplied by the (stubbed) discovery/tx layer: `our_funding`
    /// is the escrow WE funded, `their_funding` the counterparty's; the two
    /// session pubkeys fix the canonical user ordering.
    ///
    /// Role derivation (v3.14, verbatim):
    ///   `role_seed = SHA256("newkey-role" ‖ txid_lower ‖ txid_higher ‖ S)`
    /// where txid_lower/higher are the two funding txids ordered by byte value
    /// (both parties agree) and S is the confirmation height. The canonical user
    /// order is the lexicographic sort of session pubkeys — the SAME sort MuSig2
    /// KeyAgg uses (`canonical_key_agg`), so the two wallets never diverge. The
    /// seed then fixes which canonical user is SH (chooses t, publishes T, moves
    /// first) vs SL. Re-rolling a role costs a real on-chain funding, so grinding
    /// is uneconomical.
    ///
    /// NOTE: the exact bit that maps `role_seed` → SH is a v3.13 detail; the
    /// low-bit selection below is a documented stand-in. The seed FORMULA and
    /// the canonical ordering are authoritative (v3.14).
    pub fn await_funded(
        self,
        chain: &impl crate::chain::ChainView,
        our_funding: bitcoin::OutPoint,
        their_funding: bitcoin::OutPoint,
        our_session_pubkey: &ValidatedPoint,
        their_session_pubkey: &ValidatedPoint,
    ) -> Result<Funded> {
        use bitcoin::hashes::Hash as _;
        self.params.validate()?; // ordering invariant (review item #5)
        let our_h = chain
            .funding_height(our_funding)
            .ok_or(Error::Deadline("our escrow not yet confirmed"))?;
        let their_h = chain
            .funding_height(their_funding)
            .ok_or(Error::Deadline("counterparty escrow not yet confirmed"))?;

        // Co-funding window: the two confirmations must be close (else abandon).
        let skew = our_h.abs_diff(their_h);
        if skew > self.params.cofunding_window {
            return Err(Error::Deadline("co-funding window exceeded; abandon and refund"));
        }
        // S is the LATER of the two confirmations (the conservative baseline).
        let s_height = our_h.max(their_h);

        // role_seed = SHA256("newkey-role" || txid_lower || txid_higher || S_be).
        let our_txid = our_funding.txid.to_byte_array();
        let their_txid = their_funding.txid.to_byte_array();
        if our_txid == their_txid {
            return Err(Error::Validation("both escrows share a funding txid"));
        }
        let (lo, hi) = if our_txid <= their_txid {
            (our_txid, their_txid)
        } else {
            (their_txid, our_txid)
        };
        let mut preimage = Vec::with_capacity(11 + 32 + 32 + 4);
        preimage.extend_from_slice(b"newkey-role");
        preimage.extend_from_slice(&lo);
        preimage.extend_from_slice(&hi);
        preimage.extend_from_slice(&s_height.to_be_bytes());
        let seed = bitcoin::hashes::sha256::Hash::hash(&preimage).to_byte_array();

        // Canonical user A = lexicographically smaller session pubkey (same sort
        // as KeyAgg). v3.13: "the least-significant bit assigns" — the LSB of the
        // seed as a big-endian integer (last byte) selects which canonical user
        // is SH.
        let we_are_a = our_session_pubkey.to_bytes() < their_session_pubkey.to_bytes();
        let seed_picks_a = (seed[31] & 1) == 0;
        let role = if we_are_a == seed_picks_a {
            Role::SecretHolder
        } else {
            Role::SecretLearner
        };

        // We sweep the COUNTERPARTY's escrow (SH sweeps E_sl via Comp->SH; SL
        // sweeps E_sh via Comp->SL), so the sweep anchor is their funding height.
        Ok(Funded {
            params: self.params,
            peer: self.peer,
            role,
            s_height,
            sweep_escrow_height: their_h,
        })
    }

    /// Hand-fed variant for the stubbed-discovery build (Requirement 5): the
    /// operator/test supplies the confirmed funding facts (role, S) that
    /// `await_funded` will derive from the chain view once the chain layer
    /// exists. Params are validated here exactly as in `await_funded`.
    pub fn funded_manual(self, role: Role, s_height: u32) -> Result<Funded> {
        self.params.validate()?;
        // Manual mode assumes zero co-funding skew (both escrows at S), so the
        // sweep anchor is S. Skewed funding must go through `await_funded`,
        // which records the real per-escrow confirmation heights.
        Ok(Funded {
            params: self.params,
            peer: self.peer,
            role,
            s_height,
            sweep_escrow_height: s_height,
        })
    }
}

impl Funded {
    pub fn role(&self) -> Role {
        self.role
    }

    pub fn s_height(&self) -> u32 {
        self.s_height
    }

    /// Confirmation height of the escrow this party sweeps (SL's claim anchor).
    pub fn sweep_escrow_height(&self) -> u32 {
        self.sweep_escrow_height
    }

    /// Run the interlocked adaptor exchange (Phase 5 messages 1–5), ending with
    /// a VERIFIED complete pre-signature for Comp->SH. Producing `Possessing`
    /// is the ONLY way past the gate; the `PossessionWitness` that authorizes
    /// the SL enabling release is minted once in here and consumed in here.
    ///
    /// Ordering is mandatory and enforced lexically below:
    /// 1. both own sessions committed, THEN nonces revealed/exchanged
    /// 2. T received (validated) / sent
    /// 3. SH partials on BOTH completions; PartialSigVerify each
    /// 4. assemble + verify the CompletePreSig for Comp->SH  (G1)
    /// 5. (SL) release the enabling partial ONLY via the witness
    ///
    /// Any verification failure => Err (=> Abort => refund). The pre-armed
    /// refund exists BEFORE the exchange begins (G2 setup): it is an input.
    pub fn run_adaptor_exchange(mut self, inputs: ExchangeInputs) -> Result<Possessing> {
        let our_pubkey = inputs.our_seckey * secp::G;
        let base_ctx = canonical_key_agg(our_pubkey, inputs.their_pubkey.point())?;
        // Each completion spends a different escrow, so each leg signs under its
        // own taproot-tweaked context (the tweak MUST be baked in before nonce
        // generation — BIP327 binds the nonce to the tweaked aggregate key).
        let ctx_sh = tweak_ctx(&base_ctx, inputs.taproot_root_comp_sh, inputs.taproot_output_comp_sh)?;
        let ctx_sl = tweak_ctx(&base_ctx, inputs.taproot_root_comp_sl, inputs.taproot_output_comp_sl)?;

        // INV-3: one signer per swap. Both sessions share the ONE lease.
        let lease = match &inputs.lease_dir {
            Some(dir) => SingleSignerLease::acquire_in(dir, self.peer.swap_session_id)?,
            None => SingleSignerLease::acquire(self.peer.swap_session_id)?,
        };

        // Fresh sessions (INV-4), one per completion message, each under its
        // own (possibly taproot-tweaked) context.
        let mut sess_sh = SigningSession::begin(
            Rc::clone(&lease), ctx_sh.clone(), inputs.our_seckey, inputs.msg_comp_sh,
        )?;
        let mut sess_sl = SigningSession::begin(
            Rc::clone(&lease), ctx_sl.clone(), inputs.our_seckey, inputs.msg_comp_sl,
        )?;

        // (0/1) Concurrent-session interlock, ENFORCED ON THE WIRE: each party
        // commits to BOTH its session nonces, both commitments are exchanged,
        // and only THEN are nonces revealed. A counterparty therefore cannot
        // choose its nonces adaptively after seeing ours (Wagner/Drijvers).
        let ours = commit_and_reveal(&mut sess_sh, &mut sess_sl)?;
        self.peer.send_msg(&Message::NonceCommitment(nonce_commitment(&ours)))?;
        let their_commitment = expect_nonce_commitment(self.peer.recv_msg()?)?;

        // Both sides have committed; reveal now.
        self.peer.send_msg(&Message::Nonces {
            comp_sh: ours.comp_sh.clone(),
            comp_sl: ours.comp_sl.clone(),
        })?;
        let (their_nonce_sh, their_nonce_sl) = expect_nonces(self.peer.recv_msg()?)?;

        // The revealed nonces MUST match the prior commitment.
        let their_revealed = RevealedNonces {
            comp_sh: their_nonce_sh.clone(),
            comp_sl: their_nonce_sl.clone(),
        };
        if nonce_commitment(&their_revealed) != their_commitment {
            return Err(Error::Verification(
                "counterparty nonces do not match their commitment (concurrent-session interlock)",
            ));
        }

        let agg_nonce_sh = aggregate_nonces(&ours.comp_sh, &their_nonce_sh);
        let agg_nonce_sl = aggregate_nonces(&ours.comp_sl, &their_nonce_sl);

        match self.role {
            Role::SecretHolder => {
                // (2) SH publishes T = t*G; t never leaves this process.
                let t_secret = inputs
                    .adaptor_secret
                    .ok_or(Error::Ordering("SH must supply its adaptor secret"))?;
                let t_point = t_secret.point();
                self.peer.send_msg(&Message::AdaptorPointMsg(t_point.clone()))?;

                // (3) SH signs BOTH completions, adaptor-bound, and sends them.
                let p_sh = sess_sh.sign_partial(&agg_nonce_sh, &t_point)?;
                let p_sl = sess_sl.sign_partial(&agg_nonce_sl, &t_point)?;
                self.peer.send_msg(&Message::ShPartials {
                    comp_sh: p_sh.clone(),
                    comp_sl: p_sl.clone(),
                })?;

                // (5) Receive SL's enabling partial; verify BEFORE aggregation.
                let enabling = expect_sl_enabling(self.peer.recv_msg()?)?;
                verify_partial(
                    &ctx_sh, &enabling, &agg_nonce_sh, &t_point,
                    &inputs.their_pubkey, &their_nonce_sh, &inputs.msg_comp_sh,
                )?;

                // (4/G1 for SH) Assemble + verify the complete pre-signature.
                let presig_comp_sh = assemble_complete_presig(
                    &ctx_sh, &agg_nonce_sh, &t_point, &p_sh, &enabling,
                    inputs.msg_comp_sh, inputs.taproot_root_comp_sh,
                )?;
                presig_comp_sh.verify_adaptor(&t_point)?;

                Ok(Possessing {
                    params: self.params,
                    role: self.role,
                    s_height: self.s_height,
                    sweep_escrow_height: self.sweep_escrow_height,
                    presig_comp_sh,
                    t_point,
                    pre_armed_refund: inputs.pre_armed_refund,
                    role_state: RoleState::SecretHolder { t: t_secret },
                })
            }
            Role::SecretLearner => {
                // (2) Receive T (validated by the wire gate).
                let t_point = expect_adaptor_point(self.peer.recv_msg()?)?;

                // (3) Receive SH's partials on BOTH completions; verify each
                // under that leg's tweaked context.
                let (sh_p_sh, sh_p_sl) = expect_sh_partials(self.peer.recv_msg()?)?;
                verify_partial(
                    &ctx_sh, &sh_p_sh, &agg_nonce_sh, &t_point,
                    &inputs.their_pubkey, &their_nonce_sh, &inputs.msg_comp_sh,
                )?;
                verify_partial(
                    &ctx_sl, &sh_p_sl, &agg_nonce_sl, &t_point,
                    &inputs.their_pubkey, &their_nonce_sl, &inputs.msg_comp_sl,
                )?;

                // Sign our own partials (sessions consumed: single-use).
                let sl_p_sh = sess_sh.sign_partial(&agg_nonce_sh, &t_point)?;
                let sl_p_sl = sess_sl.sign_partial(&agg_nonce_sl, &t_point)?;

                // (4) G1: assemble + verify the COMPLETE pre-sig for Comp->SH —
                // the tx we must extract from — BEFORE releasing anything.
                let presig_comp_sh = assemble_complete_presig(
                    &ctx_sh, &agg_nonce_sh, &t_point, &sl_p_sh, &sh_p_sh,
                    inputs.msg_comp_sh, inputs.taproot_root_comp_sh,
                )?;
                presig_comp_sh.verify_adaptor(&t_point)?;

                // Our own leg's complete pre-sig (v3.11 lesson: hold it, don't
                // assume it).
                let presig_comp_sl = assemble_complete_presig(
                    &ctx_sl, &agg_nonce_sl, &t_point, &sl_p_sl, &sh_p_sl,
                    inputs.msg_comp_sl, inputs.taproot_root_comp_sl,
                )?;
                presig_comp_sl.verify_adaptor(&t_point)?;

                // G1 satisfied. PERSIST-THEN-RELEASE: once the enabling partial
                // is on the wire, refund is no longer a safe sink — extraction
                // is the only path, and it needs these pre-signatures. So the
                // possession record MUST hit durable storage before release,
                // making the InMempool->extraction route survive crash/restart.
                let store = inputs.possession_store.as_deref().ok_or(Error::Ordering(
                    "SL requires a possession_store: presigs must be durable before release",
                ))?;
                let record_path = write_possession_record(
                    store,
                    &self.peer.swap_session_id,
                    self.s_height,
                    self.sweep_escrow_height,
                    &self.params,
                    &t_point,
                    &presig_comp_sh,
                    &presig_comp_sl,
                    &inputs.pre_armed_refund,
                )?;

                // Mint the ONE witness (bound to this swap) and release through
                // the witness-demanding gate. Release is the point of no return:
                // if send errors, the bytes may still have been delivered, so we
                // do NOT unwind to refund — the persisted record lets this node
                // (or its restart) keep watching for SH's broadcast and extract.
                let witness = PossessionWitness {
                    swap_session_id: self.peer.swap_session_id,
                    msg_comp_sh: inputs.msg_comp_sh,
                };
                if release_enabling_partial(witness, &mut self.peer, sl_p_sh).is_err() {
                    // Delivered-or-not is unknowable (TCP/Tor). Proceed as
                    // released; the record at `record_path` covers restart.
                    let _ = &record_path;
                }

                Ok(Possessing {
                    params: self.params,
                    role: self.role,
                    s_height: self.s_height,
                    sweep_escrow_height: self.sweep_escrow_height,
                    presig_comp_sh,
                    t_point,
                    pre_armed_refund: inputs.pre_armed_refund,
                    role_state: RoleState::SecretLearner {
                        presig_comp_sl: Box::new(presig_comp_sl),
                    },
                })
            }
        }
    }
}

// ----- G1 possession record (crash-safety for the post-release window) ------

fn hex32(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use core::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Atomically write SL's possession record (tmp + rename). Layout, all LE:
/// `[1 version=2][4 s_height][4 sweep_escrow_height][params: tier(8) fee(8)
/// early(4) margin(4) buffer(4) allowance(4) cofund(4) onboard_lo(4)
/// onboard_hi(4)][33 T][230 presig_comp_sh][230 presig_comp_sl]
/// [4 csv_maturity][4 refund_len][refund_len refund bytes]`.
#[allow(clippy::too_many_arguments)]
fn write_possession_record(
    dir: &std::path::Path,
    swap_session_id: &[u8; 32],
    s_height: u32,
    sweep_escrow_height: u32,
    params: &Params,
    t_point: &AdaptorPoint,
    presig_comp_sh: &CompletePreSig,
    presig_comp_sl: &CompletePreSig,
    refund: &PreArmedRefund,
) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir).map_err(|_| Error::Abort("possession store unavailable"))?;
    let mut v = Vec::with_capacity(512 + refund.tx_bytes().len());
    v.push(2u8);
    v.extend_from_slice(&s_height.to_le_bytes());
    v.extend_from_slice(&sweep_escrow_height.to_le_bytes());
    v.extend_from_slice(&params.tier_d_sats.to_le_bytes());
    v.extend_from_slice(&params.delta_fee_sats.to_le_bytes());
    v.extend_from_slice(&params.delta_early.to_le_bytes());
    v.extend_from_slice(&params.margin.to_le_bytes());
    v.extend_from_slice(&params.delta_buffer.to_le_bytes());
    v.extend_from_slice(&params.claim_confirm_allowance.to_le_bytes());
    v.extend_from_slice(&params.cofunding_window.to_le_bytes());
    v.extend_from_slice(&params.onboarding_delay_hours.0.to_le_bytes());
    v.extend_from_slice(&params.onboarding_delay_hours.1.to_le_bytes());
    v.extend_from_slice(&t_point.to_bytes());
    v.extend_from_slice(&presig_comp_sh.to_bytes());
    v.extend_from_slice(&presig_comp_sl.to_bytes());
    v.extend_from_slice(&refund.csv_maturity_height().to_le_bytes());
    let refund_bytes = refund.tx_bytes();
    v.extend_from_slice(&(refund_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(refund_bytes);

    let path = dir.join(format!("{}.possession", hex32(swap_session_id)));
    let tmp = dir.join(format!("{}.possession.tmp", hex32(swap_session_id)));
    std::fs::write(&tmp, &v).map_err(|_| Error::Abort("possession record write failed"))?;
    std::fs::rename(&tmp, &path)
        .map_err(|_| Error::Abort("possession record rename failed"))?;
    Ok(path)
}

fn take_le_u32(b: &[u8], at: &mut usize) -> Result<u32> {
    let s = b
        .get(*at..*at + 4)
        .ok_or(Error::Validation("possession record truncated"))?;
    *at += 4;
    Ok(u32::from_le_bytes(s.try_into().map_err(|_| Error::Validation("u32 slice"))?))
}

fn take_le_u64(b: &[u8], at: &mut usize) -> Result<u64> {
    let s = b
        .get(*at..*at + 8)
        .ok_or(Error::Validation("possession record truncated"))?;
    *at += 8;
    Ok(u64::from_le_bytes(s.try_into().map_err(|_| Error::Validation("u64 slice"))?))
}

fn take_arr<const N: usize>(b: &[u8], at: &mut usize) -> Result<[u8; N]> {
    let s = b
        .get(*at..*at + N)
        .ok_or(Error::Validation("possession record truncated"))?;
    *at += N;
    s.try_into().map_err(|_| Error::Validation("array slice"))
}

/// The completed final signature for a leg, ready for the (chain-layer) Tor
/// broadcast. Producing this value is what the gates guard.
pub struct CompletionSig(pub [u8; 64]);

/// SL's claim plan: wait `delay_blocks` (privacy decorrelation), then broadcast
/// its completed leg. The delay is bounded so the claim still confirms before
/// S + delta_late (review item #5).
pub struct ClaimPlan {
    pub delay_blocks: u32,
    pub comp_sl_final: CompletionSig,
}

/// Bounded randomized claim delay. Fallible OS randomness; on RNG failure the
/// delay is 0, which is always inside the legal window (claim immediately —
/// privacy decorrelation degrades, settlement safety does not). Modulo bias is
/// immaterial for a privacy jitter. Kept as a plain function so the bound is
/// unit-testable at the boundaries (review item #5).
fn sample_claim_delay(max_delay: u64) -> u32 {
    use rand::TryRngCore;
    if max_delay == 0 {
        return 0;
    }
    let mut b = [0u8; 8];
    if rand::rngs::OsRng.try_fill_bytes(&mut b).is_err() {
        return 0;
    }
    let cap = max_delay.min(u32::MAX as u64);
    (u64::from_le_bytes(b) % (cap + 1)) as u32
}

impl Possessing {
    pub fn role(&self) -> Role {
        self.role
    }

    /// Rebuild SL's `Possessing` from the persisted G1 possession record —
    /// the crash/restart path for the post-release window. Everything is
    /// re-validated on the way in: params re-checked against the ordering
    /// invariant, both pre-signatures re-verified against (R + T, P, m), and
    /// both must be bound to the T stored in the record. A tampered or corrupt
    /// record is an Err, never a bogus possession.
    pub fn restore_secret_learner(record_path: &std::path::Path) -> Result<Possessing> {
        let b = std::fs::read(record_path)
            .map_err(|_| Error::Abort("possession record unreadable"))?;
        let mut at = 0usize;
        let version: [u8; 1] = take_arr(&b, &mut at)?;
        if version[0] != 2 {
            return Err(Error::Validation("possession record: unknown version"));
        }
        let s_height = take_le_u32(&b, &mut at)?;
        let sweep_escrow_height = take_le_u32(&b, &mut at)?;
        let params = Params {
            tier_d_sats: take_le_u64(&b, &mut at)?,
            delta_fee_sats: take_le_u64(&b, &mut at)?,
            delta_early: take_le_u32(&b, &mut at)?,
            margin: take_le_u32(&b, &mut at)?,
            delta_buffer: take_le_u32(&b, &mut at)?,
            claim_confirm_allowance: take_le_u32(&b, &mut at)?,
            cofunding_window: take_le_u32(&b, &mut at)?,
            onboarding_delay_hours: (take_le_u32(&b, &mut at)?, take_le_u32(&b, &mut at)?),
        };
        params.validate()?; // the record cannot smuggle in bad timelocks
        let t_bytes: [u8; 33] = take_arr(&b, &mut at)?;
        let t_point = AdaptorPoint::new(ValidatedPoint::from_bytes(&t_bytes)?); // <-- gate
        let presig_sh_bytes: [u8; 230] = take_arr(&b, &mut at)?;
        let presig_comp_sh = CompletePreSig::from_bytes(&presig_sh_bytes)?; // re-verifies
        let presig_sl_bytes: [u8; 230] = take_arr(&b, &mut at)?;
        let presig_comp_sl = CompletePreSig::from_bytes(&presig_sl_bytes)?; // re-verifies
        // Both pre-signatures must be bound to the record's T.
        presig_comp_sh.verify_adaptor(&t_point)?;
        presig_comp_sl.verify_adaptor(&t_point)?;
        let csv = take_le_u32(&b, &mut at)?;
        let refund_len = take_le_u32(&b, &mut at)? as usize;
        let refund_bytes = b
            .get(at..at + refund_len)
            .ok_or(Error::Validation("possession record truncated (refund)"))?;
        if b.len() != at + refund_len {
            return Err(Error::Validation("possession record: trailing bytes"));
        }
        let pre_armed_refund = PreArmedRefund::from_signed_tx(refund_bytes.to_vec(), csv)?;

        Ok(Possessing {
            params,
            role: Role::SecretLearner,
            s_height,
            sweep_escrow_height,
            presig_comp_sh,
            t_point,
            pre_armed_refund,
            role_state: RoleState::SecretLearner {
                presig_comp_sl: Box::new(presig_comp_sl),
            },
        })
    }

    pub fn s_height(&self) -> u32 {
        self.s_height
    }

    pub fn t_point(&self) -> &AdaptorPoint {
        &self.t_point
    }

    pub fn presig_comp_sh(&self) -> &CompletePreSig {
        &self.presig_comp_sh
    }

    /// SH ONLY: complete Comp->SH for broadcast, revealing t. Gate G2: refuses
    /// unless (a) there is runway to confirm before S + delta_early -
    /// delta_buffer (no first broadcast inside the buffer), and (b) an armed
    /// watchtower holds THIS pre-armed refund (witness receipt, not a bool).
    /// Broadcast is irrevocable reveal; the network send itself is the
    /// chain-layer fill.
    pub fn broadcast_completion(
        &self,
        current_height: u32,
        watchtower: &WatchtowerReceipt,
    ) -> Result<CompletionSig> {
        let t = match &self.role_state {
            RoleState::SecretHolder { t } => t,
            RoleState::SecretLearner { .. } => {
                return Err(Error::Ordering("only SH broadcasts Comp->SH"))
            }
        };
        // Total u64 math; validated params guarantee buffer < early.
        let deadline =
            self.s_height as u64 + self.params.delta_early as u64 - self.params.delta_buffer as u64;
        if current_height as u64 >= deadline {
            return Err(Error::Deadline(
                "inside delta_buffer: do not broadcast; fall back to pre-armed refund",
            ));
        }
        if !watchtower.matches(&self.pre_armed_refund) {
            return Err(Error::Deadline(
                "watchtower receipt does not cover the pre-armed refund; refuse to broadcast (G2)",
            ));
        }
        let sig = self.presig_comp_sh.complete_with(t)?;
        // IMPLEMENT (chain layer): dedicated Tor circuit, multi-peer broadcast,
        // babysit to confirmation, opt-in fee bump.
        Ok(CompletionSig(sig))
    }

    /// SL ONLY: on seeing Comp->SH's final signature in the mempool, extract t
    /// (via the verified CompletePreSig — G1), complete our own leg, and plan a
    /// randomized claim delay bounded so we still confirm before the SH-funded
    /// escrow's LATE refund matures (review item #5). The bound is enforced by
    /// construction: the sampled delay cannot exceed `params.max_claim_delay`,
    /// which is anchored to the escrow WE sweep — NOT to the co-funding
    /// baseline S — so co-funding skew cannot widen the race window.
    pub fn claim_after_reveal(
        &self,
        final_sig_comp_sh: &ValidatedFinalSig,
        current_height: u32,
    ) -> Result<ClaimPlan> {
        let presig_comp_sl = match &self.role_state {
            RoleState::SecretLearner { presig_comp_sl } => presig_comp_sl,
            RoleState::SecretHolder { .. } => {
                return Err(Error::Ordering("only SL claims after reveal"))
            }
        };
        // Extraction (review item #2): t = s_final - s_hat, checked t*G == T.
        let t = self.presig_comp_sh.extract_secret(final_sig_comp_sh)?;

        // Bounded randomized decorrelation delay, anchored to the SWEPT escrow's
        // confirmation height (fixes the co-funding-skew race window).
        let max_delay = self
            .params
            .max_claim_delay(self.sweep_escrow_height, current_height);
        let delay_blocks = sample_claim_delay(max_delay);

        let sig = presig_comp_sl.complete_with(&t)?;
        Ok(ClaimPlan { delay_blocks, comp_sl_final: CompletionSig(sig) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::refund::confirm_watchtower_handoff;
    use std::sync::mpsc;

    /// In-memory duplex transport: two mpsc channels.
    struct ChannelTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }

    impl Transport for ChannelTransport {
        fn send(&mut self, bytes: &[u8]) -> Result<()> {
            self.tx.send(bytes.to_vec()).map_err(|_| Error::Abort("peer hung up"))
        }
        fn recv(&mut self) -> Result<Vec<u8>> {
            self.rx.recv().map_err(|_| Error::Abort("peer hung up"))
        }
    }

    fn duplex() -> (ChannelTransport, ChannelTransport) {
        let (tx_a, rx_b) = mpsc::channel();
        let (tx_b, rx_a) = mpsc::channel();
        (ChannelTransport { tx: tx_a, rx: rx_a }, ChannelTransport { tx: tx_b, rx: rx_b })
    }

    struct PartySetup {
        seckey: Scalar,
        pubkey: Point,
    }

    fn keypair() -> PartySetup {
        let mut rng = rand::rng();
        let seckey = Scalar::random(&mut rng);
        PartySetup { seckey, pubkey: seckey * secp::G }
    }

    /// Independently recompute the 2-of-2 aggregate key (canonical ordering)
    /// and BIP340-verify a completed leg signature against `message`. This does
    /// NOT rely on any production-internal check — it catches a regression in
    /// complete_with that the "len() == 64" tautology would miss.
    fn independently_verify_leg(a: Point, b: Point, message: &[u8; 32], sig: &[u8; 64]) {
        let ctx = canonical_key_agg(a, b).expect("agg");
        let agg: Point = ctx.aggregated_pubkey();
        let lifted = musig2::LiftedSignature::from_bytes(sig).expect("well-formed sig");
        musig2::verify_single(agg, lifted, message).expect("leg must verify under aggregate key");
    }

    /// Result bundle from a full happy-path exchange, retaining the artifacts
    /// the assertions and negative tests need.
    struct ExchangeOutcome {
        sl_possessing: Possessing,
        sh_completion: CompletionSig,
        sh_t_point: [u8; 33],
        possession_record: std::path::PathBuf,
    }

    #[allow(clippy::too_many_arguments)]
    fn run_happy_exchange(
        swap_id: [u8; 32],
        msg_comp_sh: [u8; 32],
        msg_comp_sl: [u8; 32],
        s_height: u32,
        broadcast_height: u32,
        sh_keys: &PartySetup,
        sl_keys: &PartySetup,
        store_dir: &std::path::Path,
    ) -> ExchangeOutcome {
        let (io_sh, io_sl) = duplex();
        let params = Params::testnet_provisional();
        let lease_dir_sh = tempfile::tempdir().expect("tempdir");
        let lease_dir_sl = tempfile::tempdir().expect("tempdir");
        let sh_params = params.clone();
        let (sh_sk, sl_pub) = (sh_keys.seckey, sl_keys.pubkey);

        let sh_handle = std::thread::spawn(move || -> Result<(CompletionSig, [u8; 33])> {
            let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + 300)?;
            let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
            let (t_secret, _t_point) = AdaptorSecret::generate()?;
            let peer = PeerSession::new(swap_id, Box::new(io_sh));
            let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
            let possessing = funded.run_adaptor_exchange(ExchangeInputs {
                our_seckey: sh_sk,
                their_pubkey: ValidatedPoint::from_bytes(&sl_pub.serialize())?,
                msg_comp_sh,
                msg_comp_sl,
                pre_armed_refund: refund,
                adaptor_secret: Some(t_secret),
                lease_dir: Some(lease_dir_sh.path().to_path_buf()),
                possession_store: None, // SH crash is refund-safe; no record needed
                taproot_root_comp_sh: None,
                taproot_root_comp_sl: None,
                taproot_output_comp_sh: None,
                taproot_output_comp_sl: None,
            })?;
            let t_point_bytes = possessing.t_point().to_bytes();
            let sig = possessing.broadcast_completion(broadcast_height, &receipt)?;
            Ok((sig, t_point_bytes))
        });

        let refund = PreArmedRefund::from_signed_tx(vec![0xbb; 64], s_height + 200).unwrap();
        let peer = PeerSession::new(swap_id, Box::new(io_sl));
        let funded = Funding::new(params, peer)
            .funded_manual(Role::SecretLearner, s_height)
            .expect("funded");
        let sl_possessing = funded
            .run_adaptor_exchange(ExchangeInputs {
                our_seckey: sl_keys.seckey,
                their_pubkey: ValidatedPoint::from_bytes(&sh_keys.pubkey.serialize()).unwrap(),
                msg_comp_sh,
                msg_comp_sl,
                pre_armed_refund: refund,
                adaptor_secret: None,
                lease_dir: Some(lease_dir_sl.path().to_path_buf()),
                possession_store: Some(store_dir.to_path_buf()),
                taproot_root_comp_sh: None,
                taproot_root_comp_sl: None,
                taproot_output_comp_sh: None,
                taproot_output_comp_sl: None,
            })
            .expect("SL exchange");

        let (sh_completion, sh_t_point) =
            sh_handle.join().expect("SH thread").expect("SH side");
        let possession_record = store_dir.join(format!("{}.possession", hex32(&swap_id)));
        ExchangeOutcome { sl_possessing, sh_completion, sh_t_point, possession_record }
    }

    /// Full two-party in-process exchange + settlement crypto:
    ///   exchange -> SH broadcast authorization -> SL extraction -> SL claim.
    /// Proves G1/G2 wiring and the adaptor math end-to-end without a chain,
    /// with INDEPENDENT signature verification of both completed legs.
    #[test]
    fn two_party_exchange_extract_and_claim() {
        let sh_keys = keypair();
        let sl_keys = keypair();
        let swap_id = [0xabu8; 32];
        let msg_comp_sh = [0x51u8; 32];
        let msg_comp_sl = [0x52u8; 32];
        let s_height = 100_000;
        let store = tempfile::tempdir().expect("store");

        let out = run_happy_exchange(
            swap_id, msg_comp_sh, msg_comp_sl, s_height, s_height + 10,
            &sh_keys, &sl_keys, store.path(),
        );

        // Both parties agreed on T.
        assert_eq!(out.sl_possessing.t_point().to_bytes(), out.sh_t_point);

        // SH's completed Comp->SH is a valid BIP340 sig under the aggregate key
        // (independent of any production-internal verification).
        independently_verify_leg(sh_keys.pubkey, sl_keys.pubkey, &msg_comp_sh, &out.sh_completion.0);

        // "Mempool observation": SL sees SH's final signature, extracts t, claims.
        let observed = ValidatedFinalSig::from_bytes(&out.sh_completion.0).expect("well-formed");
        let plan = out
            .sl_possessing
            .claim_after_reveal(&observed, s_height + 12)
            .expect("extract + claim");

        // Review-item-#5 bound holds for the ACTUAL sampled delay.
        let p = Params::testnet_provisional();
        assert!(
            (s_height + 12) as u64 + plan.delay_blocks as u64 + p.claim_confirm_allowance as u64
                <= s_height as u64 + p.delta_late()
        );

        // SL's completed Comp->SL independently verifies — proves extraction
        // recovered the correct t (a wrong t could not have produced this sig).
        independently_verify_leg(
            sh_keys.pubkey, sl_keys.pubkey, &msg_comp_sl, &plan.comp_sl_final.0,
        );
    }

    /// G1 NEGATIVE HALF: a corrupted SH partial must make SL abort WITHOUT ever
    /// putting its enabling partial (tag 0x04) on the wire. This is the gate the
    /// whole scaffold exists to protect; here it is proven, not just lexical.
    #[test]
    fn sl_aborts_without_releasing_on_corrupt_sh_partial() {
        use std::sync::{Arc, Mutex};

        /// Wraps SL's transport: flips a byte inside the ShPartials (tag 0x03)
        /// comp_sh scalar as it arrives, and records the tags SL sends out.
        struct CorruptingTransport {
            inner: ChannelTransport,
            sent_tags: Arc<Mutex<Vec<u8>>>,
        }
        impl Transport for CorruptingTransport {
            fn send(&mut self, bytes: &[u8]) -> Result<()> {
                if let Some(&tag) = bytes.first() {
                    self.sent_tags.lock().unwrap().push(tag);
                }
                self.inner.send(bytes)
            }
            fn recv(&mut self) -> Result<Vec<u8>> {
                let mut b = self.inner.recv()?;
                // ShPartials = [0x03][32 comp_sh][32 comp_sl]; flip the last
                // byte of comp_sh — stays a valid scalar (< n w.h.p.), so it
                // passes the WIRE gate and must fail verify_partial instead.
                if b.first() == Some(&0x03) && b.len() >= 33 {
                    b[32] ^= 0x01;
                }
                Ok(b)
            }
        }

        let sh_keys = keypair();
        let sl_keys = keypair();
        let (io_sh, io_sl) = duplex();
        let swap_id = [0xeeu8; 32];
        let (msg_a, msg_b) = ([0x71u8; 32], [0x72u8; 32]);
        let params = Params::testnet_provisional();
        let s_height = 9_000;
        let store = tempfile::tempdir().expect("store");
        let lease_dir_sh = tempfile::tempdir().expect("tempdir");
        let lease_dir_sl = tempfile::tempdir().expect("tempdir");

        let sh_params = params.clone();
        let (sh_sk, sl_pub) = (sh_keys.seckey, sl_keys.pubkey);
        // SH plays honestly; it will error when SL aborts and drops the channel.
        let sh = std::thread::spawn(move || -> Result<()> {
            let refund = PreArmedRefund::from_signed_tx(vec![0x11; 32], s_height + 300)?;
            let (t_secret, _) = AdaptorSecret::generate()?;
            let peer = PeerSession::new(swap_id, Box::new(io_sh));
            let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
            let _ = funded.run_adaptor_exchange(ExchangeInputs {
                our_seckey: sh_sk,
                their_pubkey: ValidatedPoint::from_bytes(&sl_pub.serialize())?,
                msg_comp_sh: msg_a,
                msg_comp_sl: msg_b,
                pre_armed_refund: refund,
                adaptor_secret: Some(t_secret),
                lease_dir: Some(lease_dir_sh.path().to_path_buf()),
                possession_store: None,
                taproot_root_comp_sh: None,
                taproot_root_comp_sl: None,
                taproot_output_comp_sh: None,
                taproot_output_comp_sl: None,
            })?;
            Ok(())
        });

        let sent_tags = Arc::new(Mutex::new(Vec::new()));
        let transport = CorruptingTransport { inner: io_sl, sent_tags: Arc::clone(&sent_tags) };
        let peer = PeerSession::new(swap_id, Box::new(transport));
        let funded = Funding::new(params, peer)
            .funded_manual(Role::SecretLearner, s_height)
            .expect("funded");
        let result = funded.run_adaptor_exchange(ExchangeInputs {
            our_seckey: sl_keys.seckey,
            their_pubkey: ValidatedPoint::from_bytes(&sh_keys.pubkey.serialize()).unwrap(),
            msg_comp_sh: msg_a,
            msg_comp_sl: msg_b,
            pre_armed_refund: PreArmedRefund::from_signed_tx(vec![0x33; 32], s_height + 200).unwrap(),
            adaptor_secret: None,
            lease_dir: Some(lease_dir_sl.path().to_path_buf()),
            possession_store: Some(store.path().to_path_buf()),
            taproot_root_comp_sh: None,
            taproot_root_comp_sl: None,
            taproot_output_comp_sh: None,
            taproot_output_comp_sl: None,
        });

        // SL MUST abort...
        assert!(result.is_err(), "SL accepted a corrupted SH partial");
        // ...and MUST NOT have released its enabling partial (tag 0x04).
        let tags = sent_tags.lock().unwrap();
        assert!(!tags.contains(&0x04), "SL released enabling partial despite bad SH partial (G1 breach)");
        // ...and no possession record was written (nothing to persist pre-release).
        assert!(
            std::fs::read_dir(store.path()).unwrap().next().is_none(),
            "possession record written before a verified pre-sig"
        );
        let _ = sh.join();
    }

    /// G1 CRASH-SAFETY: after release, SL can rebuild its full possession from
    /// the persisted record (fresh process), then extract + claim. Proves the
    /// post-release window is crash-safe, not fund-losing.
    #[test]
    fn sl_restores_possession_after_crash_and_claims() {
        let sh_keys = keypair();
        let sl_keys = keypair();
        let swap_id = [0x5au8; 32];
        let msg_comp_sh = [0x61u8; 32];
        let msg_comp_sl = [0x62u8; 32];
        let s_height = 200_000;
        let store = tempfile::tempdir().expect("store");

        let out = run_happy_exchange(
            swap_id, msg_comp_sh, msg_comp_sl, s_height, s_height + 10,
            &sh_keys, &sl_keys, store.path(),
        );
        // The record exists on disk (persist-then-release).
        assert!(out.possession_record.exists(), "no possession record persisted");

        // Simulate a crash: throw away the in-memory Possessing entirely.
        let sh_completion = out.sh_completion;
        drop(out.sl_possessing);

        // Fresh process rebuilds from the record — everything re-validated.
        let restored = Possessing::restore_secret_learner(&out.possession_record)
            .expect("restore from possession record");
        assert_eq!(restored.role(), Role::SecretLearner);

        // Extraction + claim succeed post-restore; leg independently verifies.
        let observed = ValidatedFinalSig::from_bytes(&sh_completion.0).expect("well-formed");
        let plan = restored.claim_after_reveal(&observed, s_height + 15).expect("claim after restore");
        independently_verify_leg(
            sh_keys.pubkey, sl_keys.pubkey, &msg_comp_sl, &plan.comp_sl_final.0,
        );
    }

    /// A tampered possession record never yields a valid Possessing.
    #[test]
    fn corrupt_possession_record_is_rejected() {
        let sh_keys = keypair();
        let sl_keys = keypair();
        let swap_id = [0x3cu8; 32];
        let s_height = 50_000;
        let store = tempfile::tempdir().expect("store");
        let out = run_happy_exchange(
            swap_id, [7u8; 32], [8u8; 32], s_height, s_height + 10,
            &sh_keys, &sl_keys, store.path(),
        );
        let mut bytes = std::fs::read(&out.possession_record).unwrap();
        // Flip a byte inside the first pre-signature (past the header+params+T).
        // Header = version(1) + s_height(4) + sweep(4) + params(44) + T(33) = 86;
        // land 10 bytes into presig_comp_sh so from_bytes re-verify fails.
        let idx = 1 + 4 + 4 + 44 + 33 + 10;
        bytes[idx] ^= 0x01;
        let bad = store.path().join("bad.possession");
        std::fs::write(&bad, &bytes).unwrap();
        assert!(Possessing::restore_secret_learner(&bad).is_err());
    }

    /// Extraction defensive paths (review item #2): a final signature from a
    /// DIFFERENT swap must never yield a secret.
    #[test]
    fn extraction_rejects_unrelated_final_sig() {
        let sh_keys = keypair();
        let sl_keys = keypair();
        let store_a = tempfile::tempdir().expect("a");
        let store_b = tempfile::tempdir().expect("b");
        let s = 300_000;
        let a = run_happy_exchange([1u8; 32], [0x11; 32], [0x12; 32], s, s + 10, &sh_keys, &sl_keys, store_a.path());
        let b = run_happy_exchange([2u8; 32], [0x21; 32], [0x22; 32], s, s + 10, &sh_keys, &sl_keys, store_b.path());

        // Swap B's final signature fed to swap A's Comp->SH pre-signature.
        let foreign = ValidatedFinalSig::from_bytes(&b.sh_completion.0).expect("well-formed");
        assert!(
            a.sl_possessing.presig_comp_sh().extract_secret(&foreign).is_err(),
            "extracted a secret from an unrelated final signature"
        );
        // The matching one still works.
        let own = ValidatedFinalSig::from_bytes(&a.sh_completion.0).expect("well-formed");
        assert!(a.sl_possessing.presig_comp_sh().extract_secret(&own).is_ok());
    }

    /// complete_with and verify_adaptor reject a secret / adaptor point that
    /// does not match the pre-signature's bound T (adaptor.rs defensive paths).
    #[test]
    fn completion_and_verify_reject_wrong_adaptor_material() {
        let sh_keys = keypair();
        let sl_keys = keypair();
        let store = tempfile::tempdir().expect("store");
        let s = 400_000;
        let out = run_happy_exchange(
            [4u8; 32], [0x31; 32], [0x32; 32], s, s + 10, &sh_keys, &sl_keys, store.path(),
        );
        let presig = out.sl_possessing.presig_comp_sh();

        // A secret for an unrelated T cannot complete this pre-signature.
        let (wrong_secret, wrong_point) = AdaptorSecret::generate().unwrap();
        assert!(presig.complete_with(&wrong_secret).is_err());
        // ...and verifying against the wrong adaptor point is refused.
        assert!(presig.verify_adaptor(&wrong_point).is_err());
        // The correct T still verifies.
        assert!(presig.verify_adaptor(out.sl_possessing.t_point()).is_ok());
    }

    #[test]
    fn broadcast_gate_boundary_and_receipt() {
        let sh_keys = keypair();
        let sl_keys = keypair();
        let (io_sh, io_sl) = duplex();
        let swap_id = [0xcdu8; 32];
        let (msg_a, msg_b) = ([1u8; 32], [2u8; 32]);
        let params = Params::testnet_provisional();
        let s_height = 5_000;
        let store = tempfile::tempdir().expect("store");
        let lease_dir_sh = tempfile::tempdir().expect("tempdir");
        let lease_dir_sl = tempfile::tempdir().expect("tempdir");

        let sl_pub = sl_keys.pubkey;
        let sh_params = params.clone();
        let sh_sk = sh_keys.seckey;
        let sh = std::thread::spawn(move || -> Result<()> {
            let refund = PreArmedRefund::from_signed_tx(vec![0x11; 32], s_height + 300)?;
            let good_receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
            let other = PreArmedRefund::from_signed_tx(vec![0x22; 32], s_height + 300)?;
            let wrong_receipt = confirm_watchtower_handoff(&other, other.fingerprint())?;

            let (t_secret, _) = AdaptorSecret::generate()?;
            let peer = PeerSession::new(swap_id, Box::new(io_sh));
            let funded =
                Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
            let possessing = funded.run_adaptor_exchange(ExchangeInputs {
                our_seckey: sh_sk,
                their_pubkey: ValidatedPoint::from_bytes(&sl_pub.serialize())?,
                msg_comp_sh: msg_a,
                msg_comp_sl: msg_b,
                pre_armed_refund: refund,
                adaptor_secret: Some(t_secret),
                lease_dir: Some(lease_dir_sh.path().to_path_buf()),
                possession_store: None,
                taproot_root_comp_sh: None,
                taproot_root_comp_sl: None,
                taproot_output_comp_sh: None,
                taproot_output_comp_sl: None,
            })?;

            // deadline = S + 144 - 24 = S + 120.
            // Exact boundary: refused.
            assert!(matches!(
                possessing.broadcast_completion(s_height + 120, &good_receipt),
                Err(Error::Deadline(_))
            ));
            // Last permitted height S + 119: allowed (pins the runway window).
            assert!(possessing.broadcast_completion(s_height + 119, &good_receipt).is_ok());
            // Wrong watchtower receipt: refused.
            assert!(matches!(
                possessing.broadcast_completion(s_height + 10, &wrong_receipt),
                Err(Error::Deadline(_))
            ));
            // Proper receipt + runway: authorized.
            assert!(possessing.broadcast_completion(s_height + 10, &good_receipt).is_ok());
            Ok(())
        });

        let refund = PreArmedRefund::from_signed_tx(vec![0x33; 32], s_height + 200).unwrap();
        let peer = PeerSession::new(swap_id, Box::new(io_sl));
        let funded = Funding::new(params, peer)
            .funded_manual(Role::SecretLearner, s_height)
            .expect("funded");
        let _sl = funded
            .run_adaptor_exchange(ExchangeInputs {
                our_seckey: sl_keys.seckey,
                their_pubkey: ValidatedPoint::from_bytes(&sh_keys.pubkey.serialize()).unwrap(),
                msg_comp_sh: msg_a,
                msg_comp_sl: msg_b,
                pre_armed_refund: refund,
                adaptor_secret: None,
                lease_dir: Some(lease_dir_sl.path().to_path_buf()),
                possession_store: Some(store.path().to_path_buf()),
                taproot_root_comp_sh: None,
                taproot_root_comp_sl: None,
                taproot_output_comp_sh: None,
                taproot_output_comp_sl: None,
            })
            .expect("SL exchange");

        sh.join().expect("SH thread").expect("SH assertions");
    }

    #[test]
    fn claim_delay_sampler_respects_boundaries() {
        // max_delay == 0 => always 0.
        for _ in 0..1000 {
            assert_eq!(sample_claim_delay(0), 0);
        }
        // max_delay == 1 => only 0 or 1, both observed over many draws.
        let mut seen0 = false;
        let mut seen1 = false;
        for _ in 0..2000 {
            let d = sample_claim_delay(1);
            assert!(d <= 1, "sampled delay {d} exceeds max 1");
            seen0 |= d == 0;
            seen1 |= d == 1;
        }
        assert!(seen0 && seen1, "sampler did not cover both endpoints of [0, 1]");
        // Larger cap: never exceeds it.
        for _ in 0..2000 {
            assert!(sample_claim_delay(198) <= 198);
        }
    }
}
