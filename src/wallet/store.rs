//! Crash-safe SwapStore (wallet rank 1; v3.16 residual critical risk).
//!
//! One sealed file per swap: `<hex swap_session_id>.swap`, encrypted with
//! AES-256-GCM under the per-swap TEK (`crypto::storage::derive_tek`) — the
//! same spec formula the possession record uses, so one TEK covers all of a
//! swap's at-rest artifacts. A record from swap A cannot be opened as swap B.
//!
//! WHAT IS (and is NOT) IN A RECORD — the INV-1 boundary:
//!   * IN: lifecycle phase, params snapshot, escrow outpoints, deadline
//!     heights, the PRE-ARMED refund, the finalized completion tx once one
//!     exists, and the path of SL's possession record. Everything needed to
//!     meet deadlines after a crash. All of it public bytes.
//!   * STRUCTURALLY OUT: secret signing nonces and signing-session state.
//!     `SwapRecord` has no field that can hold them — every field is a typed
//!     public artifact; there is no opaque extension blob for unforeseen
//!     (secret) material to hide in — and the signing layer's `SecretNonce`
//!     is non-serializable by construction.
//!
//! LIFECYCLE LAW (INV-2/INV-4, enforced by `open` + the transition table):
//!   * `Signing` found on disk at startup == we died mid-session. The volatile
//!     nonces are gone; the session is NON-RESUMABLE. `open` routes the swap
//!     by G1 evidence: if the record's possession pointer (registered at
//!     `put(Signing)` time, BEFORE the window opens) resolves to an
//!     authenticating possession record, the persist-then-release ordering
//!     means SL's release may already be on the wire — the safe phase is
//!     `Released` (restore-and-extract; the refund fallback stays reachable
//!     via `Released -> AbortRefund`). Otherwise nothing was released and the
//!     swap is atomically routed to `AbortRefund`.
//!   * There is NO `AbortRefund -> Signing` edge: an aborted swap can never be
//!     "retried" in place. A retry is a brand-new swap (fresh session keys,
//!     fresh swap_session_id, fresh nonces) — INV-4 at the wallet layer.
//!
//! ORCHESTRATOR WRITE-ORDERING CONTRACT (what rank 4 must uphold; the store
//! enforces everything below that is enforceable from record state alone):
//!   1. `put(Funding)` with the escrow outpoints BEFORE broadcasting any
//!      Setup tx — money never confirms into an escrow the store has not
//!      heard of.
//!   2. SL: `put(Signing)` carries the (deterministic) possession-record path
//!      BEFORE `run_adaptor_exchange` — enforced by `check`.
//!   3. `put(Completing)` carries the finalized completion tx BEFORE it is
//!      broadcast — enforced by `check`; a crash straddling the broadcast
//!      leaves either a Signing record (routed by G1 evidence) or a
//!      rebroadcastable Completing record. Never a revealed-t orphan.
//!   4. Drivers derive their work from RECORDS (scan for AbortRefund /
//!      Released / Completing), not from `RecoveryAction` — the actions are
//!      one-shot USER-FACING notifications, not the work queue.
//!
//! G2's crash half: a funded escrow (or any signing-phase record) without its
//! pre-armed refund is unrepresentable — the wallet cannot even encode
//! "money locked, no exit".
//!
//! KNOWN LIMITS (documented stand-ins, mirrored in the review packet):
//!   * No anti-rollback: an attacker who can restore an OLD sealed record
//!     file wins a phase rewind. True rollback protection needs an
//!     enclave-held monotonic counter — the same real-infra seam as the
//!     modeled `platform_secure_key`.
//!   * The settlement layer's possession record seals under the MODELED
//!     platform key directly; when a real `EnclaveKeyProvider` lands, the
//!     same key must be threaded into `write_possession_record` or the two
//!     artifacts diverge (rank-4 / K-ENCLAVE completion item).

use crate::settlement::params::Params;
use crate::settlement::refund::PreArmedRefund;
use crate::settlement::state_machine::Role;
use crate::{Error, Result};
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ----- Enclave seam ----------------------------------------------------------

/// The device-bound platform key seam. In production this is the Secure
/// Enclave / Keystore key: stable across restarts, never leaves the device.
/// The wallet layer only ever sees the 32 bytes it derives TEKs from.
pub trait EnclaveKeyProvider {
    fn platform_key(&self) -> [u8; 32];
}

/// Prototype provider wrapping the modeled constant in `crypto::storage`.
/// A real build supplies an OS-keystore-backed implementation instead; every
/// consumer is already coded against the trait, so nothing else changes.
pub struct ModeledEnclave;

impl EnclaveKeyProvider for ModeledEnclave {
    fn platform_key(&self) -> [u8; 32] {
        crate::crypto::storage::platform_secure_key()
    }
}

// ----- Record ----------------------------------------------------------------

/// Wallet-visible swap lifecycle phase. Coarser than the settlement
/// typestates on purpose: this is what must be KNOWN AFTER A CRASH, not the
/// in-memory protocol position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapPhase {
    /// Setups constructed/broadcast; awaiting co-funding confirmation.
    /// Crash-safe: funding is chain-observable, no volatile signing state.
    Funding,
    /// A LIVE Phase-5 signing session is in flight. Volatile nonces exist
    /// only in memory — a record found in this phase at startup means the
    /// session died with them. Non-resumable (INV-2).
    Signing,
    /// SL only: enabling partial released under G1 (or possibly released —
    /// see `open`'s G1-evidence routing), possession record persisted.
    /// Crash => restore-and-extract, NOT refund.
    Released,
    /// Our completion (SH) or claim (SL) is finalized and persisted in
    /// `completion_tx`; broadcasting/babysitting it in.
    Completing,
    /// Terminal: our output confirmed.
    Completed,
    /// Refund path engaged. The refund driver (completion-supersedes first,
    /// then pre-armed refund at maturity) owns this record now.
    AbortRefund,
    /// Terminal: refund confirmed.
    Refunded,
}

impl SwapPhase {
    fn to_byte(self) -> u8 {
        match self {
            SwapPhase::Funding => 0,
            SwapPhase::Signing => 1,
            SwapPhase::Released => 2,
            SwapPhase::Completing => 3,
            SwapPhase::Completed => 4,
            SwapPhase::AbortRefund => 5,
            SwapPhase::Refunded => 6,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            0 => SwapPhase::Funding,
            1 => SwapPhase::Signing,
            2 => SwapPhase::Released,
            3 => SwapPhase::Completing,
            4 => SwapPhase::Completed,
            5 => SwapPhase::AbortRefund,
            6 => SwapPhase::Refunded,
            _ => return Err(Error::Validation("swap record: unknown phase")),
        })
    }

    fn is_terminal(self) -> bool {
        matches!(self, SwapPhase::Completed | SwapPhase::Refunded)
    }

    /// Phases in which a signing session has started (or finished): funding
    /// is confirmed, both escrows are known, and the pre-armed refund exists.
    fn is_post_funding(self) -> bool {
        matches!(
            self,
            SwapPhase::Signing | SwapPhase::Released | SwapPhase::Completing
        )
    }
}

/// The allowed phase graph. Everything not listed is an ordering violation.
/// The load-bearing ABSENCES: no `AbortRefund -> Signing` (a dead session is
/// never resumed — INV-4), no in-place update of a terminal record, and no
/// exit from a terminal EXCEPT the two chain-proven-supersede edges below.
/// `AbortRefund -> Completed` is completion-supersedes: the refund driver
/// discovers the counterparty's completion winning and takes the swap.
/// `AbortRefund -> Completing` is the SL half of the same rule: SH's
/// completion revealed t while our refund path was armed, so recovery
/// EXECUTES the take-the-swap arm — the extracted claim is persisted (rule 3)
/// and babysat exactly like any `Completing`. No signing session resumes
/// (the claim derives from the possession record + the on-chain reveal
/// alone), so INV-4's absence is untouched.
///
/// The two CHAIN-PROVEN-SUPERSEDE exits from a terminal (recovery-owned; a
/// live driver never takes them — a terminal was only ever persisted from a
/// confirmed spend, and only the chain can prove that spend was reverted or
/// misattributed):
/// - `Completed -> AbortRefund`: the swept escrow's confirmed spend is
///   ATTRIBUTED (spending witness vs the persisted completion signature) to a
///   FOREIGN tx — the counterparty's own refund/claim won, so the recorded
///   "paid" terminal is false and our own escrow's exit must be driven.
/// - `Refunded -> Completing`: the mirror — our recorded refund was reorged
///   out and the counterparty's completion confirmed instead, revealing t;
///   recovery executes take-the-swap (rule 3 persist, then babysit).
fn transition_ok(from: SwapPhase, to: SwapPhase) -> bool {
    use SwapPhase::*;
    if from == to {
        // In-place updates (new outpoints, refund attached) are fine while
        // live; terminal records are frozen.
        return !from.is_terminal();
    }
    matches!(
        (from, to),
        (Funding, Signing)
            | (Funding, AbortRefund)
            | (Signing, Released)
            | (Signing, Completing)
            | (Signing, AbortRefund)
            | (Released, Completing)
            | (Released, Completed)
            | (Released, AbortRefund)
            | (Completing, Completed)
            | (Completing, AbortRefund)
            | (AbortRefund, Refunded)
            | (AbortRefund, Completed)
            | (AbortRefund, Completing)
            | (Completed, AbortRefund)
            | (Refunded, Completing)
    )
}

/// Everything the wallet must remember about one swap to meet its deadlines
/// after a crash. See the module docs for what is structurally excluded.
#[derive(Clone, Debug)]
pub struct SwapRecord {
    pub swap_session_id: [u8; 32],
    pub role: Role,
    pub phase: SwapPhase,
    /// Params snapshot this swap was agreed under (a later manifest update
    /// must not silently change a live swap's deadlines). Immutable once the
    /// record exists; re-validated on every put AND every load.
    pub params: Params,
    /// Co-funding baseline S (later of the two funding confirmations).
    /// 0 until known; immutable once set.
    pub s_height: u32,
    /// Confirmation height of the escrow WE sweep (claim-deadline anchor).
    /// 0 until known; immutable once set.
    pub sweep_escrow_height: u32,
    /// The escrow OUR funds sit in (what the pre-armed refund spends).
    /// Write-once.
    pub our_escrow_outpoint: Option<OutPoint>,
    /// The counterparty's escrow (what our completion sweeps). Write-once.
    pub their_escrow_outpoint: Option<OutPoint>,
    /// Pre-armed refund: fully-signed tx + CSV maturity height. MUST be
    /// present the moment `our_escrow_outpoint` is — the store refuses a
    /// record that represents "money locked, no exit" (G2 crash half).
    /// Write-once (a refund is armed exactly once).
    pub pre_armed_refund: Option<PreArmedRefund>,
    /// The finalized completion/claim tx, persisted BEFORE broadcast so a
    /// fresh process can rebroadcast/babysit it. Required at `Completing`.
    /// Write-once.
    pub completion_tx: Option<Vec<u8>>,
    /// The signed Setup tx WE broadcast (spends the pre-encumbrance coin into
    /// our escrow), persisted at `setup_broadcast` so recovery can idempotently
    /// re-submit it if it fell out of every mempool and never confirmed — the
    /// stranded never-confirming-Setup residual (a permanently non-terminal
    /// `AbortRefund` whose refund spends an escrow outpoint that never came to
    /// exist). Present ONLY while pre-`Proceed` (`Funding`/`AbortRefund`): the
    /// funding handoff clears it once both escrows confirm, since a confirmed
    /// escrow's Setup can never need re-broadcast. NOT write-once (it is cleared
    /// at the handoff) but it may never be SWAPPED to a different tx — see
    /// `check_against` — so recovery's rebroadcast can never be redirected.
    pub setup_tx: Option<Vec<u8>>,
    /// SL only: path of the sealed possession record (G1 artifact) that
    /// `Possessing::restore_secret_learner` rebuilds from. REGISTERED AT
    /// `put(Signing)` TIME (the path is deterministic before the file
    /// exists) so a crash inside the exchange never strands the pointer.
    /// Write-once. Must be valid UTF-8 (lossy round-trips are corruption).
    pub possession_record: Option<PathBuf>,
}

impl SwapRecord {
    /// Structural invariants that must hold for a record to be persistable
    /// or loadable. Total: hostile/buggy callers get Err, never a panic.
    /// Deterministic on record CONTENTS only (no filesystem probes — those
    /// live in `put`, so a moved possession store cannot quarantine a valid
    /// record on reload).
    fn check(&self) -> Result<()> {
        self.params.validate()?;
        // G2 crash half: funded escrow => pre-armed refund exists.
        if self.our_escrow_outpoint.is_some() && self.pre_armed_refund.is_none() {
            return Err(Error::Deadline(
                "swap record has a funded escrow but no pre-armed refund (G2)",
            ));
        }
        // Signing starts only after co-funding: both escrows known, S known,
        // refund pre-armed BEFORE any signing session (G2).
        if self.phase.is_post_funding() {
            if self.pre_armed_refund.is_none() {
                return Err(Error::Deadline(
                    "cannot enter a signing phase without the pre-armed refund (G2)",
                ));
            }
            if self.our_escrow_outpoint.is_none() || self.their_escrow_outpoint.is_none() {
                return Err(Error::Ordering(
                    "signing phases require both escrow outpoints (funding precedes Phase 5)",
                ));
            }
            if self.s_height == 0 {
                return Err(Error::Ordering(
                    "signing phases require the co-funding baseline S",
                ));
            }
        }
        // The G1-evidence pointer must exist BEFORE the exchange runs: an SL
        // record cannot enter Signing without its possession-record path.
        if self.phase == SwapPhase::Signing
            && self.role == Role::SecretLearner
            && self.possession_record.is_none()
        {
            return Err(Error::Ordering(
                "SL must register the possession-record path at put(Signing) (G1 pointer)",
            ));
        }
        // Released is G1's post-release window: SL only, possession pointer set.
        if self.phase == SwapPhase::Released {
            if self.role != Role::SecretLearner {
                return Err(Error::Ordering("Released is an SL-only phase"));
            }
            if self.possession_record.is_none() {
                return Err(Error::Ordering(
                    "Released requires a persisted possession record (G1 persist-then-release)",
                ));
            }
        }
        // Completing must be self-sufficient: the tx to babysit is IN the
        // record (persisted before broadcast, per the ordering contract).
        if self.phase == SwapPhase::Completing && self.completion_tx.is_none() {
            return Err(Error::Ordering(
                "Completing requires the finalized completion tx in the record",
            ));
        }
        if self.completion_tx.as_ref().is_some_and(|t| t.is_empty()) {
            return Err(Error::Validation("completion tx must not be empty"));
        }
        if self.setup_tx.as_ref().is_some_and(|t| t.is_empty()) {
            return Err(Error::Validation("setup tx must not be empty"));
        }
        // Reject paths that cannot round-trip losslessly through UTF-8.
        if let Some(p) = &self.possession_record {
            if p.to_str().is_none() {
                return Err(Error::Validation(
                    "possession record path must be valid UTF-8",
                ));
            }
        }
        Ok(())
    }

    /// Immutability rules relative to what is already on disk: identity,
    /// role (post-funding), and params are pinned; money-bearing artifacts are
    /// write-once. This is what makes a "legal put" unable to erase the
    /// refund, flip the role into an SL-only phase, or silently re-deadline a
    /// live swap.
    fn check_against(&self, existing: &SwapRecord) -> Result<()> {
        // Role is pinned from the first post-funding put. While the EXISTING
        // record is still `Funding` it is PROVISIONAL: the real role derives
        // from the two funding txids + S only after both escrows confirm
        // (v3.14), yet the crash-safe early Funding record must exist from the
        // moment our Setup is on the wire — so a put over a still-Funding
        // record may correct it. Sound because no Funding-phase consumer reads
        // role (recovery surfaces the standing refund from the outpoint +
        // pre-armed refund alone; the backstop classifies Funding role-free),
        // and `check()` enforces the SL-only phase constraints against the NEW
        // record's role, so a correction can never smuggle a role into an
        // SL-only phase.
        if self.role != existing.role && existing.phase != SwapPhase::Funding {
            return Err(Error::Ordering("swap record role is immutable after funding"));
        }
        if self.params != existing.params {
            return Err(Error::Ordering(
                "params snapshot is immutable for a live swap",
            ));
        }
        fn frozen<T: PartialEq>(new: &Option<T>, old: &Option<T>, what: &'static str) -> Result<()> {
            match (old, new) {
                (Some(o), Some(n)) if o == n => Ok(()),
                (Some(_), _) => Err(Error::Ordering(what)),
                (None, _) => Ok(()),
            }
        }
        frozen(
            &self.our_escrow_outpoint,
            &existing.our_escrow_outpoint,
            "our escrow outpoint is write-once",
        )?;
        frozen(
            &self.their_escrow_outpoint,
            &existing.their_escrow_outpoint,
            "their escrow outpoint is write-once",
        )?;
        frozen(
            &self.possession_record,
            &existing.possession_record,
            "possession record path is write-once",
        )?;
        frozen(
            &self.completion_tx,
            &existing.completion_tx,
            "completion tx is write-once",
        )?;
        // setup_tx is a rebroadcast aid, not a money-bearing artifact: it is
        // ADDED at setup_broadcast and CLEARED once funding confirms (the
        // funding handoff writes None), so — unlike the write-once fields above
        // — a None-over-Some transition is legal. But it can NEVER be swapped to
        // a DIFFERENT tx: a same-platform-key rewrite must not be able to
        // redirect recovery's idempotent Setup re-submission at a foreign tx.
        if let (Some(o), Some(n)) = (&existing.setup_tx, &self.setup_tx) {
            if o != n {
                return Err(Error::Ordering("setup tx cannot be swapped to a different tx"));
            }
        }
        // PreArmedRefund has no PartialEq; a refund is armed exactly once,
        // so pin by fingerprint.
        match (&existing.pre_armed_refund, &self.pre_armed_refund) {
            (Some(o), Some(n)) if o.fingerprint() == n.fingerprint() => {}
            (Some(_), _) => {
                return Err(Error::Ordering("pre-armed refund is write-once"));
            }
            (None, _) => {}
        }
        for (new_h, old_h, what) in [
            (self.s_height, existing.s_height, "S height is write-once"),
            (
                self.sweep_escrow_height,
                existing.sweep_escrow_height,
                "sweep escrow height is write-once",
            ),
        ] {
            if old_h != 0 && new_h != old_h {
                return Err(Error::Ordering(what));
            }
        }
        Ok(())
    }

    // ---- serialization (record format v4, all integers LE) ----
    //
    // [1 version=4][32 swap_session_id][1 role][1 phase]
    // [60 params: tier(8) fee(8) anchor(8) setup_fee(8) early(4) margin(4)
    //             buffer(4) allowance(4) cofund(4) onboard_lo(4) onboard_hi(4)]
    // [4 s_height][4 sweep_escrow_height][1 flags]
    // (v3 added the scheme-(a) fee components; v4 added the optional setup_tx
    // for the never-confirming-Setup recovery arm. Earlier versions are
    // rejected — no deployed data predates this.)
    // flags bit0: our_outpoint    -> [32 txid][4 vout]
    // flags bit1: their_outpoint  -> [32 txid][4 vout]
    // flags bit2: refund          -> [4 csv_maturity][4 len][len tx bytes]
    // flags bit3: possession path -> [4 len][len utf8]
    // flags bit4: completion tx   -> [4 len][len tx bytes]
    // flags bit5: setup tx        -> [4 len][len tx bytes]
    // Fixed field order, no extension/blob field.

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(256);
        v.push(4u8);
        v.extend_from_slice(&self.swap_session_id);
        v.push(match self.role {
            Role::SecretHolder => 0,
            Role::SecretLearner => 1,
        });
        v.push(self.phase.to_byte());
        v.extend_from_slice(&self.params.tier_d_sats.to_le_bytes());
        v.extend_from_slice(&self.params.delta_fee_sats.to_le_bytes());
        v.extend_from_slice(&self.params.anchor_sats.to_le_bytes());
        v.extend_from_slice(&self.params.setup_fee_sats.to_le_bytes());
        v.extend_from_slice(&self.params.delta_early.to_le_bytes());
        v.extend_from_slice(&self.params.margin.to_le_bytes());
        v.extend_from_slice(&self.params.delta_buffer.to_le_bytes());
        v.extend_from_slice(&self.params.claim_confirm_allowance.to_le_bytes());
        v.extend_from_slice(&self.params.cofunding_window.to_le_bytes());
        v.extend_from_slice(&self.params.onboarding_delay_hours.0.to_le_bytes());
        v.extend_from_slice(&self.params.onboarding_delay_hours.1.to_le_bytes());
        v.extend_from_slice(&self.s_height.to_le_bytes());
        v.extend_from_slice(&self.sweep_escrow_height.to_le_bytes());
        let mut flags = 0u8;
        if self.our_escrow_outpoint.is_some() {
            flags |= 1;
        }
        if self.their_escrow_outpoint.is_some() {
            flags |= 2;
        }
        if self.pre_armed_refund.is_some() {
            flags |= 4;
        }
        if self.possession_record.is_some() {
            flags |= 8;
        }
        if self.completion_tx.is_some() {
            flags |= 16;
        }
        if self.setup_tx.is_some() {
            flags |= 32;
        }
        v.push(flags);
        for op in [&self.our_escrow_outpoint, &self.their_escrow_outpoint]
            .into_iter()
            .flatten()
        {
            v.extend_from_slice(&op.txid.to_byte_array());
            v.extend_from_slice(&op.vout.to_le_bytes());
        }
        if let Some(r) = &self.pre_armed_refund {
            v.extend_from_slice(&r.csv_maturity_height().to_le_bytes());
            v.extend_from_slice(&(r.tx_bytes().len() as u32).to_le_bytes());
            v.extend_from_slice(r.tx_bytes());
        }
        if let Some(p) = &self.possession_record {
            let s = p.to_string_lossy(); // check() guarantees lossless
            let b = s.as_bytes();
            v.extend_from_slice(&(b.len() as u32).to_le_bytes());
            v.extend_from_slice(b);
        }
        if let Some(t) = &self.completion_tx {
            v.extend_from_slice(&(t.len() as u32).to_le_bytes());
            v.extend_from_slice(t);
        }
        if let Some(t) = &self.setup_tx {
            v.extend_from_slice(&(t.len() as u32).to_le_bytes());
            v.extend_from_slice(t);
        }
        v
    }

    /// Total parser: any malformed input is Err, never a panic. Only ever
    /// called on plaintext that already passed GCM authentication — but total
    /// anyway (defense in depth; the parser must not be the trust boundary).
    fn from_bytes(b: &[u8]) -> Result<SwapRecord> {
        let mut at = 0usize;
        let version = take_arr::<1>(b, &mut at)?[0];
        if version != 4 {
            return Err(Error::Validation("swap record: unknown version"));
        }
        let swap_session_id = take_arr::<32>(b, &mut at)?;
        let role = match take_arr::<1>(b, &mut at)?[0] {
            0 => Role::SecretHolder,
            1 => Role::SecretLearner,
            _ => return Err(Error::Validation("swap record: unknown role")),
        };
        let phase = SwapPhase::from_byte(take_arr::<1>(b, &mut at)?[0])?;
        let params = Params {
            tier_d_sats: take_le_u64(b, &mut at)?,
            delta_fee_sats: take_le_u64(b, &mut at)?,
            anchor_sats: take_le_u64(b, &mut at)?,
            setup_fee_sats: take_le_u64(b, &mut at)?,
            delta_early: take_le_u32(b, &mut at)?,
            margin: take_le_u32(b, &mut at)?,
            delta_buffer: take_le_u32(b, &mut at)?,
            claim_confirm_allowance: take_le_u32(b, &mut at)?,
            cofunding_window: take_le_u32(b, &mut at)?,
            onboarding_delay_hours: (take_le_u32(b, &mut at)?, take_le_u32(b, &mut at)?),
        };
        let s_height = take_le_u32(b, &mut at)?;
        let sweep_escrow_height = take_le_u32(b, &mut at)?;
        let flags = take_arr::<1>(b, &mut at)?[0];
        if flags & !0x3f != 0 {
            return Err(Error::Validation("swap record: unknown flag bits"));
        }
        let mut outpoint = |set: bool| -> Result<Option<OutPoint>> {
            if !set {
                return Ok(None);
            }
            let txid = Txid::from_byte_array(take_arr::<32>(b, &mut at)?);
            let vout = take_le_u32(b, &mut at)?;
            Ok(Some(OutPoint::new(txid, vout)))
        };
        let our_escrow_outpoint = outpoint(flags & 1 != 0)?;
        let their_escrow_outpoint = outpoint(flags & 2 != 0)?;
        let pre_armed_refund = if flags & 4 != 0 {
            let maturity = take_le_u32(b, &mut at)?;
            let bytes = take_len_prefixed(b, &mut at, "refund")?;
            Some(PreArmedRefund::from_signed_tx(bytes, maturity)?)
        } else {
            None
        };
        let possession_record = if flags & 8 != 0 {
            let bytes = take_len_prefixed(b, &mut at, "path")?;
            let s = String::from_utf8(bytes)
                .map_err(|_| Error::Validation("swap record: path not utf-8"))?;
            Some(PathBuf::from(s))
        } else {
            None
        };
        let completion_tx = if flags & 16 != 0 {
            Some(take_len_prefixed(b, &mut at, "completion")?)
        } else {
            None
        };
        let setup_tx = if flags & 32 != 0 {
            Some(take_len_prefixed(b, &mut at, "setup")?)
        } else {
            None
        };
        if at != b.len() {
            return Err(Error::Validation("swap record: trailing bytes"));
        }
        let rec = SwapRecord {
            swap_session_id,
            role,
            phase,
            params,
            s_height,
            sweep_escrow_height,
            our_escrow_outpoint,
            their_escrow_outpoint,
            pre_armed_refund,
            completion_tx,
            setup_tx,
            possession_record,
        };
        // Loaded records must satisfy the same structural invariants as
        // persisted ones (re-checked at every trust boundary).
        rec.check()?;
        Ok(rec)
    }
}

// ----- Store -----------------------------------------------------------------

/// What `open` had to do (or failed to do) to bring the store to a safe
/// state. These are USER-FACING notifications — `Quarantined` in particular
/// must be surfaced loudly, because the swap it names is no longer tracked.
/// Drivers do NOT consume these: they scan records (see the module docs'
/// ordering contract, rule 4), so a crash after `open` loses no work.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// A live signing session died with the process AND no possession record
    /// exists: nothing was released. Routed to ABORT_REFUND (INV-2); the
    /// refund driver picks it up from the record.
    AbortedLiveSigning { swap_session_id: [u8; 32] },
    /// A live signing session died AFTER the possession record was persisted
    /// (persist-then-release: the enabling partial may be on the wire).
    /// Routed to RELEASED — restore-and-extract, with `Released ->
    /// AbortRefund` as the fallback if the counterparty never completes.
    RestoredPostRelease { swap_session_id: [u8; 32] },
    /// A record failed GCM authentication or parsing: tampered, corrupt, or
    /// sealed under a different platform key. Renamed aside (never deleted —
    /// the bytes may still matter forensically), swap NO LONGER TRACKED.
    /// This must reach the user as an alarm, not a log line.
    Quarantined { path: PathBuf },
    /// A file could not be read at all (I/O). Left in place; the swap is
    /// invisible until the I/O condition clears. NOT quarantined — transient
    /// I/O must not destroy tracking.
    Unreadable { path: PathBuf },
    /// A recovery rewrite (Signing -> AbortRefund/Released) could not be
    /// written. The record is UNCHANGED on disk (still Signing); the next
    /// `open` will retry. Surfaced so the user knows recovery is incomplete.
    RewriteFailed { swap_session_id: [u8; 32] },
}

/// Crash-safe, sealed-at-rest swap store. One instance per wallet data dir,
/// enforced by an OS file lock (auto-released on process death, so a crash
/// never wedges the store shut).
pub struct SwapStore {
    dir: PathBuf,
    platform_key: [u8; 32],
    /// Held for the store's lifetime; the OS drops it if we die.
    _dir_lock: std::fs::File,
    /// Serializes read-check-write cycles within this process: `put`'s
    /// transition check and `open`'s recovery rewrites are atomic w.r.t.
    /// each other.
    write_gate: Mutex<()>,
}

impl SwapStore {
    /// Open (or create) the store and bring it to a SAFE state: any record
    /// found mid-signing-session is routed by G1 evidence — `Released` if
    /// its possession record exists and authenticates (the enabling partial
    /// may be on the wire; restore-and-extract), `AbortRefund` otherwise
    /// (INV-2; nothing was released). Per-record failures never abort the
    /// scan: one bad file must not hide every other swap's deadlines.
    pub fn open(
        dir: &Path,
        enclave: &dyn EnclaveKeyProvider,
    ) -> Result<(SwapStore, Vec<RecoveryAction>)> {
        std::fs::create_dir_all(dir).map_err(|_| Error::Abort("swap store dir unavailable"))?;
        // Exclusive advisory lock: a second wallet process gets a clean
        // refusal instead of torn read-check-write races. The OS releases
        // the lock when the holder dies — crash-safe by construction.
        let lock_path = dir.join(".store.lock");
        let dir_lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| Error::Abort("swap store lock file unavailable"))?;
        if dir_lock.try_lock().is_err() {
            return Err(Error::Abort(
                "another process holds this swap store (single-instance)",
            ));
        }
        let store = SwapStore {
            dir: dir.to_path_buf(),
            platform_key: enclave.platform_key(),
            _dir_lock: dir_lock,
            write_gate: Mutex::new(()),
        };
        let mut actions = Vec::new();
        let entries =
            std::fs::read_dir(dir).map_err(|_| Error::Abort("swap store dir unreadable"))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(sid) = sid_from_path(&path) else { continue };
            let sealed = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => {
                    actions.push(RecoveryAction::Unreadable { path });
                    continue;
                }
            };
            let tek = crate::crypto::storage::derive_tek(&store.platform_key, &sid);
            let rec = crate::crypto::storage::open(&tek, &sealed)
                .and_then(|pt| SwapRecord::from_bytes(&pt))
                // The filename must agree with the sealed identity. (Cross-swap
                // splices already fail the per-swap TEK; this catches same-key
                // renames.)
                .and_then(|r| {
                    if r.swap_session_id == sid {
                        Ok(r)
                    } else {
                        Err(Error::Validation("swap record: filename/identity mismatch"))
                    }
                });
            let mut rec = match rec {
                Ok(r) => r,
                Err(_) => {
                    match quarantine(&path) {
                        Ok(qpath) => actions.push(RecoveryAction::Quarantined { path: qpath }),
                        Err(_) => actions.push(RecoveryAction::Unreadable { path }),
                    }
                    continue;
                }
            };
            if rec.phase == SwapPhase::Signing {
                // G1 evidence: persist-then-release means an authenticating
                // possession record implies the release MAY have happened —
                // and Released is the safe phase in BOTH sub-cases (extract
                // on reveal; `Released -> AbortRefund` if the counterparty
                // never completes). No possession record => nothing released
                // => refund.
                let action;
                if rec.role == Role::SecretLearner
                    && store.possession_record_authenticates(&rec)
                {
                    rec.phase = SwapPhase::Released;
                    action = RecoveryAction::RestoredPostRelease { swap_session_id: sid };
                } else {
                    rec.phase = SwapPhase::AbortRefund;
                    action = RecoveryAction::AbortedLiveSigning { swap_session_id: sid };
                }
                // A failed rewrite must not abort the whole scan: the record
                // stays Signing on disk and the next open retries.
                match store.write_record(&rec) {
                    Ok(()) => actions.push(action),
                    Err(_) => {
                        actions.push(RecoveryAction::RewriteFailed { swap_session_id: sid })
                    }
                }
            }
        }
        Ok((store, actions))
    }

    /// Does the record's possession pointer resolve to a file that
    /// authenticates under this swap's TEK? (Existence alone is not enough —
    /// a truncated/corrupt file must route to refund, not to a Released
    /// record that can never restore.)
    fn possession_record_authenticates(&self, rec: &SwapRecord) -> bool {
        let Some(path) = &rec.possession_record else { return false };
        let Ok(sealed) = std::fs::read(path) else { return false };
        let tek =
            crate::crypto::storage::derive_tek(&self.platform_key, &rec.swap_session_id);
        crate::crypto::storage::open(&tek, &sealed).is_ok()
    }

    /// Persist a record. Enforces the structural invariants, the phase
    /// transition table, and the immutability rules against whatever is
    /// already on disk. First insert must be `Funding` — a swap cannot
    /// appear mid-flight from nowhere.
    pub fn put(&self, rec: &SwapRecord) -> Result<()> {
        rec.check()?;
        let _gate = self.write_gate.lock().map_err(|_| Error::Abort("store gate poisoned"))?;
        match self.get(&rec.swap_session_id)? {
            None => {
                if rec.phase != SwapPhase::Funding {
                    return Err(Error::Ordering("new swap records must start in Funding"));
                }
            }
            Some(existing) => {
                if !transition_ok(existing.phase, rec.phase) {
                    return Err(Error::Ordering("illegal swap phase transition"));
                }
                rec.check_against(&existing)?;
            }
        }
        // Entering Released via put is a claim that G1's persist happened:
        // verify it (open's recovery path verifies independently).
        if rec.phase == SwapPhase::Released && !self.possession_record_authenticates(rec) {
            return Err(Error::Ordering(
                "Released requires an existing, authenticating possession record",
            ));
        }
        self.write_record(rec)
    }

    /// Load one record. `Ok(None)` if absent. A record that fails GCM/parse
    /// is an Err — `get` never guesses. (Startup-time cleanup is `open`'s job.)
    pub fn get(&self, swap_session_id: &[u8; 32]) -> Result<Option<SwapRecord>> {
        let path = self.record_path(swap_session_id);
        let sealed = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Abort("swap record unreadable")),
        };
        let tek = crate::crypto::storage::derive_tek(&self.platform_key, swap_session_id);
        let pt = crate::crypto::storage::open(&tek, &sealed)?;
        let rec = SwapRecord::from_bytes(&pt)?;
        if &rec.swap_session_id != swap_session_id {
            return Err(Error::Validation("swap record: filename/identity mismatch"));
        }
        Ok(Some(rec))
    }

    /// All live (non-quarantined) records, plus the paths of any records
    /// that could not be loaded. A single bad file never hides the rest —
    /// and never silently: the failures come back alongside the successes.
    pub fn list(&self) -> Result<(Vec<SwapRecord>, Vec<PathBuf>)> {
        let mut out = Vec::new();
        let mut failed = Vec::new();
        let entries =
            std::fs::read_dir(&self.dir).map_err(|_| Error::Abort("swap store dir unreadable"))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(sid) = sid_from_path(&path) {
                match self.get(&sid) {
                    Ok(Some(rec)) => out.push(rec),
                    Ok(None) => {}
                    Err(_) => failed.push(path),
                }
            }
        }
        Ok((out, failed))
    }

    fn record_path(&self, sid: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.swap", hex32(sid)))
    }

    /// Seal + durable atomic replace: write tmp, fsync the FILE, rename over
    /// the record. The fsync closes the power-loss window in which a rename
    /// could land before the data blocks (a truncated record would quarantine
    /// — untracking a fund-bearing swap). Directory-entry durability is
    /// filesystem-specific; on NTFS the metadata journal covers the rename.
    fn write_record(&self, rec: &SwapRecord) -> Result<()> {
        let tek = crate::crypto::storage::derive_tek(&self.platform_key, &rec.swap_session_id);
        let sealed = crate::crypto::storage::seal(&tek, &rec.to_bytes())?;
        let path = self.record_path(&rec.swap_session_id);
        let tmp = self.dir.join(format!("{}.swap.tmp", hex32(&rec.swap_session_id)));
        let mut f = std::fs::File::create(&tmp)
            .map_err(|_| Error::Abort("swap record tmp create failed"))?;
        f.write_all(&sealed)
            .and_then(|()| f.sync_all())
            .map_err(|_| Error::Abort("swap record write/sync failed"))?;
        drop(f);
        std::fs::rename(&tmp, &path).map_err(|_| Error::Abort("swap record rename failed"))?;
        Ok(())
    }
}

/// `<64 hex>.swap` -> sid. Anything else (tmp files, quarantine, lock file,
/// strangers) is not a record.
fn sid_from_path(path: &Path) -> Option<[u8; 32]> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".swap")?;
    if stem.len() != 64 {
        return None;
    }
    let mut sid = [0u8; 32];
    for (i, chunk) in stem.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        sid[i] = (hi << 4) | lo;
    }
    Some(sid)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex32(id: &[u8; 32]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Move a bad record aside without destroying it. Bounded numbered suffixes so
/// repeated corruption cannot loop forever.
fn quarantine(path: &Path) -> Result<PathBuf> {
    for n in 0u32..1000 {
        let q = path.with_extension(format!("swap.quarantine{n}"));
        if !q.exists() {
            std::fs::rename(path, &q).map_err(|_| Error::Abort("quarantine rename failed"))?;
            return Ok(q);
        }
    }
    Err(Error::Abort("quarantine namespace exhausted"))
}

fn take_arr<const N: usize>(b: &[u8], at: &mut usize) -> Result<[u8; N]> {
    let s = b
        .get(*at..*at + N)
        .ok_or(Error::Validation("swap record truncated"))?;
    *at += N;
    s.try_into().map_err(|_| Error::Validation("array slice"))
}

fn take_le_u32(b: &[u8], at: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take_arr::<4>(b, at)?))
}

fn take_le_u64(b: &[u8], at: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take_arr::<8>(b, at)?))
}

fn take_len_prefixed(b: &[u8], at: &mut usize, what: &'static str) -> Result<Vec<u8>> {
    let len = take_le_u32(b, at)? as usize;
    let end = at
        .checked_add(len)
        .ok_or(Error::Validation("swap record: length overflow"))?;
    let s = b.get(*at..end).ok_or(match what {
        "refund" => Error::Validation("swap record truncated (refund)"),
        "path" => Error::Validation("swap record truncated (path)"),
        "setup" => Error::Validation("swap record truncated (setup)"),
        _ => Error::Validation("swap record truncated (completion)"),
    })?;
    *at = end;
    Ok(s.to_vec())
}

// ----- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn refund() -> PreArmedRefund {
        PreArmedRefund::from_signed_tx(vec![0xab; 64], 700_144).expect("refund")
    }

    fn outpoint(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(Txid::from_byte_array(b), 0)
    }

    /// Base record: SL, fully funded, possession pointer registered (as the
    /// ordering contract requires at put(Signing)).
    fn base_record(seed: u8, phase: SwapPhase) -> SwapRecord {
        SwapRecord {
            swap_session_id: sid(seed),
            role: Role::SecretLearner,
            phase,
            params: Params::testnet_provisional(),
            s_height: 700_000,
            sweep_escrow_height: 699_995,
            our_escrow_outpoint: Some(outpoint(1)),
            their_escrow_outpoint: Some(outpoint(2)),
            pre_armed_refund: Some(refund()),
            completion_tx: None,
            setup_tx: None,
            possession_record: Some(PathBuf::from("possession/never-written")),
        }
    }

    fn open_store(dir: &Path) -> (SwapStore, Vec<RecoveryAction>) {
        SwapStore::open(dir, &ModeledEnclave).expect("open store")
    }

    /// Write a REAL sealed possession-record stand-in (authenticates under
    /// the swap's TEK; content is opaque to the store) and point rec at it.
    fn attach_real_possession(dir: &Path, rec: &mut SwapRecord) {
        let tek = crate::crypto::storage::derive_tek(
            &ModeledEnclave.platform_key(),
            &rec.swap_session_id,
        );
        let sealed = crate::crypto::storage::seal(&tek, b"possession bytes").unwrap();
        let path = dir.join(format!("{}.possession", hex32(&rec.swap_session_id)));
        std::fs::write(&path, sealed).unwrap();
        rec.possession_record = Some(path);
    }

    #[test]
    fn round_trips_a_full_record() {
        let dir = tempfile::tempdir().unwrap();
        let (store, actions) = open_store(dir.path());
        assert!(actions.is_empty());

        let mut rec = base_record(7, SwapPhase::Funding);
        rec.completion_tx = Some(vec![0xcd; 80]);
        rec.setup_tx = Some(vec![0x5e; 120]);
        store.put(&rec).expect("put");

        let got = store.get(&sid(7)).expect("get").expect("present");
        assert_eq!(got.swap_session_id, rec.swap_session_id);
        assert_eq!(got.role, rec.role);
        assert_eq!(got.phase, rec.phase);
        assert_eq!(got.params, rec.params);
        assert_eq!(got.s_height, rec.s_height);
        assert_eq!(got.sweep_escrow_height, rec.sweep_escrow_height);
        assert_eq!(got.our_escrow_outpoint, rec.our_escrow_outpoint);
        assert_eq!(got.their_escrow_outpoint, rec.their_escrow_outpoint);
        assert_eq!(
            got.pre_armed_refund.as_ref().unwrap().tx_bytes(),
            rec.pre_armed_refund.as_ref().unwrap().tx_bytes()
        );
        assert_eq!(
            got.pre_armed_refund.as_ref().unwrap().csv_maturity_height(),
            rec.pre_armed_refund.as_ref().unwrap().csv_maturity_height()
        );
        assert_eq!(got.completion_tx, rec.completion_tx);
        assert_eq!(got.setup_tx, rec.setup_tx);
        assert_eq!(got.possession_record, rec.possession_record);
        let (recs, failed) = store.list().unwrap();
        assert_eq!(recs.len(), 1);
        assert!(failed.is_empty());
    }

    #[test]
    fn record_is_sealed_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());
        let mut rec = base_record(9, SwapPhase::Funding);
        let marker = "SECRET-PATH-MARKER-must-not-appear-in-plaintext";
        rec.possession_record = Some(PathBuf::from(marker));
        store.put(&rec).unwrap();

        let raw = std::fs::read(store.record_path(&sid(9))).unwrap();
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "possession path leaked to disk in plaintext"
        );
        assert!(
            !raw.windows(64).any(|w| w == [0xab; 64]),
            "refund tx bytes leaked to disk in plaintext"
        );
    }

    #[test]
    fn live_signing_without_possession_record_aborts_and_is_not_resumable() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = open_store(dir.path());
            store.put(&base_record(3, SwapPhase::Funding)).unwrap();
            // Possession pointer registered but the file NEVER written: the
            // crash happened before the exchange persisted anything.
            store.put(&base_record(3, SwapPhase::Signing)).unwrap();
            // process "crashes" here — the in-memory session is gone
        }
        // Fresh process: INV-2 — nothing released, dead session => ABORT_REFUND.
        let (store, actions) = open_store(dir.path());
        assert_eq!(
            actions,
            vec![RecoveryAction::AbortedLiveSigning { swap_session_id: sid(3) }]
        );
        let rec = store.get(&sid(3)).unwrap().unwrap();
        assert_eq!(rec.phase, SwapPhase::AbortRefund);

        // INV-4 at the wallet layer: the aborted swap is NON-RESUMABLE — there
        // is no AbortRefund -> Signing edge. A retry is a brand-new swap.
        let err = store.put(&base_record(3, SwapPhase::Signing)).unwrap_err();
        assert!(matches!(err, Error::Ordering(_)), "got {err:?}");
        // The refund path stays open, and completion-supersedes stays legal.
        store.put(&base_record(3, SwapPhase::Refunded)).unwrap();
    }

    /// THE critical from the adversarial review: a crash AFTER the exchange
    /// persisted the possession record (release may be on the wire) must
    /// route to Released — restore-and-extract — not to a refund that would
    /// strand SL when SH completes normally.
    #[test]
    fn live_signing_with_persisted_possession_routes_to_released() {
        let dir = tempfile::tempdir().unwrap();
        let poss_dir = tempfile::tempdir().unwrap();
        let mut rec = base_record(12, SwapPhase::Funding);
        attach_real_possession(poss_dir.path(), &mut rec);
        {
            let (store, _) = open_store(dir.path());
            store.put(&rec).unwrap();
            rec.phase = SwapPhase::Signing;
            store.put(&rec).unwrap();
            // crash INSIDE the exchange, after write_possession_record —
            // the possession record exists and authenticates.
        }
        let (store, actions) = open_store(dir.path());
        assert_eq!(
            actions,
            vec![RecoveryAction::RestoredPostRelease { swap_session_id: sid(12) }]
        );
        assert_eq!(store.get(&sid(12)).unwrap().unwrap().phase, SwapPhase::Released);

        // A TRUNCATED/corrupt possession file must NOT route to Released:
        // existence is not authentication.
        let mut rec2 = base_record(13, SwapPhase::Funding);
        attach_real_possession(poss_dir.path(), &mut rec2);
        let p = rec2.possession_record.clone().unwrap();
        let mut bytes = std::fs::read(&p).unwrap();
        bytes.truncate(bytes.len() / 2);
        std::fs::write(&p, bytes).unwrap();
        drop(store);
        {
            let (store, _) = open_store(dir.path());
            store.put(&rec2).unwrap();
            rec2.phase = SwapPhase::Signing;
            store.put(&rec2).unwrap();
        }
        let (_, actions) = open_store(dir.path());
        assert!(
            actions.contains(&RecoveryAction::AbortedLiveSigning { swap_session_id: sid(13) }),
            "corrupt possession record must abort, got {actions:?}"
        );
    }

    #[test]
    fn released_records_survive_restart_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let poss_dir = tempfile::tempdir().unwrap();
        let mut rec = base_record(4, SwapPhase::Funding);
        attach_real_possession(poss_dir.path(), &mut rec);
        {
            let (store, _) = open_store(dir.path());
            store.put(&rec).unwrap();
            rec.phase = SwapPhase::Signing;
            store.put(&rec).unwrap();
            rec.phase = SwapPhase::Released;
            store.put(&rec).unwrap();
        }
        // Post-G1 crash: restore-and-extract, NOT abort — open leaves it be.
        let (store, actions) = open_store(dir.path());
        assert!(actions.is_empty(), "Released must not be force-aborted: {actions:?}");
        assert_eq!(store.get(&sid(4)).unwrap().unwrap().phase, SwapPhase::Released);
    }

    #[test]
    fn put_released_requires_authenticating_possession_record() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());
        let mut rec = base_record(14, SwapPhase::Funding);
        store.put(&rec).unwrap();
        rec.phase = SwapPhase::Signing;
        store.put(&rec).unwrap();
        // The pointer targets a file that was never written: G1's persist
        // did not happen, so claiming Released is an ordering violation.
        rec.phase = SwapPhase::Released;
        let err = store.put(&rec).unwrap_err();
        assert!(matches!(err, Error::Ordering(_)), "got {err:?}");
    }

    #[test]
    fn illegal_transitions_and_malformed_records_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());

        // A swap cannot appear from nowhere mid-flight.
        let err = store.put(&base_record(5, SwapPhase::Signing)).unwrap_err();
        assert!(matches!(err, Error::Ordering(_)));

        // Terminal phases are frozen.
        store.put(&base_record(5, SwapPhase::Funding)).unwrap();
        store.put(&base_record(5, SwapPhase::AbortRefund)).unwrap();
        store.put(&base_record(5, SwapPhase::Refunded)).unwrap();
        for next in [SwapPhase::Funding, SwapPhase::Signing, SwapPhase::Refunded] {
            assert!(store.put(&base_record(5, next)).is_err(), "{next:?} after terminal");
        }

        // G2 crash half: funded escrow without a pre-armed refund is
        // unrepresentable.
        let mut noexit = base_record(6, SwapPhase::Funding);
        noexit.pre_armed_refund = None;
        let err = store.put(&noexit).unwrap_err();
        assert!(matches!(err, Error::Deadline(_)), "got {err:?}");

        // Signing without funding completed (missing outpoints / S) is
        // unrepresentable — Phase 5 starts only after co-funding.
        let mut nofund = base_record(6, SwapPhase::Signing);
        nofund.our_escrow_outpoint = None;
        nofund.pre_armed_refund = None;
        assert!(store.put(&nofund).is_err());
        let mut no_s = base_record(6, SwapPhase::Signing);
        no_s.s_height = 0;
        assert!(store.put(&no_s).is_err());

        // SL entering Signing must carry the G1 pointer.
        let mut no_ptr = base_record(6, SwapPhase::Signing);
        no_ptr.possession_record = None;
        assert!(store.put(&no_ptr).is_err());

        // Released demands SL role.
        let mut sh_rel = base_record(6, SwapPhase::Released);
        sh_rel.role = Role::SecretHolder;
        assert!(store.put(&sh_rel).is_err());

        // Completing without the persisted completion tx is unrepresentable.
        let comp = base_record(6, SwapPhase::Completing);
        assert!(comp.completion_tx.is_none());
        assert!(store.put(&comp).is_err());

        // Hostile params snapshots are rejected on put.
        let mut bad_params = base_record(6, SwapPhase::Funding);
        bad_params.params.margin = 0;
        assert!(store.put(&bad_params).is_err());

        // AbortRefund -> Completing is the SL completion-supersedes edge
        // (recovery persists the extracted claim, rule 3); AbortRefund ->
        // Signing stays ABSENT (INV-4: a dead session never resumes).
        store.put(&base_record(8, SwapPhase::Funding)).unwrap();
        store.put(&base_record(8, SwapPhase::AbortRefund)).unwrap();
        assert!(
            store.put(&base_record(8, SwapPhase::Signing)).is_err(),
            "INV-4: AbortRefund -> Signing must stay illegal"
        );
        let mut take = base_record(8, SwapPhase::Completing);
        take.completion_tx = Some(vec![0xcd; 64]);
        store
            .put(&take)
            .expect("AbortRefund -> Completing (completion-supersedes) must be legal");
    }

    #[test]
    fn identity_and_money_fields_are_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());
        let rec = base_record(15, SwapPhase::Funding);
        store.put(&rec).unwrap();

        // Params mutation rejected (re-deadlining a live swap).
        let mut repar = rec.clone();
        repar.params.delta_buffer += 1;
        assert!(matches!(store.put(&repar).unwrap_err(), Error::Ordering(_)));

        // Outpoint erasure/replacement rejected.
        let mut noout = rec.clone();
        noout.our_escrow_outpoint = None;
        // (also trips G2? no — refund still present; erasure alone must trip)
        assert!(matches!(store.put(&noout).unwrap_err(), Error::Ordering(_)));
        let mut swapout = rec.clone();
        swapout.our_escrow_outpoint = Some(outpoint(99));
        assert!(matches!(store.put(&swapout).unwrap_err(), Error::Ordering(_)));

        // Refund erasure/replacement rejected.
        let mut noref = rec.clone();
        noref.pre_armed_refund = None;
        assert!(store.put(&noref).is_err()); // Deadline (G2) or Ordering — both refuse
        let mut reref = rec.clone();
        reref.pre_armed_refund =
            Some(PreArmedRefund::from_signed_tx(vec![0xEE; 64], 700_144).unwrap());
        assert!(matches!(store.put(&reref).unwrap_err(), Error::Ordering(_)));

        // Possession pointer retarget rejected.
        let mut repath = rec.clone();
        repath.possession_record = Some(PathBuf::from("somewhere/else"));
        assert!(matches!(store.put(&repath).unwrap_err(), Error::Ordering(_)));

        // Height rewrites rejected once set.
        let mut re_s = rec.clone();
        re_s.s_height += 1;
        assert!(matches!(store.put(&re_s).unwrap_err(), Error::Ordering(_)));
    }

    /// setup_tx is the ONE non-write-once payload: it may be ADDED at
    /// setup_broadcast and CLEARED at the funding handoff (None-over-Some), but
    /// never SWAPPED to a different tx — so recovery's idempotent Setup
    /// re-submission can never be redirected by a same-key rewrite.
    #[test]
    fn setup_tx_is_addable_clearable_but_never_swapped() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());

        // Add at Funding.
        let mut rec = base_record(22, SwapPhase::Funding);
        rec.setup_tx = Some(vec![0x5e; 64]);
        store.put(&rec).unwrap();
        assert_eq!(store.get(&sid(22)).unwrap().unwrap().setup_tx, Some(vec![0x5e; 64]));

        // Swapping to a DIFFERENT tx is refused (would redirect recovery).
        let mut swapped = rec.clone();
        swapped.setup_tx = Some(vec![0x11; 64]);
        assert!(
            matches!(store.put(&swapped).unwrap_err(), Error::Ordering(_)),
            "setup_tx must not be swappable to a different tx"
        );

        // Re-putting the SAME bytes is fine (idempotent).
        store.put(&rec).unwrap();

        // Clearing to None (the funding handoff) is allowed…
        let mut cleared = rec.clone();
        cleared.setup_tx = None;
        store.put(&cleared).unwrap();
        assert_eq!(store.get(&sid(22)).unwrap().unwrap().setup_tx, None);

        // …and once cleared, a fresh Setup value can be re-added (None-over-None
        // and None-old are both unconstrained — the swap-guard only bites
        // Some→different-Some).
        let mut readd = cleared.clone();
        readd.setup_tx = Some(vec![0x22; 64]);
        store.put(&readd).unwrap();
        assert_eq!(store.get(&sid(22)).unwrap().unwrap().setup_tx, Some(vec![0x22; 64]));

        // Empty setup bytes are rejected structurally (like an empty completion).
        let mut empty = readd.clone();
        empty.setup_tx = Some(vec![]);
        assert!(matches!(store.put(&empty).unwrap_err(), Error::Validation(_)));
    }

    /// The provisional-role rule: role is CORRECTABLE while the on-disk record
    /// is still `Funding` (the early crash-safe record is written before the
    /// role is derivable from txids+S), and PINNED from the first post-funding
    /// put onward (flipping it later would dodge the role-gated phase rules).
    #[test]
    fn provisional_role_corrects_while_funding_then_pins() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());

        // Early record with the provisional guess (SH).
        let mut early = base_record(21, SwapPhase::Funding);
        early.role = Role::SecretHolder;
        early.possession_record = None; // pre-exchange, no G1 pointer yet
        store.put(&early).unwrap();

        // The Proceed handoff derives the REAL role (SL here) and corrects it
        // while the record is still Funding — allowed.
        let mut corrected = early.clone();
        corrected.role = Role::SecretLearner;
        store.put(&corrected).expect("role correction while Funding is legal");
        assert_eq!(store.get(&sid(21)).unwrap().unwrap().role, Role::SecretLearner);

        // Advance past funding (Signing pins it; SL needs its G1 pointer).
        let mut signing = corrected.clone();
        signing.phase = SwapPhase::Signing;
        attach_real_possession(dir.path(), &mut signing);
        store.put(&signing).unwrap();

        // Any role change after funding is rejected — even phase-preserving.
        let mut flip = store.get(&sid(21)).unwrap().unwrap();
        flip.role = Role::SecretHolder;
        assert!(
            matches!(store.put(&flip).unwrap_err(), Error::Ordering(_)),
            "role must be immutable once past Funding"
        );
    }

    #[test]
    fn non_utf8_possession_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());
        let mut rec = base_record(16, SwapPhase::Funding);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            // Unpaired surrogate: valid OsString, not representable in UTF-8.
            let bad = std::ffi::OsString::from_wide(&[0x0070, 0xD800, 0x0071]);
            rec.possession_record = Some(PathBuf::from(bad));
            let err = store.put(&rec).unwrap_err();
            assert!(matches!(err, Error::Validation(_)), "got {err:?}");
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = std::ffi::OsString::from_vec(vec![0x70, 0xff, 0x71]);
            rec.possession_record = Some(PathBuf::from(bad));
            let err = store.put(&rec).unwrap_err();
            assert!(matches!(err, Error::Validation(_)), "got {err:?}");
        }
    }

    #[test]
    fn tampered_and_foreign_key_records_are_quarantined_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = open_store(dir.path());
            store.put(&base_record(8, SwapPhase::Funding)).unwrap();
            store.put(&base_record(10, SwapPhase::Funding)).unwrap();
            let p = store.record_path(&sid(8));
            let mut raw = std::fs::read(&p).unwrap();
            let last = raw.len() - 1;
            raw[last] ^= 0x01;
            std::fs::write(&p, &raw).unwrap();
        }
        // Reopen: the tampered record is quarantined (GCM fails), the healthy
        // one is untouched, and open() itself succeeds — one bad file must
        // not brick the wallet.
        let (store, actions) = open_store(dir.path());
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], RecoveryAction::Quarantined { .. }));
        assert!(store.get(&sid(8)).unwrap().is_none(), "tampered record still tracked");
        assert!(store.get(&sid(10)).unwrap().is_some(), "healthy record lost");
        // list() reports cleanly with the bad record quarantined away.
        let (recs, failed) = store.list().unwrap();
        assert_eq!(recs.len(), 1);
        assert!(failed.is_empty());

        // A store under a DIFFERENT platform key cannot read these records
        // (device-bound custody): they quarantine, they do not decrypt.
        struct OtherEnclave;
        impl EnclaveKeyProvider for OtherEnclave {
            fn platform_key(&self) -> [u8; 32] {
                [0x5e; 32]
            }
        }
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::copy(
            store.record_path(&sid(10)),
            dir2.path().join(format!("{}.swap", hex32(&sid(10)))),
        )
        .unwrap();
        let (store2, actions2) = SwapStore::open(dir2.path(), &OtherEnclave).expect("open");
        assert_eq!(actions2.len(), 1);
        assert!(matches!(actions2[0], RecoveryAction::Quarantined { .. }));
        assert!(store2.get(&sid(10)).unwrap().is_none());
    }

    #[test]
    fn second_store_instance_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, _) = open_store(dir.path());
        // Same process or another: the OS lock refuses a second live store
        // on the same dir (torn read-check-write prevention).
        match SwapStore::open(dir.path(), &ModeledEnclave) {
            Err(Error::Abort(_)) => {}
            Err(e) => panic!("wrong error: {e:?}"),
            Ok(_) => panic!("second instance must be refused"),
        }
    }

    #[test]
    fn store_reopens_after_crash_lock_released() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = open_store(dir.path());
            store.put(&base_record(17, SwapPhase::Funding)).unwrap();
            // store dropped here = process exit; OS releases the lock
        }
        let (store, _) = open_store(dir.path());
        assert!(store.get(&sid(17)).unwrap().is_some());
    }

    #[test]
    fn crashed_lease_and_store_abort_compose() {
        // INV-2 + INV-3 together at the wallet layer: after a crash mid-signing,
        // (a) the store routes the swap to ABORT_REFUND, and (b) the signing
        // lease is still held on disk, so a zombie/second process CANNOT start
        // signing the same swap even if it ignores the store.
        let dir = tempfile::tempdir().unwrap();
        let lease_dir = tempfile::tempdir().unwrap();
        let swap_sid = sid(11);
        {
            let (store, _) = open_store(dir.path());
            store.put(&base_record(11, SwapPhase::Funding)).unwrap();
            let lease =
                crate::signing::SingleSignerLease::acquire_in(lease_dir.path(), swap_sid)
                    .expect("lease");
            store.put(&base_record(11, SwapPhase::Signing)).unwrap();
            // Crash: Drop never runs; the lease file stays held.
            std::mem::forget(lease);
        }
        let (store, actions) = open_store(dir.path());
        assert_eq!(
            actions,
            vec![RecoveryAction::AbortedLiveSigning { swap_session_id: swap_sid }]
        );
        assert_eq!(store.get(&swap_sid).unwrap().unwrap().phase, SwapPhase::AbortRefund);
        // The lease still refuses a second signer (INV-3 held conservatively).
        let err = crate::signing::SingleSignerLease::acquire_in(lease_dir.path(), swap_sid)
            .unwrap_err();
        assert!(matches!(err, Error::NonceInvariant(_)), "got {err:?}");
    }
}
