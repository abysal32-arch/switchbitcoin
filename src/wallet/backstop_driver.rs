//! Single-swap congestion backstop — the CPFP/watchtower counterpart to
//! [`SwapDriver`](crate::wallet::driver::SwapDriver), and the primary-INDEPENDENT
//! half of the orchestration layer.
//!
//! [`BackstopDriver`] wraps a [`WatchtowerDriver`] and, on each `tick`, holds the
//! "forward-or-refund at all costs" invariant under a rising mempool fee floor.
//! It composes two independent concerns on two different escrows. The REFUND
//! side (`E_ours`, the escrow our pre-armed refund spends) is owned by the tower,
//! which fires the dead-device refund at CSV maturity and surfaces the refund's
//! own relay-floor congestion. The COMPLETION/SETUP side (`E_theirs`, the escrow
//! our completion sweeps) is owned by the canonical record→[`StalledTx`]
//! classifier plus the pure [`backstop_decision`] table, which decide what to do
//! about OUR stalled tx.
//!
//! The two are separate txs on separate escrows and are both live during
//! `Completing`, so the tower owns the refund ENTIRELY and `classify_stalled_tx`
//! owns ONLY the non-refund side — they never double-handle.
//!
//! # Scope (increment 2a — the CPFP bump is wired)
//! [`tick`](BackstopDriver::tick) is a PURE decision: the caller passes
//! `reserve_available` (computed from the ledger via
//! [`Ledger::has_leasable_reserve`](crate::wallet::ledger::Ledger::has_leasable_reserve)
//! sized against [`required_child_fee`](crate::tx::backstop::required_child_fee)),
//! and `tick` routes each congested case. When no suitable reserve exists every
//! path is a SAFE fallback — `KeepWaiting` (refund), `FallbackToRefund`
//! (unbroadcast completion), `KeepFighting` (in-flight/revealed completion),
//! `AbortBeforeLock` (setup) — plus the dead-device refund fire; none strands a
//! coin or misses a deadline, so fund-safety holds with the bump inert. When a
//! reserve IS available the decision is [`BackstopTick::Bump`] (silent, refund)
//! or [`BackstopTick::NeedsConsent`] (a completion bump links the reserve's
//! provenance, so it awaits a privacy `LinkageAck`), and the caller EXECUTES the
//! 1P1C bump via [`run_cpfp_bump`] — lease → build → enclave-sign → submit →
//! mark-spent, releasing the lease on any failure so a reserve is never
//! stranded. What remains for a full deployment: a PRODUCTION path that MINTS a
//! reserve (onboarding promoting change instead of folding it to fee) and the
//! dead-device reserve-key custody (who holds the `KeySource` when the owner's
//! device is down); the bump machinery here is complete and test-driven.
//!
//! # Classification safe-default (fund-load-bearing)
//! The unbroadcast↔in-flight split for SH is NOT derivable from the persisted
//! record (`completion_tx` is present the moment the sig is FINALIZED, before
//! broadcast). It is derived from a LIVE chain read of the reveal escrow, with
//! the safe default that `CompletionUnbroadcast` (which MAY abandon to refund)
//! is emitted ONLY when the reveal escrow is POSITIVELY non-public (`Unspent`);
//! anything else is `CompletionInFlight` (never abandon). Abandoning a revealed
//! leg loses D; fighting an already-safe leg only wastes fees.
//!
//! # Frozen-surface note
//! Pure composition of built wallet ranks over the existing `ChainView` trait —
//! no curve math, no new settlement-core surface.

use bitcoin::{OutPoint, Txid};

use crate::chain::{AuthoritativeChainView, SpendStatus};
use crate::settlement::state_machine::Role;
use crate::tx::backstop::{build_cpfp_bump, finalize_cpfp_bump, required_child_fee};
use crate::tx::setup::pre_encumbrance_spk;
use crate::wallet::keys::{KeyPurpose, KeySource};
use crate::wallet::ledger::{BumpTarget, Ledger, LinkageAck};
use crate::wallet::store::{SwapPhase, SwapRecord};
use crate::wallet::watchtower_driver::{
    backstop_decision, bump_target, BackstopAction, StalledTx, WatchtowerDriver, WatchtowerTick,
};
use crate::Result;

/// The outcome of one [`BackstopDriver::tick`]. Every congested path is a SAFE
/// fallback in increment 2 (no reserve provisioned); the two `Bump*`/`Needs*`
/// variants are unreachable until increment 2a and are present so that increment
/// only has to flip one method + wire the CPFP build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackstopTick {
    /// Nothing actionable this tick.
    Idle,
    /// The pre-armed refund was broadcast this tick (dead-device recovery — the
    /// owner need not be online).
    FiredRefund,
    /// A stalled REFUND with no reserve: keep waiting — the CSV never expires and
    /// it relays once congestion clears.
    KeepWaiting,
    /// A stalled UNBROADCAST completion with no reserve: abandon to the pre-armed
    /// refund (safe — nothing was revealed).
    FallbackToRefund,
    /// A stalled IN-FLIGHT / revealed completion with no reserve: NEVER abandon —
    /// RBF / rebroadcast until it confirms.
    KeepFighting,
    /// A stalled SETUP with no reserve: the escrow won't confirm and the
    /// pre-encumbrance coin is untouched — abort cleanly before any lock.
    AbortBeforeLock,
    /// Congested, a suitably-sized reserve is available, and `target` should be
    /// CPFP-bumped NOW (a refund bump is silent; a completion bump only reaches
    /// here with standing consent). The caller executes it with
    /// [`run_cpfp_bump`]. Reachable only when the caller passed
    /// `reserve_available = true`.
    Bump { target: BumpTarget },
    /// A COMPLETION bump is warranted and a reserve is available, but it links
    /// the reserve's provenance to this swap — it awaits an explicit privacy
    /// [`LinkageAck`](crate::wallet::ledger::LinkageAck) before the caller may
    /// [`run_cpfp_bump`] it. Reachable only when `reserve_available = true`.
    NeedsConsent { target: BumpTarget },
}

/// A congestion backstop bound to one swap's pre-armed refund (via the wrapped
/// [`WatchtowerDriver`]). Re-entrant and crash-safe: `tick` re-reads chain state
/// every call and derives all work from the persisted record.
pub struct BackstopDriver {
    tower: WatchtowerDriver,
}

impl BackstopDriver {
    /// Wrap an armed [`WatchtowerDriver`] (armed with this swap's pre-armed
    /// refund + `E_ours` escrow outpoint + the G2 receipt).
    pub fn arm(tower: WatchtowerDriver) -> Self {
        Self { tower }
    }

    /// One backstop poll for this swap. Idempotent + crash-safe.
    ///
    /// `congested` is the caller's observation that OUR current non-refund tx
    /// (the setup or completion it broadcasts, at the engine boundary) could not
    /// relay under the fee floor. The refund's own congestion is detected here
    /// internally by the tower and needs no caller signal. `reserve_available`
    /// is the caller's ledger read — `Ledger::has_leasable_reserve(min)` for a
    /// conservative `required_child_fee` estimate — kept a parameter (not a
    /// ledger handle) so `tick` stays a pure decision; on a `Bump`/`NeedsConsent`
    /// result the caller executes the bump with [`run_cpfp_bump`], whose build
    /// step re-checks the exact reserve sizing.
    pub fn tick(
        &self,
        rec: &SwapRecord,
        chain: &impl AuthoritativeChainView,
        congested: bool,
        reserve_available: bool,
    ) -> Result<BackstopTick> {
        // 1) REFUND side (dead-device, primary-independent). The tower owns
        //    E_ours entirely — the fire, and the refund's relay-floor congestion.
        //    `Some` = the refund side handled this tick; `None` (Idle/StandDown) =
        //    fall through to the COMPLETION side, a DIFFERENT escrow (E_theirs)
        //    whose stalled sweep can outlive the refund escrow standing down.
        //    `congested` (the caller's fee-floor observation) also feeds the
        //    refund side so an ALREADY-RELAYED refund stuck below the
        //    confirmation feerate is surfaced as a bump, not left Idle forever.
        if let Some(tick) = self.refund_side(chain, reserve_available, congested)? {
            return Ok(tick);
        }

        // 2) COMPLETION / SETUP side. Classify from the persisted record + a live
        //    chain read, then route through the pure decision table.
        match classify_stalled_tx(rec, chain) {
            Some(kind) => {
                let action = backstop_decision(
                    kind,
                    congested,
                    reserve_available,
                    // Dead-device policy (adopted): no standing pre-authorized
                    // consent — an in-flight completion keeps fighting until the
                    // owner returns, never a reserve-linking bump behind their back.
                    None,
                );
                Ok(resolve(action, bump_target(kind)))
            }
            None => Ok(BackstopTick::Idle),
        }
    }

    /// Poll ONLY the refund / dead-device tower side — for a swap whose durable
    /// [`SwapRecord`] does not exist yet (a pre-`Proceed` funded abort: our Setup
    /// went on the wire, so E_ours is funded, but `record_funding` — reached only
    /// at the `Proceed` handoff — never ran, so the completion-side classifier has
    /// nothing to read). The tower needs only the escrow + chain, never a record,
    /// so the dead-device refund still fires at CSV maturity and the refund's own
    /// relay-floor congestion is still surfaced. The completion side is skipped
    /// (there is no record to classify). Falls to [`BackstopTick::Idle`] when the
    /// refund needs nothing this tick.
    pub fn tick_refund_only(
        &self,
        chain: &impl AuthoritativeChainView,
        reserve_available: bool,
        refund_congested: bool,
    ) -> Result<BackstopTick> {
        Ok(self
            .refund_side(chain, reserve_available, refund_congested)?
            .unwrap_or(BackstopTick::Idle))
    }

    /// The REFUND-side decision, shared by [`tick`](Self::tick) and
    /// [`tick_refund_only`](Self::tick_refund_only): `Some` when the tower fired
    /// or the refund is congested (broadcast-time OR relayed-but-stuck), `None`
    /// (Idle/StandDown) when it needs nothing. `refund_congested` lets the tower
    /// surface an already-in-mempool refund below the confirmation feerate.
    fn refund_side(
        &self,
        chain: &impl AuthoritativeChainView,
        reserve_available: bool,
        refund_congested: bool,
    ) -> Result<Option<BackstopTick>> {
        Ok(match self.tower.tick(chain, refund_congested)? {
            WatchtowerTick::FiredRefund => Some(BackstopTick::FiredRefund),
            WatchtowerTick::RefundStalledBelowFeeFloor => {
                let action = backstop_decision(StalledTx::Refund, true, reserve_available, None);
                Some(resolve(action, BumpTarget::Refund))
            }
            WatchtowerTick::Idle | WatchtowerTick::StandDown => None,
        })
    }
}

/// Map a pure [`BackstopAction`] to the driver's [`BackstopTick`].
fn resolve(action: BackstopAction, target: BumpTarget) -> BackstopTick {
    match action {
        BackstopAction::None => BackstopTick::Idle,
        BackstopAction::KeepWaiting => BackstopTick::KeepWaiting,
        BackstopAction::FallbackToRefund => BackstopTick::FallbackToRefund,
        BackstopAction::KeepFighting => BackstopTick::KeepFighting,
        BackstopAction::AbortBeforeLock => BackstopTick::AbortBeforeLock,
        // Reserve is available: the caller executes the bump via `run_cpfp_bump`.
        // A refund bump is silent; a completion bump reaching here already
        // carries standing consent (the wallet's dead-device policy passes
        // consent=None, so a completion routes to NeedsConsent instead).
        BackstopAction::BumpSilently | BackstopAction::BumpConsented => {
            BackstopTick::Bump { target }
        }
        BackstopAction::NeedsConsent => BackstopTick::NeedsConsent { target },
    }
}

/// Everything [`run_cpfp_bump`] needs about the STALLED PARENT and the desired
/// bump, besides the ledger/keys/chain. The caller assembles it at the engine
/// boundary (it knows the parent tx it broadcast and the fee floor it observed).
pub struct CpfpBumpRequest<'a> {
    /// What is being bumped (drives the consent gate + the taint).
    pub target: BumpTarget,
    /// The privacy consent for a COMPLETION bump (spec: refunds are silent, so
    /// `None` is fine for a refund; a completion without it is refused).
    pub linkage_ack: Option<LinkageAck>,
    /// Lease holder id (the swap_session_id / backstop id), so a crash between
    /// lease and spend is reconciled by `Ledger::reconcile_leases`.
    pub lessee: [u8; 32],
    /// The fully-signed stalled parent, for the 1P1C `submit_package`.
    pub parent_bytes: &'a [u8],
    /// The parent's anchor outpoint `(parent_txid, ANCHOR_VOUT)`.
    pub parent_anchor: OutPoint,
    /// The parent anchor output's real value (`Params::anchor_sats`) — the
    /// prevout the child sighash commits to.
    pub anchor_value_sats: u64,
    /// The stalled parent's own fee and vsize, and the feerate the package must
    /// reach — together they fix `required_child_fee`.
    pub parent_fee_sats: u64,
    pub parent_vsize_vb: u64,
    pub target_feerate_sat_vb: u64,
    /// A FRESH, unused `Reserve` key index for the child's single output. The
    /// executor DERIVES the change scriptPubKey from this (never an opaque
    /// caller spk) so the residual reserve value lands at a key the wallet can
    /// re-sign, and registers it as a new Reserve coin — the pool replenishes
    /// itself instead of leaking the change untracked. The caller allocates the
    /// index the same way onboarding allocates the next key.
    pub change_key_index: u32,
}

/// The result of a [`run_cpfp_bump`] attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BumpOutcome {
    /// The 1P1C package was accepted. `deposit_linked` is `true` for a
    /// completion bump — the caller MUST persist the taint on the swapped
    /// output (`Ledger::record_swapped_output(.., deposit_linked = true)`).
    Submitted {
        child_txid: Txid,
        reserve_outpoint: OutPoint,
        deposit_linked: bool,
        /// The child's change output, registered as a new Reserve coin so the
        /// backstop pool survives the bump (`change_outpoint = child_txid:0`).
        change_outpoint: OutPoint,
        change_amount_sats: u64,
    },
    /// No suitable reserve was leasable, or the bump could not be built/submitted
    /// (e.g. the reserve was too small, or the package still did not clear the
    /// floor). The lease, if taken, was RELEASED — nothing is stranded — and the
    /// caller keeps its safe fallback (`KeepFighting` / `KeepWaiting`).
    NoBump,
}

/// Execute the CPFP congestion bump the [`BackstopDriver`] decided on: lease a
/// reserve, build the anchor+reserve child sized to lift the parent+child
/// package to the target feerate, sign the reserve input through the enclave
/// seam, and submit the 1P1C package; then mark the reserve spent.
///
/// Fund-safety: the lease is RELEASED on every failure after it is taken (a bad
/// build, a signing error, or a package the mempool still rejects), so a reserve
/// is never stranded Leased — the swap simply keeps its safe fallback. The
/// reserve is marked spent ONLY after the package is accepted. A completion
/// target without a `LinkageAck` is refused by `lease_reserve` before anything
/// is leased (the privacy gate).
pub fn run_cpfp_bump(
    ledger: &mut Ledger,
    keys: &dyn KeySource,
    chain: &impl AuthoritativeChainView,
    req: CpfpBumpRequest<'_>,
) -> Result<BumpOutcome> {
    let child_fee = required_child_fee(
        req.target_feerate_sat_vb,
        req.parent_fee_sats,
        req.parent_vsize_vb,
    );

    // F4 belt-and-braces: NEVER bump a parent that is already CONFIRMED. If the
    // outpoint the parent spends is confirmed-spent by the parent's own txid,
    // the parent is mined and a CPFP child would burn a reserve accelerating
    // nothing. Covers Setup/Refund/Completion uniformly against any stale caller
    // observation (the classifier guards its own side, but the executor is the
    // last line before a reserve key is issued). Undecodable parent bytes fall
    // through to the normal build, which errors — never a silent bump.
    if let Ok(parent) =
        bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(req.parent_bytes)
    {
        if let Some(input) = parent.input.first() {
            let prev = input.previous_output;
            if matches!(chain.spend_status(prev), SpendStatus::Confirmed(_))
                && chain.spend_txid(prev) == Some(parent.compute_txid())
            {
                return Ok(BumpOutcome::NoBump);
            }
        }
    }

    // The child change lands at a fresh, TRACKED Reserve key so it replenishes
    // the pool (derived here, never an opaque caller spk — the on-chain output
    // and the coin we later re-sign can never diverge).
    let change_xonly = keys.derive_xonly(KeyPurpose::Reserve, req.change_key_index)?;
    let change_spk = pre_encumbrance_spk(change_xonly)?;

    // Lease first — this enforces the completion consent gate AND the size gate
    // (a reserve too small for the fee is not leased, matching
    // `has_leasable_reserve`). `None` means no leasable reserve; nothing was
    // taken, so just fall back.
    let reserve = match ledger.lease_reserve(req.target, child_fee, req.linkage_ack, req.lessee)? {
        Some(c) => c,
        None => return Ok(BumpOutcome::NoBump),
    };

    // Build + sign + submit WITHOUT touching the ledger, so any failure leaves
    // exactly one thing to undo: the lease. The reserve signs under the key
    // purpose it was ISSUED with (change promoted to reserve still signs under
    // OnboardingChange), never under its current class. The closure returns the
    // child txid and its change value.
    let built = (|| -> Result<(Txid, u64)> {
        let reserve_xonly = keys.derive_xonly(reserve.key_purpose, reserve.key_index)?;
        let bump = build_cpfp_bump(
            req.parent_anchor,
            req.anchor_value_sats,
            reserve.outpoint,
            reserve.amount_sats,
            reserve_xonly,
            child_fee,
            change_spk,
        )?;
        let sig = keys.sign_key_path(reserve.key_purpose, reserve.key_index, bump.reserve_sighash)?;
        let child_bytes = finalize_cpfp_bump(bump, sig);
        let (_parent_txid, child_txid) = chain.submit_package(req.parent_bytes, &child_bytes)?;
        // build_cpfp_bump already validated this is > dust and non-overflowing.
        let change_amount = req.anchor_value_sats + reserve.amount_sats - child_fee;
        Ok((child_txid, change_amount))
    })();

    match built {
        Ok((child_txid, change_amount)) => {
            let change_outpoint = OutPoint::new(child_txid, 0);
            // ONE persist: mark the reserve spent AND register the change as a
            // new Reserve coin (deposit provenance follows the value). The
            // change keeps the pool non-empty across the bump.
            ledger.spend_reserve_into_change(
                reserve.outpoint,
                change_outpoint,
                change_amount,
                req.change_key_index,
                chain.tip_height(),
                reserve.deposit_linked,
            )?;
            Ok(BumpOutcome::Submitted {
                child_txid,
                reserve_outpoint: reserve.outpoint,
                deposit_linked: req.target == BumpTarget::Completion,
                change_outpoint,
                change_amount_sats: change_amount,
            })
        }
        Err(_) => {
            // Self-heal a PHANTOM reserve (review finding): if the leased
            // reserve's outpoint is already consumed on chain — a crash in a
            // PRIOR bump's submit→persist window left it Leased-then-released-
            // to-Unspent while its child is on the wire — mark it Spent so it
            // is never re-selected (else its deterministic max_by_key selection
            // fails every future bump at submit, silently disabling the pool).
            // A genuine build/undersize failure leaves the outpoint Unspent, so
            // the lease is released to be retried (a bigger reserve, or once
            // congestion eases) — the swap keeps its safe fallback meanwhile.
            if matches!(chain.spend_status(reserve.outpoint), SpendStatus::Unspent) {
                ledger.release_lease(reserve.outpoint)?;
            } else {
                ledger.mark_spent(reserve.outpoint)?;
            }
            Ok(BumpOutcome::NoBump)
        }
    }
}

/// The canonical record→[`StalledTx`] classifier for the NON-refund side (the
/// "undefined-in-code" mapping, now in code). Returns `None` when there is no
/// non-refund tx of ours to back-stop — an off-chain/volatile phase, a terminal,
/// or the refund path (which the tower owns). See the module-doc classification
/// safe-default for the unbroadcast↔in-flight split.
pub fn classify_stalled_tx(rec: &SwapRecord, chain: &impl AuthoritativeChainView) -> Option<StalledTx> {
    match rec.phase {
        // Escrow-funding Setup in flight (the coordinator's tx; classified for
        // completeness even though its broadcast is increment-3 territory).
        SwapPhase::Funding => Some(StalledTx::Setup),
        // The adaptor exchange is off-chain and volatile — nothing to bump.
        SwapPhase::Signing => None,
        // SL pre-settle: if SH's reveal is already public, SL is post-reveal and
        // must never abandon; otherwise nothing of ours is on the wire (and the
        // refund, if SL aborts, is the tower's job).
        SwapPhase::Released => match rec.role {
            Role::SecretLearner if reveal_is_public(rec, chain) => {
                Some(StalledTx::CompletionInFlight)
            }
            _ => None,
        },
        // A completion is finalized in `completion_tx`.
        // F4: a CONFIRMED spend of the swept escrow means the leg already
        // resolved (our completion won, or it was superseded) — nothing to
        // bump. Guard first (mirroring the Completed arm) so an
        // already-confirmed completion is never classified CompletionInFlight,
        // which would let backstop_execute burn a Reserve key CPFP-ing a
        // confirmed parent. Completed is persisted the moment the sig is
        // finalized (before confirmation), so this state is reachable at
        // Completing whenever the completion confirms before the record advances.
        SwapPhase::Completing if our_completion_confirmed(rec, chain) => None,
        SwapPhase::Completing => match rec.role {
            // SL reaches Completing ONLY after observing the reveal → always
            // in-flight (never abandon).
            Role::SecretLearner => Some(StalledTx::CompletionInFlight),
            // SH: `completion_tx` present means FINALIZED, not broadcast. Safe
            // default — `Unbroadcast` ONLY when the reveal escrow is POSITIVELY
            // non-public (`Unspent`); anything else is in-flight.
            Role::SecretHolder => {
                if reveal_is_public(rec, chain) {
                    Some(StalledTx::CompletionInFlight)
                } else {
                    Some(StalledTx::CompletionUnbroadcast)
                }
            }
        },
        // Sig finalized; if our output hasn't confirmed, the completion can still
        // be stuck on the wire under congestion → keep fighting.
        SwapPhase::Completed => {
            if our_completion_confirmed(rec, chain) {
                None
            } else {
                Some(StalledTx::CompletionInFlight)
            }
        }
        // Refund path / terminals: the tower owns the refund; nothing here.
        SwapPhase::AbortRefund | SwapPhase::Refunded => None,
    }
}

/// Is the reveal (SH's `t`) public — i.e. is the SL-funded escrow `E_sl` spent
/// BY THE COMPLETION? `E_sl` is `our_escrow_outpoint` for SL (SL funded it;
/// SH's completion spends it) and `their_escrow_outpoint` for SH (SH sweeps it;
/// SH's own completion spends it).
///
/// WHO spent it matters (adversarial-review LOW): for SL, its OWN pre-armed
/// refund also spends `E_sl` — a dead-device refund fire must NOT read as a
/// reveal, or a refunded SL classifies as a phantom `CompletionInFlight`
/// forever (and, once a reserve exists, could prompt a reserve-linking bump
/// for a completion that is actually its refund). `E_sl` has exactly two
/// spend paths — SH's completion key-path and SL's refund leaf — so "spent,
/// and not by our refund" IS the reveal. Unknown spender (`spend_txid` = None
/// on views that don't track it) stays conservative: treat as revealed —
/// `KeepFighting` never abandons, which is the safe direction.
fn reveal_is_public(rec: &SwapRecord, chain: &impl AuthoritativeChainView) -> bool {
    let e_sl = match rec.role {
        Role::SecretLearner => rec.our_escrow_outpoint,
        Role::SecretHolder => rec.their_escrow_outpoint,
    };
    let Some(op) = e_sl else { return false };
    if matches!(chain.spend_status(op), SpendStatus::Unspent) {
        return false;
    }
    // Spent — but our own refund spending it is not a reveal. (For SH the
    // record's refund spends E_ours, never E_sl, so this simply never matches.)
    !matches!(
        (chain.spend_txid(op), our_refund_txid(rec)),
        (Some(spender), Some(ours)) if spender == ours
    )
}

/// The txid of OUR pre-armed refund, from the persisted record. Malformed
/// bytes degrade to `None` (⇒ the conservative treat-as-revealed path).
fn our_refund_txid(rec: &SwapRecord) -> Option<bitcoin::Txid> {
    let refund = rec.pre_armed_refund.as_ref()?;
    let tx: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize(refund.tx_bytes()).ok()?;
    Some(tx.compute_txid())
}

/// Is OUR completion confirmed — i.e. is the escrow WE sweep
/// (`their_escrow_outpoint`) confirmed spent (by us)?
fn our_completion_confirmed(rec: &SwapRecord, chain: &impl AuthoritativeChainView) -> bool {
    match rec.their_escrow_outpoint {
        Some(op) => matches!(chain.spend_status(op), SpendStatus::Confirmed(_)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ChainView, SimChain};
    use crate::settlement::params::Params;
    use crate::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
    use bitcoin::OutPoint;

    fn op(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b)),
            0,
        )
    }

    fn std_p2tr_spk() -> bitcoin::ScriptBuf {
        let mut v = vec![0x51u8, 0x20];
        v.extend_from_slice(&[0x77u8; 32]);
        bitcoin::ScriptBuf::from_bytes(v)
    }

    /// A real spend of `outpoint`, so the sim gives it a matching mempool/chain
    /// entry. `csv = Some(blocks)` for a CSV refund, `None` for a completion.
    fn spend_of(outpoint: OutPoint, out: u64, csv: Option<u16>) -> Vec<u8> {
        use bitcoin::{
            absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
            Witness,
        };
        let sequence = match csv {
            Some(b) => Sequence::from_height(b),
            None => Sequence::ENABLE_RBF_NO_LOCKTIME,
        };
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: std_p2tr_spk() }],
        };
        bitcoin::consensus::encode::serialize(&tx)
    }

    /// A minimal SwapRecord for the classifier: only phase/role/escrow outpoints
    /// are read, so the rest is filler (the classifier never touches them).
    fn rec(
        phase: SwapPhase,
        role: Role,
        our_escrow: Option<OutPoint>,
        their_escrow: Option<OutPoint>,
    ) -> SwapRecord {
        SwapRecord {
            swap_session_id: [0u8; 32],
            role,
            phase,
            params: Params::testnet_provisional(),
            s_height: 0,
            sweep_escrow_height: 0,
            our_escrow_outpoint: our_escrow,
            their_escrow_outpoint: their_escrow,
            pre_armed_refund: None,
            completion_tx: None,
            setup_tx: None,
            possession_record: None,
        }
    }

    // ------- classifier: the fund-load-bearing table -------

    #[test]
    fn classify_funding_is_setup() {
        let chain = SimChain::new(100);
        assert_eq!(
            classify_stalled_tx(&rec(SwapPhase::Funding, Role::SecretHolder, Some(op(1)), Some(op(2))), &chain),
            Some(StalledTx::Setup)
        );
    }

    #[test]
    fn classify_signing_and_terminals_are_none() {
        let chain = SimChain::new(100);
        for phase in [SwapPhase::Signing, SwapPhase::AbortRefund, SwapPhase::Refunded] {
            assert_eq!(
                classify_stalled_tx(&rec(phase, Role::SecretLearner, Some(op(1)), Some(op(2))), &chain),
                None,
                "{phase:?} is off-chain/terminal or the tower's refund"
            );
        }
    }

    #[test]
    fn classify_sl_released_is_reveal_gated() {
        // E_sl = our_escrow_outpoint for SL. Unspent → not yet revealed → None.
        let e_sl = op(10);
        let chain = SimChain::new(100);
        chain.fund(e_sl, 100);
        let r = rec(SwapPhase::Released, Role::SecretLearner, Some(e_sl), Some(op(11)));
        assert_eq!(classify_stalled_tx(&r, &chain), None, "pre-reveal SL: nothing on the wire");

        // SH reveals (spends E_sl) → SL is post-reveal → must never abandon.
        chain.broadcast(&spend_of(e_sl, 900_000, None)).unwrap();
        assert_eq!(
            classify_stalled_tx(&r, &chain),
            Some(StalledTx::CompletionInFlight),
            "post-reveal SL must be in-flight (never abandon)"
        );
    }

    #[test]
    fn classify_sh_completing_split_is_safe_default() {
        // E_sl = their_escrow_outpoint for SH (the escrow SH sweeps / its
        // completion spends, revealing t).
        let e_sl = op(20);
        let chain = SimChain::new(100);
        chain.fund(e_sl, 100);
        let r = rec(SwapPhase::Completing, Role::SecretHolder, Some(op(21)), Some(e_sl));

        // Positively non-public (Unspent) → the ONLY case that may abandon.
        assert_eq!(
            classify_stalled_tx(&r, &chain),
            Some(StalledTx::CompletionUnbroadcast),
            "unbroadcast only when the reveal escrow is positively unspent"
        );

        // Once SH's completion is on the wire → in-flight (never abandon).
        chain.broadcast(&spend_of(e_sl, 900_000, None)).unwrap();
        assert_eq!(
            classify_stalled_tx(&r, &chain),
            Some(StalledTx::CompletionInFlight),
            "any non-Unspent reveal escrow ⇒ in-flight (safe default)"
        );
    }

    #[test]
    fn classify_sl_own_refund_is_not_a_reveal() {
        // SL dead-device case (adversarial-review LOW): the record is still
        // Released and the watchtower fired SL's OWN pre-armed refund of E_sl.
        // Spent-by-our-refund must NOT read as a reveal — the backstop
        // quiesces instead of reporting a phantom in-flight completion.
        let e_sl = op(80);
        let chain = SimChain::new(500_200);
        chain.fund(e_sl, 500_000);
        let refund_bytes = spend_of(e_sl, 900_000, Some(144));
        let refund = PreArmedRefund::from_signed_tx(refund_bytes.clone(), 500_144).unwrap();
        let mut r = rec(SwapPhase::Released, Role::SecretLearner, Some(e_sl), Some(op(81)));
        r.pre_armed_refund = Some(refund);

        chain.broadcast(&refund_bytes).unwrap(); // our refund spends E_sl
        assert_eq!(
            classify_stalled_tx(&r, &chain),
            None,
            "our own refund spending E_sl is not a reveal"
        );
        chain.mine();
        assert_eq!(classify_stalled_tx(&r, &chain), None, "still quiesced once confirmed");

        // Counter-case: a DIFFERENT spender (SH's completion) with the refund
        // present must still classify as revealed → in-flight (never abandon).
        let e_sl2 = op(82);
        let chain2 = SimChain::new(500_200);
        chain2.fund(e_sl2, 500_000);
        let refund2 =
            PreArmedRefund::from_signed_tx(spend_of(e_sl2, 900_000, Some(144)), 500_344).unwrap();
        let mut r2 = rec(SwapPhase::Released, Role::SecretLearner, Some(e_sl2), Some(op(83)));
        r2.pre_armed_refund = Some(refund2);
        chain2.broadcast(&spend_of(e_sl2, 995_000, None)).unwrap(); // SH's Comp→SH
        assert_eq!(
            classify_stalled_tx(&r2, &chain2),
            Some(StalledTx::CompletionInFlight),
            "a non-refund spender is a real reveal — the exclusion must not over-fire"
        );
    }

    #[test]
    fn classify_sl_completing_is_always_in_flight() {
        // SL reaches Completing only AFTER observing the reveal, so it is
        // record-derivable as in-flight without a chain read.
        let chain = SimChain::new(100);
        let r = rec(SwapPhase::Completing, Role::SecretLearner, Some(op(30)), Some(op(31)));
        assert_eq!(classify_stalled_tx(&r, &chain), Some(StalledTx::CompletionInFlight));
    }

    #[test]
    fn classify_completed_is_done_only_when_our_output_confirmed() {
        // our completion sweeps their_escrow_outpoint (E_theirs).
        let e_theirs = op(40);
        let chain = SimChain::new(100);
        chain.fund(e_theirs, 100);
        let r = rec(SwapPhase::Completed, Role::SecretHolder, Some(op(41)), Some(e_theirs));

        // Still stuck on the wire → keep fighting.
        chain.broadcast(&spend_of(e_theirs, 900_000, None)).unwrap();
        assert_eq!(
            classify_stalled_tx(&r, &chain),
            Some(StalledTx::CompletionInFlight),
            "an unconfirmed completion under congestion keeps fighting"
        );
        // Confirmed → nothing to do.
        chain.mine();
        assert_eq!(classify_stalled_tx(&r, &chain), None, "confirmed output ⇒ done");
    }

    /// F4: a CONFIRMED completion spend of the swept escrow at `Completing` must
    /// classify `None` (a confirmed parent is nothing to bump), not
    /// `CompletionInFlight` — the confirmation can land before the record
    /// advances to `Completed`, so this state is reachable at `Completing`.
    #[test]
    fn classify_completing_confirmed_completion_is_done_not_in_flight() {
        let e_theirs = op(42); // the escrow WE sweep
        let chain = SimChain::new(100);
        chain.fund(e_theirs, 100);
        let r = rec(SwapPhase::Completing, Role::SecretLearner, Some(op(43)), Some(e_theirs));

        // In the mempool: still in-flight (keep fighting).
        chain.broadcast(&spend_of(e_theirs, 900_000, None)).unwrap();
        assert_eq!(classify_stalled_tx(&r, &chain), Some(StalledTx::CompletionInFlight));
        // Confirmed: nothing to bump (before the fix: still CompletionInFlight,
        // which let backstop_execute burn a reserve on a confirmed parent).
        chain.mine();
        assert_eq!(
            classify_stalled_tx(&r, &chain),
            None,
            "a confirmed completion at Completing is done"
        );
    }

    // ------- tick: composition + routing -------

    fn armed_tower(escrow: OutPoint, refund_amount: u64, csv: u16, maturity: u32) -> WatchtowerDriver {
        let refund =
            PreArmedRefund::from_signed_tx(spend_of(escrow, refund_amount, Some(csv)), maturity).unwrap();
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
        WatchtowerDriver::arm(refund, escrow, &receipt).unwrap()
    }

    #[test]
    fn tick_fires_dead_device_refund_at_maturity() {
        // E_ours unspent at CSV maturity → the tower broadcasts the refund.
        let e_ours = op(50);
        let maturity = 500_144u32;
        let chain = SimChain::new(maturity); // tip == maturity
        chain.fund(e_ours, 490_000);
        let driver = BackstopDriver::arm(armed_tower(e_ours, 900_000, 144, maturity));
        let r = rec(SwapPhase::AbortRefund, Role::SecretHolder, Some(e_ours), Some(op(51)));
        assert_eq!(driver.tick(&r, &chain, false, false).unwrap(), BackstopTick::FiredRefund);
    }

    #[test]
    fn tick_completion_side_keeps_fighting_a_revealed_leg() {
        // Tower Idle (E_ours unspent, far from maturity) → fall through to the
        // completion side. SH Completing with the reveal escrow SPENT ⇒ in-flight
        // + congested ⇒ never abandon.
        let e_ours = op(60);
        let e_sl = op(61); // their_escrow_outpoint for SH
        let chain = SimChain::new(500_000);
        chain.fund(e_ours, 490_000);
        chain.fund(e_sl, 490_000);
        chain.broadcast(&spend_of(e_sl, 900_000, None)).unwrap(); // reveal public
        let driver = BackstopDriver::arm(armed_tower(e_ours, 900_000, 144, 500_144));
        let r = rec(SwapPhase::Completing, Role::SecretHolder, Some(e_ours), Some(e_sl));
        assert_eq!(driver.tick(&r, &chain, true, false).unwrap(), BackstopTick::KeepFighting);
        // Not congested ⇒ nothing to do.
        assert_eq!(driver.tick(&r, &chain, false, false).unwrap(), BackstopTick::Idle);
    }

    #[test]
    fn tick_completion_side_may_abandon_only_unbroadcast() {
        // SH Completing, reveal escrow UNSPENT ⇒ unbroadcast + congested + no
        // reserve ⇒ fall back to the pre-armed refund (safe — nothing revealed).
        let e_ours = op(70);
        let e_sl = op(71);
        let chain = SimChain::new(500_000);
        chain.fund(e_ours, 490_000);
        chain.fund(e_sl, 490_000); // unspent
        let driver = BackstopDriver::arm(armed_tower(e_ours, 900_000, 144, 500_144));
        let r = rec(SwapPhase::Completing, Role::SecretHolder, Some(e_ours), Some(e_sl));
        assert_eq!(driver.tick(&r, &chain, true, false).unwrap(), BackstopTick::FallbackToRefund);
    }

    #[test]
    fn tick_refund_only_fires_the_tower_without_a_record() {
        // The record-less arm (a pre-Proceed funded escrow): the tower needs
        // only the escrow + chain, so the dead-device refund still fires at
        // CSV maturity, and pre-maturity it is a quiet Idle.
        let e_ours = op(95);
        let maturity = 500_144u32;
        let chain = SimChain::new(500_000);
        chain.fund(e_ours, 500_000);
        let driver = BackstopDriver::arm(armed_tower(e_ours, 900_000, 144, maturity));

        assert_eq!(
            driver.tick_refund_only(&chain, false, false).unwrap(),
            BackstopTick::Idle,
            "immature refund: nothing to do"
        );
        while chain.tip_height() < maturity {
            chain.mine();
        }
        assert_eq!(
            driver.tick_refund_only(&chain, false, false).unwrap(),
            BackstopTick::FiredRefund,
            "matured, unspent, record-less: the tower fires"
        );
        chain.mine();
        assert_eq!(
            driver.tick_refund_only(&chain, false, false).unwrap(),
            BackstopTick::Idle,
            "confirmed refund: stand down maps to Idle"
        );
    }

    #[test]
    fn reserve_available_flips_completion_to_needs_consent() {
        // A revealed, congested completion: with NO reserve it keeps fighting;
        // with a reserve available it surfaces NeedsConsent (the dead-device
        // policy passes consent=None, so a completion never bumps silently).
        // This is the increment-2a behaviour change — `reserve_available` now
        // flows through `tick` instead of being hardcoded false.
        let e_ours = op(90);
        let e_sl = op(91);
        let chain = SimChain::new(500_000);
        chain.fund(e_ours, 490_000);
        chain.fund(e_sl, 490_000);
        chain.broadcast(&spend_of(e_sl, 900_000, None)).unwrap(); // reveal public
        let driver = BackstopDriver::arm(armed_tower(e_ours, 900_000, 144, 500_144));
        let r = rec(SwapPhase::Completing, Role::SecretHolder, Some(e_ours), Some(e_sl));
        assert_eq!(
            driver.tick(&r, &chain, true, false).unwrap(),
            BackstopTick::KeepFighting,
            "no reserve ⇒ keep fighting"
        );
        assert_eq!(
            driver.tick(&r, &chain, true, true).unwrap(),
            BackstopTick::NeedsConsent { target: BumpTarget::Completion },
            "reserve available ⇒ a completion bump awaits consent"
        );
    }
}
