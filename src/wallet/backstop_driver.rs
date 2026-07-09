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
//! # Scope (increment 2 — safe fallbacks; bump inert)
//! No reserve coin is provisioned in the wallet yet (`promote_change_to_reserve`
//! is test-only; onboarding's single change output folds into fee), so
//! `reserve_available` is unconditionally false and every congested path routes
//! to a SAFE fallback — `KeepWaiting` (refund), `FallbackToRefund` (unbroadcast
//! completion), `KeepFighting` (in-flight/revealed completion), `AbortBeforeLock`
//! (setup) — plus the dead-device refund fire. None strands a coin or misses a
//! deadline, so fund-safety holds. The actual CPFP BUMP (lease a reserve, then
//! build, sign, and submit the 1P1C child) is deferred to increment 2a, which
//! provisions a reserve and computes `reserve_available` for real (sized against
//! `tx::backstop::required_child_fee`).
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

use crate::chain::{ChainView, SpendStatus};
use crate::settlement::state_machine::Role;
use crate::wallet::ledger::BumpTarget;
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
    /// Congested and a reserve WOULD CPFP-bump `target`, but reserve provisioning
    /// is increment 2a — the bump build/submit is intentionally not wired yet.
    /// Unreachable while `reserve_available` is false.
    BumpDeferred { target: BumpTarget },
    /// A completion bump awaits an explicit privacy `LinkageAck` (increment 2a).
    /// Unreachable while `reserve_available` is false.
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
    /// internally by the tower and needs no caller signal.
    pub fn tick(
        &self,
        rec: &SwapRecord,
        chain: &impl ChainView,
        congested: bool,
    ) -> Result<BackstopTick> {
        // 1) REFUND side (dead-device, primary-independent). The tower owns
        //    E_ours entirely — the fire, and the refund's relay-floor congestion.
        match self.tower.tick(chain)? {
            WatchtowerTick::FiredRefund => return Ok(BackstopTick::FiredRefund),
            WatchtowerTick::RefundStalledBelowFeeFloor => {
                let action =
                    backstop_decision(StalledTx::Refund, true, self.reserve_available(), None);
                return Ok(resolve(action, BumpTarget::Refund));
            }
            // Idle / StandDown: the refund needs nothing this tick. Fall through
            // to the COMPLETION side — a DIFFERENT escrow (E_theirs) whose
            // stalled sweep can outlive the refund escrow standing down.
            WatchtowerTick::Idle | WatchtowerTick::StandDown => {}
        }

        // 2) COMPLETION / SETUP side. Classify from the persisted record + a live
        //    chain read, then route through the pure decision table.
        match classify_stalled_tx(rec, chain) {
            Some(kind) => {
                let action = backstop_decision(
                    kind,
                    congested,
                    self.reserve_available(),
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

    /// Increment 2 provisions no reserve, so this is unconditionally false and
    /// every congested path routes to a safe fallback. Increment 2a computes it
    /// from a leasable `Reserve` coin sized against `required_child_fee`.
    fn reserve_available(&self) -> bool {
        false
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
        // Reachable only once increment 2a sets `reserve_available`; the actual
        // lease + CPFP build + submit is that increment's work.
        BackstopAction::BumpSilently | BackstopAction::BumpConsented => {
            BackstopTick::BumpDeferred { target }
        }
        BackstopAction::NeedsConsent => BackstopTick::NeedsConsent { target },
    }
}

/// The canonical record→[`StalledTx`] classifier for the NON-refund side (the
/// "undefined-in-code" mapping, now in code). Returns `None` when there is no
/// non-refund tx of ours to back-stop — an off-chain/volatile phase, a terminal,
/// or the refund path (which the tower owns). See the module-doc classification
/// safe-default for the unbroadcast↔in-flight split.
pub fn classify_stalled_tx(rec: &SwapRecord, chain: &impl ChainView) -> Option<StalledTx> {
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
fn reveal_is_public(rec: &SwapRecord, chain: &impl ChainView) -> bool {
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
fn our_completion_confirmed(rec: &SwapRecord, chain: &impl ChainView) -> bool {
    match rec.their_escrow_outpoint {
        Some(op) => matches!(chain.spend_status(op), SpendStatus::Confirmed(_)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::SimChain;
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
        assert_eq!(driver.tick(&r, &chain, false).unwrap(), BackstopTick::FiredRefund);
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
        assert_eq!(driver.tick(&r, &chain, true).unwrap(), BackstopTick::KeepFighting);
        // Not congested ⇒ nothing to do.
        assert_eq!(driver.tick(&r, &chain, false).unwrap(), BackstopTick::Idle);
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
        assert_eq!(driver.tick(&r, &chain, true).unwrap(), BackstopTick::FallbackToRefund);
    }
}
