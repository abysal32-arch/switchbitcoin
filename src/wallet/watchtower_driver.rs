//! Own-device watchtower driver + fee-backstop routing (wallet rank 6).
//!
//! Closes the dead-device deadline hole. The own-device watchtower (a second
//! device or a local background process the owner controls) holds the SH-side
//! PRE-ARMED refund and, if the owner's primary device is dead, fires it at
//! the deadline so the escrow is always reclaimable — recovery never depends
//! on the primary being online (v3.13 gate G2 crash-safety).
//!
//! `WatchtowerDriver::tick` is the poll the background loop calls: it wraps
//! the built `Watchtower::poll` (which already fires the refund only when the
//! escrow is unspent AND the CSV has matured, and treats an in-mempool
//! completion as transient, not a permanent stand-down) and surfaces the
//! richer terminal/idle/fired state the driver needs.
//!
//! FEE BACKSTOP (v3.13, congestion-only, opt-in for completions): under a fee
//! spike beyond the baked-in Δ_fee, a stalled contract tx is pulled up by a
//! CPFP child spending its ephemeral anchor + a RESERVE coin
//! (`tx::backstop`). The privacy asymmetry is enforced here:
//!   * a stalled REFUND bumps SILENTLY — a refund already revealed its leaf,
//!     so there is no privacy left to protect;
//!   * a stalled COMPLETION bump LINKS the reserve to the swap, a real
//!     privacy loss, so it is gated behind explicit consent (`LinkageAck`).
//!     CALLER CONTRACT: when a consented completion bump is taken, the caller
//!     MUST pass `deposit_linked = true` to `ledger::record_swapped_output`
//!     for that swap's output — the taint is not inferred automatically (the
//!     tighter lease→output binding is a documented rank-3 follow-up).
//!
//! If no reserve is available, a completion falls back to abandon-to-refund
//! (the pre-armed refund is the always-available exit) — never a stuck coin.
//!
//! SIM NOTE (honest): `SimChain` models congestion as a broadcast-time relay
//! threshold and does not model package relay / a low-fee tx lingering across
//! blocks, so the CPFP PACKAGE acceptance is a real-node behavior (like Script
//! execution, deferred to the testnet run). What is tested here is the
//! DECISION logic (when/what to bump, and the consent gate) and the
//! dead-device refund fire; the bump tx itself is built + bitcoin-side
//! verified in `tx::backstop`.

use crate::chain::{AuthoritativeChainView, SpendStatus};
use crate::settlement::refund::{PreArmedRefund, Watchtower, WatchtowerReceipt};
use crate::wallet::ledger::{BumpTarget, LinkageAck};
use crate::Result;
use bitcoin::OutPoint;

/// The own-device watchtower driver: the refund tower plus the escrow it
/// guards, polled by the background loop.
pub struct WatchtowerDriver {
    tower: Watchtower,
    escrow_outpoint: OutPoint,
    csv_maturity_height: u32,
}

/// The outcome of one watchtower poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchtowerTick {
    /// Nothing to do this poll (not matured, or a completion pending in the
    /// mempool that may still evict).
    Idle,
    /// The escrow was unspent at/after CSV maturity: the pre-armed refund was
    /// broadcast THIS tick (dead-device recovery — the owner need not be up).
    FiredRefund,
    /// The refund is MATURE and should fire, but its baked-in fee is below the
    /// current relay floor so it could not relay (finding #2/#4 — a congestion
    /// spike beyond Δ_fee with a dead device). This is NOT terminal and NOT a
    /// bare error: the outer loop must run the SILENT refund backstop
    /// (`backstop_decision(StalledTx::Refund, congested=true, …)` →
    /// `BumpSilently`) to CPFP the refund's anchor from a reserve. The
    /// watchtower process must therefore be provisioned with a reserve coin
    /// (or a pre-staged, pre-signed child) so it can act with the primary
    /// device dead — see the module docs.
    RefundStalledBelowFeeFloor,
    /// The escrow is confirmed spent (a completion won, or our refund already
    /// confirmed): terminal, nothing more to do.
    StandDown,
}

impl WatchtowerDriver {
    /// Arm the driver with a refund whose fingerprint the owner acknowledged
    /// (the same `WatchtowerReceipt` that satisfies gate G2).
    pub fn arm(
        refund: PreArmedRefund,
        escrow_outpoint: OutPoint,
        receipt: &WatchtowerReceipt,
    ) -> Result<Self> {
        let csv_maturity_height = refund.csv_maturity_height();
        let tower = Watchtower::arm(refund, escrow_outpoint, receipt)?;
        Ok(WatchtowerDriver { tower, escrow_outpoint, csv_maturity_height })
    }

    /// One poll of the background loop. Idempotent and crash-safe: it
    /// re-reads chain state every call, so a restart just re-evaluates.
    ///
    /// Requires an [`AuthoritativeChainView`]: this is the standalone
    /// second-device watchtower's fund-deciding surface (it decides the
    /// terminal `StandDown` and fires the pre-armed refund from `spend_status`),
    /// and a lying explorer fabricating a `Confirmed` spend must never be able
    /// to stand the tower down on a still-unspent escrow.
    pub fn tick(&self, chain: &impl AuthoritativeChainView) -> Result<WatchtowerTick> {
        match chain.spend_status(self.escrow_outpoint) {
            // A completion won or our own refund already confirmed: terminal.
            SpendStatus::Confirmed(_) => Ok(WatchtowerTick::StandDown),
            // A completion pending in the mempool is TRANSIENT (it may evict);
            // keep watching rather than standing down forever.
            SpendStatus::InMempool => Ok(WatchtowerTick::Idle),
            SpendStatus::Unspent => {
                // Not matured yet → nothing to fire (Ok(false) from poll).
                if chain.tip_height() < self.csv_maturity_height {
                    return Ok(WatchtowerTick::Idle);
                }
                // Matured: try to fire. A broadcast failure here is the
                // refund's fee falling below the relay floor (congestion
                // beyond Δ_fee) — surface it as an ACTIONABLE stall the outer
                // loop routes to the silent backstop, NOT a bare error that
                // strands the escrow past the deadline with a dead device.
                match self.tower.poll(chain) {
                    Ok(true) => Ok(WatchtowerTick::FiredRefund),
                    Ok(false) => Ok(WatchtowerTick::Idle),
                    Err(_) => Ok(WatchtowerTick::RefundStalledBelowFeeFloor),
                }
            }
        }
    }
}

/// Which contract tx the backstop would bump. The distinction is REVEAL- and
/// role-aware (finding #5): the safe no-reserve fallback differs by whether an
/// already-signed refund exit still exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StalledTx {
    /// A refund — no privacy left; bump silently. If it can't fund, WAIT: the
    /// CSV never expires and it relays when congestion clears.
    Refund,
    /// A Setup that won't confirm. Bumping links the reserve to the escrow
    /// (privacy loss ⇒ consent). If it can't fund, the escrow simply never
    /// confirms and the pre-encumbrance coin is untouched — the swap aborts
    /// before anything is locked. (Its structural 0-fee / mandatory-CPFP
    /// requirement is the fee-model item in `tx::txbuild` / the review packet.)
    Setup,
    /// SH's completion BEFORE it is broadcast — nothing revealed yet, so the
    /// pre-armed refund is still a safe exit if we can't fund the bump.
    CompletionUnbroadcast,
    /// A completion ALREADY on the wire — SH's broadcast Comp→SH, or SL's
    /// post-reveal claim. There is NO refund for a revealed leg (SL abandoning
    /// its claim would simply lose D), so we must KEEP FIGHTING (RBF /
    /// rebroadcast), never abandon.
    CompletionInFlight,
}

/// The fee-backstop decision for a stalled contract tx.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackstopAction {
    /// Not congested (or the tx already confirmed): nothing to do.
    None,
    /// Silent auto-bump — a stalled REFUND carries no privacy. Caller: lease a
    /// reserve coin and build the CPFP child.
    BumpSilently,
    /// A stalled Setup/completion: bumping links the reserve to the swap (a
    /// privacy loss), so surface the consent prompt. No bump until a
    /// `LinkageAck` is provided.
    NeedsConsent,
    /// Consent given: bump (and record the deposit-link taint on the swapped
    /// output for a completion — see `ledger::record_swapped_output`).
    BumpConsented,
    /// REFUND, no reserve: keep waiting — the CSV won't expire and it relays
    /// once congestion clears. Safe (no stuck coin, no missed deadline).
    KeepWaiting,
    /// UNBROADCAST completion, no reserve: abandon to the pre-armed refund
    /// (the always-available exit). Safe ONLY because nothing was revealed.
    FallbackToRefund,
    /// IN-FLIGHT completion / SL claim, no reserve: NEVER abandon — the leg is
    /// RBF-able and timelock-free and stays valid, so rebroadcast / fee-fight
    /// until it confirms. (Winning may need the reserve; this is the honest
    /// "no reserve, keep trying" state, not a stuck coin.)
    KeepFighting,
    /// SETUP, no reserve: the escrow will not confirm; the pre-encumbrance
    /// coin is untouched, so abort the swap cleanly before any lock.
    AbortBeforeLock,
}

/// Decide the backstop action for a stalled tx. Pure; the wallet layer wires
/// this to `ledger::lease_reserve` (which re-checks the `LinkageAck` for a
/// consented bump) and `tx::backstop::build_cpfp_bump`.
///
/// `congested` = "this tx cannot currently relay / is below the fee floor."
/// `reserve_available` = the ledger holds a reserve coin big enough for the
/// currently-required child fee (the caller computes sufficiency — finding #9).
pub fn backstop_decision(
    kind: StalledTx,
    congested: bool,
    reserve_available: bool,
    consent: Option<&LinkageAck>,
) -> BackstopAction {
    if !congested {
        return BackstopAction::None;
    }
    match kind {
        StalledTx::Refund => {
            if reserve_available {
                BackstopAction::BumpSilently
            } else {
                BackstopAction::KeepWaiting
            }
        }
        StalledTx::Setup => {
            if !reserve_available {
                BackstopAction::AbortBeforeLock
            } else if consent.is_some() {
                BackstopAction::BumpConsented
            } else {
                BackstopAction::NeedsConsent
            }
        }
        StalledTx::CompletionUnbroadcast => {
            if !reserve_available {
                BackstopAction::FallbackToRefund
            } else if consent.is_some() {
                BackstopAction::BumpConsented
            } else {
                BackstopAction::NeedsConsent
            }
        }
        StalledTx::CompletionInFlight => {
            if !reserve_available {
                BackstopAction::KeepFighting
            } else if consent.is_some() {
                BackstopAction::BumpConsented
            } else {
                BackstopAction::NeedsConsent
            }
        }
    }
}

/// The `BumpTarget` a `StalledTx` maps to for `ledger::lease_reserve`. A
/// refund bump is silent; a Setup or completion bump links the reserve to the
/// swap and so goes through the completion consent gate.
pub fn bump_target(kind: StalledTx) -> BumpTarget {
    match kind {
        StalledTx::Refund => BumpTarget::Refund,
        StalledTx::Setup | StalledTx::CompletionUnbroadcast | StalledTx::CompletionInFlight => {
            BumpTarget::Completion
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ChainView, SimChain};
    use crate::settlement::refund::confirm_watchtower_handoff;
    use crate::wallet::ledger::{acknowledge_linkage, LINKAGE_WARNING};

    fn op(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b)), 0)
    }

    /// A standard P2TR-shaped scriptPubKey (`OP_1 <32 bytes>`). The relay-policy
    /// gate rejects an empty (non-standard) spk, so fixtures must look real.
    fn std_p2tr_spk() -> bitcoin::ScriptBuf {
        let mut v = vec![0x51u8, 0x20];
        v.extend_from_slice(&[0x77u8; 32]);
        bitcoin::ScriptBuf::from_bytes(v)
    }

    /// A REAL spend of the escrow, so the sim gives it a matching outpoint.
    /// `csv` = Some(blocks) for a CSV refund (sim enforces maturity), None for
    /// a no-timelock completion (spendable immediately).
    fn spend_of(outpoint: OutPoint, out: u64, csv: Option<u16>) -> Vec<u8> {
        use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
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

    /// Dead-device recovery: the owner is offline; the watchtower fires the
    /// pre-armed refund at CSV maturity with no owner action.
    #[test]
    fn dead_device_watchtower_fires_refund_at_maturity() {
        let escrow = op(1);
        let maturity = 800_144u32;
        let chain = SimChain::new(800_000);
        chain.fund(escrow, 800_000);

        let refund =
            PreArmedRefund::from_signed_tx(spend_of(escrow, 990_000, Some(144)), maturity).unwrap();
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
        let driver = WatchtowerDriver::arm(refund, escrow, &receipt).unwrap();

        // Before maturity: idle (nothing to fire).
        assert_eq!(driver.tick(&chain).unwrap(), WatchtowerTick::Idle);
        // At maturity, owner offline: the tower fires the refund itself.
        while chain.tip_height() < maturity {
            chain.mine();
        }
        assert_eq!(driver.tick(&chain).unwrap(), WatchtowerTick::FiredRefund);
        chain.mine();
        // Now confirmed: stand down.
        assert_eq!(driver.tick(&chain).unwrap(), WatchtowerTick::StandDown);
    }

    /// If a completion wins first, the watchtower stands down and never
    /// fights it (completion-supersedes), even past maturity.
    #[test]
    fn watchtower_stands_down_on_a_winning_completion() {
        let escrow = op(2);
        let maturity = 500_144u32;
        let chain = SimChain::new(500_000);
        chain.fund(escrow, 500_000);
        let refund =
            PreArmedRefund::from_signed_tx(spend_of(escrow, 990_000, Some(144)), maturity).unwrap();
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
        let driver = WatchtowerDriver::arm(refund, escrow, &receipt).unwrap();

        // The counterparty completion (no timelock) confirms against the escrow.
        chain.broadcast(&spend_of(escrow, 995_000, None)).unwrap();
        chain.mine();
        // Even past maturity, the tower stands down (never double-spends).
        while chain.tip_height() < maturity + 10 {
            chain.mine();
        }
        assert_eq!(driver.tick(&chain).unwrap(), WatchtowerTick::StandDown);
    }

    #[test]
    fn backstop_routing_is_reveal_and_role_aware() {
        let ack = acknowledge_linkage(LINKAGE_WARNING).unwrap();

        // Not congested: no bump.
        assert_eq!(backstop_decision(StalledTx::Refund, false, true, None), BackstopAction::None);

        // Refund: silent with reserve; safe KEEP-WAITING without (CSV won't
        // expire) — never a bare stall.
        assert_eq!(backstop_decision(StalledTx::Refund, true, true, None), BackstopAction::BumpSilently);
        assert_eq!(backstop_decision(StalledTx::Refund, true, false, None), BackstopAction::KeepWaiting);

        // Consent gating for anything that links the reserve to the swap.
        assert_eq!(
            backstop_decision(StalledTx::CompletionUnbroadcast, true, true, None),
            BackstopAction::NeedsConsent
        );
        assert_eq!(
            backstop_decision(StalledTx::CompletionUnbroadcast, true, true, Some(&ack)),
            BackstopAction::BumpConsented
        );

        // THE finding-#5 fix: an UNBROADCAST completion with no reserve may
        // abandon to its pre-armed refund (nothing revealed) — but an
        // IN-FLIGHT completion / SL claim must NEVER abandon (no refund exists
        // for a revealed leg); it keeps fighting.
        assert_eq!(
            backstop_decision(StalledTx::CompletionUnbroadcast, true, false, Some(&ack)),
            BackstopAction::FallbackToRefund
        );
        assert_eq!(
            backstop_decision(StalledTx::CompletionInFlight, true, false, Some(&ack)),
            BackstopAction::KeepFighting
        );

        // Setup: consent-gated; no reserve ⇒ abort before anything locks.
        assert_eq!(
            backstop_decision(StalledTx::Setup, true, false, None),
            BackstopAction::AbortBeforeLock
        );
        assert_eq!(
            backstop_decision(StalledTx::Setup, true, true, Some(&ack)),
            BackstopAction::BumpConsented
        );
    }

    #[test]
    fn bump_target_maps_kind_to_ledger_consent() {
        assert_eq!(bump_target(StalledTx::Refund), BumpTarget::Refund);
        assert_eq!(bump_target(StalledTx::Setup), BumpTarget::Completion);
        assert_eq!(bump_target(StalledTx::CompletionUnbroadcast), BumpTarget::Completion);
        assert_eq!(bump_target(StalledTx::CompletionInFlight), BumpTarget::Completion);
    }

    /// The G2 fee-floor fix (finding #2/#4): a matured refund that can't relay
    /// under congestion surfaces as an actionable stall, not a bare error.
    #[test]
    fn matured_refund_below_fee_floor_surfaces_as_actionable_stall() {
        let escrow = op(5);
        let maturity = 600_144u32;
        let chain = SimChain::new(600_000);
        chain.fund_with_amount(escrow, 600_000, 1_000_000);
        // A refund whose baked-in fee is small.
        let refund =
            PreArmedRefund::from_signed_tx(spend_of(escrow, 999_000, Some(144)), maturity).unwrap();
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
        let driver = WatchtowerDriver::arm(refund, escrow, &receipt).unwrap();

        while chain.tip_height() < maturity {
            chain.mine();
        }
        // Congestion floor above the refund's fee: broadcast would be rejected.
        chain.set_congestion(50_000);
        assert_eq!(
            driver.tick(&chain).unwrap(),
            WatchtowerTick::RefundStalledBelowFeeFloor,
            "a congested matured refund must be an actionable stall, not a bare Err"
        );
        // Congestion clears: it fires.
        chain.set_congestion(0);
        assert_eq!(driver.tick(&chain).unwrap(), WatchtowerTick::FiredRefund);
    }
}
