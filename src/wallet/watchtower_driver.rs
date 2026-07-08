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
//!     privacy loss, so it is gated behind explicit consent (`LinkageAck`)
//!     and, when taken, the swapped output is marked deposit-linked (the
//!     rank-3 ledger already records the taint).
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

use crate::chain::{ChainView, SpendStatus};
use crate::settlement::refund::{PreArmedRefund, Watchtower, WatchtowerReceipt};
use crate::wallet::ledger::{BumpTarget, LinkageAck};
use crate::Result;
use bitcoin::OutPoint;

/// The own-device watchtower driver: the refund tower plus the escrow it
/// guards, polled by the background loop.
pub struct WatchtowerDriver {
    tower: Watchtower,
    escrow_outpoint: OutPoint,
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
        let tower = Watchtower::arm(refund, escrow_outpoint, receipt)?;
        Ok(WatchtowerDriver { tower, escrow_outpoint })
    }

    /// One poll of the background loop. Idempotent and crash-safe: it
    /// re-reads chain state every call, so a restart just re-evaluates.
    pub fn tick(&self, chain: &impl ChainView) -> Result<WatchtowerTick> {
        match chain.spend_status(self.escrow_outpoint) {
            // A completion won or our own refund already confirmed: terminal.
            SpendStatus::Confirmed(_) => Ok(WatchtowerTick::StandDown),
            // A completion pending in the mempool is TRANSIENT (it may evict);
            // keep watching rather than standing down forever.
            SpendStatus::InMempool => Ok(WatchtowerTick::Idle),
            SpendStatus::Unspent => {
                if self.tower.poll(chain)? {
                    Ok(WatchtowerTick::FiredRefund)
                } else {
                    Ok(WatchtowerTick::Idle)
                }
            }
        }
    }
}

/// Which contract tx the backstop would bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StalledTx {
    /// A refund — no privacy left; bump silently.
    Refund,
    /// A completion — bumping links the reserve to the swap; needs consent.
    Completion,
}

/// The fee-backstop decision for a stalled contract tx.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackstopAction {
    /// Not congested (or the tx already confirmed): nothing to do.
    None,
    /// Silent auto-bump — a stalled REFUND carries no privacy, so the
    /// backstop fires without a prompt. Caller: lease a reserve coin and
    /// build the CPFP child.
    BumpSilently,
    /// A stalled COMPLETION: bumping is a real privacy loss, so surface the
    /// consent prompt to the user. No bump until a `LinkageAck` is provided.
    NeedsCompletionConsent,
    /// Consent given: bump the completion (and record the deposit-link taint
    /// on the swapped output).
    BumpCompletion,
    /// Congested but no reserve coin is available to fund the bump. For a
    /// completion, the safe fallback is to let the pre-armed refund reclaim
    /// (abandon-to-refund) — never a stuck coin. For a refund, keep
    /// retrying/waiting for congestion to clear.
    NoReserveAvailable,
}

/// Decide the backstop action for a stalled tx. Pure; the wallet layer wires
/// this to `ledger::lease_reserve` (which itself re-checks the `LinkageAck`
/// for a completion) and `tx::backstop::build_cpfp_bump`.
///
/// `congested` is the "this contract tx cannot currently relay / is stalled
/// below the fee floor" signal from the chain view. `reserve_available` is
/// whether the ledger holds a leasable reserve coin.
pub fn backstop_decision(
    kind: StalledTx,
    congested: bool,
    reserve_available: bool,
    completion_consent: Option<&LinkageAck>,
) -> BackstopAction {
    if !congested {
        return BackstopAction::None;
    }
    if !reserve_available {
        return BackstopAction::NoReserveAvailable;
    }
    match kind {
        StalledTx::Refund => BackstopAction::BumpSilently,
        StalledTx::Completion => {
            if completion_consent.is_some() {
                BackstopAction::BumpCompletion
            } else {
                BackstopAction::NeedsCompletionConsent
            }
        }
    }
}

/// The `BumpTarget` a `StalledTx` maps to, for `ledger::lease_reserve`
/// (refund bumps are silent; completion bumps demand the linkage ack).
pub fn bump_target(kind: StalledTx) -> BumpTarget {
    match kind {
        StalledTx::Refund => BumpTarget::Refund,
        StalledTx::Completion => BumpTarget::Completion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::SimChain;
    use crate::settlement::refund::confirm_watchtower_handoff;
    use crate::wallet::ledger::{acknowledge_linkage, LINKAGE_WARNING};

    fn op(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b)), 0)
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
            output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: ScriptBuf::new() }],
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
    fn backstop_refund_bumps_silently_completion_needs_consent() {
        // Not congested: no bump.
        assert_eq!(
            backstop_decision(StalledTx::Refund, false, true, None),
            BackstopAction::None
        );
        // Congested refund with reserve: silent auto-bump (no privacy to lose).
        assert_eq!(
            backstop_decision(StalledTx::Refund, true, true, None),
            BackstopAction::BumpSilently
        );
        // Congested completion, no consent yet: surface the prompt.
        assert_eq!(
            backstop_decision(StalledTx::Completion, true, true, None),
            BackstopAction::NeedsCompletionConsent
        );
        // With the typed consent: bump.
        let ack = acknowledge_linkage(LINKAGE_WARNING).unwrap();
        assert_eq!(
            backstop_decision(StalledTx::Completion, true, true, Some(&ack)),
            BackstopAction::BumpCompletion
        );
        // Congested but no reserve: cannot bump (completion falls back to
        // the pre-armed refund; never a stuck coin).
        assert_eq!(
            backstop_decision(StalledTx::Completion, true, false, Some(&ack)),
            BackstopAction::NoReserveAvailable
        );
        assert_eq!(
            backstop_decision(StalledTx::Refund, true, false, None),
            BackstopAction::NoReserveAvailable
        );
    }

    #[test]
    fn bump_target_maps_kind_to_ledger_consent() {
        assert_eq!(bump_target(StalledTx::Refund), BumpTarget::Refund);
        assert_eq!(bump_target(StalledTx::Completion), BumpTarget::Completion);
    }
}
