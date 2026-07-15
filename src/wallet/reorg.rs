//! Tester-visible reorg observation (Task 22).
//!
//! The drivers already survive reorgs CONSERVATIVELY: every deadline is read
//! from the CURRENT chain each poll, so a reorg that un-confirms a funding or
//! shifts an anchor makes the wallet HOLD — the refund CSV re-derives from the
//! live funding height ([`WatchtowerDriver`](crate::wallet::watchtower_driver)),
//! the proceed-to-sign gate withdraws its go-signal
//! ([`FundingCoordinator`](crate::wallet::orchestrator)), the claim scheduler
//! fights a foreign re-mine winner, and terminal records re-validate against the
//! chain ([`RecoveryDriver`](crate::wallet::recovery_driver)). A reorg can only
//! ever DELAY an exit, never accelerate one — the audit's guiding principle
//! (`docs/reorg-audit.md`).
//!
//! But "the wallet is holding, on purpose" looks identical to "the wallet is
//! stuck" to a tester. This module turns the silent hold into a LOUD, honest
//! line so a testnet4 reorg (routine there; regtest never reorged under us)
//! reads as the safety system working, not a hang. It is a pure OBSERVATION —
//! it changes no decision; the drivers own every routing choice.

use bitcoin::OutPoint;

use crate::chain::AuthoritativeChainView;
use crate::wallet::store::{SwapPhase, SwapRecord};

/// Which of a swap's two escrows an observation is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscrowSide {
    /// The escrow WE funded — our pre-armed refund reclaims it.
    Ours,
    /// The escrow WE sweep (the counterparty-funded one) — the SL claim anchor.
    Swept,
}

impl EscrowSide {
    fn label(self) -> &'static str {
        match self {
            EscrowSide::Ours => "our escrow",
            EscrowSide::Swept => "the swept escrow",
        }
    }
}

/// A reorg-relevant fact about a LIVE swap, worth surfacing to the tester.
/// Ordered by severity of "why am I waiting": a vanished confirmation first,
/// then a silently-shifted anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReorgSignal {
    /// A funding output a post-funding swap depends on has UN-CONFIRMED (a
    /// reorg orphaned its block). Every exit HOLDS until it re-confirms — the
    /// conservative direction. `authoritative_funding_height` reads `None`.
    FundingUnconfirmed { which: EscrowSide },
    /// The swept escrow RE-CONFIRMED at a DIFFERENT height than the record's
    /// write-once `sweep_escrow_height` anchor. Chain-derived deadlines (the
    /// refund CSV) re-derive from the current height automatically; the
    /// settlement-core claim ceiling still reads the cached anchor (a documented
    /// cryptographer-review residual — see the audit doc). Surfaced so the
    /// tester and a bug report see the shift.
    AnchorShifted { cached: u32, current: u32 },
}

impl ReorgSignal {
    /// A loud, tester-facing line naming the swap (`sid`, hex).
    pub fn describe(self, sid: &[u8; 32]) -> String {
        let sid = hex32(sid);
        match self {
            ReorgSignal::FundingUnconfirmed { which } => format!(
                "reorg detected: {} funding for {sid} un-confirmed; HOLDING until it re-confirms \
                 (a reorg can only delay an exit, never fire one early)",
                which.label()
            ),
            ReorgSignal::AnchorShifted { cached, current } => format!(
                "reorg detected: swept-escrow funding for {sid} re-confirmed at height {current} \
                 (was {cached}); refund maturity re-derives from the current chain"
            ),
        }
    }
}

/// Observe any reorg-relevant condition on a LIVE swap, for the tester-facing
/// poll log. Returns `None` for a swap that is pre-funding (`sweep_escrow_height`
/// not yet set), terminal, or on a chain that shows no reorg. Pure: reads only
/// the record + the authoritative chain, decides nothing.
pub fn observe(rec: &SwapRecord, chain: &dyn AuthoritativeChainView) -> Option<ReorgSignal> {
    // Only meaningful once co-funding fixed the anchors (Funding→Signing) and
    // before the swap terminates — a terminal is re-validated by the recovery
    // driver, not held.
    if rec.sweep_escrow_height == 0
        || matches!(rec.phase, SwapPhase::Completed | SwapPhase::Refunded)
    {
        return None;
    }

    // A vanished confirmation is the loudest signal — check both escrows.
    for (which, op) in [
        (EscrowSide::Ours, rec.our_escrow_outpoint),
        (EscrowSide::Swept, rec.their_escrow_outpoint),
    ] {
        if let Some(op) = op {
            if funding_gone(chain, op) {
                return Some(ReorgSignal::FundingUnconfirmed { which });
            }
        }
    }

    // The swept escrow re-confirmed at a height different from the cached
    // anchor — the silent anchor-shift the audit flags.
    if let Some(swept) = rec.their_escrow_outpoint {
        if let Some(current) = chain.authoritative_funding_height(swept) {
            if current != rec.sweep_escrow_height {
                return Some(ReorgSignal::AnchorShifted {
                    cached: rec.sweep_escrow_height,
                    current,
                });
            }
        }
    }
    None
}

/// A post-funding escrow whose authoritative funding height reads `None` has
/// UN-CONFIRMED (a reorg orphaned it). The authoritative (self-verifying) read
/// is deliberate — matching every other fund-deciding seam, a lying source that
/// merely HIDES a confirmation must not be able to fabricate a reorg alarm.
fn funding_gone(chain: &dyn AuthoritativeChainView, op: OutPoint) -> bool {
    chain.authoritative_funding_height(op).is_none()
}

fn hex32(id: &[u8; 32]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::SimChain;
    use crate::settlement::params::Params;
    use crate::settlement::refund::PreArmedRefund;
    use crate::settlement::state_machine::Role;
    use bitcoin::Txid;

    fn op(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b)), 0)
    }

    fn refund() -> PreArmedRefund {
        PreArmedRefund::from_signed_tx(vec![0xab; 64], 700_144).unwrap()
    }

    /// A post-funding record whose two escrows sit at `our_h`/`their_h`.
    fn live_record(our: OutPoint, their: OutPoint, sweep_h: u32) -> SwapRecord {
        SwapRecord {
            swap_session_id: [7u8; 32],
            role: Role::SecretLearner,
            phase: SwapPhase::Released,
            params: Params::testnet_provisional(),
            s_height: 700_000,
            sweep_escrow_height: sweep_h,
            our_escrow_outpoint: Some(our),
            their_escrow_outpoint: Some(their),
            pre_armed_refund: Some(refund()),
            completion_tx: None,
            setup_tx: None,
            possession_record: None,
        }
    }

    #[test]
    fn pre_funding_and_terminal_records_are_silent() {
        let chain = SimChain::new(700_100);
        // sweep_escrow_height == 0 (pre Funding→Signing): nothing to observe.
        let mut rec = live_record(op(1), op(2), 0);
        rec.phase = SwapPhase::Funding;
        assert_eq!(observe(&rec, &chain), None);
        // Terminal: re-validated by recovery, not held.
        let mut term = live_record(op(1), op(2), 700_010);
        term.phase = SwapPhase::Refunded;
        assert_eq!(observe(&term, &chain), None);
    }

    #[test]
    fn healthy_live_swap_is_silent() {
        let chain = SimChain::new(700_100);
        chain.fund(op(1), 700_000); // our escrow
        chain.fund(op(2), 700_005); // swept escrow, matches the anchor
        let rec = live_record(op(1), op(2), 700_005);
        assert_eq!(observe(&rec, &chain), None, "matching anchors: no signal");
    }

    #[test]
    fn our_funding_unconfirmed_is_surfaced() {
        let chain = SimChain::new(700_100);
        chain.fund(op(1), 700_000);
        chain.fund(op(2), 700_005);
        let rec = live_record(op(1), op(2), 700_005);
        chain.unconfirm_funding(op(1)); // our escrow orphaned
        assert_eq!(
            observe(&rec, &chain),
            Some(ReorgSignal::FundingUnconfirmed { which: EscrowSide::Ours })
        );
        assert!(observe(&rec, &chain).unwrap().describe(&rec.swap_session_id).contains("un-confirmed"));
    }

    #[test]
    fn swept_funding_unconfirmed_is_surfaced() {
        let chain = SimChain::new(700_100);
        chain.fund(op(1), 700_000);
        chain.fund(op(2), 700_005);
        let rec = live_record(op(1), op(2), 700_005);
        chain.unconfirm_funding(op(2));
        assert_eq!(
            observe(&rec, &chain),
            Some(ReorgSignal::FundingUnconfirmed { which: EscrowSide::Swept })
        );
    }

    #[test]
    fn swept_anchor_shift_is_surfaced() {
        let chain = SimChain::new(700_100);
        chain.fund(op(1), 700_000);
        chain.fund(op(2), 700_005);
        let rec = live_record(op(1), op(2), 700_005);
        // A reorg re-confirms the swept escrow LOWER — the dangerous, window-
        // widening direction the audit flags for the claim ceiling.
        chain.unconfirm_funding(op(2));
        chain.reconfirm_funding_at(op(2), 700_002);
        assert_eq!(
            observe(&rec, &chain),
            Some(ReorgSignal::AnchorShifted { cached: 700_005, current: 700_002 })
        );
        let msg = observe(&rec, &chain).unwrap().describe(&rec.swap_session_id);
        assert!(msg.contains("700002") && msg.contains("700005"));
    }
}
