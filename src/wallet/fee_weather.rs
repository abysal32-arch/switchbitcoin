//! Fee-weather preflight (Task 26).
//!
//! Before a swap leases its pre-encumbrance unit, compare the live node feerate
//! estimate against the BAKED Setup feerate and the DERIVED settlement feerate
//! and WARN-AND-PROCEED when live congestion outruns them. The dynamic
//! reserve-CPFP backstop ([`crate::tx::backstop`]) is what actually bridges the
//! gap after a Setup/settlement strands; this is the operator heads-up BEFORE
//! funding into bad weather (a stranded Setup on testnet reads to a tester as a
//! stuck attempt / bug).
//!
//! DECISION (Task 26, pre-made): warn-and-proceed — NO new gate, NO flag. The
//! backstop exists precisely for this, and refusing would strand testers behind
//! testnet spam waves. `None` estimate (fresh/degraded node) → say so, proceed.
//!
//! MEASURED BASELINE: the three vsizes below are the Task-14 measured sizes,
//! the same baseline asserted by `tests/runner.rs::task14_baked_fees_clear_the_
//! relay_floor_with_margin` and documented in `settlement::params`. Task 26
//! step 1 CALIBRATES them against the leg-2 live artifact: if live vsizes differ
//! beyond rounding, update THESE constants + the runner baseline + the params
//! comment together (never the signed params — a params change ships on a
//! manifest, Task 27).

use crate::settlement::params::Params;
use crate::tx::backstop::required_child_fee;

/// Measured Setup vsize (vB): one taproot key-path input, P2TR escrow output +
/// P2A anchor. Setup fee `setup_fee_sats` / this = the baked Setup feerate.
pub const SETUP_VSIZE_VB: u64 = 124;
/// Measured Completion vsize (vB). Kept for calibration symmetry; the Refund is
/// the weakest link, so the settlement floor keys off `REFUND_VSIZE_VB`.
pub const COMPLETION_VSIZE_VB: u64 = 124;
/// Measured Refund vsize (vB): the larger settlement tx (script-path witness).
/// Its lower per-vB feerate is the weakest link, so it sets the settlement
/// feerate floor the preflight warns against.
pub const REFUND_VSIZE_VB: u64 = 143;

/// Baked Setup feerate (sat/vB, integer floor): `setup_fee_sats / Setup vsize`.
/// Flooring is deliberately conservative — it only ever warns when the live
/// estimate STRICTLY exceeds a rate at or below the true baked rate, so there
/// is no false warning at the boundary. (1200/124 → 9.)
pub fn baked_setup_feerate(params: &Params) -> u64 {
    params.setup_fee_sats / SETUP_VSIZE_VB
}

/// Baked settlement feerate (sat/vB, integer floor): the derived
/// `settlement_fee_sats()` over the Refund vsize (the weakest-link settlement
/// tx). (3320/143 → 23.)
pub fn baked_settlement_feerate(params: &Params) -> u64 {
    params.settlement_fee_sats() / REFUND_VSIZE_VB
}

/// One fee-weather reading: the live estimate against the two baked feerates,
/// plus the honest sats a congestion bump would burn from the reserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeWeather {
    /// Live node estimate (sat/vB); `None` when the node has no fee data.
    pub estimate_sat_vb: Option<u64>,
    /// Baked Setup feerate (sat/vB).
    pub setup_baked_sat_vb: u64,
    /// Baked settlement (refund) feerate (sat/vB).
    pub settlement_baked_sat_vb: u64,
    /// Live estimate strictly exceeds the baked Setup feerate.
    pub over_setup: bool,
    /// Live estimate strictly exceeds the baked settlement feerate.
    pub over_settlement: bool,
    /// If adverse: sats a reserve-CPFP bump of the refund package (parent plus
    /// child) to the live estimate would burn, sized the way the backstop sizes
    /// it via [`required_child_fee`]. `None` when not adverse / no estimate.
    pub bump_burn_sats: Option<u64>,
}

impl FeeWeather {
    /// Read the weather: `estimate` is `chain.estimated_feerate_sat_vb()`
    /// (fresh-or-none). Pure; never touches the chain or the node.
    pub fn assess(params: &Params, estimate: Option<u64>) -> Self {
        let setup_baked = baked_setup_feerate(params);
        let settlement_baked = baked_settlement_feerate(params);
        let (over_setup, over_settlement, bump_burn_sats) = match estimate {
            Some(est) => {
                let over_setup = est > setup_baked;
                let over_settlement = est > settlement_baked;
                // Honest bump cost: lift the refund package to the live estimate
                // from the reserve, reusing the backstop's own package sizing.
                let burn = (over_setup || over_settlement)
                    .then(|| required_child_fee(est, params.settlement_fee_sats(), REFUND_VSIZE_VB));
                (over_setup, over_settlement, burn)
            }
            None => (false, false, None),
        };
        FeeWeather {
            estimate_sat_vb: estimate,
            setup_baked_sat_vb: setup_baked,
            settlement_baked_sat_vb: settlement_baked,
            over_setup,
            over_settlement,
            bump_burn_sats,
        }
    }

    /// True when the live estimate exceeds a baked rate — the LOUD case.
    pub fn is_adverse(&self) -> bool {
        self.over_setup || self.over_settlement
    }

    /// Which baked rate(s) the estimate exceeds, for the warning text.
    fn exceeded(&self) -> &'static str {
        match (self.over_setup, self.over_settlement) {
            (true, true) => "Setup + settlement",
            (true, false) => "Setup",
            (false, true) => "settlement",
            (false, false) => "none",
        }
    }

    /// The single operator log line. STABLE text — the TESTER-GUIDE fee-weather
    /// row and the preflight tests key on the leading marker of each arm
    /// (`FEE WEATHER WARNING` / `fee weather OK` / `fee weather: no live`).
    pub fn log_line(&self) -> String {
        let (s, t) = (self.setup_baked_sat_vb, self.settlement_baked_sat_vb);
        match self.estimate_sat_vb {
            None => format!(
                "fee weather: no live estimate — proceeding on baked fees \
                 (Setup {s} / settlement {t} sat/vB)"
            ),
            Some(est) if !self.is_adverse() => format!(
                "fee weather OK: live {est} sat/vB \u{2264} baked \
                 (Setup {s} / settlement {t} sat/vB)"
            ),
            Some(est) => format!(
                "FEE WEATHER WARNING: live {est} sat/vB exceeds baked {} \
                 (Setup {s} / settlement {t} sat/vB) — proceeding; the reserve-CPFP \
                 backstop bridges it (a bump could burn ~{} sats of your reserve)",
                self.exceeded(),
                self.bump_burn_sats.unwrap_or(0),
            ),
        }
    }

    /// Append-only `/status` object (Task 26 field; Task 28 surfaces it).
    pub fn json(&self) -> String {
        let num = |o: Option<u64>| o.map(|n| n.to_string()).unwrap_or_else(|| "null".into());
        format!(
            "{{\"estimate_sat_vb\":{},\"setup_baked_sat_vb\":{},\
             \"settlement_baked_sat_vb\":{},\"over_setup\":{},\"over_settlement\":{},\
             \"adverse\":{},\"bump_burn_sats\":{}}}",
            num(self.estimate_sat_vb),
            self.setup_baked_sat_vb,
            self.settlement_baked_sat_vb,
            self.over_setup,
            self.over_settlement,
            self.is_adverse(),
            num(self.bump_burn_sats),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Params {
        Params::testnet_provisional()
    }

    #[test]
    fn baked_rates_match_the_measured_baseline() {
        let p = params();
        // 1200/124 = 9 (9.68 floored); 3320/143 = 23 (23.2 floored).
        assert_eq!(baked_setup_feerate(&p), 9);
        assert_eq!(baked_settlement_feerate(&p), 23);
    }

    #[test]
    fn no_estimate_is_never_adverse_and_says_so() {
        let fw = FeeWeather::assess(&params(), None);
        assert!(!fw.is_adverse());
        assert_eq!(fw.bump_burn_sats, None);
        assert!(fw.log_line().starts_with("fee weather: no live estimate"));
    }

    #[test]
    fn estimate_at_or_below_both_is_quiet_ok() {
        // 9 ≤ setup(9) and ≤ settlement(23): not adverse (strict >).
        let fw = FeeWeather::assess(&params(), Some(9));
        assert!(!fw.is_adverse());
        assert!(!fw.over_setup);
        assert!(!fw.over_settlement);
        assert_eq!(fw.bump_burn_sats, None);
        assert!(fw.log_line().starts_with("fee weather OK"));
    }

    #[test]
    fn estimate_between_setup_and_settlement_warns_on_setup_only() {
        // 15 > setup(9), ≤ settlement(23).
        let fw = FeeWeather::assess(&params(), Some(15));
        assert!(fw.is_adverse());
        assert!(fw.over_setup);
        assert!(!fw.over_settlement);
        let line = fw.log_line();
        assert!(line.starts_with("FEE WEATHER WARNING"));
        assert!(line.contains("exceeds baked Setup ("));
    }

    #[test]
    fn estimate_above_both_warns_on_both_with_burn() {
        // 50 > setup(9) and > settlement(23).
        let fw = FeeWeather::assess(&params(), Some(50));
        assert!(fw.over_setup && fw.over_settlement);
        assert!(fw.log_line().contains("Setup + settlement"));
        // Honest bump cost: 50*(143+120) - 3320 = 9830 sats.
        assert_eq!(fw.bump_burn_sats, Some(50 * (143 + 120) - 3320));
    }

    #[test]
    fn bump_burn_cross_checks_the_reserve_sustaining_rate() {
        // The params comment claims the 25k reserve sustains a bump to ≈107
        // sat/vB; the honest burn at 107 must land just under the 25k reserve.
        let fw = FeeWeather::assess(&params(), Some(107));
        let burn = fw.bump_burn_sats.unwrap();
        assert!(burn <= params().cpfp_reserve_sats, "burn {burn} must fit the 25k reserve");
        assert!(burn > 24_000, "…and be close to it (got {burn})");
    }

    #[test]
    fn json_is_well_formed_both_arms() {
        let ok = FeeWeather::assess(&params(), Some(9)).json();
        assert!(ok.contains("\"adverse\":false"));
        assert!(ok.contains("\"bump_burn_sats\":null"));
        let bad = FeeWeather::assess(&params(), Some(50)).json();
        assert!(bad.contains("\"adverse\":true"));
        assert!(bad.contains("\"over_setup\":true"));
        let none = FeeWeather::assess(&params(), None).json();
        assert!(none.contains("\"estimate_sat_vb\":null"));
    }
}
