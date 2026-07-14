//! Provisional testnet parameters (v3.16 Requirement 6).
//!
//! Named constants, marked testnet-provisional, to be confirmed against testnet
//! data before mainnet. In production these arrive as SIGNED, VERSIONED values on
//! the manifest trust path — NOT free-form wallet settings. Here they are compiled
//! defaults so the prototype has real numbers to run.
//!
//! SAFETY-CRITICAL: the ORDERING invariant (checked in `Params::validate`) may
//! never be violated even if individual values are tuned. This is what makes the
//! extract-and-race region unreachable (cryptographer review item #5).
//!
//! ARITHMETIC RULE: params come (in production) from a signed manifest, but the
//! validator must be TOTAL — a hostile/corrupt manifest gets `Err`, never a
//! panic. All height arithmetic is done in u64 (u32 inputs cannot overflow it),
//! so `overflow-checks = true` has nothing to trip on here.

use crate::{Error, Result};

/// Floor for the Setup's baked fee: a Setup is ~125 vB (one taproot key-path
/// input, P2TR escrow output + P2A anchor), so 200 sats keeps it strictly
/// above the 1 sat/vB min-relay with headroom. Testnet-tunable.
pub const MIN_SETUP_FEE_SATS: u64 = 200;

/// Floor for the derived settlement fee: the refund (the larger settlement
/// tx, ~205 vB with its script-path witness) must clear min-relay with
/// headroom. Testnet-tunable.
pub const MIN_SETTLEMENT_FEE_SATS: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Exactly-equal swapped output per tier (satoshis). Testnet: 0.01 tBTC.
    pub tier_d_sats: u64,
    /// Baked-in fee margin (satoshis). Under the scheme-(a) fee model
    /// (§4.98 resolution) it is CONSUMED EXACTLY by the four components:
    /// `setup_fee + anchor + settlement_fee + anchor == delta_fee`, where
    /// `settlement_fee` is derived (`settlement_fee_sats()`), so the
    /// completion/refund destination still receives exactly D.
    pub delta_fee_sats: u64,
    /// Value of the P2A anchor output every contract tx (Setup, Completion,
    /// Refund) carries. Must be at least the 240-sat P2A dust floor so a
    /// POSITIVE-fee parent relays standalone on real Core (the ephemeral
    /// 0-value anchor is only relayable on 0-fee package parents). Manifest-
    /// signed like every fee component: equal anchors across the tier.
    pub anchor_sats: u64,
    /// The Setup's baked fee. Positive, so the Setup relays STANDALONE and
    /// the anchor CPFP stays truly congestion-only.
    pub setup_fee_sats: u64,
    /// The dedicated CPFP-reserve output the onboarding split carves, apart
    /// from the D + Δ_fee pre-encumbrance units — the coin the congestion
    /// backstop leases to anchor-bump a stalled settlement. Carved once per
    /// deposit split (when the deposit can fund it); without it the CPFP
    /// backstop is inert. Manifest-signed like every other amount.
    pub cpfp_reserve_sats: u64,
    /// SL refund maturity, relative blocks from S.
    pub delta_early: u32,
    /// Extra margin so SH refund matures later. delta_late = delta_early + margin.
    pub margin: u32,
    /// SH must CONFIRM Comp->SH by S + delta_early - delta_buffer, else abandon.
    pub delta_buffer: u32,
    /// Blocks budgeted for the SL claim to confirm after broadcast (bounds the
    /// randomized claim delay: reveal + delay + allowance <= S + delta_late).
    pub claim_confirm_allowance: u32,
    /// Both Setups must confirm within this many blocks of each other (widened + jitter).
    pub cofunding_window: u32,
    /// Onboarding delay bounds (hours) — severs withdrawal<->encumbrance timing.
    pub onboarding_delay_hours: (u32, u32),
}

impl Params {
    /// Provisional testnet defaults (Requirement 6 table).
    ///
    /// Fee baseline VALIDATED against measured vsizes (Task 14; the signed
    /// fixture txs, asserted by `task14_baked_fees_clear_the_relay_floor_with_
    /// margin` in tests/runner.rs): Setup 124 vB → 1_200 sats ≈ 9.7 sat/vB;
    /// Completion 124 vB and Refund 143 vB → 3_320 sats (the derived
    /// `settlement_fee_sats`) ≈ 26.8 / 23.2 sat/vB. All three clear bitcoind's
    /// stock 1 sat/vB relay floor with 9–26x margin, so the numbers KEEP.
    /// When live congestion outruns a baked feerate (estimate above ~9 sat/vB
    /// strands a Setup, above ~23 an exit), the DYNAMIC backstop (Task 14:
    /// `estimated_feerate_sat_vb` → CPFP) bridges the gap — the
    /// `cpfp_reserve_sats` below sustains a refund-package bump (143+120 vB)
    /// to ≈107 sat/vB, and `MAX_BUMP_FEE_SATS` caps the burn.
    pub fn testnet_provisional() -> Self {
        Params {
            tier_d_sats: 1_000_000,      // 0.01 tBTC
            delta_fee_sats: 5_000,       // = setup_fee + 2*anchor + settlement_fee (measured-validated)
            anchor_sats: 240,            // the P2A dust floor (Core 28+)
            setup_fee_sats: 1_200,       // Setup MEASURED 124 vB → ~9.7 sat/vB baked
            cpfp_reserve_sats: 25_000,   // 0.00025 BTC — the advertised reserve
            delta_early: 144,            // ~24 h
            margin: 72,                  // ~12 h -> delta_late ~ 216
            delta_buffer: 24,            // ~4 h
            claim_confirm_allowance: 6,  // ~1 h to confirm the SL claim
            cofunding_window: 12,        // widened from 6; + runtime jitter
            onboarding_delay_hours: (24, 72),
        }
    }

    /// delta_late = delta_early + margin, computed in u64: total for any inputs.
    pub fn delta_late(&self) -> u64 {
        self.delta_early as u64 + self.margin as u64
    }

    // ---- Fee-model arithmetic (scheme (a), §4.98 resolution) ----------------
    // The pre-encumbrance coin is exactly D + Δ_fee (onboarding split target,
    // unchanged). The Setup consumes setup_cost = setup_fee + anchor from it,
    // so the escrow is D + Δ_fee − setup_cost; the settlement (completion or
    // refund) delivers exactly D, carries its own anchor, and pays the
    // remainder: settlement_fee = Δ_fee − setup_fee − 2·anchor. All four
    // components are manifest-signed, so escrows stay EQUAL across a tier
    // (the privacy linchpin). All accessors are total (saturating); on
    // `validate()`-accepted params they are exact.

    /// The onboarding split target / pre-encumbrance coin size: exactly D + Δ_fee.
    pub fn pre_encumbrance_sats(&self) -> u64 {
        self.tier_d_sats.saturating_add(self.delta_fee_sats)
    }

    /// What the Setup consumes from Δ_fee: its baked fee plus its anchor.
    pub fn setup_cost_sats(&self) -> u64 {
        self.setup_fee_sats.saturating_add(self.anchor_sats)
    }

    /// The escrow amount every tier participant funds: D + Δ_fee − setup_cost.
    /// THE encumbrance-verification amount (the funding gate compares the
    /// counterparty escrow against exactly this).
    pub fn escrow_amount_sats(&self) -> u64 {
        self.pre_encumbrance_sats().saturating_sub(self.setup_cost_sats())
    }

    /// The baked settlement fee a completion/refund pays:
    /// escrow − D − anchor = Δ_fee − setup_fee − 2·anchor.
    pub fn settlement_fee_sats(&self) -> u64 {
        self.escrow_amount_sats()
            .saturating_sub(self.tier_d_sats)
            .saturating_sub(self.anchor_sats)
    }

    /// THE ordering invariant. Cryptographer review item #5 depends on this holding.
    /// Values may be tuned; this check may not fail. Total: hostile params => Err.
    pub fn validate(&self) -> Result<()> {
        // delta_late strictly after delta_early:
        if self.margin == 0 {
            return Err(Error::Deadline("margin must be > 0 (delta_late must exceed delta_early)"));
        }
        // buffer must leave SH a real deadline strictly before SL's refund:
        if self.delta_buffer == 0 || self.delta_buffer >= self.delta_early {
            return Err(Error::Deadline("delta_buffer must be in (0, delta_early)"));
        }
        // SL's GUARANTEED post-reveal claim window under MAX co-funding skew,
        // against a MALICIOUS SH (adversary-proof, CRYPTOGRAPHER REVIEW ITEM #5).
        // The honest-SH broadcast gate (`broadcast_completion`) voluntarily
        // reveals by `S + delta_early - delta_buffer`, which would widen the
        // window by `delta_buffer` — but a malicious SH BYPASSES that gate (it
        // crafts the final Comp→SH signature with `CompletePreSig::complete_with`
        // and broadcasts raw, no runway check), so the adversary-proof latest
        // reveal is bounded only by E_sl's own refund timelock at
        // `f_sl + delta_early`. With the claim anchored to the swept escrow's own
        // height `f_sh = S - skew` and worst case `f_sl = f_sh + cofunding_window`,
        // the window is `margin - cofunding_window` blocks — NO delta_buffer
        // term. The allowance must fit strictly inside `(0, margin - cofunding_window)`.
        // (Previously `margin + delta_buffer - cofunding_window`, an honest-SH
        // assumption; tightened in lockstep with the manifest delay-bound window
        // and the provisional posture bounds. The runtime `max_claim_delay` clamp
        // was already adversary-proof — this closes the defensive pre-check.)
        let claim_window = (self.margin as u64).saturating_sub(self.cofunding_window as u64);
        if self.claim_confirm_allowance == 0
            || self.claim_confirm_allowance as u64 >= claim_window
        {
            return Err(Error::Deadline(
                "claim_confirm_allowance must be in (0, margin - cofunding_window)",
            ));
        }
        // Economic sanity: fee margin covers dust + a real fee, output stays exactly D.
        if self.delta_fee_sats == 0 {
            return Err(Error::Deadline("delta_fee must be > 0"));
        }
        // The swapped output must be a real, non-dust amount, and the fee
        // margin must be a MARGIN — smaller than the principal it protects.
        // (A zero/dust tier or a fee that swallows the tier passes no other
        // check but breaks every economic assumption downstream.)
        if self.tier_d_sats < 1_000 {
            return Err(Error::Deadline("tier D must be at least 1000 sats (non-dust)"));
        }
        if self.delta_fee_sats >= self.tier_d_sats {
            return Err(Error::Deadline("delta_fee must be smaller than tier D"));
        }
        // The CPFP reserve must be a RELAYABLE output (else the carved coin is
        // dust the split cannot even create) and a reserve — strictly smaller
        // than the tier principal. reserve < D < unit also guarantees an RBF
        // split re-plan can never GROW k when a higher fee drops the reserve
        // (ledger invariant: attempts only shrink).
        if self.cpfp_reserve_sats < crate::chain::policy::DUST_P2TR_SATS {
            return Err(Error::Deadline("cpfp reserve below the P2TR dust floor (330 sats)"));
        }
        if self.cpfp_reserve_sats >= self.tier_d_sats {
            return Err(Error::Deadline("cpfp reserve must be smaller than tier D"));
        }
        // --- Fee-model components (scheme (a)): every contract tx must be
        // STANDALONE-relayable on real Core policy, or the G2 dead-device
        // refund fire is dead on arrival. The anchor must clear the P2A dust
        // floor (a below-dust anchor on a positive-fee parent is rejected as
        // dust); the setup fee and the DERIVED settlement fee must clear
        // real min-relay floors with headroom. Checked arithmetic: hostile
        // params get Err, never an underflowed escrow amount.
        if self.anchor_sats < crate::chain::policy::DUST_P2A_SATS {
            return Err(Error::Deadline("anchor must be at least the P2A dust floor (240 sats)"));
        }
        if self.setup_fee_sats < MIN_SETUP_FEE_SATS {
            return Err(Error::Deadline("setup fee below the standalone-relay floor"));
        }
        let committed = self
            .setup_fee_sats
            .checked_add(self.anchor_sats.checked_mul(2).ok_or(Error::Deadline("anchor overflow"))?)
            .ok_or(Error::Deadline("fee component overflow"))?;
        let settlement_fee = self
            .delta_fee_sats
            .checked_sub(committed)
            .ok_or(Error::Deadline("delta_fee cannot cover setup fee + two anchors"))?;
        if settlement_fee < MIN_SETTLEMENT_FEE_SATS {
            return Err(Error::Deadline(
                "derived settlement fee below the standalone-relay floor",
            ));
        }
        // Onboarding delay: zero lower bound would defeat the withdrawal<->
        // encumbrance timing decorrelation entirely; inverted bounds are
        // malformed.
        if self.onboarding_delay_hours.0 == 0
            || self.onboarding_delay_hours.0 > self.onboarding_delay_hours.1
        {
            return Err(Error::Deadline(
                "onboarding delay bounds must satisfy 0 < lo <= hi",
            ));
        }
        // On-chain CSV field is BIP68 16-bit relative-height. Both refund
        // maturities must fit, or `Sequence::from_height` would truncate and a
        // refund could mature FAR earlier than intended (collapsing the
        // ordering). delta_late() = delta_early + margin is the larger.
        if self.delta_late() > u16::MAX as u64 {
            return Err(Error::Deadline("delta_late exceeds the 16-bit BIP68 CSV field"));
        }
        // Defense-in-depth against co-funding skew: S is the LATER of the two
        // funding confirmations, so the earlier-funded escrow's CSV is measured
        // from up to `cofunding_window` blocks before S. The SH broadcast buffer
        // must absorb that skew, else the reveal deadline can slip.
        if self.delta_buffer as u64 <= self.cofunding_window as u64 {
            return Err(Error::Deadline("delta_buffer must exceed cofunding_window (absorb funding skew)"));
        }
        Ok(())
    }

    /// Upper bound for the randomized SL claim delay (in blocks), such that
    /// broadcast at `reveal_height + delay` still confirms (within the
    /// allowance) strictly before the SH-funded escrow's LATE refund matures.
    ///
    /// `anchor_height` MUST be the confirmation height of the escrow SL sweeps
    /// (the SH-funded escrow), NOT the co-funding baseline S. Bitcoin's relative
    /// timelock matures at `anchor_height + delta_late` measured from THAT
    /// escrow's own funding, so anchoring to S (= max of the two funding heights)
    /// would over-grant by up to `cofunding_window` blocks and open a reachable
    /// extract-and-race window under co-funding skew. Total; never panics.
    /// Returns 0 when the window is already tight or past — claim IMMEDIATELY.
    ///
    /// STRICTLY-BEFORE semantics (adversarial-review fix): under BIP68 the SH
    /// refund is includable in block `anchor + delta_late` itself, so the
    /// claim must be budgeted to confirm by `deadline - 1` at the latest — a
    /// budget that merely reaches the deadline puts claim and refund in the
    /// same block and reopens the race at the boundary. Hence the extra -1.
    pub fn max_claim_delay(&self, anchor_height: u32, reveal_height: u32) -> u64 {
        let deadline = anchor_height as u64 + self.delta_late();
        let budget_end = deadline
            .saturating_sub(self.claim_confirm_allowance as u64)
            .saturating_sub(1);
        budget_end.saturating_sub(reveal_height as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisional_defaults_validate() {
        assert!(Params::testnet_provisional().validate().is_ok());
    }

    #[test]
    fn fee_components_conserve_delta_fee_and_output_stays_d() {
        let p = Params::testnet_provisional();
        // setup_fee + anchor + settlement_fee + anchor == delta_fee, exactly.
        assert_eq!(
            p.setup_fee_sats + p.anchor_sats + p.settlement_fee_sats() + p.anchor_sats,
            p.delta_fee_sats
        );
        // Escrow = pre-encumbrance − setup_cost; settlement delivers exactly D.
        assert_eq!(p.escrow_amount_sats(), p.pre_encumbrance_sats() - p.setup_cost_sats());
        assert_eq!(
            p.escrow_amount_sats() - p.settlement_fee_sats() - p.anchor_sats,
            p.tier_d_sats
        );
    }

    #[test]
    fn fee_component_violations_are_rejected() {
        let base = Params::testnet_provisional();

        // Sub-dust anchor: the §4.98 defect shape (0-value anchor) must be
        // unrepresentable in validated params.
        let mut p = base.clone();
        p.anchor_sats = 0;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.anchor_sats = 239;
        assert!(p.validate().is_err());

        // Zero/dusty setup fee: the Setup could not relay standalone.
        let mut p = base.clone();
        p.setup_fee_sats = 0;
        assert!(p.validate().is_err());

        // delta_fee too small to cover the components: rejected, not underflowed.
        let mut p = base.clone();
        p.delta_fee_sats = p.setup_fee_sats + 2 * p.anchor_sats; // settlement fee would be 0
        assert!(p.validate().is_err());

        // Hostile extremes: total, never a panic.
        let mut p = base.clone();
        p.anchor_sats = u64::MAX;
        p.setup_fee_sats = u64::MAX;
        assert!(p.validate().is_err());
        let _ = p.escrow_amount_sats();
        let _ = p.settlement_fee_sats();
    }

    #[test]
    fn cpfp_reserve_bounds_are_enforced() {
        let base = Params::testnet_provisional();
        assert_eq!(base.cpfp_reserve_sats, 25_000, "the frontend-advertised reserve");

        // Sub-dust (or zero) reserve: the carved output would be unrelayable.
        let mut p = base.clone();
        p.cpfp_reserve_sats = 0;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.cpfp_reserve_sats = 329;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.cpfp_reserve_sats = 330;
        assert!(p.validate().is_ok());

        // A "reserve" rivaling the principal is absurd (and would break the
        // ledger's k-never-grows RBF invariant).
        let mut p = base.clone();
        p.cpfp_reserve_sats = p.tier_d_sats;
        assert!(p.validate().is_err());
        let mut p = base.clone();
        p.cpfp_reserve_sats = u64::MAX;
        assert!(p.validate().is_err());
    }

    #[test]
    fn ordering_violations_are_rejected_not_panicked() {
        let base = Params::testnet_provisional();

        let mut p = base.clone();
        p.margin = 0;
        assert!(p.validate().is_err());

        let mut p = base.clone();
        p.delta_buffer = 0;
        assert!(p.validate().is_err());

        let mut p = base.clone();
        p.delta_buffer = p.delta_early;
        assert!(p.validate().is_err());

        // Hostile extremes must return Err, never overflow-panic.
        let mut p = base.clone();
        p.margin = u32::MAX;
        p.delta_buffer = u32::MAX - 1;
        p.delta_early = u32::MAX;
        assert!(p.validate().is_ok() || p.validate().is_err()); // total, no panic
        let _ = p.delta_late();
        let _ = p.max_claim_delay(u32::MAX, 0);
        let _ = p.max_claim_delay(0, u32::MAX);
    }
}
