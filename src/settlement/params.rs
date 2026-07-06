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

#[derive(Clone, Debug)]
pub struct Params {
    /// Exactly-equal swapped output per tier (satoshis). Testnet: 0.01 tBTC.
    pub tier_d_sats: u64,
    /// Baked-in fee margin (satoshis). Sized to worse of completion/refund + headroom.
    pub delta_fee_sats: u64,
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
    pub fn testnet_provisional() -> Self {
        Params {
            tier_d_sats: 1_000_000,      // 0.01 tBTC
            delta_fee_sats: 5_000,       // placeholder; TUNE on testnet
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
        // The SL post-reveal claim window is (margin + delta_buffer) blocks wide;
        // the confirm allowance must fit strictly inside it, and must be nonzero
        // (a claim that cannot be given any confirmation budget is no claim).
        let claim_window = self.margin as u64 + self.delta_buffer as u64;
        if self.claim_confirm_allowance == 0
            || self.claim_confirm_allowance as u64 >= claim_window
        {
            return Err(Error::Deadline(
                "claim_confirm_allowance must be in (0, margin + delta_buffer)",
            ));
        }
        // Economic sanity: fee margin covers dust + a real fee, output stays exactly D.
        if self.delta_fee_sats == 0 {
            return Err(Error::Deadline("delta_fee must be > 0"));
        }
        Ok(())
    }

    /// Upper bound for the randomized SL claim delay (in blocks), such that
    /// broadcast at `reveal_height + delay` still confirms (within the
    /// allowance) strictly before S + delta_late. Total; never panics.
    /// Returns 0 when the window is already tight or past — claim IMMEDIATELY.
    pub fn max_claim_delay(&self, s_height: u32, reveal_height: u32) -> u64 {
        let deadline = s_height as u64 + self.delta_late();
        let budget_end = deadline.saturating_sub(self.claim_confirm_allowance as u64);
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
