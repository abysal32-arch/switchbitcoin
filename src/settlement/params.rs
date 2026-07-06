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
    /// Both Setups must confirm within this many blocks of each other (widened + jitter).
    pub cofunding_window: u32,
    /// Onboarding delay bounds (hours) — severs withdrawal<->encumbrance timing.
    pub onboarding_delay_hours: (u32, u32),
}

impl Params {
    /// Provisional testnet defaults (Requirement 6 table).
    pub fn testnet_provisional() -> Self {
        Params {
            tier_d_sats: 1_000_000,     // 0.01 tBTC
            delta_fee_sats: 5_000,      // placeholder; TUNE on testnet
            delta_early: 144,           // ~24 h
            margin: 72,                 // ~12 h -> delta_late ~ 216
            delta_buffer: 24,           // ~4 h
            cofunding_window: 12,       // widened from 6; + runtime jitter
            onboarding_delay_hours: (24, 72),
        }
    }

    pub fn delta_late(&self) -> u32 {
        self.delta_early + self.margin
    }

    /// THE ordering invariant. Cryptographer review item #5 depends on this holding.
    /// Values may be tuned; this check may not fail.
    pub fn validate(&self) -> Result<()> {
        // delta_late strictly after delta_early:
        if self.margin == 0 {
            return Err(Error::Deadline("margin must be > 0 (delta_late must exceed delta_early)"));
        }
        // buffer must leave SH a real deadline strictly before SL's refund:
        if self.delta_buffer == 0 || self.delta_buffer >= self.delta_early {
            return Err(Error::Deadline("delta_buffer must be in (0, delta_early)"));
        }
        // SL's post-reveal claim window (>= margin + delta_buffer) must be positive:
        if self.margin + self.delta_buffer == 0 {
            return Err(Error::Deadline("claim window non-positive"));
        }
        // Economic sanity: fee margin covers dust + a real fee, output stays exactly D.
        if self.delta_fee_sats == 0 {
            return Err(Error::Deadline("delta_fee must be > 0"));
        }
        Ok(())
    }
}
