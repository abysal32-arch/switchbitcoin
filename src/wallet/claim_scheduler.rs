//! SL claim scheduler + SH broadcast routing (wallet rank 5).
//!
//! THE PRIMARY PRIVACY-VS-LIVENESS DIAL. v3.14: "SL waits a random interval
//! d before broadcasting Comp→SL, with d drawn from a signed, versioned
//! distribution bounded safely inside the remaining margin (SL always
//! retains enough window to confirm before S + Δ_late even at the maximum
//! d)." The distribution is the manifest's active posture (minimal /
//! moderate / aggressive).
//!
//! TWO BOUNDS, COMPOSED:
//!
//!   * PRIVACY target — the active posture's [min, max] delay (from the
//!     signed manifest). More decorrelation ⇒ wider.
//!   * SAFETY ceiling — `Possessing::claim_delay_ceiling`, the hard bound
//!     anchored to the escrow SL sweeps (NOT the co-funding baseline S), so
//!     co-funding skew cannot widen the race window.
//!
//! The sampled delay is drawn from the posture range CLAMPED to the ceiling.
//! Safety always wins: if the ceiling is below the posture minimum (a tight
//! or late reveal), the ceiling caps the delay even at the cost of
//! decorrelation. This is the one place the two dials meet, and the clamp is
//! what makes "even at maximum d, SL confirms before S + Δ_late" TRUE for
//! every posture the operator can publish.
//!
//! MEMPOOL-FIRST reveal: a visible Comp→SH (even unconfirmed in the mempool)
//! already exposes s_final, so the scheduler extracts the INSTANT the reveal
//! appears — it does not wait for confirmation. A counterparty who parks a
//! low-fee completion is handing SL the secret, not delaying it.
//!
//! SH SIDE — broadcast routing (v3.13): SH broadcasts Comp→SH only while it
//! still has runway (deadline − tip ≥ safe_depth) AND the watchtower is
//! armed; below that runway it abandons to the pre-armed refund. The runway
//! check here is the wallet policy on top of `broadcast_completion`'s hard
//! Δ_buffer gate.

use crate::chain::{ChainView, SpendStatus};
use crate::crypto::ValidatedFinalSig;
use crate::settlement::state_machine::{CompletionSig, Possessing};
use crate::wallet::manifest::SignedManifest;
use crate::Result;
use bitcoin::{OutPoint, Txid};
use rand::TryRngCore;

/// The SL claim scheduler, parameterized by the signed manifest's active
/// posture. Poll-driven and re-enterable: reveal detection and the timed
/// broadcast are separate decisions the outer loop steps.
pub struct ClaimScheduler {
    posture_min: u32,
    posture_max: u32,
}

/// A prepared claim: the finalized Comp→SL signature and the height at which
/// to broadcast it (reveal height + the sampled posture delay).
pub struct ScheduledClaim {
    pub comp_sl_final: CompletionSig,
    pub reveal_height: u32,
    pub delay_blocks: u32,
    pub broadcast_at_height: u32,
}

/// The scheduler's decision while waiting to broadcast a prepared claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimBroadcast {
    /// The sampled delay has not elapsed: hold.
    Wait,
    /// The delay elapsed and our claim is not yet on-chain: broadcast now.
    Broadcast,
    /// Our claim confirmed (or the escrow was otherwise swept by us): done.
    Done,
}

impl ClaimScheduler {
    pub fn from_manifest(manifest: &SignedManifest) -> Self {
        let (posture_min, posture_max) = manifest.delay_bounds(manifest.active_posture());
        ClaimScheduler { posture_min, posture_max }
    }

    /// Observe whether Comp→SH has revealed its final signature against the
    /// SL-funded escrow `e_sl` (the escrow SH sweeps). Mempool-first: returns
    /// the 64-byte reveal the moment the completion appears, confirmed or not.
    pub fn observe_reveal(
        chain: &dyn ChainView,
        e_sl_outpoint: OutPoint,
    ) -> Option<[u8; 64]> {
        match chain.spend_status(e_sl_outpoint) {
            SpendStatus::Unspent => None,
            // Both InMempool and Confirmed expose the witness signature.
            _ => chain.spending_witness_sig(e_sl_outpoint),
        }
    }

    /// On the observed reveal: extract t, complete our leg, and sample the
    /// posture delay clamped to the hard settlement ceiling. Fallible RNG
    /// degrades to the minimum in-range delay (safety, never a breach).
    pub fn schedule_claim(
        &self,
        possessing: &Possessing,
        comp_sh_reveal: &[u8; 64],
        reveal_height: u32,
    ) -> Result<ScheduledClaim> {
        let observed = ValidatedFinalSig::from_bytes(comp_sh_reveal)?;
        let comp_sl_final = possessing.extract_and_complete_claim(&observed)?;
        let ceiling = possessing.claim_delay_ceiling(reveal_height);
        let delay_blocks = self.sample_posture_delay(ceiling);
        let broadcast_at_height = reveal_height.saturating_add(delay_blocks);
        Ok(ScheduledClaim {
            comp_sl_final,
            reveal_height,
            delay_blocks,
            broadcast_at_height,
        })
    }

    /// Sample d from the active posture [min, max], CLAMPED to `[0, ceiling]`.
    /// Safety beats privacy: the ceiling caps both endpoints, so even the
    /// aggressive posture can never push the claim past the swept escrow's
    /// late-refund maturity.
    pub fn sample_posture_delay(&self, ceiling: u64) -> u32 {
        let hi = (self.posture_max as u64).min(ceiling);
        let lo = (self.posture_min as u64).min(hi);
        sample_uniform_inclusive(lo, hi) as u32
    }

    /// Poll: decide whether to broadcast the prepared claim. `our_claim_txid`
    /// is the txid we broadcast (once we have), so a confirmed sweep by US is
    /// recognized as Done rather than mistaken for someone else.
    pub fn next_broadcast(
        chain: &dyn ChainView,
        e_sh_outpoint: OutPoint,
        schedule: &ScheduledClaim,
        our_claim_txid: Option<Txid>,
    ) -> ClaimBroadcast {
        match chain.spend_status(e_sh_outpoint) {
            // The escrow we sweep is confirmed spent. If it was OUR claim,
            // we are done; if somehow someone else (only the late refund
            // could, and only after our deadline), also terminal.
            SpendStatus::Confirmed(_) => ClaimBroadcast::Done,
            // A pending spend of the escrow we sweep — ours (awaiting
            // confirmation) or, at worst, the late refund racing us. Either
            // way do not double-broadcast: hold. (`our_claim_txid` is
            // consulted so a future caller can distinguish for reporting.)
            SpendStatus::InMempool => {
                let _ = (our_claim_txid, chain.spend_txid(e_sh_outpoint));
                ClaimBroadcast::Wait
            }
            SpendStatus::Unspent => {
                if chain.tip_height() >= schedule.broadcast_at_height {
                    ClaimBroadcast::Broadcast
                } else {
                    ClaimBroadcast::Wait
                }
            }
        }
    }
}

/// SH-side completion broadcast routing decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShBroadcast {
    /// Runway OK and watchtower armed: broadcast Comp→SH (call
    /// `Possessing::broadcast_completion`).
    Broadcast,
    /// Not yet — Comp→SH is not needed yet, or we are simply early. (This
    /// prototype broadcasts as soon as the swap is possessed, so this is only
    /// returned when the watchtower is not yet armed.)
    Wait,
    /// Runway exhausted (`deadline − tip < safe_depth`): abandon the
    /// completion and let the pre-armed refund reclaim our escrow.
    FallbackToRefund,
}

/// Decide SH's completion-broadcast action (v3.13: broadcast only if runway
/// to `S + Δ_early − Δ_buffer` ≥ safe confirmation depth AND watchtower
/// armed). Pure; the outer loop calls `broadcast_completion` on `Broadcast`.
pub fn sh_broadcast_decision(
    possessing: &Possessing,
    tip_height: u32,
    safe_confirmation_depth: u32,
    watchtower_armed: bool,
) -> Result<ShBroadcast> {
    let deadline = possessing.sh_broadcast_deadline()?;
    let runway = (deadline as i64) - (tip_height as i64);
    if runway < safe_confirmation_depth as i64 {
        // Not enough blocks to confirm safely before the buffer — the
        // pre-armed refund is the crash-safe fallback (G2).
        return Ok(ShBroadcast::FallbackToRefund);
    }
    if !watchtower_armed {
        // Runway is fine but G2's watchtower half is not satisfied yet.
        return Ok(ShBroadcast::Wait);
    }
    Ok(ShBroadcast::Broadcast)
}

/// Uniform inclusive sample in [lo, hi] from the OS CSPRNG. On RNG failure
/// returns `lo` (always in range; the claim still confirms — decorrelation
/// degrades, safety does not). Modulo bias is immaterial for a privacy delay.
fn sample_uniform_inclusive(lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return lo;
    }
    let span = hi - lo + 1;
    let mut b = [0u8; 8];
    if rand::rngs::OsRng.try_fill_bytes(&mut b).is_err() {
        return lo;
    }
    lo + (u64::from_le_bytes(b) % span)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::params::Params;
    use crate::wallet::manifest::ClaimDelayPosture;

    fn manifest(posture: ClaimDelayPosture) -> SignedManifest {
        SignedManifest::compose(
            1,
            Params::testnet_provisional(),
            posture,
            [(0, 6), (6, 36), (12, 72)],
            6,
            3,
        )
        .unwrap()
    }

    #[test]
    fn posture_sampling_respects_range_and_hard_ceiling() {
        // Aggressive posture: [12, 72].
        let sched = ClaimScheduler::from_manifest(&manifest(ClaimDelayPosture::Aggressive));
        // Ample ceiling: samples land within the posture band.
        for _ in 0..2000 {
            let d = sched.sample_posture_delay(1000);
            assert!((12..=72).contains(&d), "sampled {d} outside aggressive band");
        }
        // TIGHT ceiling below the posture minimum: safety wins — the delay is
        // clamped to the ceiling even though the posture wants >= 12.
        for _ in 0..2000 {
            let d = sched.sample_posture_delay(5);
            assert!(d <= 5, "clamp to ceiling failed: {d} > 5");
        }
        // Zero ceiling (window already tight): claim immediately.
        assert_eq!(sched.sample_posture_delay(0), 0);
    }

    #[test]
    fn minimal_posture_is_narrower_than_aggressive() {
        let mn = ClaimScheduler::from_manifest(&manifest(ClaimDelayPosture::Minimal));
        let ag = ClaimScheduler::from_manifest(&manifest(ClaimDelayPosture::Aggressive));
        let mut max_mn = 0;
        let mut max_ag = 0;
        for _ in 0..5000 {
            max_mn = max_mn.max(mn.sample_posture_delay(1000));
            max_ag = max_ag.max(ag.sample_posture_delay(1000));
        }
        assert!(max_mn <= 6, "minimal posture exceeded its band: {max_mn}");
        assert!(max_ag > max_mn, "aggressive must decorrelate more than minimal");
    }
}
