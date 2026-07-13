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

use crate::chain::{AuthoritativeChainView, SpendStatus};
use crate::crypto::ValidatedFinalSig;
use crate::settlement::state_machine::{CompletionSig, Possessing};
use crate::wallet::manifest::{ClaimDelayPosture, SignedManifest};
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

/// The engine-surfaced facts of a scheduled SL claim hold: everything the
/// broadcasting caller needs to rebuild the [`ScheduledClaim`] it polls
/// [`ClaimScheduler::next_broadcast`] with. The 64-byte final signature is NOT
/// carried here — it rides the `Completed` outcome separately (the engine
/// boundary keeps the finalized signature on the terminal), and
/// [`into_schedule`](ClaimHold::into_schedule) re-marries the two.
///
/// `Copy`, so it threads cleanly through the `Copy` `DriveStatus`/`AppTick`
/// terminals without heap or borrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimHold {
    /// Height at which the reveal was observed (the delay's anchor).
    pub reveal_height: u32,
    /// The sampled, ceiling-CLAMPED posture delay (blocks).
    pub delay_blocks: u32,
    /// `reveal_height + delay_blocks` — the tip height at which the held claim
    /// is released. Already clamped to the settlement ceiling by
    /// `schedule_claim`, so honoring it can never race the swept escrow's late
    /// refund.
    pub broadcast_at_height: u32,
}

impl ClaimHold {
    /// Re-marry the hold's heights with the finalized Comp→SL signature (which
    /// travelled separately on the `Completed` outcome) into the
    /// [`ScheduledClaim`] the broadcasting loop polls `next_broadcast` with.
    pub fn into_schedule(self, comp_sl_final_sig: [u8; 64]) -> ScheduledClaim {
        ScheduledClaim {
            comp_sl_final: CompletionSig(comp_sl_final_sig),
            reveal_height: self.reveal_height,
            delay_blocks: self.delay_blocks,
            broadcast_at_height: self.broadcast_at_height,
        }
    }
}

/// The scheduler's decision while waiting to broadcast a prepared claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimBroadcast {
    /// The sampled delay has not elapsed, or our own claim is pending
    /// confirmation: hold.
    Wait,
    /// (Re)broadcast our claim NOW: either the delay elapsed with the escrow
    /// unspent, OR a FOREIGN spend (SH's late refund) is racing us — our
    /// Comp→SL is RBF-able and timelock-free, so it stays valid and can fight
    /// the refund by fee (the winning fee bump is the rank-6 backstop's job).
    Broadcast,
    /// Terminal: OUR claim confirmed — swap won.
    Won,
    /// Terminal: a FOREIGN spend (SH's late refund) confirmed the escrow we
    /// were sweeping — we LOST the race. The driver must alert + account for
    /// the loss, never report this as a success.
    Lost,
}

impl ClaimScheduler {
    pub fn from_manifest(manifest: &SignedManifest) -> Self {
        Self::for_posture(manifest, manifest.active_posture())
    }

    /// Build a scheduler for an EXPLICIT posture, still drawn from the signed
    /// manifest. The posture only SELECTS among the manifest's three signed,
    /// validator-bounded bands (minimal/moderate/aggressive) — a caller can
    /// never invent bounds outside the manifest, and the runtime ceiling clamp
    /// in [`schedule_claim`](Self::schedule_claim) still binds regardless. This
    /// is how an operator override (`--claim-posture`) picks a band without
    /// touching the trust path.
    pub fn for_posture(manifest: &SignedManifest, posture: ClaimDelayPosture) -> Self {
        let (posture_min, posture_max) = manifest.delay_bounds(posture);
        ClaimScheduler { posture_min, posture_max }
    }

    /// Observe whether Comp→SH has revealed its final signature against the
    /// SL-funded escrow `e_sl` (the escrow SH sweeps). Mempool-first: returns
    /// the 64-byte reveal the moment the completion appears, confirmed or not.
    pub fn observe_reveal(
        chain: &dyn AuthoritativeChainView,
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
        chain: &dyn AuthoritativeChainView,
        e_sh_outpoint: OutPoint,
        schedule: &ScheduledClaim,
        our_claim_txid: Option<Txid>,
    ) -> ClaimBroadcast {
        // Who is spending the escrow we sweep? The ONLY spenders of the 2-of-2
        // E_sh are our own RBF-able, timelock-free Comp→SL and SH's script-path
        // late refund (valid only at sweep_height + Δ_late). So a spend that is
        // NOT ours is necessarily SH's refund racing us — which we can still
        // beat, because our claim carries no timelock and can RBF.
        let seen = chain.spend_txid(e_sh_outpoint);
        let is_ours = matches!((our_claim_txid, seen), (Some(m), Some(s)) if m == s);
        match chain.spend_status(e_sh_outpoint) {
            SpendStatus::Confirmed(_) => {
                if is_ours {
                    ClaimBroadcast::Won
                } else if seen.is_some() {
                    // A foreign tx (SH's late refund) confirmed the escrow.
                    ClaimBroadcast::Lost
                } else if our_claim_txid.is_some() {
                    // We broadcast and something confirmed but the source can't
                    // report the txid: best-effort assume it was ours (single
                    // spend). Degraded-source case; documented.
                    ClaimBroadcast::Won
                } else {
                    // We never broadcast yet something confirmed it: we lost.
                    ClaimBroadcast::Lost
                }
            }
            SpendStatus::InMempool => {
                if is_ours {
                    // Our own claim is pending confirmation: hold.
                    ClaimBroadcast::Wait
                } else if seen.is_some() || our_claim_txid.is_none() {
                    // A FOREIGN spend (the late refund) is racing us — do NOT
                    // stand down: (re)broadcast and fight the race by fee.
                    ClaimBroadcast::Broadcast
                } else {
                    // We broadcast, source can't report the txid: assume it is
                    // ours and wait rather than spam rebroadcasts.
                    ClaimBroadcast::Wait
                }
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
    use crate::chain::{ChainView, SimChain};
    use crate::settlement::params::Params;
    use crate::wallet::manifest::ClaimDelayPosture;

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

    /// A real spend of `outpoint` paying `out` sats, so the sim gives it a txid.
    fn spend_of(outpoint: OutPoint, out: u64) -> Vec<u8> {
        use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: std_p2tr_spk() }],
        };
        bitcoin::consensus::encode::serialize(&tx)
    }

    fn synthetic_schedule(broadcast_at: u32) -> ScheduledClaim {
        ScheduledClaim {
            comp_sl_final: CompletionSig([0u8; 64]),
            reveal_height: broadcast_at,
            delay_blocks: 0,
            broadcast_at_height: broadcast_at,
        }
    }

    /// THE adversarial-review HIGH: a foreign spend of the escrow we sweep
    /// (SH's late refund) must make us FIGHT (Broadcast), never stand down
    /// (Wait) — and a foreign CONFIRMED spend is a distinct Lost terminal,
    /// not a success.
    #[test]
    fn foreign_spend_is_fought_and_reported_as_lost_not_won() {
        let e_sh = op(1);
        let chain = SimChain::new(500);
        chain.fund_with_amount(e_sh, 500, 1_000_000);
        let schedule = synthetic_schedule(400); // delay already elapsed

        // SH's late refund parks in E_sh's mempool; we have NOT broadcast.
        let foreign = spend_of(e_sh, 900_000);
        chain.broadcast(&foreign).unwrap();
        assert_eq!(
            ClaimScheduler::next_broadcast(&chain, e_sh, &schedule, None),
            ClaimBroadcast::Broadcast,
            "must fight a foreign mempool spend, not Wait"
        );

        // It confirms before we react → Lost (a distinct terminal, not Won).
        chain.mine();
        assert_eq!(
            ClaimScheduler::next_broadcast(&chain, e_sh, &schedule, None),
            ClaimBroadcast::Lost,
            "a foreign-confirmed sweep must report Lost, never Won"
        );
    }

    #[test]
    fn our_own_claim_pending_then_confirmed_is_wait_then_won() {
        let e_sh = op(2);
        let chain = SimChain::new(500);
        chain.fund_with_amount(e_sh, 500, 1_000_000);
        let schedule = synthetic_schedule(400);

        let ours = spend_of(e_sh, 990_000);
        let our_txid = chain.broadcast(&ours).unwrap();
        // Our own claim pending → Wait (not a needless rebroadcast).
        assert_eq!(
            ClaimScheduler::next_broadcast(&chain, e_sh, &schedule, Some(our_txid)),
            ClaimBroadcast::Wait
        );
        chain.mine();
        assert_eq!(
            ClaimScheduler::next_broadcast(&chain, e_sh, &schedule, Some(our_txid)),
            ClaimBroadcast::Won
        );
    }

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
