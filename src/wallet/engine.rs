//! Swap engine (wallet rank 7) — the wallet's core loop that COMPOSES every
//! rank into one driven, crash-recoverable swap lifecycle.
//!
//! Ranks 1–6 built the parts: the sealed `SwapStore` (lifecycle persistence),
//! the `Ledger` (coins/onboarding), the `ManifestStore` (signed params), the
//! `FundingCoordinator` + `AbortDriver` (rank 4), the `ClaimScheduler`
//! (rank 5), and the `WatchtowerDriver` (rank 6). Each is a decision function
//! or a store — nothing CALLED them in sequence. This is that sequence.
//!
//! SCOPE. The engine owns the wallet's three stores and a `KeySource`, and
//! drives the FUNDED → SETTLED half of a swap for one party: it persists the
//! `SwapRecord` through every phase (so the whole swap — not just the
//! settlement possession record — is crash-recoverable as one unit), runs the
//! interlocked adaptor exchange, settles via the claim scheduler (SL) or the
//! runway-gated broadcast (SH), and reconciles the ledger (mark the funding
//! coin spent, record the fresh swapped output). Failure at any point routes
//! to the abort path and the pre-armed refund.
//!
//! The PRE-funding half (broadcasting Setups, waiting out the co-funding
//! window) is driven by the rank-4 `FundingCoordinator` and handed to the
//! engine as a `Funded` (which carries the derived role + S + sweep height).
//! Assembling the escrows / sighashes / pre-armed refund is the tx-layer glue
//! (`tx::*`, already built + bitcoin-side verified); the engine takes those as
//! a `SwapContext` and owns the STATE MACHINE + PERSISTENCE + LEDGER
//! composition, which is the integration surface the parts couldn't prove on
//! their own.

use crate::chain::ChainView;
use crate::crypto::adaptor::AdaptorSecret;
use crate::crypto::{ValidatedFinalSig, ValidatedPoint};
use crate::settlement::refund::{PreArmedRefund, WatchtowerReceipt};
use crate::settlement::state_machine::{ExchangeInputs, Funded, Possessing, Role};
use crate::wallet::claim_scheduler::{ClaimScheduler, ScheduledClaim};
use crate::wallet::keys::KeySource;
use crate::wallet::ledger::Ledger;
use crate::wallet::manifest::{ManifestStore, ManifestTrustRoot};
use crate::wallet::store::{EnclaveKeyProvider, RecoveryAction, SwapPhase, SwapRecord, SwapStore};
use crate::{Error, Result};
use bitcoin::OutPoint;
use std::path::PathBuf;

/// Everything a swap needs beyond the engine's own stores. Assembled by the
/// funding/exchange glue from the peer session and the tx builders.
pub struct SwapContext {
    pub swap_session_id: [u8; 32],
    pub our_seckey: secp::Scalar,
    pub their_pubkey: ValidatedPoint,
    /// The escrow WE funded — our pre-armed refund spends it.
    pub our_escrow_op: OutPoint,
    /// The escrow WE sweep (SH sweeps E_sl, SL sweeps E_sh).
    pub their_escrow_op: OutPoint,
    /// The SL-funded escrow (E_sl) that SH's Comp→SH spends — where SL
    /// observes the reveal. Equals `their_escrow_op` for SH, `our_escrow_op`
    /// for SL. Carried explicitly so reveal-watching is unambiguous.
    pub reveal_escrow_op: OutPoint,
    pub escrow_amount: u64,
    pub msg_comp_sh: [u8; 32],
    pub msg_comp_sl: [u8; 32],
    pub pre_armed_refund: PreArmedRefund,
    /// SH supplies its adaptor secret; SL passes `None`.
    pub adaptor_secret: Option<AdaptorSecret>,
    pub taproot_root_comp_sh: [u8; 32],
    pub taproot_root_comp_sl: [u8; 32],
    pub taproot_output_comp_sh: [u8; 32],
    pub taproot_output_comp_sl: [u8; 32],
    pub lease_dir: PathBuf,
    pub possession_store: PathBuf,
    /// The watchtower handoff receipt (G2) covering our pre-armed refund.
    pub watchtower_receipt: WatchtowerReceipt,
    /// The leased pre-encumbrance coin funding our escrow (to mark spent).
    pub funding_coin: OutPoint,
}

/// The terminal outcome of a driven swap.
#[derive(Debug)]
pub enum SwapOutcome {
    /// The swap completed. `our_final_sig` is the completed signature for OUR
    /// leg, ready for the (chain-layer) broadcast; `reveal` (SL only) is the
    /// secret-carrying counterparty signature we extracted from.
    Completed { our_final_sig: [u8; 64] },
    /// A failure path was taken; the pre-armed refund is the exit. Idempotent
    /// to re-drive via `recover`.
    Aborted(&'static str),
}

/// The wallet's swap engine: owns the three stores + the key source.
pub struct SwapEngine {
    store: SwapStore,
    ledger: Ledger,
    manifest: ManifestStore,
    keys: Box<dyn KeySource>,
}

impl SwapEngine {
    /// Open the wallet: all three stores, reconcile any orphaned leases from a
    /// prior crash, and surface the SwapStore recovery actions (INV-2 aborts,
    /// post-release restorations). The ledger MUST already exist (onboarding
    /// created it); this is the operating path, not first-run.
    pub fn open(
        dir: &std::path::Path,
        enclave: &dyn EnclaveKeyProvider,
        keys: Box<dyn KeySource>,
        manifest_root: &dyn ManifestTrustRoot,
    ) -> Result<(SwapEngine, Vec<RecoveryAction>)> {
        let (store, actions) = SwapStore::open(dir, enclave)?;
        let mut ledger = Ledger::open(dir, enclave)?;
        let (manifest, _report) = ManifestStore::open(dir, manifest_root)?;

        // Reconcile leases against the swaps that are still live: any coin
        // leased to a swap that no longer exists (crashed before its
        // SwapRecord was written) is released back to unspent.
        let live: Vec<[u8; 32]> = store
            .list()?
            .0
            .iter()
            .filter(|r| !matches!(r.phase, SwapPhase::Completed | SwapPhase::Refunded))
            .map(|r| r.swap_session_id)
            .collect();
        ledger.reconcile_leases(&live)?;

        Ok((SwapEngine { store, ledger, manifest, keys }, actions))
    }

    pub fn manifest(&self) -> &ManifestStore {
        &self.manifest
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }
    pub fn store(&self) -> &SwapStore {
        &self.store
    }
    /// The wallet's key source (enclave seam) — for issuing fresh swap
    /// destinations and signing outside the settlement core.
    pub fn keys(&self) -> &dyn KeySource {
        self.keys.as_ref()
    }

    /// Persist the initial `Funding` record for a swap (before any escrow
    /// confirms — the rank-1 G2 rule requires the pre-armed refund present).
    pub fn record_funding(
        &self,
        ctx: &SwapContext,
        role: Role,
        params: crate::settlement::params::Params,
    ) -> Result<()> {
        self.store.put(&SwapRecord {
            swap_session_id: ctx.swap_session_id,
            role,
            phase: SwapPhase::Funding,
            params,
            s_height: 0,
            sweep_escrow_height: 0,
            our_escrow_outpoint: Some(ctx.our_escrow_op),
            their_escrow_outpoint: Some(ctx.their_escrow_op),
            pre_armed_refund: Some(ctx.pre_armed_refund.clone()),
            completion_tx: None,
            possession_record: None,
        })
    }

    /// PHASE A — run the interlocked adaptor exchange over the peer transport,
    /// persisting `Signing` (SL registers its deterministic possession pointer
    /// FIRST, per the rank-1 G1 ordering) → and, on success, `Released` (SL).
    /// Returns the `Possessing` for the settlement phase, or persists
    /// `AbortRefund` and returns Err on any exchange failure (the pre-armed
    /// refund is the exit). The caller pumps the peer, then calls `settle`.
    pub fn run_exchange(
        &mut self,
        funded: Funded,
        ctx: &mut SwapContext,
        _chain: &impl ChainView,
    ) -> Result<Possessing> {
        let role = funded.role();
        let params = self.manifest.current().params().clone();
        let possession_path = ctx
            .possession_store
            .join(format!("{}.possession", hex32(&ctx.swap_session_id)));

        self.store.put(&SwapRecord {
            swap_session_id: ctx.swap_session_id,
            role,
            phase: SwapPhase::Signing,
            params,
            s_height: funded.s_height(),
            sweep_escrow_height: funded.sweep_escrow_height(),
            our_escrow_outpoint: Some(ctx.our_escrow_op),
            their_escrow_outpoint: Some(ctx.their_escrow_op),
            pre_armed_refund: Some(ctx.pre_armed_refund.clone()),
            completion_tx: None,
            possession_record: match role {
                Role::SecretLearner => Some(possession_path.clone()),
                Role::SecretHolder => None,
            },
        })?;

        let inputs = ExchangeInputs {
            our_seckey: ctx.our_seckey,
            their_pubkey: ctx.their_pubkey.clone(),
            msg_comp_sh: ctx.msg_comp_sh,
            msg_comp_sl: ctx.msg_comp_sl,
            pre_armed_refund: ctx.pre_armed_refund.clone(),
            adaptor_secret: ctx.adaptor_secret.take(),
            lease_dir: Some(ctx.lease_dir.clone()),
            possession_store: match role {
                Role::SecretLearner => Some(ctx.possession_store.clone()),
                Role::SecretHolder => None,
            },
            taproot_root_comp_sh: Some(ctx.taproot_root_comp_sh),
            taproot_root_comp_sl: Some(ctx.taproot_root_comp_sl),
            taproot_output_comp_sh: Some(ctx.taproot_output_comp_sh),
            taproot_output_comp_sl: Some(ctx.taproot_output_comp_sl),
        };
        let possessing = match funded.run_adaptor_exchange(inputs) {
            Ok(p) => p,
            Err(e) => {
                self.abort(ctx);
                return Err(e);
            }
        };

        // SL: G1 satisfied (possession persisted + partial released) → Released.
        if role == Role::SecretLearner {
            let mut rec = self
                .store
                .get(&ctx.swap_session_id)?
                .ok_or(Error::Abort("swap record vanished"))?;
            rec.phase = SwapPhase::Released;
            rec.possession_record = Some(possession_path);
            self.store.put(&rec)?;
        }
        Ok(possessing)
    }

    /// PHASE B — settle. Dispatches on the derived role: SL observes SH's
    /// reveal (mempool-first), extracts + schedules its posture-bounded claim
    /// and persists `Completing` (the finalized claim goes into the record
    /// BEFORE broadcast); SH broadcasts Comp→SH through the runway gate. Then
    /// the funding coin is marked spent and the record moves to `Completed`.
    /// The chain-layer finalize+broadcast and the fresh-output ledger entry are
    /// the caller's (a new UTXO's outpoint exists only post-confirmation).
    pub fn settle(
        &mut self,
        possessing: Possessing,
        ctx: &SwapContext,
        chain: &impl ChainView,
    ) -> Result<SwapOutcome> {
        let final_sig = match possessing.role() {
            Role::SecretLearner => {
                let reveal = match ClaimScheduler::observe_reveal(chain, ctx.reveal_escrow_op) {
                    Some(sig) => sig,
                    None => {
                        // No reveal yet → the caller re-drives; if the deadline
                        // passes with no reveal, the abort/refund path owns it.
                        return Ok(SwapOutcome::Aborted("no reveal observed yet"));
                    }
                };
                let scheduler = ClaimScheduler::from_manifest(self.manifest.current());
                let schedule: ScheduledClaim =
                    scheduler.schedule_claim(&possessing, &reveal, chain.tip_height())?;
                let mut rec = self
                    .store
                    .get(&ctx.swap_session_id)?
                    .ok_or(Error::Abort("record vanished"))?;
                rec.phase = SwapPhase::Completing;
                rec.completion_tx = Some(schedule.comp_sl_final.0.to_vec());
                self.store.put(&rec)?;
                schedule.comp_sl_final.0
            }
            Role::SecretHolder => {
                let sig = match possessing
                    .broadcast_completion(chain.tip_height(), &ctx.watchtower_receipt)
                {
                    Ok(s) => s,
                    Err(_) => {
                        self.abort(ctx);
                        return Ok(SwapOutcome::Aborted("broadcast gate closed; refund is the exit"));
                    }
                };
                let mut rec = self
                    .store
                    .get(&ctx.swap_session_id)?
                    .ok_or(Error::Abort("record vanished"))?;
                rec.phase = SwapPhase::Completing;
                rec.completion_tx = Some(sig.0.to_vec());
                self.store.put(&rec)?;
                sig.0
            }
        };

        self.ledger.mark_spent(ctx.funding_coin).ok();
        let mut rec = self
            .store
            .get(&ctx.swap_session_id)?
            .ok_or(Error::Abort("record vanished"))?;
        rec.phase = SwapPhase::Completed;
        self.store.put(&rec)?;
        Ok(SwapOutcome::Completed { our_final_sig: final_sig })
    }

    /// Route to the abort path: persist AbortRefund (unless a completion has
    /// already superseded), leaving the pre-armed refund as the exit.
    /// Best-effort + idempotent — the refund driver / watchtower owns it from
    /// here, so this never fails the caller.
    fn abort(&self, ctx: &SwapContext) {
        if let Ok(Some(mut rec)) = self.store.get(&ctx.swap_session_id) {
            if !matches!(rec.phase, SwapPhase::Completed | SwapPhase::Refunded) {
                rec.phase = SwapPhase::AbortRefund;
                let _ = self.store.put(&rec);
            }
        }
    }

    /// Helper for a driven claim: extract + complete SL's leg from an observed
    /// reveal, for callers that own the broadcast. Exposed so the app's event
    /// loop can settle after `run_swap` scheduled the claim.
    pub fn extract_and_complete(
        possessing: &Possessing,
        reveal: &[u8; 64],
    ) -> Result<[u8; 64]> {
        let observed = ValidatedFinalSig::from_bytes(reveal)?;
        Ok(possessing.extract_and_complete_claim(&observed)?.0)
    }
}

fn hex32(id: &[u8; 32]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}
