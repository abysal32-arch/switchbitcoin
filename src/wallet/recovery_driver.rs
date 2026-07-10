//! Crash-recovery re-entry — increment 4 of the orchestration layer.
//!
//! After a crash, [`SwapEngine::open`](crate::wallet::engine::SwapEngine::open)
//! brings the store to a safe state and hands back one-shot
//! [`RecoveryAction`](crate::wallet::store::RecoveryAction) notifications. But
//! per the store's ordering contract (module docs, rule 4) those actions are
//! USER-FACING alarms, not the work queue — the work queue is the RECORDS
//! themselves. [`RecoveryDriver`] is that queue: it scans every non-terminal
//! record and re-enters each swap into the SAME per-phase continuation a live
//! wallet would drive, so no swap is stranded past a restart and the
//! forward-or-refund invariant holds across process death.
//!
//! # Why re-enter from the RECORD, not a live context
//! A crash destroys the in-memory `SwapContext` (our secret key, the peer
//! transport, the tx templates). The record + (for a released SL) the sealed
//! possession record are DELIBERATELY self-sufficient for everything a
//! deadline-driven recovery needs — this driver is the proof of that claim:
//! - `Released` (SL only): [`Possessing::restore_secret_learner`] rebuilds the
//!   claim material from the possession record; the completed claim is derived
//!   from the on-chain reveal alone (no fresh signing), exactly as
//!   `settle`'s live SL arm does. The `Released -> AbortRefund` fallback (SH
//!   never completed) is the [`AbortDriver`] decision on our own escrow.
//! - `AbortRefund`: the completion-supersedes decision ([`AbortDriver`]).
//! - `Completing`: the finalized completion signature was persisted BEFORE
//!   broadcast (rule 3), so recovery rebroadcasts it idempotently.
//! - `Funding`: chain-observable, no volatile signing state — but the peer
//!   transport did not survive, so a resumed negotiation is caller-owned; the
//!   standing pre-armed refund is the exit for an already-funded escrow.
//!
//! # Engine boundary (consistent with increments 1-3)
//! The driver DECIDES and reads chain state; the CALLER performs every
//! broadcast. The only writes this driver makes are the two the recovery
//! itself owns: persisting the finalized claim as `Completing` before it is
//! handed back (rule 3), and marking a confirmed completion `Completed`. It
//! never touches the frozen settlement-core surface.

use std::path::PathBuf;

use bitcoin::Txid;

use crate::chain::ChainView;
use crate::crypto::ValidatedFinalSig;
use crate::settlement::refund::PreArmedRefund;
use crate::settlement::state_machine::{Possessing, Role};
use crate::wallet::claim_scheduler::ClaimScheduler;
use crate::wallet::orchestrator::{AbortAction, AbortDriver};
use crate::wallet::store::{SwapPhase, SwapRecord, SwapStore};
use crate::{Error, Result};

/// How one crashed swap re-enters its lifecycle. Each variant maps to the same
/// continuation a live wallet would drive; the caller performs the broadcasts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryTick {
    /// Terminal record (`Completed`/`Refunded`) — nothing to re-enter.
    Settled,
    /// `Funding` phase: no volatile signing state, but the peer transport did
    /// not survive the crash. `refund` is `Some(action)` when our escrow is
    /// already funded on chain (the standing pre-armed refund is the exit if
    /// the swap cannot proceed); `None` when nothing is locked yet — resuming
    /// needs a fresh `FundingDriver` + re-established transport (caller-owned).
    Funding { refund: Option<AbortAction> },
    /// A `Signing` record survived `open`'s rewrite (a `RewriteFailed`
    /// condition): the session is non-resumable (INV-2) and recovery is
    /// INCOMPLETE for this swap. The next `open` retries the rewrite; surfaced
    /// so the caller knows this swap is not yet driven.
    RewritePending,
    /// SL restore-and-extract (`Released`). `final_sig` is `Some` when the
    /// reveal is already on chain — the finalized Comp->SL to broadcast, now
    /// persisted `Completing`; `None` when the reveal is not yet observed and
    /// `fallback` is the [`AbortDriver`] decision on OUR escrow (the
    /// `Released -> AbortRefund` exit if SH never completes).
    Extract {
        final_sig: Option<[u8; 64]>,
        fallback: AbortAction,
    },
    /// `Completing`: rebroadcast the persisted final signature (idempotent) and
    /// babysit. `confirmed` is `true` once our completion swept its escrow (the
    /// record was advanced to `Completed`).
    Rebroadcast {
        final_sig: [u8; 64],
        confirmed: bool,
    },
    /// `AbortRefund`: the completion-supersedes decision on our escrow.
    Refund(AbortAction),
}

/// The result of a whole-store recovery scan: one `(swap_session_id, tick)`
/// per readable record, plus the paths of any records that could not be
/// loaded (surfaced, never silently dropped).
pub type RecoveryScan = (Vec<([u8; 32], RecoveryTick)>, Vec<PathBuf>);

/// Re-enters crashed swaps from the persisted [`SwapStore`]. Takes only the
/// store (not the whole engine): recovery needs the record + chain and nothing
/// from the ledger/manifest (the funding coin was already reconciled at funding
/// time). Stateless: every decision is re-derived from the record + chain on
/// each call, so a crash mid-recovery just re-runs (idempotent, like
/// `AbortDriver`).
pub struct RecoveryDriver;

impl RecoveryDriver {
    /// Scan every tracked record and re-enter each. Returns `(sid, tick)` per
    /// readable record plus the paths of any that could not be loaded —
    /// surfaced, never silently skipped (matches [`SwapStore::list`]; a corrupt
    /// file must not hide another swap's deadline).
    pub fn reenter_all(store: &SwapStore, chain: &dyn ChainView) -> Result<RecoveryScan> {
        let (records, failed) = store.list()?;
        let mut ticks = Vec::with_capacity(records.len());
        for rec in &records {
            ticks.push((rec.swap_session_id, Self::reenter_one(store, rec, chain)?));
        }
        Ok((ticks, failed))
    }

    /// Re-enter one record. Pure decision plus the two recovery-owned persists
    /// (the rule-3 `Completing` write and the `Completed` finalize); the caller
    /// performs every broadcast.
    pub fn reenter_one(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn ChainView,
    ) -> Result<RecoveryTick> {
        match rec.phase {
            SwapPhase::Completed | SwapPhase::Refunded => Ok(RecoveryTick::Settled),
            SwapPhase::Signing => Ok(RecoveryTick::RewritePending),
            SwapPhase::Funding => Self::reenter_funding(rec, chain),
            SwapPhase::Released => Self::reenter_released(store, rec, chain),
            SwapPhase::Completing => Self::reenter_completing(store, rec, chain),
            SwapPhase::AbortRefund => Ok(RecoveryTick::Refund(Self::abort_action(rec, chain)?)),
        }
    }

    /// `Funding`: if our escrow is confirmed on chain the standing pre-armed
    /// refund is the exit (a stuck funding still unwinds safely); otherwise
    /// nothing is locked and resuming needs a fresh driver + transport.
    fn reenter_funding(rec: &SwapRecord, chain: &dyn ChainView) -> Result<RecoveryTick> {
        let refund = match rec.our_escrow_outpoint {
            Some(escrow) if chain.funding_height(escrow).is_some() => {
                Some(Self::abort_action(rec, chain)?)
            }
            _ => None,
        };
        Ok(RecoveryTick::Funding { refund })
    }

    /// `Released` (SL restore-and-extract). Restore the possession record,
    /// observe the reveal on OUR escrow (the E_sl that SH's Comp->SH spends),
    /// and either finalize the claim (persisting `Completing` first, rule 3) or
    /// fall back to the abort decision on our escrow.
    fn reenter_released(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn ChainView,
    ) -> Result<RecoveryTick> {
        // Released is SL-only (see SwapPhase docs); an SH record here is a
        // corrupt/foreign record, not a state we drive.
        if rec.role != Role::SecretLearner {
            return Err(Error::Ordering("Released record is not SecretLearner"));
        }
        let record_path = rec
            .possession_record
            .as_ref()
            .ok_or(Error::Ordering("Released record without a possession pointer"))?;
        // For SL, the escrow WE funded (our_escrow_outpoint) is the E_sl that
        // SH sweeps via Comp->SH — i.e. reveal_escrow_op. It is also the escrow
        // our own pre-armed refund reclaims.
        let our_escrow = rec
            .our_escrow_outpoint
            .ok_or(Error::Ordering("Released record without our escrow outpoint"))?;

        let restored = Possessing::restore_secret_learner(record_path, &rec.swap_session_id)?;

        match ClaimScheduler::observe_reveal(chain, our_escrow) {
            Some(reveal) => {
                let observed = ValidatedFinalSig::from_bytes(&reveal)?;
                // Extract t and complete our leg; the delay is clamped inside to
                // the swept escrow's claim ceiling (never past S + delta_late).
                let plan = restored.claim_after_reveal(&observed, chain.tip_height())?;
                let final_sig = plan.comp_sl_final.0;
                // Rule 3: persist the finalized claim as `Completing` BEFORE it
                // is handed back for broadcast, so a re-crash rebroadcasts it.
                let mut next = rec.clone();
                next.phase = SwapPhase::Completing;
                next.completion_tx = Some(final_sig.to_vec());
                store.put(&next)?;
                Ok(RecoveryTick::Extract { final_sig: Some(final_sig), fallback: AbortAction::Wait })
            }
            None => {
                // No reveal yet: SH has not completed. The safe fallback is the
                // AbortDriver decision on OUR escrow — wait, refund at maturity,
                // or (if SH's completion is winning) take the swap next scan.
                let refund = rec
                    .pre_armed_refund
                    .as_ref()
                    .ok_or(Error::Deadline("Released record without a pre-armed refund (G2)"))?;
                let action = AbortDriver::next_abort_action(
                    chain,
                    our_escrow,
                    refund,
                    refund_txid(refund),
                );
                Ok(RecoveryTick::Extract { final_sig: None, fallback: action })
            }
        }
    }

    /// `Completing`: the finalized completion signature was persisted before
    /// broadcast. Rebroadcast it (the caller finalizes the tx from the sig +
    /// template, as at the live boundary), and mark `Completed` once our
    /// completion has swept the counterparty escrow.
    fn reenter_completing(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn ChainView,
    ) -> Result<RecoveryTick> {
        let final_sig = completion_sig(rec)?;
        // Our completion spends the counterparty's escrow (the one we sweep).
        let swept = rec
            .their_escrow_outpoint
            .ok_or(Error::Ordering("Completing record without the swept escrow outpoint"))?;
        let confirmed = matches!(chain.spend_status(swept), crate::chain::SpendStatus::Confirmed(_));
        if confirmed {
            let mut next = rec.clone();
            next.phase = SwapPhase::Completed;
            store.put(&next)?;
        }
        Ok(RecoveryTick::Rebroadcast { final_sig, confirmed })
    }

    /// The completion-supersedes decision on our escrow, shared by the
    /// `AbortRefund` and funded-`Funding` paths.
    fn abort_action(rec: &SwapRecord, chain: &dyn ChainView) -> Result<AbortAction> {
        let our_escrow = rec
            .our_escrow_outpoint
            .ok_or(Error::Ordering("abort path without our escrow outpoint"))?;
        let refund = rec
            .pre_armed_refund
            .as_ref()
            .ok_or(Error::Deadline("abort path without a pre-armed refund (G2)"))?;
        Ok(AbortDriver::next_abort_action(chain, our_escrow, refund, refund_txid(refund)))
    }
}

/// The txid of our own pre-armed refund, for the `AbortDriver`'s
/// ours-vs-theirs spend discrimination. `None` if the stored bytes cannot be
/// decoded (conservative: `AbortDriver` then treats an unknown spend as a
/// winning completion rather than double-spending).
fn refund_txid(refund: &PreArmedRefund) -> Option<Txid> {
    let tx: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize(refund.tx_bytes()).ok()?;
    Some(tx.compute_txid())
}

/// The 64-byte completion signature persisted in a `Completing` record.
fn completion_sig(rec: &SwapRecord) -> Result<[u8; 64]> {
    let bytes = rec
        .completion_tx
        .as_ref()
        .ok_or(Error::Abort("Completing record missing its completion signature"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Validation("persisted completion signature is not 64 bytes"))
}
