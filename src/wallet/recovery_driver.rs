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
//! broadcast. The only writes this driver makes are the ones the recovery
//! itself owns: persisting the finalized claim as `Completing` before it is
//! handed back (rule 3), marking a confirmed completion `Completed` — and the
//! chain-proven-supersede routings out of a false terminal (`Completed ->
//! AbortRefund` / `Refunded -> Completing` / `Completing -> AbortRefund`),
//! taken only under SPENDER ATTRIBUTION (the confirmed spend is provably not
//! ours / provably the counterparty's completion). It never touches the
//! frozen settlement-core surface.
//!
//! # Spender attribution (never a spender-blind terminal)
//! Every terminal this driver persists or re-validates asks WHO spent, not
//! merely whether a spend confirmed. The swept escrow has exactly two spend
//! paths — our completion (key path; its 64-byte witness signature IS the
//! persisted `completion_tx`) and the counterparty's own refund leaf (script
//! path) — so the witness comparison is a proof, not a heuristic. Our own
//! escrow's spend is attributed by txid against the persisted pre-armed
//! refund (the same who-spent rule as the live `our_refund_confirmed`
//! terminal and `AbortDriver`). A view that cannot report the spender leaves
//! the record honestly non-terminal — never a guessed `Settled`.

use std::path::PathBuf;

use bitcoin::{OutPoint, Txid};

use crate::chain::AuthoritativeChainView;
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
    /// SL restore-and-extract (`Released`, or the post-release `AbortRefund`
    /// corner where SH's completion supersedes our armed refund). `final_sig`
    /// is `Some` when the reveal is already observable — the finalized
    /// Comp->SL to broadcast, now persisted `Completing`; `None` (Released
    /// only) when the reveal is not yet observed and `fallback` is the
    /// [`AbortDriver`] decision on OUR escrow (the `Released -> AbortRefund`
    /// exit if SH never completes).
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
    /// `AbortRefund`: the completion-supersedes decision on our escrow (an SL
    /// record with G1 possession whose reveal is already observable EXECUTES
    /// the take-the-swap arm instead, surfacing as [`Extract`](Self::Extract)).
    Refund(AbortAction),
    /// The never-confirming-Setup recovery arm (store v4 `setup_tx`): our
    /// escrow's Setup was broadcast and persisted but fell out of every mempool
    /// without ever confirming, so the record is non-terminal with no reachable
    /// exit (the pre-armed refund spends an escrow outpoint that never came to
    /// exist). Re-submit the persisted signed Setup — idempotent — so the escrow
    /// can confirm and the ordinary refund/settlement path becomes reachable
    /// instead of stranding. The caller performs the broadcast (engine boundary).
    RebroadcastSetup { setup_tx: Vec<u8> },
}

/// The result of a whole-store recovery scan. Every failure mode is SURFACED
/// per-record, never allowed to hide another swap's deadline (the same
/// segregation [`SwapStore::list`] already applies to unreadable files, now
/// carried all the way through re-entry).
pub struct RecoveryScan {
    /// One `(swap_session_id, tick)` per record that re-entered successfully.
    pub ticks: Vec<([u8; 32], RecoveryTick)>,
    /// Paths of records that could not be LOADED at all (corrupt/unreadable
    /// `.swap` files — from [`SwapStore::list`]'s failed-file segregation).
    /// Surfaced for the operator; nothing is driven for them.
    pub unreadable: Vec<PathBuf>,
    /// Records that LOADED but whose per-record re-entry itself FAILED — a
    /// lost/corrupt possession file (restore `Err`), a structurally-degenerate
    /// record (a missing outpoint/completion field a legal put sequence can
    /// still produce), or a recovery-owned store put that hit a full/read-only
    /// disk. Carried as `(swap_session_id, error)` and surfaced LOUDLY, one
    /// entry per damaged swap — the scan does NOT abort, so every OTHER swap's
    /// deadline is still driven. A permanently-failing record recurs here on
    /// every scan (it never heals silently), which is the intended alarm.
    pub failed: Vec<([u8; 32], Error)>,
}

/// Re-enters crashed swaps from the persisted [`SwapStore`]. Takes only the
/// store (not the whole engine): recovery needs the record + chain and nothing
/// from the ledger/manifest (the funding coin was already reconciled at funding
/// time). Stateless: every decision is re-derived from the record + chain on
/// each call, so a crash mid-recovery just re-runs (idempotent, like
/// `AbortDriver`).
pub struct RecoveryDriver;

impl RecoveryDriver {
    /// Scan every tracked record and re-enter each, ISOLATING per-record
    /// failures. A single damaged record (a lost possession file, a degenerate
    /// field, a store put on a full disk) is collected into
    /// [`RecoveryScan::failed`] and the scan CONTINUES — one swap's corruption
    /// must never hide another swap's deadline (the same rule
    /// [`SwapStore::list`] applies to unreadable files, now carried through
    /// re-entry). Only a failure to enumerate the store at all is a hard `Err`.
    pub fn reenter_all(store: &SwapStore, chain: &impl AuthoritativeChainView) -> Result<RecoveryScan> {
        let (records, unreadable) = store.list()?;
        let mut ticks = Vec::with_capacity(records.len());
        let mut failed = Vec::new();
        for rec in &records {
            match Self::reenter_one(store, rec, chain) {
                Ok(tick) => ticks.push((rec.swap_session_id, tick)),
                Err(e) => failed.push((rec.swap_session_id, e)),
            }
        }
        Ok(RecoveryScan { ticks, unreadable, failed })
    }

    /// Re-enter one record. Pure decision plus the two recovery-owned persists
    /// (the rule-3 `Completing` write and the `Completed` finalize); the caller
    /// performs every broadcast.
    pub fn reenter_one(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &impl AuthoritativeChainView,
    ) -> Result<RecoveryTick> {
        match rec.phase {
            SwapPhase::Completed => Self::reenter_completed(store, rec, chain),
            SwapPhase::Refunded => Self::reenter_refunded(store, rec, chain),
            SwapPhase::Signing => Ok(RecoveryTick::RewritePending),
            SwapPhase::Funding => Self::reenter_funding(store, rec, chain),
            SwapPhase::Released => Self::reenter_released(store, rec, chain),
            SwapPhase::Completing => Self::reenter_completing(store, rec, chain),
            SwapPhase::AbortRefund => Self::reenter_abort_refund(store, rec, chain),
        }
    }

    /// `Completed` — RE-VALIDATED against the chain, not trusted blindly (deep
    /// audit finding: a reorg can revert a shallowly-confirmed completion, and
    /// mapping the record straight to `Settled` would leave recovery blind to
    /// an escrow that is contestable again). Our completion swept the
    /// counterparty escrow (`their_escrow_outpoint`); `Settled` requires that
    /// spend to be CONFIRMED **and provably ours** — the spending witness's
    /// key-path signature must equal the persisted completion signature.
    /// `Completed` is persisted the moment the signature is finalized, BEFORE
    /// any broadcast confirms, so a confirmed spend of the swept escrow can be
    /// the counterparty's own refund leaf (we lost the sweep race) — a
    /// spender-blind `Settled` would record a lost swap as a permanent "paid"
    /// terminal AND leave our own funded escrow unguarded by every scan. On a
    /// provably-foreign confirmed spend the record re-enters the abort path
    /// (`Completed -> AbortRefund`, chain-proven supersede) so our escrow's
    /// standing pre-armed refund is driven. An unattributable spend (view
    /// reports no witness) stays honestly non-terminal (`Wait`) — a false
    /// `Settled` abandons a funded escrow, and driving the refund on a spend
    /// that might be OUR OWN completion would take both sides. If a reorg
    /// reverted the spend entirely, we rebroadcast the persisted completion
    /// signature — idempotent, exactly the `Completing` babysit.
    fn reenter_completed(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
    ) -> Result<RecoveryTick> {
        let swept = rec
            .their_escrow_outpoint
            .ok_or(Error::Ordering("Completed record without the swept escrow outpoint"))?;
        if spend_confirmed(chain, swept) {
            let Ok(final_sig) = completion_sig(rec) else {
                // No persisted signature to attribute against (not a shape our
                // own writers produce): nothing actionable — report Settled
                // rather than fabricate work from an unverifiable record.
                return Ok(RecoveryTick::Settled);
            };
            return match swept_spend_is_ours(chain, swept, &final_sig) {
                Some(true) => Ok(RecoveryTick::Settled),
                Some(false) => {
                    // Provably foreign: our completion did NOT sweep. Undo the
                    // false "paid" terminal and drive our own escrow's exit.
                    // The abort decision is taken BEFORE any persist (it reads
                    // only the chain + the record's outpoints, never the
                    // phase): when it walks straight back to `Completed` for an
                    // SH — our own escrow is ALSO foreign-confirmed-spent, so
                    // the supersede terminal is the very phase the record
                    // already rests at — re-persisting the Completed →
                    // AbortRefund → Completed round-trip every scan would churn
                    // the store forever (and a crash inside the hop would leave
                    // a transient non-terminal on disk). Leave the record at
                    // rest and report the decision.
                    let mut next = rec.clone();
                    next.phase = SwapPhase::AbortRefund;
                    let action = Self::abort_action(&next, chain)?;
                    if action == AbortAction::Completed && next.role == Role::SecretHolder {
                        return Ok(RecoveryTick::Refund(action));
                    }
                    store.put(&next)?;
                    Self::persist_abort_terminal(store, &next, action)?;
                    Ok(RecoveryTick::Refund(action))
                }
                None => Ok(RecoveryTick::Refund(AbortAction::Wait)),
            };
        }
        // Reverted: rebroadcast our completion if we retained its signature.
        match completion_sig(rec) {
            Ok(final_sig) => Ok(RecoveryTick::Rebroadcast { final_sig, confirmed: false }),
            // No signature to rebroadcast (should not happen for Completed) —
            // nothing actionable; report Settled rather than fabricate work.
            Err(_) => Ok(RecoveryTick::Settled),
        }
    }

    /// `Refunded` — RE-VALIDATED like `Completed`. Our refund spent our own
    /// escrow (`our_escrow_outpoint`); `Settled` requires that spend to be
    /// CONFIRMED **and the spender to BE our refund** (txid match against the
    /// persisted pre-armed refund — the same who-spent rule as the live
    /// `our_refund_confirmed` terminal). Spender-blind, a shallow reorg that
    /// replaces our 1-conf refund with the counterparty's timelock-free
    /// completion would read `Settled` while t sits revealed on chain — an SL
    /// holding G1 possession would never take the swap and lose D. So on a
    /// spend that is not provably ours: an SL with possession EXECUTES
    /// take-the-swap from the observed reveal (`Refunded -> Completing`,
    /// chain-proven supersede — the same executor as the `AbortRefund`
    /// re-entry); otherwise the `AbortDriver` decision resolves it honestly
    /// (`Completed` for a named foreign confirmed spend, `Wait` for an
    /// unreportable spender — never a guessed terminal — and the refund
    /// re-drive when a reorg reverted the spend entirely).
    fn reenter_refunded(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
    ) -> Result<RecoveryTick> {
        let our_escrow = rec
            .our_escrow_outpoint
            .ok_or(Error::Ordering("Refunded record without our escrow outpoint"))?;
        if spend_confirmed(chain, our_escrow) {
            let ours = rec
                .pre_armed_refund
                .as_ref()
                .and_then(refund_txid)
                .zip(chain.spend_txid(our_escrow))
                .is_some_and(|(mine, seen)| mine == seen);
            if ours {
                return Ok(RecoveryTick::Settled);
            }
        }
        // Not (or no longer) settled by our own refund. If the counterparty's
        // completion is the (possibly reorg-replacing) spender it revealed t:
        // an SL with possession takes the swap instead of abandoning it. The
        // `spend_is_our_refund` guard keeps this from firing on OUR OWN refund
        // sitting in the mempool (a script-path witness whose first element is
        // a 64-byte sig, which `observe_reveal` would otherwise surface as a
        // spurious reveal — driving a needless restore that Errs on a
        // migrated/pruned possession file).
        if rec.role == Role::SecretLearner
            && rec.possession_record.is_some()
            && !Self::swept_claim_futile(rec, chain)
            && !Self::spend_is_our_refund(rec, chain, our_escrow)
        {
            if let Some(reveal) = ClaimScheduler::observe_reveal(chain, our_escrow) {
                if let Some(tick) = Self::restore_and_extract(store, rec, chain, &reveal)? {
                    return Ok(tick);
                }
            }
        }
        Ok(RecoveryTick::Refund(Self::abort_action(rec, chain)?))
    }

    /// `AbortRefund`: the completion-supersedes decision on our escrow — with
    /// the SL take-the-swap EXECUTOR for the post-release corner. An SL that
    /// released its enabling partial (possession persisted, G1) and only then
    /// aborted can still be handed the swap: SH's completion spends OUR escrow
    /// and reveals t. Observing that reveal here EXECUTES the claim — restore,
    /// extract, persist `Completing` (rule 3, via the `AbortRefund →
    /// Completing` completion-supersedes edge) — exactly as the `Released`
    /// re-entry does, instead of merely signalling `Refund(TakeTheSwap)` with
    /// no extractor. SH records and pre-exchange (early-record) aborts carry
    /// no possession material and keep the plain refund decision. SL's own
    /// script-path refund can never masquerade as the reveal:
    /// `observe_reveal` surfaces key-path witnesses only.
    fn reenter_abort_refund(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
    ) -> Result<RecoveryTick> {
        if rec.role == Role::SecretLearner
            && rec.possession_record.is_some()
            && !Self::swept_claim_futile(rec, chain)
        {
            if let Some(our_escrow) = rec.our_escrow_outpoint {
                // Never treat OUR OWN (mempool) refund of E_sl as the reveal —
                // its script-path witness carries a leading 64-byte sig that
                // `observe_reveal` would surface, forcing a needless restore
                // that Errs on a lost possession file (poisoning the scan).
                if !Self::spend_is_our_refund(rec, chain, our_escrow) {
                    if let Some(reveal) = ClaimScheduler::observe_reveal(chain, our_escrow) {
                        if let Some(tick) = Self::restore_and_extract(store, rec, chain, &reveal)? {
                            return Ok(tick);
                        }
                        // The witness failed extraction (mangled — a degraded
                        // source, not a claim): keep the plain refund decision
                        // below; a genuine reveal is picked up on the next scan.
                    }
                }
            }
        }
        // Never-confirming-Setup arm: a pre-funding abort whose Setup never
        // confirmed has no reachable exit (the refund spends an outpoint that
        // never came to exist). Re-submit the persisted Setup so the escrow can
        // confirm and the refund below becomes reachable. Ranks ABOVE the refund
        // decision precisely because the refund is unbroadcastable until then.
        if let Some(tick) = Self::rebroadcast_setup_if_unconfirmed(rec, chain) {
            return Ok(tick);
        }
        let action = Self::abort_action(rec, chain)?;
        // F6: persist the refund-side terminal (AbortRefund → Refunded, or → the
        // SH Completed supersede) so the record settles instead of lingering
        // non-terminal forever. Non-terminal actions (Wait/BroadcastRefund/
        // TakeTheSwap) leave the record where it is.
        Self::persist_abort_terminal(store, rec, action)?;
        Ok(RecoveryTick::Refund(action))
    }

    /// The never-confirming-Setup recovery arm: if our escrow is NOT yet
    /// confirmed on chain and we persisted the signed Setup bytes (store v4),
    /// re-submit them (idempotent) so the escrow can confirm. Returns `None`
    /// (fall through to the normal per-phase decision) when the escrow is
    /// already confirmed or no Setup was retained (the record-less crash shape).
    ///
    /// The confirmation read is the AUTHORITATIVE (self-verifying) source, not
    /// the agreement-required `funding_height`: a lying source that hides a real
    /// confirmation must not be able to force a needless re-submission (or, when
    /// the escrow genuinely confirmed on truth alone, keep us from the ordinary
    /// refund path). Same reasoning as `terminate_abort`'s funded discriminator.
    fn rebroadcast_setup_if_unconfirmed(
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
    ) -> Option<RecoveryTick> {
        let escrow = rec.our_escrow_outpoint?;
        let setup_tx = rec.setup_tx.as_ref()?;
        // Confirmed already ⇒ nothing to re-submit (the ordinary paths apply).
        if chain.authoritative_funding_height(escrow).is_some() {
            return None;
        }
        Some(RecoveryTick::RebroadcastSetup { setup_tx: setup_tx.clone() })
    }

    /// Restore the SL possession record and complete the claim from an observed
    /// on-chain reveal, persisting the finalized signature as `Completing`
    /// BEFORE it is handed back (rule 3). Shared by the `Released` re-entry and
    /// the post-release `AbortRefund` completion-supersedes executor.
    ///
    /// Returns `Ok(None)` when the OBSERVED WITNESS fails extraction (a
    /// malformed BIP340 signature, or a valid one whose extracted t does not
    /// open T) — the recovery twin of settle's mangled-reveal re-drive: an
    /// extraction-failing witness is EVIDENCE-FREE (it cannot take the swap),
    /// so the caller falls back to its no-reveal decision — the refund path —
    /// exactly as if nothing had been observed. This is a CORRECTNESS choice,
    /// not just robustness: a mangled reveal is not a claim, so the right
    /// answer is the refund, never a hard error. Restore/possession failures
    /// still `Err` — the record claims G1 evidence, and corruption there must
    /// SURFACE. It surfaces per-record now: [`reenter_all`] isolates each
    /// record's `Err` into [`RecoveryScan::failed`] and keeps scanning, so a
    /// corrupt possession file alarms loudly without hiding any other swap's
    /// deadline (it never poisons the whole scan).
    fn restore_and_extract(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
        reveal: &[u8; 64],
    ) -> Result<Option<RecoveryTick>> {
        let record_path = rec
            .possession_record
            .as_ref()
            .ok_or(Error::Ordering("restore-and-extract without a possession pointer"))?;
        let restored = Possessing::restore_secret_learner(record_path, &rec.swap_session_id)?;
        let observed = match ValidatedFinalSig::from_bytes(reveal) {
            Ok(o) => o,
            // Not even a valid signature encoding: a degraded source's garbage.
            Err(_) => return Ok(None),
        };
        // Extract t and complete our leg; the delay is clamped inside to the
        // swept escrow's claim ceiling (never past S + delta_late).
        let plan = match restored.claim_after_reveal(&observed, chain.tip_height()) {
            Ok(p) => p,
            // Extraction failed (t*G != T): a mangled reveal, not a claim.
            Err(_) => return Ok(None),
        };
        let final_sig = plan.comp_sl_final.0;
        let mut next = rec.clone();
        next.phase = SwapPhase::Completing;
        next.completion_tx = Some(final_sig.to_vec());
        store.put(&next)?;
        Ok(Some(RecoveryTick::Extract { final_sig: Some(final_sig), fallback: AbortAction::Wait }))
    }

    /// `Funding`: if our escrow is confirmed on chain the standing pre-armed
    /// refund is the exit (a stuck funding still unwinds safely); otherwise
    /// nothing is locked and resuming needs a fresh driver + transport.
    fn reenter_funding(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
    ) -> Result<RecoveryTick> {
        // AUTHORITATIVE read (matching the rebroadcast arm below, `terminate_abort`,
        // and this module's stated intent): a lying source that HIDES a real
        // confirmation must not be able to suppress our standing pre-armed refund.
        // On the agreement-required `funding_height` a single untrusted explorer
        // disagreeing would collapse a genuinely-funded escrow to `None` and
        // report "nothing locked", leaving the automatic refund unsurfaced.
        let refund = match rec.our_escrow_outpoint {
            Some(escrow) if chain.authoritative_funding_height(escrow).is_some() => {
                Some(Self::abort_action(rec, chain)?)
            }
            _ => None,
        };
        // Escrow not confirmed: if the persisted Setup exists but never
        // confirmed, re-submit it (idempotent) rather than reporting a bare
        // "nothing locked" that needs a fresh driver — the same
        // never-confirming-Setup arm the `AbortRefund` path uses.
        if refund.is_none() {
            if let Some(tick) = Self::rebroadcast_setup_if_unconfirmed(rec, chain) {
                return Ok(tick);
            }
        }
        // F6: a funded Funding record whose refund already CONFIRMED settles
        // (Funding → AbortRefund → Refunded) instead of being rescanned forever.
        if let Some(action) = refund {
            Self::persist_abort_terminal(store, rec, action)?;
        }
        Ok(RecoveryTick::Funding { refund })
    }

    /// `Released` (SL restore-and-extract). Restore the possession record,
    /// observe the reveal on OUR escrow (the E_sl that SH's Comp->SH spends),
    /// and either finalize the claim (persisting `Completing` first, rule 3) or
    /// fall back to the abort decision on our escrow.
    fn reenter_released(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
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

        // Restore up front even when no reveal is observable yet: a corrupt
        // possession record must surface NOW (the record claims G1 evidence),
        // not only once SH completes.
        let _validated = Possessing::restore_secret_learner(record_path, &rec.swap_session_id)?;

        if !Self::swept_claim_futile(rec, chain) {
            if let Some(reveal) = ClaimScheduler::observe_reveal(chain, our_escrow) {
                if let Some(tick) = Self::restore_and_extract(store, rec, chain, &reveal)? {
                    return Ok(tick);
                }
                // The observed witness failed extraction (mangled — a degraded/
                // lying source): fall through to the SAME safe fallback as no
                // reveal at all. A hard Err here would poison the whole scan
                // forever on a source that never heals.
            }
        }
        // No reveal (or none usable): SH has not completed. The safe fallback
        // is the AbortDriver decision on OUR escrow — wait, refund at maturity,
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
        // F6: a Released SL whose dead-device refund already CONFIRMED settles
        // (Released → AbortRefund → Refunded) instead of re-restoring the
        // possession record and re-deciding on every future scan.
        Self::persist_abort_terminal(store, rec, action)?;
        Ok(RecoveryTick::Extract { final_sig: None, fallback: action })
    }

    /// `Completing`: the finalized completion signature was persisted before
    /// broadcast. Rebroadcast it (the caller finalizes the tx from the sig +
    /// template, as at the live boundary), and mark `Completed` once **our**
    /// completion has swept the counterparty escrow — attributed by the
    /// spending witness against the persisted signature, never by a bare
    /// "spent, confirmed". A confirmed FOREIGN spend (the counterparty's own
    /// refund leaf / a superseding claim) means we LOST the sweep: the record
    /// routes `Completing -> AbortRefund` so our own escrow's exit is driven
    /// and the loss stays visible, instead of freezing a lost swap as a
    /// permanent false `Completed`. An unattributable confirmed spend keeps
    /// the honest non-terminal babysit (`confirmed: false`).
    fn reenter_completing(
        store: &SwapStore,
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
    ) -> Result<RecoveryTick> {
        let final_sig = completion_sig(rec)?;
        // Our completion spends the counterparty's escrow (the one we sweep).
        let swept = rec
            .their_escrow_outpoint
            .ok_or(Error::Ordering("Completing record without the swept escrow outpoint"))?;
        if spend_confirmed(chain, swept) {
            return match swept_spend_is_ours(chain, swept, &final_sig) {
                Some(true) => {
                    let mut next = rec.clone();
                    next.phase = SwapPhase::Completed;
                    store.put(&next)?;
                    Ok(RecoveryTick::Rebroadcast { final_sig, confirmed: true })
                }
                Some(false) => {
                    let mut next = rec.clone();
                    next.phase = SwapPhase::AbortRefund;
                    store.put(&next)?;
                    let action = Self::abort_action(&next, chain)?;
                    Self::persist_abort_terminal(store, &next, action)?;
                    Ok(RecoveryTick::Refund(action))
                }
                None => Ok(RecoveryTick::Rebroadcast { final_sig, confirmed: false }),
            };
        }
        Ok(RecoveryTick::Rebroadcast { final_sig, confirmed: false })
    }

    /// TRUE iff the escrow OUR claim would sweep (`their_escrow_outpoint`) is
    /// already CONFIRMED-spent by a tx that is provably not our claim — the
    /// take-the-swap executor would derive a claim that can never confirm, and
    /// persisting it as `Completing` would flip-flop forever with
    /// `reenter_completing`'s foreign-spend routing (`-> AbortRefund -> extract
    /// -> Completing -> ...`). At the phases that consult this (`Released` /
    /// `AbortRefund` / `Refunded`) a persisted claim can exist only from a
    /// prior `Completing` detour; with none persisted, ANY confirmed spend is
    /// foreign (rule 3: our claim is persisted `Completing` before it is ever
    /// handed out to broadcast). An unreportable witness never declares
    /// futility — the executor stays available and the resulting `Completing`
    /// babysit is honestly non-terminal either way.
    fn swept_claim_futile(rec: &SwapRecord, chain: &dyn AuthoritativeChainView) -> bool {
        let Some(swept) = rec.their_escrow_outpoint else { return false };
        if !spend_confirmed(chain, swept) {
            return false;
        }
        match (completion_sig(rec).ok(), chain.spending_witness_sig(swept)) {
            (Some(ours), Some(w)) => w != ours,
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    /// Persist a recovery-discovered refund-side TERMINAL, walking the legal
    /// phase graph from the record's current phase (finding: recovery drove the
    /// forward terminals — Completing→Completed — but never the refund-side ones,
    /// so an `AbortRefund`/`Funding`/`Released` record whose refund confirmed
    /// stayed non-terminal FOREVER: rescanned every startup, kept in
    /// `live_lessees`, its `restore_secret_learner` re-run every scan, the
    /// user-facing state never "settled"). This mirrors the driver's existing
    /// `Completing→Completed` finalize (module rule 3).
    ///
    /// Persists only a PROVEN terminal: `AbortAction::Refunded` (AbortDriver
    /// already required a `spend_txid` match against OUR refund) → `Refunded`,
    /// for any role; `AbortAction::Completed` → `Completed` only for an SH
    /// record (where it means OUR completion won). An SL `Completed` is the
    /// lost-race supersede — there is no "lost" terminal, and recording it
    /// `Completed` would be false-success accounting, so it stays non-terminal
    /// (the loss surfaces each scan). Best-effort like `SwapEngine::abort`: the
    /// terminal is chain-proven, so a store hiccup just leaves the record to be
    /// re-terminalized next scan — never a false terminal.
    fn persist_abort_terminal(
        store: &SwapStore,
        rec: &SwapRecord,
        action: AbortAction,
    ) -> Result<()> {
        let terminal = match (action, rec.role) {
            (AbortAction::Refunded, _) => SwapPhase::Refunded,
            (AbortAction::Completed, Role::SecretHolder) => SwapPhase::Completed,
            _ => return Ok(()),
        };
        if matches!(rec.phase, SwapPhase::Completed | SwapPhase::Refunded) {
            return Ok(());
        }
        let mut cur = rec.clone();
        // Pre-AbortRefund records hop through AbortRefund first (both are legal
        // single edges: Funding|Released → AbortRefund, then → the terminal).
        if !matches!(cur.phase, SwapPhase::AbortRefund) {
            cur.phase = SwapPhase::AbortRefund;
            store.put(&cur)?;
        }
        cur.phase = terminal;
        store.put(&cur)?;
        Ok(())
    }

    /// The completion-supersedes decision on our escrow, shared by the
    /// `AbortRefund`, funded-`Funding`, and foreign-swept re-routing paths.
    ///
    /// FORWARD-OR-REFUND both-sides guard (first, before any refund decision):
    /// if OUR OWN completion has provably swept the counterparty escrow we went
    /// FORWARD on that leg — we are paid — so broadcasting our own escrow's
    /// refund on top would take BOTH sides (the counterparty is denied E_ours
    /// while we keep E_theirs). `AbortDriver` reads only our own escrow, so it
    /// cannot see this; without the guard a matured, still-unspent E_ours would
    /// return `BroadcastRefund` even though our completion already swept
    /// E_theirs (reachable when a shallow reorg flips the swept escrow back to
    /// our completion after the record was routed to `AbortRefund`/`Refunded`).
    /// On a provably-ours swept spend we report `Completed` (the leg went
    /// through), never a refund. Conservative: an unspent/foreign/unattributable
    /// swept escrow reads through to the normal decision.
    fn abort_action(rec: &SwapRecord, chain: &dyn AuthoritativeChainView) -> Result<AbortAction> {
        let our_escrow = rec
            .our_escrow_outpoint
            .ok_or(Error::Ordering("abort path without our escrow outpoint"))?;
        let refund = rec
            .pre_armed_refund
            .as_ref()
            .ok_or(Error::Deadline("abort path without a pre-armed refund (G2)"))?;
        if Self::our_completion_swept(rec, chain) {
            return Ok(AbortAction::Completed);
        }
        Ok(AbortDriver::next_abort_action(chain, our_escrow, refund, refund_txid(refund)))
    }

    /// TRUE iff OUR OWN completion has (provably) swept the counterparty escrow
    /// — mempool OR confirmed. The complement of the foreign-spend attribution:
    /// the swept escrow's spending witness key-path signature equals our
    /// persisted completion signature (the only key-path spend of that escrow).
    /// Conservative FALSE on an unspent swept escrow, an unattributable witness,
    /// or a record with no persisted completion signature (e.g. a `Funding`
    /// record — no completion exists, so this never mis-fires pre-settlement).
    fn our_completion_swept(rec: &SwapRecord, chain: &dyn AuthoritativeChainView) -> bool {
        let Some(swept) = rec.their_escrow_outpoint else { return false };
        if matches!(chain.spend_status(swept), crate::chain::SpendStatus::Unspent) {
            return false;
        }
        matches!(
            (completion_sig(rec).ok(), chain.spending_witness_sig(swept)),
            (Some(ours), Some(w)) if w == ours
        )
    }

    /// TRUE iff `escrow`'s current spend (mempool or confirmed) is OUR OWN
    /// pre-armed refund, by txid — the same who-spent rule as the live
    /// `our_refund_confirmed` / `AbortDriver`. Keeps the take-the-swap executor
    /// from firing on our own refund's script-path witness (which
    /// `observe_reveal` surfaces as a leading 64-byte sig). Unreportable spender
    /// reads FALSE (the extraction attempt then self-limits: a non-reveal
    /// witness fails extraction to the safe fallback).
    fn spend_is_our_refund(
        rec: &SwapRecord,
        chain: &dyn AuthoritativeChainView,
        escrow: OutPoint,
    ) -> bool {
        matches!(
            (rec.pre_armed_refund.as_ref().and_then(refund_txid), chain.spend_txid(escrow)),
            (Some(mine), Some(seen)) if mine == seen
        )
    }
}

/// Is `outpoint` CONFIRMED spent (not merely in the mempool)? The re-validation
/// gate for a terminal record: only a confirmed spend proves the terminal still
/// holds after a possible reorg. An `InMempool` or `Unspent` reading means the
/// terminal's defining spend is not (or no longer) on chain — re-drive.
fn spend_confirmed(chain: &dyn AuthoritativeChainView, outpoint: OutPoint) -> bool {
    matches!(chain.spend_status(outpoint), crate::chain::SpendStatus::Confirmed(_))
}

/// Attribute the SWEPT escrow's spend against our persisted completion
/// signature. `Some(true)` — provably OUR completion: the spender's key-path
/// witness signature equals `final_sig` (our completion is the escrow's only
/// key-path spend, so equality is a proof). `Some(false)` — provably FOREIGN:
/// the view reports the spending witness and it does not match (the only other
/// spend path is the counterparty's own script-path refund leaf). `None` — the
/// view cannot report the witness: attribution is impossible, never guess a
/// terminal from it.
fn swept_spend_is_ours(
    chain: &dyn AuthoritativeChainView,
    swept: OutPoint,
    final_sig: &[u8; 64],
) -> Option<bool> {
    chain.spending_witness_sig(swept).map(|w| &w == final_sig)
}

/// The txid of our own pre-armed refund, for the `AbortDriver`'s
/// ours-vs-theirs spend discrimination. `None` if the stored bytes cannot be
/// decoded (conservative: `AbortDriver` then treats an unknown spend as a
/// winning completion rather than double-spending).
pub(crate) fn refund_txid(refund: &PreArmedRefund) -> Option<Txid> {
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
