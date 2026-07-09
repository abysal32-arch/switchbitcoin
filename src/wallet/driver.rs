//! Single-role, end-to-end swap driver — the wallet-layer composition seam.
//!
//! [`SwapDriver`] composes the [`SwapEngine`] settlement spine — `record_funding`
//! → `run_exchange` → `settle` — into ONE re-enterable API that drives either
//! role (SH or SL) from a confirmed `Funded` + assembled [`SwapContext`] to a
//! persisted terminal. Before this, that lifecycle was only choreographed
//! inside integration tests; nothing composed it as a callable production path.
//!
//! # Scope (increment 1 — the settlement spine)
//! The driver stops exactly where the engine draws its own line
//! ([`SwapEngine::settle`]): it returns OUR final completion signature and the
//! refund terminal, and leaves the chain-layer finalize, broadcast, and
//! fresh-output ledger entry to the caller. Three further composition increments
//! live OUTSIDE this type and are tracked separately: the pre-funding
//! `FundingCoordinator` half, the watchtower/CPFP congestion backstop, and
//! crash-recovery re-entry from the `RecoveryAction`s `SwapEngine::open` returns.
//!
//! # Frozen-surface note
//! This is pure composition of already-built wallet ranks over the existing
//! `Transport`/`ChainView` traits — no curve math, no new settlement-core
//! surface. The load-bearing invariant it must never break: a swap goes through
//! for both parties, or the refund is automatic — so the only terminals are
//! `Completed` and `Refunding`; every "cannot proceed yet" is a re-drive.

use crate::chain::ChainView;
use crate::settlement::state_machine::{Funded, Possessing, Role};
use crate::wallet::claim_scheduler::ClaimScheduler;
use crate::wallet::engine::{SwapContext, SwapEngine, SwapOutcome};
use crate::wallet::store::SwapPhase;
use crate::Result;

/// The outcome of a driver [`poll`](SwapDriver::poll): a durable terminal, or a
/// non-terminal re-drive signal. Every "cannot proceed right now" is a re-drive,
/// NEVER a terminal — the forward-or-refund invariant means the only terminals
/// are a completed swap or the (automatic) refund exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveStatus {
    /// OUR leg is settled and the record is persisted `Completed`.
    /// `our_final_sig` is the 64-byte signature the caller finalizes+broadcasts
    /// onto its own completion tx (the engine boundary — see the module docs).
    Completed { our_final_sig: [u8; 64] },
    /// SL only: the counterparty's reveal is not on chain yet. Advance the
    /// `ChainView` and call `poll` again — the swap has NOT failed, and the
    /// in-flight `Possessing` is retained so no work is lost.
    AwaitingReveal,
    /// The swap routed to its pre-armed refund exit; `AbortRefund` is persisted
    /// and the refund driver / watchtower owns the broadcast from here. Call
    /// [`SwapEngine::record_refunded`] once the refund confirms. Carries the
    /// engine's static reason.
    Refunding(&'static str),
}

/// Private lifecycle state. The in-flight `Possessing` is an in-memory,
/// non-persisted object, so it must live INSIDE the driver across poll steps —
/// a stateless step-fn could not hold it. `settle` only BORROWS it, so the
/// driver keeps ownership and every not-ready poll is a clean re-drive.
enum Stage {
    /// Phase A done; holds the `Possessing` that `settle` borrows each poll.
    /// Boxed because `Possessing` dwarfs the other variant (large_enum_variant).
    Active(Box<Possessing>),
    /// A terminal (or terminal-refund) was reached; `poll` returns it idempotently.
    Done(DriveStatus),
}

/// A single-role swap driver bound to one [`SwapEngine`] and one [`SwapContext`].
///
/// Holds `&mut SwapEngine` for its lifetime, so drop it before reusing the
/// engine directly (e.g. to inspect the store). Re-enterable: `poll` is safe to
/// call repeatedly as the chain advances, and short-circuits once terminal.
pub struct SwapDriver<'e> {
    engine: &'e mut SwapEngine,
    ctx: SwapContext,
    stage: Stage,
}

impl<'e> SwapDriver<'e> {
    /// Begin driving: persist the initial `Funding` record (manifest-params
    /// gated) and run the interlocked Phase-A adaptor exchange over the peer the
    /// `Funded` owns. On the adaptor-exchange failure path the engine routes to
    /// the pre-armed refund (`AbortRefund` persisted) and the driver starts in a
    /// terminal `Refunding` stage. Any other Phase-A failure (a `record_funding`
    /// params-vs-manifest rejection, or a store fault that left the record at
    /// `Funding`/`Signing`/`Released` without persisting `AbortRefund`) is
    /// returned as `Err` — the caller recovers by re-opening the engine, and a
    /// post-release SL (where refund is not a safe sink) is never mislabelled
    /// `Refunding`.
    pub fn start(
        engine: &'e mut SwapEngine,
        role: Role,
        funded: Funded,
        mut ctx: SwapContext,
        chain: &impl ChainView,
    ) -> Result<Self> {
        // The manifest is the ONLY legitimate params source (record_funding
        // enforces params == the signed manifest), so read it from the engine.
        let params = engine.manifest().current().params().clone();
        engine.record_funding(&ctx, role, params)?;

        let stage = match engine.run_exchange(funded, &mut ctx, chain) {
            Ok(possessing) => Stage::Active(Box::new(possessing)),
            Err(e) => {
                // run_exchange routes to abort() (→ AbortRefund) ONLY on the
                // adaptor-exchange failure path; its pre-exchange and post-release
                // store failures return Err WITHOUT persisting AbortRefund. Trust
                // the PERSISTED phase, never the bare Err: report Refunding only
                // when the refund exit is actually armed. Otherwise surface the
                // error so the caller recovers (re-opening the engine drives the
                // record's recovery path) — a post-release SL, where refund is
                // NOT a safe sink, must never be reported as Refunding.
                let sid = SwapEngine::swap_session_id(&ctx)?;
                match engine.store().get(&sid)?.map(|r| r.phase) {
                    Some(SwapPhase::AbortRefund) => Stage::Done(DriveStatus::Refunding(
                        "phase-A exchange failed; pre-armed refund is the exit",
                    )),
                    _ => return Err(e),
                }
            }
        };
        Ok(Self { engine, ctx, stage })
    }

    /// Drive Phase B one step. Re-enterable and idempotent: safe to call
    /// repeatedly as the chain advances. Returns a terminal
    /// (`Completed`/`Refunding`) or the non-terminal `AwaitingReveal`.
    pub fn poll(&mut self, chain: &impl ChainView) -> Result<DriveStatus> {
        // Terminal already reached — return it idempotently. Otherwise borrow
        // the retained `Possessing`; `settle` only borrows, so nothing here can
        // strand it.
        let possessing: &Possessing = match &self.stage {
            Stage::Done(status) => return Ok(*status),
            Stage::Active(p) => p,
        };

        // SL: the reveal must be observable before `settle` can extract the
        // claim. A not-ready poll is a clean re-drive — the `Possessing` stays
        // retained, so the next poll can progress.
        if possessing.role() == Role::SecretLearner
            && ClaimScheduler::observe_reveal(chain, self.ctx.reveal_escrow_op).is_none()
        {
            return Ok(DriveStatus::AwaitingReveal);
        }

        let status = match self.engine.settle(possessing, &self.ctx, chain)? {
            SwapOutcome::Completed { our_final_sig } => DriveStatus::Completed { our_final_sig },
            SwapOutcome::Aborted(reason) => {
                // Discriminate a genuine terminal refund (SH broadcast-gate-closed
                // persists AbortRefund) from a benign re-drive by re-reading the
                // PERSISTED phase — never the overloaded reason string. A
                // non-AbortRefund phase is re-drivable: our SL reveal peek and
                // `settle`'s own re-observe are two independent, non-atomic
                // ChainView reads, so a reveal seen by the peek can be evicted /
                // reorged before `settle` re-reads (→ "no reveal observed yet");
                // the `Possessing` is retained, so the next poll simply tries
                // again. `AbortRefund` is the only terminal exit here.
                let sid = SwapEngine::swap_session_id(&self.ctx)?;
                match self.engine.store().get(&sid)?.map(|r| r.phase) {
                    Some(SwapPhase::AbortRefund) => DriveStatus::Refunding(reason),
                    _ => return Ok(DriveStatus::AwaitingReveal),
                }
            }
        };
        self.stage = Stage::Done(status);
        Ok(status)
    }
}
