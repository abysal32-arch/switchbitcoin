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
use crate::wallet::engine::{SettleEntry, SwapContext, SwapEngine};
use crate::Result;

// `DriveStatus` moved to the engine (it is the return of the shared
// settlement-step primitive `SwapEngine::step_settlement`); re-exported here so
// `wallet::driver::DriveStatus` — the historical path — still resolves.
pub use crate::wallet::engine::DriveStatus;

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
        // Delegate to the shared settlement-spine primitive: record the funding
        // record, run Phase A, and discriminate a persisted-AbortRefund exit
        // from a genuine error (see `SwapEngine::enter_settlement`).
        let stage = match engine.enter_settlement(role, funded, &mut ctx, chain)? {
            SettleEntry::Active(possessing) => Stage::Active(possessing),
            SettleEntry::Refunding(reason) => Stage::Done(DriveStatus::Refunding(reason)),
        };
        Ok(Self { engine, ctx, stage })
    }

    /// Drive Phase B one step. Re-enterable and idempotent: safe to call
    /// repeatedly as the chain advances. Returns a terminal
    /// (`Completed`/`Refunding`) or the non-terminal `AwaitingReveal`.
    pub fn poll(&mut self, chain: &impl ChainView) -> Result<DriveStatus> {
        // Terminal already reached — return it idempotently. Otherwise borrow
        // the retained `Possessing` and take one shared settlement step;
        // `step_settlement` only BORROWS the `Possessing`, so nothing here can
        // strand it, and a non-terminal `AwaitingReveal` leaves the stage Active.
        let possessing: &Possessing = match &self.stage {
            Stage::Done(status) => return Ok(*status),
            Stage::Active(p) => p,
        };
        let status = self.engine.step_settlement(possessing, &self.ctx, chain)?;
        // Cache ONLY terminals; `AwaitingReveal` must leave the driver Active so
        // the retained `Possessing` survives for the next poll.
        if matches!(status, DriveStatus::Completed { .. } | DriveStatus::Refunding(_)) {
            self.stage = Stage::Done(status);
        }
        Ok(status)
    }
}
