//! `SwapApp` — the top-level run-loop that composes the four orchestration
//! drivers into ONE re-enterable "run a swap" entry point for an app/frontend.
//!
//! Increments 1–4 built the seams as SEPARATE drivers — the pre-funding
//! [`FundingDriver`], the settlement-spine [`SwapDriver`] (over the
//! [`SwapEngine`] Phase-A/Phase-B primitives), the congestion
//! [`BackstopDriver`], and the crash-re-entry [`RecoveryDriver`] — but nothing
//! wired them end-to-end. `SwapApp` is that wiring: a single caller-facing type
//! that carries one swap from a match through funding and settlement to a
//! persisted terminal, with the backstop and the whole-wallet crash recovery
//! exposed through the same surface.
//!
//! # The two halves of the API
//! * **One live swap** — [`SwapApp::begin`] → [`poll`](SwapApp::poll)* →
//!   terminal. `poll` sequences the FundingDriver poll loop and, on
//!   `Proceed`, crosses the [`into_funded`](FundingDriver::into_funded) handoff
//!   into the engine's settlement spine ([`enter_settlement`](SwapEngine::enter_settlement)
//!   → [`step_settlement`](SwapEngine::step_settlement)) — all behind one
//!   [`AppTick`]. [`backstop_tick`](SwapApp::backstop_tick) is the
//!   primary-INDEPENDENT congestion/dead-device concern, run on its own cadence.
//! * **Whole wallet** — [`SwapApp::recover`] re-enters every crashed swap from
//!   the persisted store (delegating to [`RecoveryDriver::reenter_all`]). A live
//!   `SwapApp`'s in-flight `Possessing`/transport do NOT survive a crash by
//!   design — the durable truth is the engine's `SwapRecord`, and recovery
//!   re-derives the deadline-driven continuation from the record alone.
//!
//! # Engine boundary + forward-or-refund (unchanged from the drivers it composes)
//! The app DECIDES; the caller BROADCASTS. [`AppTick::BroadcastSetup`] and
//! [`AppTick::Completed`] hand signed bytes / a signature to the caller for the
//! wire. The only terminals are [`AppTick::Completed`] (both legs go through),
//! [`AppTick::Refunding`] (the pre-armed refund is the automatic exit, our
//! escrow was locked), and [`AppTick::Aborted`] (nothing was ever locked); every
//! "cannot proceed yet" is a re-drive ([`Wait`](AppTick::Wait) /
//! [`AwaitingReveal`](AppTick::AwaitingReveal) /
//! [`AwaitingVerification`](AppTick::AwaitingVerification)).
//!
//! # Frozen-surface note
//! Pure composition of the built wallet ranks over the existing
//! `Transport`/`ChainView` traits — no curve math, no new settlement-core
//! surface.
//!
//! # Crash story: the early `Funding` record
//! [`SwapApp::setup_broadcast`] persists a PROVISIONAL-ROLE `Funding` record the
//! moment the caller confirms our Setup is on the wire — the instant the
//! crash-exposure window of a funded escrow opens. From then on the swap is
//! durable: a crash anywhere before the `Proceed` handoff is re-entered by
//! [`SwapApp::recover`] (the record surfaces the standing pre-armed refund),
//! `SwapEngine::open`'s lease reconcile keeps the funding coin leased (no
//! phantom re-expose of a coin the in-flight Setup spends), and a funded
//! pre-funding abort advances the record to `AbortRefund` so recovery drives
//! the completion-supersedes refund decision. The role is corrected to the
//! derived one at the `Proceed` handoff (the store permits this only while the
//! record is still `Funding` — see `SwapStore::check_against`). The remaining
//! unrecorded stretch is only the caller-side gap between its actual broadcast
//! and its `setup_broadcast` call; a re-driven restart heals it (the fresh
//! driver re-issues `BroadcastSetup`, the re-broadcast is idempotent, and
//! `setup_broadcast` re-runs).

use bitcoin::OutPoint;

use crate::chain::ChainView;
use crate::crypto::ValidatedPoint;
use crate::settlement::state_machine::{Funded, PeerSession, Possessing, Role};
use crate::wallet::backstop_driver::{BackstopDriver, BackstopTick};
use crate::wallet::engine::{DriveStatus, SettleEntry, SwapContext, SwapEngine};
use crate::wallet::funding_driver::{FundingDriver, FundingTick, HandoffError};
use crate::wallet::orchestrator::FundingOrder;
use crate::wallet::recovery_driver::{RecoveryDriver, RecoveryScan};
use crate::wallet::store::{SwapPhase, SwapRecord};
use crate::wallet::watchtower_driver::WatchtowerDriver;
use crate::{Error, Result};

/// The outcome of one [`SwapApp::poll`]: a durable terminal, or a non-terminal
/// re-drive signal. The forward-or-refund invariant means the only terminals are
/// `Completed`, `Refunding`, and `Aborted`; every "cannot proceed right now" is a
/// re-drive the caller re-polls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppTick {
    /// Pre-funding: nothing to do this tick (jitter still elapsing, the
    /// counterparty not yet funded, or their encumbrance not yet verified).
    /// Re-poll as the chain advances.
    Wait,
    /// Pre-funding: broadcast YOUR signed Setup tx now, then call
    /// [`SwapApp::setup_broadcast`] and re-poll.
    BroadcastSetup,
    /// Pre-funding: both escrows are authoritatively confirmed (Block-X can no
    /// longer fire) yet the verified (agreement) view still lags — a source is
    /// disagreeing. Advisory re-drive: keep polling (an agreement lag can
    /// resolve a block later). The escalation is WIRED: a stall that persists
    /// to our pre-armed refund's CSV maturity is terminated by `poll` itself
    /// (→ [`AppTick::Refunding`], record advanced to `AbortRefund`) — the
    /// same height at which [`backstop_tick`](SwapApp::backstop_tick) fires
    /// the dead-device refund regardless, so a stalled swap can never wait
    /// forever.
    AwaitingVerification,
    /// Settlement (SL only): the counterparty's reveal is not on chain yet.
    /// Advance the `ChainView` and re-poll — the swap has NOT failed and the
    /// in-flight state is retained.
    AwaitingReveal,
    /// Terminal (success): OUR leg is settled and the record is persisted
    /// `Completed`. `our_final_sig` is the 64-byte signature the caller
    /// finalizes+broadcasts onto its own completion tx (the engine boundary).
    Completed { our_final_sig: [u8; 64] },
    /// Terminal (automatic refund): the swap routed to its pre-armed refund
    /// exit and OUR escrow was locked, so the refund is the sink. `AbortRefund`
    /// is persisted on both routes — a settlement-phase failure via the engine,
    /// and a funded pre-funding abort via the early `Funding` record (see the
    /// module docs' crash story). Keep [`backstop_tick`](SwapApp::backstop_tick)
    /// running until the refund confirms — it fires the dead-device refund at
    /// CSV maturity even if the record put failed (the tower needs only the
    /// escrow + chain) — then call [`SwapEngine::record_refunded`]. Carries the
    /// static reason.
    Refunding(&'static str),
    /// Terminal (clean abort): the swap was abandoned BEFORE our escrow was ever
    /// locked (a pre-funding Block-X / co-funding-window / encumbrance /
    /// scriptPubKey abort with our Setup never broadcast). Nothing to refund.
    /// Carries the static reason.
    Aborted(&'static str),
}

/// A single swap's lifecycle phase inside [`SwapApp`].
enum AppPhase {
    /// Pre-funding: the [`FundingDriver`] poll loop. The `peer` transport waits
    /// here until the `Proceed` handoff consumes it into a [`Funded`]; it is
    /// `None` only transiently while [`into_funded`](FundingDriver::into_funded)
    /// borrows it (and is restored on a non-consuming `Refused`). The driver is
    /// boxed — it dwarfs the other variants (`large_enum_variant`).
    Funding { driver: Box<FundingDriver>, peer: Option<PeerSession> },
    /// Settlement: the retained in-memory `Possessing`. `step_settlement` only
    /// BORROWS it, so a not-ready step (SL `AwaitingReveal`) never strands it.
    /// Boxed — it dwarfs the other variants (`large_enum_variant`).
    Settling(Box<Possessing>),
    /// A terminal was reached; `poll` returns it idempotently.
    Terminal(AppTick),
    /// The crossing into settlement errored PAST the point where the pre-funding
    /// state could be restored (the `Funded` handoff went `Fatal`, or the Phase-A
    /// entry faulted). This in-memory object can no longer safely drive the swap:
    /// `poll` re-surfaces an error (NEVER a benign `Wait`), so a re-poll can never
    /// be mistaken for progress, and the caller must re-open the engine and drive
    /// [`SwapApp::recover`] — which reads the PERSISTED phase (a post-release SL is
    /// routed to extract, never mis-refunded; a funded `Funding`/`AbortRefund`
    /// record surfaces its standing refund). Also the transient placeholder
    /// `cross_into_settlement` installs while it decides, so an early error there
    /// leaves THIS honest state rather than a poisoned `Terminal(Wait)`.
    Failed,
}

/// A single-swap, crash-re-enterable run-loop composing the four orchestration
/// drivers over a [`SwapEngine`] supplied per-poll (so the engine stays a shared
/// resource across many swaps — the app never holds a long-lived exclusive
/// borrow of it).
pub struct SwapApp {
    /// The tx-layer glue (escrows, sighashes, pre-armed refund, receipt, funding
    /// coin, taproot roots/output keys, paths) — assembled by the caller, the
    /// same `SwapContext` the engine spine consumes.
    ctx: SwapContext,
    /// The congestion / dead-device backstop, armed once from `ctx`'s pre-armed
    /// refund + escrow + G2 receipt; re-entrant (`tick` re-reads chain state).
    backstop: BackstopDriver,
    phase: AppPhase,
    /// Whether we have signalled the caller to broadcast our Setup. Mirrors the
    /// FundingDriver's own flag and is the discriminator for a pre-funding abort:
    /// with our Setup on the wire our escrow is (being) funded, so an abort must
    /// route to `Refunding` (keep the backstop guarding the refund); without it
    /// nothing is locked, so the abort is a clean `Aborted`.
    our_setup_broadcast: bool,
}

impl SwapApp {
    /// Begin driving one fresh swap. Reads the signed manifest from the engine
    /// (the same source `record_funding` later enforces params against), derives
    /// our session pubkey from `ctx.our_seckey`, and arms both the pre-funding
    /// [`FundingDriver`] and the congestion [`BackstopDriver`].
    ///
    /// `peer` is the counterparty transport used for the Phase-A exchange (the
    /// pre-funding loop never touches it). `block_x` is the caller's absolute
    /// funding no-show deadline height; `jitter_blocks` the caller-sampled
    /// per-party co-funding delay (clamped to the manifest bound inside).
    pub fn begin(
        engine: &SwapEngine,
        ctx: SwapContext,
        peer: PeerSession,
        block_x: u32,
        jitter_blocks: u32,
    ) -> Result<Self> {
        let manifest = engine.manifest().current();
        let our_point = ctx.our_seckey * secp::G;
        let our_pk = ValidatedPoint::from_bytes(&our_point.serialize())?;
        let their_pk = ctx.their_pubkey.clone();

        let driver = FundingDriver::begin(
            manifest,
            &our_pk,
            &their_pk,
            ctx.our_escrow_op,
            ctx.their_escrow_op,
            block_x,
            jitter_blocks,
        )?;

        // The backstop guards OUR escrow's pre-armed refund (E_ours) — armed
        // once from ctx, ticked (re-entrant) on the caller's own cadence.
        let tower = WatchtowerDriver::arm(
            ctx.pre_armed_refund.clone(),
            ctx.our_escrow_op,
            &ctx.watchtower_receipt,
        )?;
        let backstop = BackstopDriver::arm(tower);

        Ok(Self {
            ctx,
            backstop,
            phase: AppPhase::Funding { driver: Box::new(driver), peer: Some(peer) },
            our_setup_broadcast: false,
        })
    }

    /// The counterparty-agreed funding order (who funds first), while still in
    /// the pre-funding phase; `None` once settlement/terminal.
    pub fn funding_order(&self) -> Option<FundingOrder> {
        match &self.phase {
            AppPhase::Funding { driver, .. } => Some(driver.order()),
            _ => None,
        }
    }

    /// Whether the swap will make no further progress through THIS object: a
    /// clean terminal ([`AppTick::Completed`] / [`Refunding`](AppTick::Refunding)
    /// / [`Aborted`](AppTick::Aborted)) was reached, OR the crossing errored into
    /// the `Failed` state (re-poll then errors — re-open the engine and
    /// [`recover`](SwapApp::recover)).
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, AppPhase::Terminal(_) | AppPhase::Failed)
    }

    /// Signal that the caller performed the [`AppTick::BroadcastSetup`]
    /// broadcast — our Setup is on the wire, so the crash-exposure window of a
    /// funded escrow opens HERE. Records our own flag (the abort
    /// discriminator), forwards to the pre-funding driver, and persists the
    /// EARLY `Funding` record, making the escrow durable from this moment: a
    /// crash before the `Proceed` handoff is re-entered by
    /// [`SwapApp::recover`] (the standing pre-armed refund is the exit), and
    /// `SwapEngine::open`'s lease reconcile keeps the funding coin leased
    /// instead of re-exposing a coin the in-flight Setup spends.
    ///
    /// The record's role is PROVISIONAL — the real role derives from the two
    /// funding txids + S only after both escrows confirm, so it is unknowable
    /// here; the store permits correcting it while the record is still
    /// `Funding`, and the `Proceed` handoff re-persists the derived role.
    ///
    /// Idempotent: an existing record is left untouched (a restarted caller
    /// re-confirming its idempotent re-broadcast), and an `Err` from the store
    /// is retryable by calling this again. Call this IMMEDIATELY after the
    /// broadcast — the caller-side gap between the two is the only remaining
    /// unrecorded stretch, and a re-driven restart heals it (the fresh driver
    /// re-issues `BroadcastSetup` → re-broadcast is idempotent → this re-runs).
    ///
    /// No-op outside the pre-funding phase.
    pub fn setup_broadcast(&mut self, engine: &SwapEngine) -> Result<()> {
        match &mut self.phase {
            AppPhase::Funding { driver, .. } => {
                self.our_setup_broadcast = true;
                driver.setup_broadcast();
            }
            _ => return Ok(()),
        }
        let sid = SwapEngine::swap_session_id(&self.ctx)?;
        if engine.store().get(&sid)?.is_none() {
            engine.store().put(&SwapRecord {
                swap_session_id: sid,
                // Provisional (see above) — deterministic placeholder the
                // Proceed handoff corrects once txids + S fix the real role.
                role: Role::SecretHolder,
                phase: SwapPhase::Funding,
                // Snapshot the manifest params NOW. `record_funding` at Proceed
                // re-puts the live manifest's params; the store pins the
                // snapshot, so a mid-swap manifest bump becomes a hard error
                // there instead of a silent desync from the on-chain amounts
                // the coordinator gated under the old params.
                params: engine.manifest().current().params().clone(),
                s_height: 0,
                sweep_escrow_height: 0,
                our_escrow_outpoint: Some(self.ctx.our_escrow_op),
                their_escrow_outpoint: Some(self.ctx.their_escrow_op),
                pre_armed_refund: Some(self.ctx.pre_armed_refund.clone()),
                completion_tx: None,
                possession_record: None,
            })?;
        }
        Ok(())
    }

    /// Advance the swap one step. Re-enterable and idempotent: safe to call
    /// repeatedly as the chain advances, and short-circuits once terminal.
    ///
    /// `engine` is borrowed only for this call (it is used at the `Proceed`
    /// handoff and during settlement, not the pre-funding wait), so the same
    /// engine drives many swaps. At the handoff this call runs the interlocked
    /// Phase-A adaptor exchange over the peer, which BLOCKS until the exchange
    /// completes or the transport fails — identical to `SwapDriver::start`.
    pub fn poll(&mut self, engine: &mut SwapEngine, chain: &impl ChainView) -> Result<AppTick> {
        match &self.phase {
            AppPhase::Terminal(tick) => return Ok(*tick),
            // Honest error re-surface — never a benign Wait. The original cause
            // was returned by the poll that failed; a re-poll gets this generic
            // signal so the caller re-opens the engine and drives `recover`.
            AppPhase::Failed => {
                return Err(Error::Abort(
                    "SwapApp errored crossing into settlement; re-open the engine and drive recover()",
                ))
            }
            AppPhase::Settling(_) => return self.step_settling(engine, chain),
            AppPhase::Funding { .. } => {}
        }

        let tick = match &mut self.phase {
            AppPhase::Funding { driver, .. } => driver.tick(chain)?,
            // Unreachable: the match above returned for every non-Funding phase.
            _ => unreachable!("poll: phase changed under us"),
        };
        match tick {
            FundingTick::Wait => Ok(AppTick::Wait),
            // The persistent-liar stall (both escrows authoritatively
            // confirmed, the agreement view lagging) would otherwise wait
            // FOREVER — Block-X can no longer fire, and the coordinator
            // deliberately never proceeds unverified. This is the escalation
            // the FundingDriver docs assign to its caller: once OUR pre-armed
            // refund matures, route to the refund path. Maturity IS the
            // persistence criterion (a lag that outlives the whole CSV window
            // is not resolving itself a block later), and it is exactly the
            // height at which the dead-device tower fires this refund anyway
            // (`backstop_tick`), so escalating here makes the app's terminal
            // agree with what the backstop does regardless. Pre-maturity the
            // stall stays the advisory `AwaitingVerification` re-drive.
            FundingTick::AwaitingVerification => {
                if chain.tip_height() >= self.ctx.pre_armed_refund.csv_maturity_height() {
                    Ok(self.terminate_abort(
                        engine,
                        "verification stall outlived the refund maturity; the pre-armed refund is the exit",
                    ))
                } else {
                    Ok(AppTick::AwaitingVerification)
                }
            }
            FundingTick::BroadcastOurSetup => Ok(AppTick::BroadcastSetup),
            FundingTick::Abort(reason) => Ok(self.terminate_abort(engine, reason)),
            FundingTick::Proceed { .. } => self.cross_into_settlement(engine, chain),
        }
    }

    /// One congestion/dead-device backstop poll for this swap — the
    /// primary-INDEPENDENT half, run on the caller's own cadence (e.g. the
    /// watchtower loop, even while `poll` is dormant). Pure decision: the caller
    /// executes any resulting `Bump`/`NeedsConsent` via
    /// [`run_cpfp_bump`](crate::wallet::backstop_driver::run_cpfp_bump).
    ///
    /// `congested` is the caller's observation that our current non-refund tx
    /// could not relay under the fee floor; `reserve_available` its ledger read
    /// ([`Ledger::has_leasable_reserve`](crate::wallet::ledger::Ledger::has_leasable_reserve)).
    ///
    /// Before the first durable record exists (`record_funding` runs only at the
    /// `Proceed` handoff), there is no record to classify the completion side
    /// against — but our escrow CAN already be funded (our Setup went on the wire
    /// and then the pre-funding half aborted → [`AppTick::Refunding`]). That
    /// funded escrow's pre-armed refund still must be guarded, so this polls the
    /// tower directly ([`BackstopDriver::tick_refund_only`], which needs only the
    /// escrow + chain) whenever E_ours is funded, firing the dead-device refund at
    /// CSV maturity. If E_ours is not funded, nothing is locked ⇒
    /// [`BackstopTick::Idle`].
    pub fn backstop_tick(
        &self,
        engine: &SwapEngine,
        chain: &impl ChainView,
        congested: bool,
        reserve_available: bool,
    ) -> Result<BackstopTick> {
        let sid = SwapEngine::swap_session_id(&self.ctx)?;
        match engine.store().get(&sid)? {
            Some(rec) => self.backstop.tick(&rec, chain, congested, reserve_available),
            // No durable record yet. Still guard a funded-but-record-less escrow's
            // dead-device refund (the pre-`Proceed` funded-abort case); nothing
            // locked ⇒ Idle.
            None => {
                if chain.funding_height(self.ctx.our_escrow_op).is_some() {
                    self.backstop.tick_refund_only(chain, reserve_available)
                } else {
                    Ok(BackstopTick::Idle)
                }
            }
        }
    }

    /// Whole-wallet crash re-entry: re-enter every non-terminal swap in the
    /// persisted store from the record alone (a live `SwapApp`'s in-memory state
    /// does not survive a crash — the store is the durable truth). Delegates to
    /// [`RecoveryDriver::reenter_all`]; the caller drives each returned
    /// [`RecoveryTick`](crate::wallet::recovery_driver::RecoveryTick) and
    /// performs its broadcasts.
    pub fn recover(engine: &SwapEngine, chain: &dyn ChainView) -> Result<RecoveryScan> {
        RecoveryDriver::reenter_all(engine.store(), chain)
    }

    /// The outpoint our pre-armed refund reclaims (E_ours) — exposed for a
    /// caller wiring the refund/backstop broadcast at a `Refunding` terminal.
    pub fn our_escrow(&self) -> OutPoint {
        self.ctx.our_escrow_op
    }

    // --- internals ---

    /// Cross the `Proceed` handoff: mint the [`Funded`] and enter the engine's
    /// settlement spine. A non-consuming `Refused` restores the pre-funding
    /// phase for a plain re-drive; a terminal-abort refusal ends the swap.
    fn cross_into_settlement(
        &mut self,
        engine: &mut SwapEngine,
        chain: &impl ChainView,
    ) -> Result<AppTick> {
        // Extract the Funding phase by value (into_funded consumes the driver +
        // peer). The transient placeholder is `Failed`, NOT `Terminal(Wait)`: if
        // an error path below returns before overwriting `phase`, the swap is
        // left in the honest error state (re-poll errors) rather than a poisoned
        // benign terminal that silently drops a funded escrow's refund.
        let (driver, peer) =
            match std::mem::replace(&mut self.phase, AppPhase::Failed) {
                AppPhase::Funding { driver, peer } => {
                    (driver, peer.expect("peer present until the funded handoff"))
                }
                // Unreachable: cross_into_settlement is only called from the
                // Funding arm of `poll`.
                _ => unreachable!("cross_into_settlement from a non-Funding phase"),
            };

        let params = engine.manifest().current().params().clone();
        match driver.into_funded(params, peer, chain) {
            Ok(funded) => self.enter_settlement(engine, funded, chain),
            Err(HandoffError::Refused { driver, peer, error }) => {
                // Nothing was consumed: restore the pre-funding phase (the
                // refused driver is already boxed by `HandoffError`).
                self.phase = AppPhase::Funding { driver, peer: Some(peer) };
                match error {
                    // A terminal refusal (sticky abort, Block-X, wrong amount,
                    // scriptPubKey mismatch): end the swap, routed by whether our
                    // escrow is locked.
                    Error::Abort(reason) => Ok(self.terminate_abort(engine, reason)),
                    // A benign re-drive refusal (no go-signal yet, unverifiable
                    // counterparty escrow): keep the restored phase and re-poll.
                    _ => Ok(AppTick::Wait),
                }
            }
            // Consumed by settlement-core validation past the point of no return
            // — with the Refused pre-checks enforced first, this is a
            // construction bug, not a chain transient. Surface it.
            Err(HandoffError::Fatal(e)) => Err(e),
        }
    }

    /// Feed the minted [`Funded`] into the engine's Phase-A spine and settle to
    /// the extent the chain allows this poll.
    fn enter_settlement(
        &mut self,
        engine: &mut SwapEngine,
        funded: Funded,
        chain: &impl ChainView,
    ) -> Result<AppTick> {
        // Role is the Funded's DERIVED role (from the two funding txids + S), so
        // record_funding persists the same role run_exchange uses — no mismatch.
        let role = funded.role();
        match engine.enter_settlement(role, funded, &mut self.ctx, chain)? {
            SettleEntry::Active(possessing) => {
                self.phase = AppPhase::Settling(possessing);
                // Advance one settlement step immediately (SH broadcasts its
                // completion; SL peeks the reveal → AwaitingReveal if not yet up).
                self.step_settling(engine, chain)
            }
            SettleEntry::Refunding(reason) => {
                // Phase A routed to the pre-armed refund; our escrow is funded,
                // so this is a refund terminal (never a clean Aborted).
                let tick = AppTick::Refunding(reason);
                self.phase = AppPhase::Terminal(tick);
                Ok(tick)
            }
        }
    }

    /// Take one settlement step over the retained `Possessing`, caching a
    /// terminal into `Terminal` (which drops the `Possessing`, no longer needed).
    fn step_settling(
        &mut self,
        engine: &mut SwapEngine,
        chain: &impl ChainView,
    ) -> Result<AppTick> {
        let status = {
            let possessing = match &self.phase {
                AppPhase::Settling(p) => p.as_ref(),
                _ => unreachable!("step_settling from a non-Settling phase"),
            };
            engine.step_settlement(possessing, &self.ctx, chain)?
        };
        let tick = app_from_drive(status);
        // Only terminals are cached; `AwaitingReveal` leaves the phase Settling
        // so the retained `Possessing` survives for the next poll.
        if matches!(status, DriveStatus::Completed { .. } | DriveStatus::Refunding(_)) {
            self.phase = AppPhase::Terminal(tick);
        }
        Ok(tick)
    }

    /// Classify a pre-funding abort into a terminal: with our Setup on the wire
    /// our escrow is (being) funded, so the pre-armed refund is the sink
    /// (`Refunding`); otherwise nothing is locked (`Aborted`).
    ///
    /// The discriminator is the in-memory flag OR the early record: the flag
    /// does not survive a restart, but the record does — a record existing for
    /// this swap means our Setup went on the wire in SOME session, so a
    /// restarted app that aborts before the caller re-confirms its idempotent
    /// re-broadcast still classifies as a FUNDED abort, never a clean
    /// "nothing locked" `Aborted`.
    ///
    /// A funded abort also advances the early `Funding` record to `AbortRefund`
    /// (best-effort, mirroring `SwapEngine::abort` — the terminal classification
    /// itself must not fail on a store hiccup; the live backstop and the G2
    /// watchtower still guard the refund regardless), so a crash after this
    /// terminal is re-entered by [`recover`](SwapApp::recover) as the
    /// completion-supersedes refund decision.
    fn terminate_abort(&mut self, engine: &SwapEngine, reason: &'static str) -> AppTick {
        let record = SwapEngine::swap_session_id(&self.ctx)
            .ok()
            .and_then(|sid| engine.store().get(&sid).ok().flatten());
        let tick = if self.our_setup_broadcast || record.is_some() {
            if let Some(mut rec) = record {
                if rec.phase == SwapPhase::Funding {
                    rec.phase = SwapPhase::AbortRefund;
                    let _ = engine.store().put(&rec);
                }
            }
            AppTick::Refunding(reason)
        } else {
            AppTick::Aborted(reason)
        };
        self.phase = AppPhase::Terminal(tick);
        tick
    }
}

/// Map a settlement [`DriveStatus`] to the caller-facing [`AppTick`].
fn app_from_drive(status: DriveStatus) -> AppTick {
    match status {
        DriveStatus::Completed { our_final_sig } => AppTick::Completed { our_final_sig },
        DriveStatus::AwaitingReveal => AppTick::AwaitingReveal,
        DriveStatus::Refunding(reason) => AppTick::Refunding(reason),
    }
}
