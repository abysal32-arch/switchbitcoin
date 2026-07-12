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
//! `setup_broadcast` re-runs), and even inside that gap a pre-funding ABORT
//! cannot mislabel: `terminate_abort` also consults the chain — the escrow's
//! authoritative funding reading once the Setup confirmed, and the funding
//! coin's spend status while it is still in the mempool — classifies funded,
//! and writes the record it found missing.
//!
//! Never-confirming-Setup handling: a funded-classified abort whose Setup later
//! falls out of every mempool and NEVER confirms would otherwise leave its
//! `AbortRefund` record permanently non-terminal (the refund spends an escrow
//! outpoint that never came to exist, so it can never confirm) with the
//! pre-encumbrance coin `Leased` to a swap that can never settle. This is now
//! retired for the common case: [`setup_broadcast`](SwapApp::setup_broadcast)
//! persists the signed Setup bytes (record `setup_tx`, store v4), and
//! [`RecoveryDriver`] re-submits them idempotently whenever our escrow is still
//! unconfirmed — so the escrow confirms and the ordinary refund path becomes
//! reachable. The only remaining residual is the record-less crash shape (a
//! crash in the caller-side broadcast→`setup_broadcast` gap on a swap the fresh
//! instance never re-drives): no bytes were captured, so there is nothing to
//! re-submit and a rescan of the untouched-on-chain coin is the fallback.

use bitcoin::OutPoint;

use crate::chain::{AuthoritativeChainView, SpendStatus};
use crate::crypto::ValidatedPoint;
use crate::settlement::state_machine::{Funded, PeerSession, Possessing, Role};
use crate::tx::backstop::{required_child_fee, ANCHOR_VOUT, MAX_BUMP_FEE_SATS};
use crate::wallet::backstop_driver::{BackstopDriver, BackstopTick, BumpOutcome, CpfpBumpRequest};
use crate::wallet::ledger::{BumpTarget, LinkageAck};
use crate::wallet::engine::{ChainReconcile, DriveStatus, SettleEntry, SwapContext, SwapEngine};
use crate::wallet::funding_driver::{FundingDriver, FundingTick, HandoffError};
use crate::wallet::orchestrator::FundingOrder;
use crate::wallet::recovery_driver::{RecoveryDriver, RecoveryScan};
use crate::wallet::store::{SwapPhase, SwapRecord};
use crate::wallet::watchtower_driver::WatchtowerDriver;
use crate::{Error, Result};

/// The caller's observation of ITS stalled non-refund tx (the Setup or
/// completion it broadcast — only the caller holds those bytes; the engine
/// boundary keeps broadcast custody outside the app): everything
/// [`SwapApp::backstop_execute`] needs to size and build a CPFP bump of it.
pub struct StalledParent<'a> {
    /// The fully-signed stalled tx, exactly as broadcast.
    pub tx_bytes: &'a [u8],
    /// That tx's own absolute fee (sats).
    pub fee_sats: u64,
    /// That tx's vsize (vB).
    pub vsize_vb: u64,
}

/// The outcome of one [`SwapApp::backstop_execute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackstopRun {
    /// No bump was executed — the decision stands on its own: an idle/fired/
    /// safe-fallback tick, or a `NeedsConsent` awaiting the owner's
    /// [`LinkageAck`](crate::wallet::ledger::LinkageAck) (and the caller's
    /// [`StalledParent`] observation).
    Decided(BackstopTick),
    /// A bump decision was EXECUTED via
    /// [`run_cpfp_bump`](crate::wallet::backstop_driver::run_cpfp_bump).
    /// `NoBump` means the lease/build/submit fell through (e.g. an undersized
    /// reserve) with nothing stranded — the decision's safe fallback stands.
    Executed { decision: BackstopTick, outcome: BumpOutcome },
}

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
    /// Whether we have signalled the caller to broadcast our Setup. One of the
    /// funded-abort discriminators (see `terminate_abort` — the flag, the early
    /// record, a store read failure, and the chain's own authoritative funding
    /// reading all classify an abort as FUNDED; only their joint absence is a
    /// clean "nothing locked" `Aborted`).
    our_setup_broadcast: bool,
    /// The signed Setup bytes the caller handed to
    /// [`setup_broadcast`](SwapApp::setup_broadcast) — persisted into the early
    /// `Funding`/`AbortRefund` record so recovery can idempotently re-submit a
    /// Setup that fell out of every mempool and never confirmed (the
    /// never-confirming-Setup residual). `None` until `setup_broadcast` runs on
    /// THIS instance.
    our_setup_tx: Option<Vec<u8>>,
    /// The params snapshot taken at [`begin`](SwapApp::begin) — the SAME
    /// manifest the FundingDriver's coordinator gates escrow amounts under, and
    /// the value the early `Funding` record pins. Snapshotting at begin (not at
    /// `setup_broadcast`) means a manifest bump ANYWHERE inside the swap's
    /// lifetime trips `record_funding`'s manifest-equality check against the
    /// store's pinned copy — a hard error, never a silent desync from the
    /// on-chain amounts the coordinator verified.
    params: crate::settlement::params::Params,
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
            params: manifest.params().clone(),
            ctx,
            backstop,
            phase: AppPhase::Funding { driver: Box::new(driver), peer: Some(peer) },
            our_setup_broadcast: false,
            our_setup_tx: None,
        })
    }

    /// The early provisional-role `Funding` record (see the module docs' crash
    /// story): everything a crash-recovery needs about this swap, buildable
    /// from the ctx + the begin-time params snapshot alone. Written by
    /// [`setup_broadcast`](SwapApp::setup_broadcast) the moment our Setup is on
    /// the wire, and by `terminate_abort` when the CHAIN proves our escrow
    /// funded but the record is missing (the record-less crash shape).
    fn early_record(&self, sid: [u8; 32]) -> SwapRecord {
        SwapRecord {
            swap_session_id: sid,
            // Provisional — the Proceed handoff corrects it once txids + S fix
            // the real role (the store permits this while still `Funding`).
            role: Role::SecretHolder,
            phase: SwapPhase::Funding,
            params: self.params.clone(),
            s_height: 0,
            sweep_escrow_height: 0,
            our_escrow_outpoint: Some(self.ctx.our_escrow_op),
            their_escrow_outpoint: Some(self.ctx.their_escrow_op),
            pre_armed_refund: Some(self.ctx.pre_armed_refund.clone()),
            completion_tx: None,
            // The signed Setup bytes the caller broadcast (Some once
            // `setup_broadcast` has run on THIS instance; None for the
            // record-less crash shape, where a fresh instance never saw them).
            // Lets recovery re-submit a Setup that fell out of every mempool and
            // never confirmed instead of stranding the swap forever.
            setup_tx: self.our_setup_tx.clone(),
            possession_record: None,
        }
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
    /// `setup_tx` is the fully-signed Setup the caller just put on the wire.
    /// It is persisted into the early record (`setup_tx` field) so recovery can
    /// idempotently re-submit it if it falls out of every mempool and never
    /// confirms — retiring the never-confirming-Setup residual instead of
    /// stranding a permanently non-terminal `AbortRefund`.
    ///
    /// Idempotent: an existing record is left untouched (a restarted caller
    /// re-confirming its idempotent re-broadcast), and an `Err` from the store
    /// is retryable by calling this again. Call this IMMEDIATELY after the
    /// broadcast — the caller-side gap between the two is the only remaining
    /// unrecorded stretch, and a re-driven restart heals it (the fresh driver
    /// re-issues `BroadcastSetup` → re-broadcast is idempotent → this re-runs).
    ///
    /// No-op outside the pre-funding phase.
    pub fn setup_broadcast(&mut self, engine: &SwapEngine, setup_tx: &[u8]) -> Result<()> {
        match &mut self.phase {
            AppPhase::Funding { driver, .. } => {
                self.our_setup_broadcast = true;
                self.our_setup_tx = Some(setup_tx.to_vec());
                driver.setup_broadcast();
            }
            _ => return Ok(()),
        }
        let sid = SwapEngine::swap_session_id(&self.ctx)?;
        if engine.store().get(&sid)?.is_none() {
            // The record pins the BEGIN-time params snapshot — the same
            // manifest the coordinator gates escrow amounts under — so any
            // manifest bump inside the swap's lifetime becomes a hard error
            // at `record_funding` (params-vs-pinned-record mismatch), never a
            // silent desync from the amounts verified on chain.
            engine.store().put(&self.early_record(sid))?;
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
    pub fn poll(&mut self, engine: &mut SwapEngine, chain: &impl AuthoritativeChainView) -> Result<AppTick> {
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
                        chain,
                        "verification stall outlived the refund maturity; the pre-armed refund is the exit",
                    ))
                } else {
                    Ok(AppTick::AwaitingVerification)
                }
            }
            FundingTick::BroadcastOurSetup => Ok(AppTick::BroadcastSetup),
            FundingTick::Abort(reason) => Ok(self.terminate_abort(engine, chain, reason)),
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
        chain: &impl AuthoritativeChainView,
        congested: bool,
        reserve_available: bool,
    ) -> Result<BackstopTick> {
        let sid = SwapEngine::swap_session_id(&self.ctx)?;
        // Three-state read — Some / None / UNREADABLE. A store read Err must
        // never suppress the dead-device refund fire: the same fail-safe as
        // `terminate_abort`'s `read_err` rule (an Err must not collapse into
        // "no record and nothing locked"). A damaged/unreadable record is
        // treated as record-less, so it falls to the refund-only tower arm
        // below — the tower needs only the escrow + chain, so a corrupt record
        // can never keep the pre-armed refund from firing at CSV maturity.
        // An Err (unreadable/damaged record) fails safe to `None` — the
        // record-less refund-only arm below still fires the dead-device refund.
        let record = engine.store().get(&sid).unwrap_or_default();
        match record {
            Some(rec) => self.backstop.tick(&rec, chain, congested, reserve_available),
            // No durable (or no readable) record. Still guard a funded escrow's
            // dead-device refund (the pre-`Proceed` funded-abort case, and now
            // the damaged-record case); nothing locked ⇒ Idle. AUTHORITATIVE
            // read, matching `terminate_abort`, `reenter_funding`, and
            // `rebroadcast_setup_if_unconfirmed`: a lying source that HIDES a
            // real confirmation must not be able to suppress the standing
            // pre-armed refund (the agreement-required read collapses to `None`
            // on any single-source disagreement, which would keep the tower
            // Idle past CSV maturity on a liar's say-so).
            None => {
                if chain.authoritative_funding_height(self.ctx.our_escrow_op).is_some() {
                    self.backstop.tick_refund_only(chain, reserve_available, congested)
                } else {
                    Ok(BackstopTick::Idle)
                }
            }
        }
    }

    /// One backstop poll for this swap that also EXECUTES the bump it decides —
    /// the autonomous counterpart to [`backstop_tick`](SwapApp::backstop_tick)
    /// (which stays a pure decision for callers that own the execution).
    ///
    /// Routing:
    /// - `Bump { target: Refund }` (the tower's own relay-floor stall) is
    ///   executed FULLY AUTONOMOUSLY: the pre-armed refund IS the stalled
    ///   parent and the app holds its bytes in ctx, so the dead-device loop
    ///   needs nothing from the caller but a target feerate. The bump is
    ///   silent by spec (no linkage consent for refunds).
    /// - `Bump`/`NeedsConsent { target: Completion }` (a stalled Setup or
    ///   completion — the caller broadcast that tx, so only the caller holds
    ///   its bytes/fee/vsize) executes only when the caller supplies BOTH the
    ///   [`StalledParent`] observation and the typed privacy
    ///   [`LinkageAck`](crate::wallet::ledger::LinkageAck); otherwise the
    ///   decision is returned untouched (`Decided`) — the dead-device policy
    ///   (consent = None) keeps fighting rather than linking the reserve
    ///   behind the owner's back.
    /// - Every other tick (Idle / FiredRefund / the no-reserve safe fallbacks)
    ///   passes through as `Decided`.
    ///
    /// Reserve sizing: the DECISION gate uses a conservative ledger read sized
    /// to the parent we would bump; `run_cpfp_bump`'s lease step re-checks the
    /// exact child fee, so an undersized reserve degrades to
    /// `Executed { outcome: NoBump }` with the lease released — the safe
    /// fallback stands and nothing is stranded. A reserve key index issued for
    /// a bump that falls through is skipped, never reused.
    pub fn backstop_execute(
        &self,
        engine: &mut SwapEngine,
        chain: &impl AuthoritativeChainView,
        target_feerate_sat_vb: u64,
        stalled_parent: Option<&StalledParent<'_>>,
        consent: Option<LinkageAck>,
    ) -> Result<BackstopRun> {
        let congested = stalled_parent.is_some();

        // Pass 1 — identify the ACTIVE side with the reserve assumed
        // UNAVAILABLE, so the tick's own refund-first priority picks the side
        // without a gate that might be sized for the WRONG parent (review
        // finding: a completion-sized gate could starve an affordable refund
        // bump — both stalls are live at once during SH Completing).
        let base = self.backstop_tick(engine, chain, congested, false)?;

        // Size the reserve gate against THAT side's own parent. The refund
        // side stalls on our pre-armed refund (bytes in ctx); the completion/
        // setup side stalls on the caller's tx (only the caller holds it).
        let (gate_fee, gate_vsize) = match base {
            // Refund side is the decider (the tower is congested).
            BackstopTick::KeepWaiting => {
                let (_, fee, vsize) = self.refund_parent()?;
                (fee, vsize)
            }
            // Completion / setup side. Needs the caller's parent to bump at all;
            // without it the decision stands as-is (never guess the parent).
            BackstopTick::FallbackToRefund
            | BackstopTick::KeepFighting
            | BackstopTick::AbortBeforeLock => match stalled_parent {
                Some(p) => (p.fee_sats, p.vsize_vb),
                None => return Ok(BackstopRun::Decided(base)),
            },
            // FiredRefund (already broadcast) / Idle / an already-reserve-gated
            // variant (unreachable in pass 1, reserve=false): nothing to bump.
            _ => return Ok(BackstopRun::Decided(base)),
        };

        let child_fee = required_child_fee(target_feerate_sat_vb, gate_fee, gate_vsize);
        // Futile-bump short-circuit (review finding): a child fee of 0 means the
        // parent already meets the target feerate; one above the build ceiling
        // can never be built. Either way a bump is guaranteed NoBump — return
        // the decision WITHOUT issuing a Reserve key or a lease/release cycle,
        // so a stale-feerate dead-device loop can't burn the key-index space or
        // churn the ledger every tick.
        if child_fee == 0 || child_fee > MAX_BUMP_FEE_SATS {
            return Ok(BackstopRun::Decided(base));
        }
        // Heal pending CPFP-change reserves BEFORE the gate is read (F5 live
        // heal): a prior bump parks its child's change `PendingConfirm`, and
        // the ONLY path back to leasable `Unspent` is this heal. Wired solely
        // into the startup reconcile, a long-lived process would deplete one
        // reserve per bump and read an empty pool until a restart — the exact
        // "pool silently disabled" failure the pending-park exists to prevent.
        // Cheap per tick: no pending change means no chain reads and no persist.
        engine.ledger_mut().heal_pending_reserve_changes(chain)?;
        let reserve_available = engine.ledger().has_leasable_reserve(child_fee);

        // Pass 2 — re-decide with the correctly-sized gate; only now can the
        // side flip to Bump / NeedsConsent.
        let decision = self.backstop_tick(engine, chain, congested, reserve_available)?;

        // `Bump { Refund }` arises ONLY from the tower's refund stall
        // (bump_target maps Setup/completions to the Completion class), so
        // the parent is unambiguous in every arm.
        let (target, parent_bytes, parent_fee, parent_vsize, ack): (_, &[u8], _, _, _) =
            match decision {
                BackstopTick::Bump { target: BumpTarget::Refund } => {
                    let (bytes, fee, vsize) = self.refund_parent()?;
                    (BumpTarget::Refund, bytes, fee, vsize, None)
                }
                BackstopTick::Bump { target: BumpTarget::Completion }
                | BackstopTick::NeedsConsent { target: BumpTarget::Completion } => {
                    match (stalled_parent, consent) {
                        (Some(p), Some(ack)) => {
                            (BumpTarget::Completion, p.tx_bytes, p.fee_sats, p.vsize_vb, Some(ack))
                        }
                        // No ack (dead-device) or no parent observation: the
                        // decision stands on its own — never bump behind the
                        // owner's back, never guess the parent.
                        _ => return Ok(BackstopRun::Decided(decision)),
                    }
                }
                other => return Ok(BackstopRun::Decided(other)),
            };

        let parent_tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(parent_bytes)
                .map_err(|_| Error::Validation("backstop_execute: parent tx bytes do not decode"))?;
        let sid = SwapEngine::swap_session_id(&self.ctx)?;
        let (change_key_index, _spk) = engine.issue_reserve_key()?;
        let outcome = engine.execute_cpfp_bump(
            chain,
            CpfpBumpRequest {
                target,
                linkage_ack: ack,
                lessee: sid,
                parent_bytes,
                parent_anchor: OutPoint::new(parent_tx.compute_txid(), ANCHOR_VOUT),
                anchor_value_sats: self.params.anchor_sats,
                parent_fee_sats: parent_fee,
                parent_vsize_vb: parent_vsize,
                target_feerate_sat_vb,
                change_key_index,
            },
        )?;
        Ok(BackstopRun::Executed { decision, outcome })
    }

    /// The pre-armed refund viewed as a bumpable STALLED PARENT: its signed
    /// bytes (held in ctx since `begin`), its own fee (escrow amount minus the
    /// sum of its outputs — checked, so hostile values error rather than
    /// wrap), and its vsize.
    fn refund_parent(&self) -> Result<(&[u8], u64, u64)> {
        let bytes = self.ctx.pre_armed_refund.tx_bytes();
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(bytes)
            .map_err(|_| Error::Validation("pre-armed refund bytes do not decode"))?;
        let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        let fee = self
            .ctx
            .escrow_amount
            .checked_sub(out_sum)
            .ok_or(Error::Validation("refund outputs exceed the escrow amount"))?;
        Ok((bytes, fee, tx.vsize() as u64))
    }

    /// Whole-wallet crash re-entry: re-enter every non-terminal swap in the
    /// persisted store from the record alone (a live `SwapApp`'s in-memory state
    /// does not survive a crash — the store is the durable truth). Delegates to
    /// [`RecoveryDriver::reenter_all`]; the caller drives each
    /// [`RecoveryScan::ticks`] entry's broadcasts and SHOULD surface
    /// [`RecoveryScan::unreadable`] / [`RecoveryScan::failed`] as operator
    /// alarms — a per-record failure never aborts the scan, so the other swaps'
    /// deadlines are still driven.
    pub fn recover(engine: &SwapEngine, chain: &impl AuthoritativeChainView) -> Result<RecoveryScan> {
        RecoveryDriver::reenter_all(engine.store(), chain)
    }

    /// Whole-wallet STARTUP over a freshly opened engine — steps 2 and 3 of
    /// the canonical sequence (see
    /// [`SwapEngine::reconcile_with_chain`](crate::wallet::engine::SwapEngine::reconcile_with_chain))
    /// in one call: the chain-aware phantom heal, then the whole-store crash
    /// re-entry scan.
    ///
    /// The two are DECOUPLED. `reconcile_with_chain` performs an unconditional
    /// ledger persist (a seal+fsync+rename, even on a zero-change reconcile), so
    /// on a disk-full / locked-ledger / read-only device it returns `Err`. The
    /// recovery scan, however, reads ONLY the store and the chain — never the
    /// ledger — and its `Refund`/`Rebroadcast`/`RebroadcastSetup` ticks are pure
    /// reads a swap at a hard CSV deadline depends on. So the reconcile outcome
    /// is returned ALONGSIDE the scan (an inner `Result`), never `?`-propagated
    /// ahead of it: a reconcile write failure must not suppress every swap's
    /// refund tick. Reconcile still runs first (its heal is what a LATER
    /// lease/bump selection consumes), but the scan runs regardless.
    ///
    /// CALLER CONTRACT: gate any lease/bump ledger action on a `reconcile`
    /// `Ok`; the recovery ticks are actionable whether or not it succeeded. Only
    /// a failure to ENUMERATE the store (nothing to recover) is a hard `Err`.
    /// Step 1 — [`SwapEngine::open`](crate::wallet::engine::SwapEngine::open) —
    /// stays separate: it must succeed even with the chain backend down, and the
    /// engine it returns is this function's input.
    pub fn startup(
        engine: &mut SwapEngine,
        chain: &impl AuthoritativeChainView,
    ) -> Result<(Result<ChainReconcile>, RecoveryScan)> {
        let reconcile = engine.reconcile_with_chain(chain);
        let scan = Self::recover(engine, chain)?;
        Ok((reconcile, scan))
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
        chain: &impl AuthoritativeChainView,
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
                    Error::Abort(reason) => Ok(self.terminate_abort(engine, chain, reason)),
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
        chain: &impl AuthoritativeChainView,
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
        chain: &impl AuthoritativeChainView,
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
            return Ok(tick);
        }
        // AwaitingReveal reconciliation against OUR OWN CONFIRMED REFUND: the
        // dead-device tower (`backstop_tick`) fires the pre-armed refund at
        // CSV maturity independent of this loop, and once that refund
        // CONFIRMS the swap is over — the reveal can never appear on a spent
        // escrow. Without this, the poll loop re-drives `AwaitingReveal`
        // forever (a permanently mangled/lying reveal source sustains it —
        // the eternal-mangled bound) and the record never leaves `Released`
        // through the app. The discrimination is the same who-spent rule the
        // `AbortDriver` terminal uses: Confirmed spend AND the spender txid
        // IS our refund's. A confirmed spend that is NOT ours (SH's
        // completion) stays AwaitingReveal — settle's own extraction path
        // owns that (a valid reveal completes; a mangled one re-drives), and
        // an unreportable spender stays honestly non-terminal.
        if matches!(status, DriveStatus::AwaitingReveal) && self.our_refund_confirmed(chain) {
            engine.abort(&self.ctx); // Released → AbortRefund (idempotent, best-effort)
            engine.record_refunded(&self.ctx)?; // AbortRefund → Refunded
            let tick = AppTick::Refunding("pre-armed refund confirmed on chain; funds reclaimed");
            self.phase = AppPhase::Terminal(tick);
            return Ok(tick);
        }
        Ok(tick)
    }

    /// True iff OUR escrow's spend is CONFIRMED and the spender IS our own
    /// pre-armed refund (by txid). Both reads are authoritative on the dual
    /// view; a view that cannot report the spender txid never matches
    /// (honestly non-terminal, same rule as `AbortDriver`'s reconciliation).
    fn our_refund_confirmed(&self, chain: &impl AuthoritativeChainView) -> bool {
        matches!(chain.spend_status(self.ctx.our_escrow_op), SpendStatus::Confirmed(_))
            && crate::wallet::recovery_driver::refund_txid(&self.ctx.pre_armed_refund)
                .zip(chain.spend_txid(self.ctx.our_escrow_op))
                .is_some_and(|(mine, seen)| mine == seen)
    }

    /// Classify a pre-funding abort into a terminal: with our escrow funded (or
    /// possibly funded) the pre-armed refund is the sink (`Refunding`); only
    /// when NOTHING indicates a locked coin is the abort a clean `Aborted`.
    ///
    /// The funded discriminator is deliberately redundant — any ONE of these
    /// classifies as funded:
    /// - the in-memory broadcast flag (lost on restart),
    /// - the early `Funding` record (survives restarts, but not a crash in the
    ///   caller-side broadcast→`setup_broadcast` gap),
    /// - a store READ FAILURE (unknown must fail safe: a false `Refunding` on
    ///   an unfunded swap is harmless — recovery's Funding arm yields no
    ///   refund action and the tower needs a funding height — while a false
    ///   `Aborted` on a funded one abandons the guard),
    /// - the CHAIN (outranks everything): the authoritative funding reading of
    ///   our escrow — it directly observes the record-less crash shape once the
    ///   Setup confirms, and it is what makes the `AwaitingVerification`
    ///   escalation — whose precondition already implies both escrows are
    ///   authoritatively confirmed — always classify as a funded abort — OR a
    ///   non-`Unspent` spend of the funding coin, which observes the SAME shape
    ///   while the Setup still sits unconfirmed in the mempool (the escrow
    ///   outpoint does not exist yet, so the funding read alone is blind, but
    ///   miners do not honor Block-X and can still confirm that Setup).
    ///
    /// A funded abort is also made DURABLE (best-effort, mirroring
    /// `SwapEngine::abort` — the terminal classification itself must not fail
    /// on a store hiccup; the live backstop and the G2 watchtower still guard
    /// the refund regardless): if the chain proved funding but no record
    /// exists, the early `Funding` record is written here — recover() must not
    /// stay blind to a chain-confirmed escrow — and then advanced
    /// `Funding → AbortRefund` so recovery drives the completion-supersedes
    /// refund decision.
    fn terminate_abort(
        &mut self,
        engine: &SwapEngine,
        chain: &impl AuthoritativeChainView,
        reason: &'static str,
    ) -> AppTick {
        // Three-state record read: Some / None / unreadable — an Err must
        // never collapse into "no record" (the clean-abort arm).
        let (sid, record, read_err) = match SwapEngine::swap_session_id(&self.ctx) {
            Ok(sid) => match engine.store().get(&sid) {
                Ok(rec) => (Some(sid), rec, false),
                Err(_) => (Some(sid), None, true),
            },
            Err(_) => (None, None, true),
        };
        // The chain is read TWICE, because the record-less crash shape has two
        // faces: after the Setup CONFIRMS, the escrow's authoritative funding
        // height observes it directly; while the Setup still sits UNCONFIRMED
        // in the mempool, the escrow outpoint does not exist yet (the funding
        // read is blind), but the pre-encumbrance coin our Setup spends
        // already reads InMempool — and a Setup the miners can still confirm
        // (they do not honor Block-X) must never be classified "nothing
        // locked". A non-Unspent funding coin is therefore funded. False
        // positives are fail-safe by the same argument as `read_err`: the
        // coin is leased to THIS swap, so nothing else spends it honestly.
        let chain_funded = chain
            .authoritative_funding_height(self.ctx.our_escrow_op)
            .is_some()
            || !matches!(chain.spend_status(self.ctx.funding_coin), SpendStatus::Unspent);
        let funded = self.our_setup_broadcast || record.is_some() || read_err || chain_funded;
        let tick = if funded {
            if let Some(sid) = sid {
                let mut rec = record;
                if rec.is_none() && chain_funded && !read_err {
                    let early = self.early_record(sid);
                    if engine.store().put(&early).is_ok() {
                        rec = Some(early);
                    }
                }
                if let Some(mut rec) = rec {
                    if rec.phase == SwapPhase::Funding {
                        rec.phase = SwapPhase::AbortRefund;
                        let _ = engine.store().put(&rec);
                    }
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
