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

use crate::chain::AuthoritativeChainView;
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
///
/// NOTE: the swap_session_id is NOT a field — it is DERIVED internally from
/// `(our_seckey·G, their_pubkey)` so the engine's SwapStore keys, the
/// possession pointer, and the settlement layer's possession file (name + seal
/// TEK, which it derives the same way) are provably the same id. A free
/// caller-supplied id could diverge (e.g. from the PeerSession routing tag,
/// which is explicitly NOT the authoritative id) and strand SL after release —
/// a fund loss (adversarial-review HIGH).
pub struct SwapContext {
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

/// The outcome of one settlement step ([`SwapEngine::step_settlement`], the
/// primitive [`SwapDriver`](crate::wallet::driver::SwapDriver) and
/// [`SwapApp`](crate::wallet::app::SwapApp) both drive): a durable terminal, or
/// a non-terminal re-drive signal. Every "cannot proceed right now" is a
/// re-drive, NEVER a terminal — the forward-or-refund invariant means the only
/// terminals are a completed swap or the (automatic) refund exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveStatus {
    /// OUR leg is settled and the record is persisted `Completed`.
    /// `our_final_sig` is the 64-byte signature the caller finalizes+broadcasts
    /// onto its own completion tx (the engine boundary — see the module docs).
    Completed { our_final_sig: [u8; 64] },
    /// SL only: the counterparty's reveal is not on chain yet. Advance the
    /// `ChainView` and step again — the swap has NOT failed, and the in-flight
    /// `Possessing` is retained so no work is lost.
    AwaitingReveal,
    /// The swap routed to its pre-armed refund exit; `AbortRefund` is persisted
    /// and the refund driver / watchtower owns the broadcast from here. Call
    /// [`SwapEngine::record_refunded`] once the refund confirms. Carries the
    /// engine's static reason.
    Refunding(&'static str),
}

/// The combined report of the composed post-open chain reconciliation
/// ([`SwapEngine::reconcile_with_chain`]): what each of the two phantom heals
/// swept/released. Empty vectors on a clean startup (no crash straddled a
/// submit→persist window).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ChainReconcile {
    /// Reserve coins the chain confirms spent but the ledger still counted
    /// spendable — now `Spent` (the CPFP-bump submit→persist phantom).
    pub reserves_swept: Vec<OutPoint>,
    /// The lease pass: confirmed-spent leasable coins swept to `Spent` (the
    /// funding-coin phantom) + orphaned leases released to `Unspent`.
    pub leases: crate::wallet::ledger::LeaseReconcile,
}

/// The result of entering settlement ([`SwapEngine::enter_settlement`], Phase A):
/// the live `Possessing` to RETAIN across settlement steps, or the pre-armed
/// refund exit if the interlocked adaptor exchange routed there.
pub enum SettleEntry {
    /// Phase A done; the `Possessing` the caller must keep (it is in-memory and
    /// non-persisted, so it must live across steps) and pass to
    /// [`SwapEngine::step_settlement`]. Boxed because it dwarfs the other
    /// variant (`large_enum_variant`).
    Active(Box<Possessing>),
    /// The exchange failed and the engine persisted `AbortRefund`; the pre-armed
    /// refund is the exit. Carries the static reason.
    Refunding(&'static str),
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
    ///
    /// This is STEP 1 of the canonical startup sequence — deliberately
    /// chain-blind (a wallet must open even with the backend down). Follow it
    /// with [`reconcile_with_chain`](Self::reconcile_with_chain) (step 2, the
    /// chain-aware phantom heals) and then `SwapApp::recover` (step 3) — see
    /// `reconcile_with_chain`'s docs for the full sequence rationale.
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
        // SwapRecord was written) is released back to unspent. This pass is
        // chain-BLIND (open takes no chain); the chain-aware phantom heal is the
        // post-open `reconcile_leases_with_chain` below (a Leased coin a terminal
        // swap already spent on chain must become Spent, not re-exposed Unspent).
        ledger.reconcile_leases(&live_lessees(&store)?)?;

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

    /// Issue a fresh Reserve change key (index + spk) through the ledger — the
    /// CPFP bump child's change output lands at it, keeping the reserve pool
    /// self-replenishing. Borrow-splitting wrapper (the ledger and the keys are
    /// both this engine's fields).
    pub fn issue_reserve_key(&mut self) -> Result<(u32, bitcoin::ScriptBuf)> {
        self.ledger.next_reserve_key(self.keys.as_ref())
    }

    /// Chain-aware reserve reconciliation — run at startup (after `open`) with
    /// the authoritative chain to sweep any phantom Reserve coin already spent
    /// on chain but still counted spendable (a crash in a prior bump's
    /// submit→persist window). See
    /// [`Ledger::sweep_spent_reserves`](crate::wallet::ledger::Ledger::sweep_spent_reserves).
    /// Returns the swept outpoints.
    pub fn reconcile_reserves(
        &mut self,
        chain: &dyn crate::chain::AuthoritativeChainView,
    ) -> Result<Vec<OutPoint>> {
        self.ledger.sweep_spent_reserves(chain)
    }

    /// Chain-aware LEASE reconciliation — run at startup (after `open`) with the
    /// authoritative chain, the lease analogue of [`reconcile_reserves`](Self::reconcile_reserves).
    /// `open`'s lease reconcile is chain-BLIND, so a `Leased` coin a terminal
    /// swap already spent on chain (e.g. a pre-funding abort whose Setup confirmed
    /// but whose `run_exchange` mark-spent never ran) is released back to
    /// `Unspent` when the swap reaches a terminal — a phantom pre-encumbrance
    /// coin a later swap would re-select and `submit_package` would reject
    /// forever. This consults
    /// [`Ledger::reconcile_leases_with_chain`](crate::wallet::ledger::Ledger::reconcile_leases_with_chain)
    /// to mark any `Leased`-or-`Unspent` coin the chain confirms spent as `Spent`
    /// (never re-leasable) and release remaining orphaned leases — closing the
    /// terminal-Refunded lease-release residual and the increment-2a phantom.
    pub fn reconcile_leases_with_chain(
        &mut self,
        chain: &dyn crate::chain::AuthoritativeChainView,
    ) -> Result<crate::wallet::ledger::LeaseReconcile> {
        let live = live_lessees(&self.store)?;
        self.ledger.reconcile_leases_with_chain(&live, chain)
    }

    /// The COMPOSED post-open chain reconciliation — THE startup seam. The
    /// canonical wallet startup sequence is:
    ///
    /// ```text
    ///   1. SwapEngine::open(..)               — chain-BLIND: store recovery
    ///      actions surface, orphaned leases release (live-record check only).
    ///   2. engine.reconcile_with_chain(chain) — THIS: both chain-aware phantom
    ///      heals, before any lease/bump decision reads the ledger.
    ///   3. SwapApp::recover(&engine, chain)   — re-enter every non-terminal
    ///      swap from its record (refund broadcasts, Setup re-submits, claims).
    /// ```
    ///
    /// `SwapApp::startup` wraps steps 2+3 into ONE call for composed callers.
    ///
    /// `open` cannot do step 2 itself (it deliberately takes no chain — a
    /// wallet must open even when the backend is down), and both heals are
    /// no-ops unless a crash straddled a submit→persist window, so a caller
    /// that skips step 2 loses only the phantom heals, never funds. But the
    /// phantoms are real: a `Leased`-or-`Unspent` coin the chain already
    /// confirms SPENT (a pre-funding abort's confirmed Setup whose
    /// `run_exchange` mark-spent never ran, or a CPFP bump child's consumed
    /// reserve whose ledger persist was lost) would be re-selected by the
    /// deterministic lease pickers and then fail every `submit_package`
    /// forever. Runs [`reconcile_reserves`](Self::reconcile_reserves) first
    /// (the Reserve-class sweep, keeping the per-class reports meaningful),
    /// then [`reconcile_leases_with_chain`](Self::reconcile_leases_with_chain)
    /// (whose sweep also covers the Reserve class — the overlap is deliberate
    /// defense in depth; both passes are idempotent). Returns both reports.
    pub fn reconcile_with_chain(
        &mut self,
        chain: &dyn crate::chain::AuthoritativeChainView,
    ) -> Result<ChainReconcile> {
        let reserves_swept = self.reconcile_reserves(chain)?;
        let leases = self.reconcile_leases_with_chain(chain)?;
        Ok(ChainReconcile { reserves_swept, leases })
    }

    /// Execute a decided CPFP bump against this wallet's ledger + enclave seam
    /// — a borrow-splitting wrapper over
    /// [`run_cpfp_bump`](crate::wallet::backstop_driver::run_cpfp_bump) (an
    /// outside caller cannot borrow the engine's ledger mutably and its keys
    /// shared at the same time).
    pub fn execute_cpfp_bump(
        &mut self,
        chain: &impl crate::chain::AuthoritativeChainView,
        req: crate::wallet::backstop_driver::CpfpBumpRequest<'_>,
    ) -> Result<crate::wallet::backstop_driver::BumpOutcome> {
        crate::wallet::backstop_driver::run_cpfp_bump(
            &mut self.ledger,
            self.keys.as_ref(),
            chain,
            req,
        )
    }

    /// The AUTHORITATIVE swap_session_id, derived exactly as the settlement
    /// layer derives it (canonical order of `our_pubkey`/`their_pubkey`), so
    /// the engine's store keys and the settlement possession file always agree.
    pub fn swap_session_id(ctx: &SwapContext) -> Result<[u8; 32]> {
        let ours = ctx.our_seckey * secp::G;
        let theirs = secp::Point::from_slice(&ctx.their_pubkey.to_bytes())
            .map_err(|_| Error::Validation("engine: invalid counterparty pubkey"))?;
        crate::settlement::state_machine::swap_session_id(ours, theirs)
    }

    /// Persist the initial `Funding` record for a swap (before any escrow
    /// confirms — the rank-1 G2 rule requires the pre-armed refund present).
    pub fn record_funding(
        &self,
        ctx: &SwapContext,
        role: Role,
        params: crate::settlement::params::Params,
    ) -> Result<()> {
        // Every swap's params MUST equal the signed, version-gated manifest —
        // they arrive as signed values, NOT free-form wallet settings (see the
        // params.rs doctrine). `run_exchange` already pins params immutable
        // ACROSS puts by reusing the frozen funding-time snapshot; this is the
        // missing bookend on the FIRST put, so an off-manifest (unsigned or
        // divergent) params value can never enter a swap's lifecycle — which
        // is what keeps the equal-Δ_fee tier anonymity set enforceable.
        if &params != self.manifest.current().params() {
            return Err(Error::Validation(
                "record_funding: params do not match the signed manifest",
            ));
        }
        self.store.put(&SwapRecord {
            swap_session_id: Self::swap_session_id(ctx)?,
            role,
            phase: SwapPhase::Funding,
            params,
            s_height: 0,
            sweep_escrow_height: 0,
            our_escrow_outpoint: Some(ctx.our_escrow_op),
            their_escrow_outpoint: Some(ctx.their_escrow_op),
            pre_armed_refund: Some(ctx.pre_armed_refund.clone()),
            completion_tx: None,
            // The pre-funding early record (SwapApp::setup_broadcast) is the
            // only writer of setup_tx; the funding handoff CLEARS it here (both
            // escrows have confirmed by Proceed, so the Setup can never need
            // re-broadcast). None-over-Some is the legal clear (check_against).
            setup_tx: None,
            possession_record: None,
        })
    }

    /// PHASE A entry — the settlement-spine primitive shared by
    /// [`SwapDriver::start`](crate::wallet::driver::SwapDriver::start) and
    /// [`SwapApp`](crate::wallet::app::SwapApp): persist the initial `Funding`
    /// record (manifest-params gated) and run the interlocked Phase-A adaptor
    /// exchange over the peer the `Funded` owns.
    ///
    /// On the adaptor-exchange failure path the engine routes to the pre-armed
    /// refund (`AbortRefund` persisted) and this returns
    /// [`SettleEntry::Refunding`]. Any OTHER Phase-A failure (a `record_funding`
    /// params-vs-manifest rejection, or a store fault that left the record at
    /// `Funding`/`Signing`/`Released` without persisting `AbortRefund`) is
    /// returned as `Err` — the caller recovers by re-opening the engine, and a
    /// post-release SL (where refund is NOT a safe sink) is never mislabelled
    /// `Refunding`. The discrimination trusts the PERSISTED phase, never the
    /// bare `Err`, so the forward-or-refund invariant holds by construction.
    ///
    /// `role` must be the `Funded`'s derived role (see `funded.role()`); it is
    /// what `record_funding` persists, while `run_exchange` re-reads it from the
    /// `Funded`.
    pub fn enter_settlement(
        &mut self,
        role: Role,
        funded: Funded,
        ctx: &mut SwapContext,
        chain: &impl AuthoritativeChainView,
    ) -> Result<SettleEntry> {
        // The manifest is the ONLY legitimate params source (record_funding
        // enforces params == the signed manifest), so read it from the engine.
        let params = self.manifest.current().params().clone();
        self.record_funding(ctx, role, params)?;

        match self.run_exchange(funded, ctx, chain) {
            Ok(possessing) => Ok(SettleEntry::Active(Box::new(possessing))),
            Err(e) => {
                // run_exchange routes to abort() (→ AbortRefund) ONLY on the
                // adaptor-exchange failure path; its pre-exchange and
                // post-release store failures return Err WITHOUT persisting
                // AbortRefund. Report Refunding only when the refund exit is
                // actually armed; otherwise surface the error.
                let sid = Self::swap_session_id(ctx)?;
                match self.store.get(&sid)?.map(|r| r.phase) {
                    Some(SwapPhase::AbortRefund) => Ok(SettleEntry::Refunding(
                        "phase-A exchange failed; pre-armed refund is the exit",
                    )),
                    _ => Err(e),
                }
            }
        }
    }

    /// PHASE B step — the re-enterable settlement-step primitive shared by
    /// [`SwapDriver::poll`](crate::wallet::driver::SwapDriver::poll) and
    /// [`SwapApp`](crate::wallet::app::SwapApp). Drives one step from a RETAINED
    /// `Possessing` (which [`settle`](Self::settle) only BORROWS, so a not-ready
    /// step never strands it) and re-reads the persisted phase to discriminate a
    /// genuine terminal refund from a benign re-drive.
    ///
    /// Returns a terminal (`Completed`/`Refunding`) or the non-terminal
    /// `AwaitingReveal`. Idempotent: safe to call repeatedly as the chain
    /// advances (the engine's own `settle` short-circuits an already-terminal
    /// record).
    pub fn step_settlement(
        &mut self,
        possessing: &Possessing,
        ctx: &SwapContext,
        chain: &impl AuthoritativeChainView,
    ) -> Result<DriveStatus> {
        // SL: the reveal must be observable before `settle` can extract the
        // claim. A not-ready step is a clean re-drive — the `Possessing` stays
        // retained by the caller, so the next step can progress.
        if possessing.role() == Role::SecretLearner
            && ClaimScheduler::observe_reveal(chain, ctx.reveal_escrow_op).is_none()
        {
            return Ok(DriveStatus::AwaitingReveal);
        }

        match self.settle(possessing, ctx, chain)? {
            SwapOutcome::Completed { our_final_sig } => {
                Ok(DriveStatus::Completed { our_final_sig })
            }
            SwapOutcome::Aborted(reason) => {
                // Discriminate a genuine terminal refund (SH broadcast-gate-closed
                // persists AbortRefund) from a benign re-drive by re-reading the
                // PERSISTED phase — never the overloaded reason string. A
                // non-AbortRefund phase is re-drivable, covering TWO benign SL
                // cases: (1) our reveal peek and `settle`'s own re-observe are
                // two independent, non-atomic ChainView reads, so a reveal seen
                // by the peek can be evicted / reorged before `settle` re-reads
                // (→ "no reveal observed yet"); (2) a degraded/lying single
                // source surfaced a witness that fails extraction (→ "reveal
                // failed extraction"), where the real reveal may still appear or
                // a second source may agree. Both retain the `Possessing`, so the
                // next step simply tries again. `AbortRefund` is the only
                // terminal exit here.
                let sid = Self::swap_session_id(ctx)?;
                match self.store.get(&sid)?.map(|r| r.phase) {
                    Some(SwapPhase::AbortRefund) => Ok(DriveStatus::Refunding(reason)),
                    _ => Ok(DriveStatus::AwaitingReveal),
                }
            }
        }
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
        chain: &impl AuthoritativeChainView,
    ) -> Result<Possessing> {
        let role = funded.role();
        let sid = Self::swap_session_id(ctx)?;
        let possession_path = ctx
            .possession_store
            .join(format!("{}.possession", hex32(&sid)));

        // Reuse the params snapshot agreed at record_funding time — NOT the
        // live manifest, which a mid-swap update could change and so fail the
        // immutable-params check on this put (adversarial-review MEDIUM).
        let funding_rec = self
            .store
            .get(&sid)?
            .ok_or(Error::Ordering("run_exchange before record_funding"))?;
        let params = funding_rec.params.clone();

        // CSV-BINDING GUARD — BEFORE any ledger/store mutation or partial
        // release. Refuse (and refund) a swept escrow whose refund leaf carries
        // the wrong CSV: the extract-and-race theft the deep audit found
        // UNBLOCKED. A mismatch aborts to the pre-armed refund exactly like an
        // adaptor-exchange failure (Funding → AbortRefund), so nothing is
        // released and the caller re-reads the phase as `Refunding`.
        if let Err(e) = self.verify_swept_escrow_csv(role, ctx, &params, chain) {
            self.abort(ctx);
            return Err(e);
        }

        // Funding is confirmed (this is `Funded`), so the pre-encumbrance coin
        // has been spent whole into our escrow on-chain. Mark it spent NOW so
        // BOTH the completion and the refund terminal leave the ledger correct
        // — reconcile can never resurrect it (adversarial-review HIGH).
        self.ledger.mark_spent(ctx.funding_coin).ok();

        self.store.put(&SwapRecord {
            swap_session_id: sid,
            role,
            phase: SwapPhase::Signing,
            params,
            s_height: funded.s_height(),
            sweep_escrow_height: funded.sweep_escrow_height(),
            our_escrow_outpoint: Some(ctx.our_escrow_op),
            their_escrow_outpoint: Some(ctx.their_escrow_op),
            pre_armed_refund: Some(ctx.pre_armed_refund.clone()),
            completion_tx: None,
            // Funding has confirmed (this is `Funded`); the Setup can never need
            // re-broadcast, so the Signing record carries no setup_tx (already
            // cleared by record_funding at the handoff).
            setup_tx: None,
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
                .get(&sid)?
                .ok_or(Error::Abort("swap record vanished"))?;
            rec.phase = SwapPhase::Released;
            rec.possession_record = Some(possession_path);
            self.store.put(&rec)?;
        }
        Ok(possessing)
    }

    /// The CSV-binding guard (closes the deep audit's one UNBLOCKED theft path).
    ///
    /// The escrow WE SWEEP is the counterparty-funded `ctx.their_escrow_op`. Its
    /// refund leaf must carry the ROLE-CORRECT CSV: as SL we sweep the SH-funded
    /// escrow and it MUST be `delta_late` — the exact runway
    /// [`max_claim_delay`](crate::settlement::params::Params::max_claim_delay)
    /// budgets our post-reveal claim against; as SH we sweep the SL-funded
    /// escrow and it must be `delta_early`. A malicious counterparty that funded
    /// the swept escrow with the WRONG (shorter) CSV would let it refund that
    /// escrow out from under our claim while also taking our escrow — BOTH sides
    /// (the audit's `SH-takes-both` path: the funding gate
    /// `verify_their_escrow_spk` admits BOTH candidate CSVs because roles are
    /// unknown at funding time, and `max_claim_delay` hard-codes `delta_late`).
    ///
    /// The P2TR output key cryptographically commits to the single refund leaf,
    /// so a reconstruction under the role-correct CSV that EQUALS the on-chain
    /// spk PROVES the leaf; any other spk is a hostile escrow → refuse + refund.
    ///
    /// Enforceable only when the chain reports the swept escrow's spk. In
    /// production the funding gate already required a reported, MATCHING spk
    /// before the `into_funded` handoff, so a real swap always reaches here with
    /// `Some`; a raw settlement caller over a view that does not retain the spk
    /// (a synthetic test fixture) opts out and owns escrow identity itself.
    fn verify_swept_escrow_csv(
        &self,
        role: Role,
        ctx: &SwapContext,
        params: &crate::settlement::params::Params,
        chain: &impl AuthoritativeChainView,
    ) -> Result<()> {
        let expected_csv = match role {
            Role::SecretLearner => u32::try_from(params.delta_late())
                .map_err(|_| Error::Deadline("delta_late exceeds the CSV height field"))?,
            Role::SecretHolder => params.delta_early,
        };
        let our_point = ctx.our_seckey * secp::G;
        let their_point = secp::Point::from_slice(&ctx.their_pubkey.to_bytes())
            .map_err(|_| Error::Validation("csv-binding: invalid counterparty pubkey"))?;
        let internal =
            crate::settlement::state_machine::canonical_internal_key(our_point, their_point)?;
        let expected_spk = crate::tx::escrow::Escrow::new(&internal, &their_point, expected_csv)?
            .funding_script_pubkey()
            .clone();
        match chain.funding_spk(ctx.their_escrow_op) {
            Some(spk) if spk == expected_spk => Ok(()),
            Some(_) => Err(Error::Abort(
                "swept escrow carries the wrong refund CSV (extract-and-race guard); refund",
            )),
            // Unreported: the funding gate is the authority (see the method docs).
            None => Ok(()),
        }
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
        possessing: &Possessing,
        ctx: &SwapContext,
        chain: &impl AuthoritativeChainView,
    ) -> Result<SwapOutcome> {
        let sid = Self::swap_session_id(ctx)?;

        // Idempotency (adversarial-review): a re-driven settle on an already-
        // advanced swap must NOT re-run the exchange/broadcast or mis-transition
        // a terminal record. Short-circuit from the persisted completion tx.
        let rec0 = self.store.get(&sid)?.ok_or(Error::Abort("record vanished"))?;
        match rec0.phase {
            SwapPhase::Completed => {
                let sig = completion_sig_from(&rec0)?;
                return Ok(SwapOutcome::Completed { our_final_sig: sig });
            }
            SwapPhase::Completing => {
                // Already broadcast/scheduled: just finalize.
                let sig = completion_sig_from(&rec0)?;
                return self.finalize_completed(sid, sig);
            }
            _ => {}
        }

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
                    match scheduler.schedule_claim(possessing, &reveal, chain.tip_height()) {
                        Ok(s) => s,
                        // A degraded/lying single source surfaced a witness that
                        // fails extraction (malformed BIP340 sig, or a valid sig
                        // whose extracted t does not open T). This is NOT a
                        // terminal: the REAL reveal may still appear, or a second
                        // source may agree. Re-drive as `AwaitingReveal` (the
                        // Possessing is retained, so the next step retries),
                        // exactly like an evicted reveal — never a hard poll
                        // error the caller must special-case, and never a false
                        // refund (only a persisted AbortRefund is Refunding).
                        Err(_) => {
                            return Ok(SwapOutcome::Aborted(
                                "observed reveal failed extraction; awaiting a valid reveal",
                            ));
                        }
                    };
                let mut rec = self.store.get(&sid)?.ok_or(Error::Abort("record vanished"))?;
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
                let mut rec = self.store.get(&sid)?.ok_or(Error::Abort("record vanished"))?;
                rec.phase = SwapPhase::Completing;
                rec.completion_tx = Some(sig.0.to_vec());
                self.store.put(&rec)?;
                sig.0
            }
        };
        // (The funding coin was already marked spent in run_exchange, once
        // funding confirmed — so both this path and the refund path leave the
        // ledger correct.)
        self.finalize_completed(sid, final_sig)
    }

    fn finalize_completed(&self, sid: [u8; 32], sig: [u8; 64]) -> Result<SwapOutcome> {
        let mut rec = self.store.get(&sid)?.ok_or(Error::Abort("record vanished"))?;
        if rec.phase != SwapPhase::Completed {
            rec.phase = SwapPhase::Completed;
            self.store.put(&rec)?;
        }
        Ok(SwapOutcome::Completed { our_final_sig: sig })
    }

    /// Record the refund terminal: the swap unwound to its pre-armed refund.
    /// Persists `Refunded` (the funding coin was already marked spent in
    /// `run_exchange`, so the ledger is correct on this path too). Idempotent.
    pub fn record_refunded(&self, ctx: &SwapContext) -> Result<()> {
        let sid = Self::swap_session_id(ctx)?;
        if let Some(mut rec) = self.store.get(&sid)? {
            if rec.phase == SwapPhase::AbortRefund {
                rec.phase = SwapPhase::Refunded;
                self.store.put(&rec)?;
            }
        }
        Ok(())
    }

    /// Route to the abort path: persist AbortRefund (unless a completion has
    /// already superseded), leaving the pre-armed refund as the exit.
    /// Best-effort + idempotent — the refund driver / watchtower owns it from
    /// here, so this never fails the caller.
    pub(crate) fn abort(&self, ctx: &SwapContext) {
        let Ok(sid) = Self::swap_session_id(ctx) else { return };
        if let Ok(Some(mut rec)) = self.store.get(&sid) {
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

/// The 64-byte completion signature persisted in a record's `completion_tx`
/// (the engine stores the raw sig there before broadcast).
fn completion_sig_from(rec: &SwapRecord) -> Result<[u8; 64]> {
    let bytes = rec
        .completion_tx
        .as_ref()
        .ok_or(Error::Abort("completed record missing its completion signature"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Abort("completion signature is not 64 bytes"))
}

fn hex32(id: &[u8; 32]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The set of swap_session_ids of every NON-terminal record — the lessees whose
/// leases are still legitimately held. Shared by `open`'s chain-blind reconcile
/// and the post-open chain-aware `reconcile_leases_with_chain`.
fn live_lessees(store: &SwapStore) -> Result<Vec<[u8; 32]>> {
    Ok(store
        .list()?
        .0
        .iter()
        .filter(|r| !matches!(r.phase, SwapPhase::Completed | SwapPhase::Refunded))
        .map(|r| r.swap_session_id)
        .collect())
}
