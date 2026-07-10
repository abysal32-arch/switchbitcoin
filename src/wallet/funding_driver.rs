//! Pre-funding driver — increment 3 of the orchestration layer.
//!
//! [`FundingDriver`] composes the (previously test-only) [`FundingCoordinator`]
//! poll loop into a re-enterable driver that owns the loop's mutable state and
//! ends by minting the [`Funded`] handoff that
//! [`SwapDriver::start`](crate::wallet::driver::SwapDriver::start) consumes:
//! `funding_order` → `next_funding_action` polls → `await_funded` role
//! derivation. This gives `FundingCoordinator::from_manifest` its production
//! caller.
//!
//! # Engine boundary (consistent with increments 1/2)
//! The driver DECIDES; the caller broadcasts. [`FundingTick::BroadcastOurSetup`]
//! asks the caller to put its (already-signed) Setup on the wire and then call
//! [`FundingDriver::setup_broadcast`]. Crash-safety note: the flag is in-memory
//! by design — the Setup is a fully-signed, deterministic tx, so a restarted
//! caller re-broadcasting the same bytes is idempotent at the chain layer (same
//! txid), and `SwapPhase::Funding` docs already class this stretch as
//! "crash-safe: funding is chain-observable, no volatile signing state".
//!
//! # What the driver deliberately does NOT decide
//! - `block_x` (the funding no-show deadline) is a WALLET-POLICY input with no
//!   spec-side derivation in the crate today; the caller supplies the absolute
//!   height.
//! - Funding order is the canonical session-pubkey sort. The orchestrator's
//!   OPEN QUESTION (SL-specifically-first vs canonical order — a spec-resolution
//!   item) stays open; this driver must not resolve it.
//! - The persistent-liar stall (authoritatively funded, never verified — the
//!   coordinator Waits forever and Block-X cannot fire) is SURFACED as
//!   [`FundingTick::AwaitingVerification`] so the caller can escalate to the
//!   `AbortDriver` refund path once its pre-armed refund matures; the
//!   escalation itself is refund-driver wiring, outside this increment
//!   (wired: `SwapApp::poll` terminates a stall at refund maturity).
//!
//! # Jitter
//! Per-party co-funding jitter is in BLOCKS, manifest-signed and bounded
//! (`2·jitter_max ≤ cofunding_window` — sized for two SEQUENTIAL delays).
//! The caller samples once per swap in `[0, jitter_max]`; the driver clamps
//! to the manifest bound. Anchoring is ORDER-AWARE: the First funder's delay
//! counts from its first tick (decorrelating Setup #1 from the off-chain
//! match), the Second funder's from the tick the counterparty escrow first
//! reads VERIFIED at the tier amount (decorrelating Setup #2 from escrow
//! #1's confirmation — the linkage the jitter exists to break; a first-tick
//! anchor would elapse concurrently with waiting for escrow #1 and put
//! Setup #2 on the wire a deterministic beat after verification). Jitter is
//! privacy, not safety — a crash that resamples and re-anchors is harmless.

use bitcoin::{OutPoint, ScriptBuf};

use crate::chain::{ChainView, FundingReading};
use crate::crypto::ValidatedPoint;
use crate::settlement::params::Params;
use crate::settlement::state_machine::{canonical_internal_key, Funded, Funding, PeerSession};
use crate::tx::escrow::Escrow;
use crate::wallet::manifest::SignedManifest;
use crate::wallet::orchestrator::{FundingAction, FundingCoordinator, FundingOrder};
use crate::{Error, Result};

/// The sticky-abort reason for a substituted counterparty escrow.
const SPK_MISMATCH_ABORT: &str =
    "counterparty escrow scriptPubKey is not the agreed 2-of-2 escrow; abort";

/// The anti-substitution check outcome for the counterparty escrow.
enum SpkCheck {
    /// On-chain spk matches an expected 2-of-2+CSV candidate — genuine escrow.
    Ok,
    /// On-chain spk is present and matches NEITHER candidate — a hostile
    /// substitution (a same-amount output the counterparty solely controls).
    Mismatch,
    /// The spk cannot be read/agreed yet (source disagreement or a view that
    /// does not report it) — unverifiable, so wait rather than proceed.
    Unverifiable,
}

/// The outcome of one [`FundingDriver::tick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingTick {
    /// Not ready — jitter still elapsing, counterparty not yet funded, or (as
    /// the Second funder) their encumbrance not yet verified. Re-poll.
    Wait,
    /// Both escrows are AUTHORITATIVELY confirmed (so Block-X can no longer
    /// fire) yet the verified (agreement) view still lags — a source is
    /// disagreeing. The coordinator deliberately Waits (an explorer lie must
    /// degrade to delay, never theft), so without escalation this waits
    /// forever. The classification excludes this driver's own pre-broadcast
    /// jitter wait (a restarted driver re-anchors its jitter with both
    /// escrows long confirmed — that is a healthy, self-resolving `Wait`,
    /// never this signal), so a PERSISTING AwaitingVerification is real:
    /// once your pre-armed refund matures, route to the `AbortDriver` refund
    /// path. Escalate on persistence across re-polls, not on one tick — an
    /// agreement lag can still resolve itself a block later.
    AwaitingVerification,
    /// Broadcast YOUR signed Setup tx now, then call
    /// [`FundingDriver::setup_broadcast`] and re-poll.
    BroadcastOurSetup,
    /// Both escrows confirmed, inside the co-funding window, encumbrance
    /// verified at the exact tier amount. Call [`FundingDriver::into_funded`].
    Proceed { our_height: u32, their_height: u32, s_height: u32 },
    /// Terminal for this swap: abandon to refunds. If your Setup never went on
    /// the wire nothing is locked; otherwise the pre-armed refund of your own
    /// escrow (armable with your key alone) is the exit via the `AbortDriver`.
    Abort(&'static str),
}

/// A single-swap pre-funding driver. Re-enterable: `tick` re-reads chain state
/// every call; the only loop state it owns is the jitter anchor, the
/// caller-confirmed broadcast flag, and a sticky terminal `Abort`.
pub struct FundingDriver {
    coordinator: FundingCoordinator,
    order: FundingOrder,
    our_escrow: OutPoint,
    their_escrow: OutPoint,
    our_pk: ValidatedPoint,
    their_pk: ValidatedPoint,
    block_x: u32,
    jitter_blocks: u32,
    /// Tip height the jitter delay counts from. Order-aware (see module
    /// docs): the first tick (First) or the counterparty-escrow verification
    /// event (Second); re-clamped whenever the tip regresses so the delay
    /// never exceeds `jitter_blocks` from the CURRENT tip.
    jitter_anchor: Option<u32>,
    our_setup_broadcast: bool,
    aborted: Option<&'static str>,
    /// The scriptPubKey(s) the counterparty escrow output is allowed to carry —
    /// the genuine 2-of-2(our_pk,their_pk) + funder-refund(their_pk) P2TR under
    /// each admissible CSV. The encumbrance gate checks the on-chain
    /// counterparty output against these so a same-amount output the
    /// counterparty solely controls cannot be substituted for the real escrow.
    /// Both candidates share the aggregate internal key, so a solo-key output
    /// matches neither regardless of which CSV the (post-funding) role fixes.
    their_escrow_spks: Vec<ScriptBuf>,
}

impl FundingDriver {
    /// Begin the pre-funding half for one swap.
    ///
    /// `manifest` is the verified signed manifest (the coordinator snapshots
    /// its params — the same signed source `record_funding` later enforces).
    /// `our_escrow`/`their_escrow` are the two Setup escrow outpoints, knowable
    /// pre-broadcast (`build_setup` fixes `setup_txid:0` at signing time; the
    /// counterparty's arrives out-of-band with its session pubkey). `block_x`
    /// is the caller's absolute no-show deadline height. `jitter_blocks` is the
    /// caller-sampled per-party delay, clamped here to the manifest bound.
    pub fn begin(
        manifest: &SignedManifest,
        our_pk: &ValidatedPoint,
        their_pk: &ValidatedPoint,
        our_escrow: OutPoint,
        their_escrow: OutPoint,
        block_x: u32,
        jitter_blocks: u32,
    ) -> Result<Self> {
        let coordinator = FundingCoordinator::from_manifest(manifest);
        // Canonical session-pubkey sort — the only coordinator-free order both
        // wallets derive identically pre-role (equal pubkeys are rejected).
        let order = FundingCoordinator::funding_order(our_pk, their_pk)?;
        let jitter_blocks = jitter_blocks.min(coordinator.jitter_max());
        let their_escrow_spks = Self::expected_their_escrow_spks(manifest.params(), our_pk, their_pk)?;
        Ok(Self {
            coordinator,
            order,
            our_escrow,
            their_escrow,
            our_pk: our_pk.clone(),
            their_pk: their_pk.clone(),
            block_x,
            jitter_blocks,
            jitter_anchor: None,
            our_setup_broadcast: false,
            aborted: None,
            their_escrow_spks,
        })
    }

    /// The admissible scriptPubKeys of the counterparty escrow: the genuine
    /// 2-of-2 P2TR under each candidate CSV. The internal key is the canonical
    /// aggregate of both session pubkeys (role-independent); the refund leaf is
    /// the counterparty's own key. The CSV is the only role-dependent input and
    /// the funding-time role is unknown (it derives from txids+S AFTER both
    /// escrows confirm — the SL-first open question), so both `delta_early` and
    /// `delta_late` are admitted. Both still bind the aggregate internal key, so
    /// admitting both never lets a solo-controlled output through.
    fn expected_their_escrow_spks(
        params: &Params,
        our_pk: &ValidatedPoint,
        their_pk: &ValidatedPoint,
    ) -> Result<Vec<ScriptBuf>> {
        let internal = canonical_internal_key(our_pk.point(), their_pk.point())?;
        let their_point = their_pk.point();
        let delta_late = u32::try_from(params.delta_late())
            .map_err(|_| Error::Deadline("delta_late exceeds the CSV height field"))?;
        let mut spks = Vec::with_capacity(2);
        for csv in [params.delta_early, delta_late] {
            let spk = Escrow::new(&internal, &their_point, csv)?
                .funding_script_pubkey()
                .clone();
            if !spks.contains(&spk) {
                spks.push(spk);
            }
        }
        Ok(spks)
    }

    /// Anti-substitution read of the counterparty escrow's on-chain spk.
    fn verify_their_escrow_spk(&self, chain: &impl ChainView) -> SpkCheck {
        match chain.funding_spk(self.their_escrow) {
            Some(spk) if self.their_escrow_spks.contains(&spk) => SpkCheck::Ok,
            Some(_) => SpkCheck::Mismatch,
            None => SpkCheck::Unverifiable,
        }
    }

    /// The counterparty-agreed funding order for this swap (who funds first).
    pub fn order(&self) -> FundingOrder {
        self.order
    }

    /// The caller performed the [`FundingTick::BroadcastOurSetup`] broadcast.
    pub fn setup_broadcast(&mut self) {
        self.our_setup_broadcast = true;
    }

    /// One pre-funding poll. Idempotent per chain state; safe to re-drive.
    /// `chain` must be the dual-source (or single self-verifying) view — the
    /// same one later handed to [`FundingDriver::into_funded`].
    pub fn tick(&mut self, chain: &impl ChainView) -> Result<FundingTick> {
        if let Some(reason) = self.aborted {
            return Ok(FundingTick::Abort(reason));
        }
        let tip = chain.tip_height();
        // Classification inputs are read BEFORE the coordinator poll: a
        // confirmation landing between two reads of a live chain must never
        // let a Wait decided on the older snapshot be judged against the
        // newer one (a fabricated one-tick AwaitingVerification).
        let both_auth = chain.authoritative_funding_height(self.our_escrow).is_some()
            && chain.authoritative_funding_height(self.their_escrow).is_some();
        // The Second funder's anchor readiness: counterparty escrow VERIFIED
        // at exactly the tier amount, read the same way the coordinator's
        // encumbrance gate reads it (one read, reused for classification).
        let their_verified_ok = match self.order {
            FundingOrder::First => false, // unused for First
            FundingOrder::Second => {
                let expected = self.coordinator.expected_escrow_amount()?;
                matches!(
                    chain.verified_funding_reading(self.their_escrow),
                    FundingReading::Confirmed { amount: Some(a), .. } if a == expected
                )
            }
        };

        // Jitter: sampled by the caller, bounded by the manifest (2·max ≤
        // window, so two honest SEQUENTIAL delays always fit). Anchoring is
        // order-aware — see the module docs — and the anchor re-clamps to a
        // regressing tip (reorg, or a briefly-ahead authoritative source) so
        // a regression extends the wait by at most nothing: the delay is
        // always ≤ `jitter_blocks` from the CURRENT tip, never tip-recovery
        // plus jitter.
        let anchor_now = match self.order {
            FundingOrder::First => true,
            FundingOrder::Second => self.our_setup_broadcast || their_verified_ok,
        };
        if anchor_now && self.jitter_anchor.is_none() {
            self.jitter_anchor = Some(tip);
        }
        if let Some(anchor) = self.jitter_anchor.as_mut() {
            *anchor = (*anchor).min(tip);
        }
        let jitter_ready = self
            .jitter_anchor
            .is_some_and(|anchor| tip >= anchor.saturating_add(self.jitter_blocks));

        let action = self.coordinator.next_funding_action(
            chain,
            self.order,
            self.our_escrow,
            self.their_escrow,
            self.our_setup_broadcast,
            jitter_ready,
            self.block_x,
        )?;
        Ok(match action {
            FundingAction::Wait => {
                // Distinguish the persistent-liar stall from healthy waits.
                // Both escrows authoritatively confirmed means Block-X can
                // never fire — but that alone is NOT a stall: a restarted
                // driver (broadcast flag lost, jitter re-anchored) Waits on
                // its own jitter with both escrows long confirmed. The stall
                // additionally requires that the pre-broadcast jitter gate
                // cannot be the cause: we have broadcast, or our jitter has
                // elapsed, or (as the Second funder) the anchor itself is
                // blocked by an unverifiable counterparty reading — which IS
                // a source disagreeing. What remains is the agreement view
                // lagging or an unverifiable encumbrance read.
                if both_auth
                    && (self.our_setup_broadcast
                        || jitter_ready
                        || (self.order == FundingOrder::Second && !their_verified_ok))
                {
                    FundingTick::AwaitingVerification
                } else {
                    FundingTick::Wait
                }
            }
            FundingAction::BroadcastOurSetup => {
                // The Second funder is about to fund AGAINST the counterparty
                // escrow, so bind that escrow's identity first: a same-amount
                // output the counterparty solely controls must not draw our
                // Setup onto the wire. The First funder funds unconditionally
                // (no counterparty escrow exists yet) and is instead protected
                // at the Proceed gate below, before it ever signs the exchange.
                match self.order {
                    FundingOrder::First => FundingTick::BroadcastOurSetup,
                    FundingOrder::Second => match self.verify_their_escrow_spk(chain) {
                        SpkCheck::Ok => FundingTick::BroadcastOurSetup,
                        SpkCheck::Mismatch => {
                            self.aborted = Some(SPK_MISMATCH_ABORT);
                            FundingTick::Abort(SPK_MISMATCH_ABORT)
                        }
                        SpkCheck::Unverifiable => FundingTick::Wait,
                    },
                }
            }
            FundingAction::Proceed { our_height, their_height, s_height } => {
                // Final identity gate before the exchange: the counterparty
                // escrow we are about to sweep must carry the agreed 2-of-2 spk.
                // A substituted output is a terminal Abort (refund our escrow);
                // an unverifiable read is a re-drive (never proceed unverified).
                match self.verify_their_escrow_spk(chain) {
                    SpkCheck::Ok => FundingTick::Proceed { our_height, their_height, s_height },
                    SpkCheck::Mismatch => {
                        self.aborted = Some(SPK_MISMATCH_ABORT);
                        FundingTick::Abort(SPK_MISMATCH_ABORT)
                    }
                    SpkCheck::Unverifiable => FundingTick::Wait,
                }
            }
            FundingAction::Abort(reason) => {
                self.aborted = Some(reason);
                FundingTick::Abort(reason)
            }
        })
    }

    /// Cross into the funded half: mint the [`Funded`] that
    /// [`SwapDriver::start`](crate::wallet::driver::SwapDriver::start)
    /// consumes. Call after a [`FundingTick::Proceed`].
    ///
    /// The go-signal is re-enforced HERE, by construction rather than by
    /// caller discipline: the handoff re-polls the coordinator against the
    /// same chain view and consumes the session only on a `Proceed` — the
    /// sticky abort, a missing broadcast confirmation, the Block-X deadline,
    /// the co-funding window, and the tier-amount encumbrance gate all
    /// refuse the handoff exactly as `tick` would, handing the driver and
    /// the peer session back untouched ([`HandoffError::Refused`]). A reorg
    /// between a `Proceed` tick and this call is therefore a plain re-drive
    /// of the RETURNED driver — nothing is torn down. Settlement's
    /// `await_funded` then independently re-derives both heights, re-enforces
    /// the window, and derives the role from the two funding txids + S; a
    /// failure past that point ([`HandoffError::Fatal`]) does consume the
    /// peer session, but with the pre-checks above every remaining cause is
    /// a construction bug, not a chain transient.
    ///
    /// `params` must be the manifest params (`engine.manifest().current()
    /// .params().clone()`) — `record_funding` enforces the equality later.
    /// `peer` rides inside the `Funded` into the exchange; the pre-funding
    /// loop itself never touches the transport.
    pub fn into_funded(
        self,
        params: Params,
        peer: PeerSession,
        chain: &impl ChainView,
    ) -> std::result::Result<Funded, HandoffError> {
        if let Some(reason) = self.aborted {
            return Err(HandoffError::Refused {
                driver: Box::new(self),
                peer,
                error: Error::Abort(reason),
            });
        }
        // `jitter_ready = true` cannot force a false go-signal: jitter only
        // gates pre-broadcast paths, none of which yield Proceed.
        let action = match self.coordinator.next_funding_action(
            chain,
            self.order,
            self.our_escrow,
            self.their_escrow,
            self.our_setup_broadcast,
            true,
            self.block_x,
        ) {
            Ok(action) => action,
            Err(error) => {
                return Err(HandoffError::Refused { driver: Box::new(self), peer, error })
            }
        };
        match action {
            FundingAction::Proceed { .. } => {
                // Un-bypassable identity gate: even on a coordinator go-signal,
                // never mint a Funded against a substituted counterparty escrow.
                match self.verify_their_escrow_spk(chain) {
                    SpkCheck::Ok => {}
                    SpkCheck::Mismatch => {
                        let mut driver = self;
                        driver.aborted = Some(SPK_MISMATCH_ABORT);
                        return Err(HandoffError::Refused {
                            driver: Box::new(driver),
                            peer,
                            error: Error::Abort(SPK_MISMATCH_ABORT),
                        });
                    }
                    SpkCheck::Unverifiable => {
                        return Err(HandoffError::Refused {
                            driver: Box::new(self),
                            peer,
                            error: Error::Deadline(
                                "counterparty escrow identity unverifiable; re-drive tick()",
                            ),
                        })
                    }
                }
            }
            FundingAction::Abort(reason) => {
                // Keep the terminal sticky on the returned driver, exactly
                // as the equivalent tick would have.
                let mut driver = self;
                driver.aborted = Some(reason);
                return Err(HandoffError::Refused {
                    driver: Box::new(driver),
                    peer,
                    error: Error::Abort(reason),
                });
            }
            FundingAction::Wait | FundingAction::BroadcastOurSetup => {
                return Err(HandoffError::Refused {
                    driver: Box::new(self),
                    peer,
                    error: Error::Ordering(
                        "funding handoff without a coordinator go-signal; re-drive tick()",
                    ),
                });
            }
        }
        Funding::new(params, peer)
            .await_funded(chain, self.our_escrow, self.their_escrow, &self.our_pk, &self.their_pk)
            .map_err(HandoffError::Fatal)
    }
}

/// Why [`FundingDriver::into_funded`] did not mint a [`Funded`].
///
/// `Refused` is the NON-CONSUMING arm: the driver and the peer session come
/// back untouched, so a transient (e.g. the counterparty escrow reorged out
/// between a `Proceed` tick and the handoff) really is a plain re-drive —
/// keep ticking the returned driver and hand off again on the next
/// `Proceed`. Terminal refusals (the sticky abort, Block-X, the encumbrance
/// gate) surface here too, with the reason in `error`; route those to the
/// `AbortDriver` refund path instead of re-driving.
///
/// `Fatal` failures happen past the point of no return (inside settlement's
/// `await_funded`, after the peer session is consumed). With the `Refused`
/// pre-checks enforced first, every remaining cause is a construction bug
/// (params failing validation, both escrows sharing a funding txid), not a
/// state a correctly-built swap reaches.
pub enum HandoffError {
    /// Nothing was consumed; re-drive `driver`, or escalate `error` if it is
    /// a terminal abort.
    Refused { driver: Box<FundingDriver>, peer: PeerSession, error: Error },
    /// Consumed by settlement-core validation; the session is gone.
    Fatal(Error),
}

impl core::fmt::Debug for HandoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Manual: the returned driver/peer are not Debug (live transport).
        match self {
            HandoffError::Refused { error, .. } => write!(f, "Refused({error:?})"),
            HandoffError::Fatal(error) => write!(f, "Fatal({error:?})"),
        }
    }
}
