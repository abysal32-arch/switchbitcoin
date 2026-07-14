//! Standalone watchtower mode (Task 19) — the second-device dead-device
//! refund guard, runnable OUTSIDE the live `swap`/`serve` loop.
//!
//! # Why this exists
//! The G2 crash-safety guarantee — a funded escrow ALWAYS gets its pre-armed
//! refund fired at CSV maturity even if the primary device dies — structurally
//! assumes a WATCHTOWER that outlives the primary. The pieces have existed
//! since rank 6 ([`WatchtowerDriver`] fires the refund from the escrow + chain
//! alone; the refund and its G2 [`WatchtowerReceipt`] ride in the store record
//! and the `.artifacts` sidecar), but the guard only ran inside the live
//! `swap`/`serve` process. This module is the standalone RUN mode: arm one
//! guard per persisted swap and poll them on a cadence until every guarded
//! escrow's exit CONFIRMS — with no live [`SwapContext`], no transport, and no
//! session key anywhere.
//!
//! # What a watchtower may do — and provably may not (theft/grief argument)
//! Every transaction this mode can ever put on the wire is one of exactly two
//! shapes, both harmless to everyone but the mempool:
//!
//! 1. **The owner's own pre-armed refund** — single-signed at negotiate time,
//!    spends only the owner's OWN escrow through its CSV leaf (the chain
//!    enforces maturity), and pays the owner's own `SwapDestination` key. It
//!    cannot be altered here (the bytes are write-once in the record) and it
//!    cannot take anyone else's funds.
//! 2. **A CPFP child of that refund** — spends the refund's own P2A anchor
//!    plus the owner's own reserve coin (signed via the wallet's key seam).
//!    A refund bump is SILENT by spec (a refund already revealed its leaf, so
//!    no privacy is left to protect); no `LinkageAck` is ever consulted and
//!    `linkage_ack = None` is passed structurally.
//!
//! The watchtower holds NO session key (session keys are ephemeral and never
//! persisted — both exits are fully signed at negotiate time), never signs or
//! broadcasts a completion (that stays the owning wallet's business, including
//! the SL claim), never negotiates (no hello, no manifest exchange), and
//! stands down on any CONFIRMED spend of the escrow (completion-supersedes:
//! [`WatchtowerDriver::tick`] fires only on an UNSPENT escrow, treats an
//! in-mempool completion as transient, and the chain's single-spend rule
//! settles any race). Two devices firing the same refund is idempotent — the
//! same signed bytes have the same txid, so a second submission deduplicates
//! (in-mempool) or is refused as already-known (confirmed); it can never
//! double-spend, on Core and on `SimChain` alike.
//!
//! # The delegation packet (task-19 decision)
//! The artifact set handed to the second device is **the Task-17 `backup`
//! bundle, restored with `restore --from` into a fresh data dir** — not a
//! purpose-built minimal packet. Rationale:
//!
//! * Everything the tower needs already rides in the bundle byte-faithfully:
//!   the record (pre-armed refund — the G2 crash half — plus both escrow
//!   outpoints and the pinned params), the `.artifacts` sidecar (destination
//!   spk/index, so the reclaimed coin is registered), the ledger (the reserve
//!   the silent CPFP leases), and the keystore (which signs ONLY the bump
//!   child's reserve input — see the theft argument above).
//! * A minimal packet (refund bytes + fingerprint + escrow outpoint) could
//!   fire an UNBUMPED refund but could not CPFP it under congestion (no
//!   reserve, no key seam) and could not register the reclaimed output — it
//!   silently downgrades the exact guarantee this mode exists to strengthen.
//!   Rejected for pre-alpha; a true third-party tower packet is out of scope
//!   by the frozen-surface rule (no 3rd-party watchtower in the core).
//! * The stale-bundle manifest caveat (`wallet::backup` docs): restoring an
//!   old bundle rewinds `manifest.current`/`manifest.floor`. On a watch-only
//!   device this is INERT — `watch` never runs the hello handshake and never
//!   negotiates params, so no old-params swap can be opened through it. Use a
//!   fresh bundle anyway, and never run `swap`/`serve` from a stale restore
//!   without re-ingesting the newest signed manifest first.
//! * Isolation is structural: the restored dir is its own store (the
//!   single-instance locks are per-dir), so a primary and a watchtower can
//!   never contend for the same files — they interact only through the chain,
//!   where the refund's idempotence and completion-supersedes hold.
//!
//! # Reserve provisioning (the no-reserve case)
//! The silent refund CPFP needs a leasable reserve ON THIS DEVICE (the bundle
//! carries the primary's reserve coin — both devices then race to lease their
//! own copy of it, which is safe: the child spends the same UTXO, so at most
//! one wins). With no leasable reserve the stall is surfaced LOUDLY
//! ([`WatchtowerTick::RefundStalledBelowFeeFloor`] → an ALARM log line) and
//! the refund simply fires unbumped once congestion clears — the CSV never
//! expires, so nothing is lost, only confirmation waits on the mempool.
//!
//! # What this module deliberately does NOT do
//! * Drive recovery ticks (`Extract`/`Rebroadcast` broadcast completions).
//! * Advance any record except along the refund path (a confirmed OWN refund
//!   advances `… → AbortRefund → Refunded`, the same route the live app
//!   takes); a completion win is logged and left for the owner's `recover`.
//! * Offer a dry run: a tick's purpose is to FIRE the dead-device refund.
//!
//! `Completed`-phase records are guarded too (deliberate): our leg settled,
//! but OUR escrow may still be unspent — the counterparty's claim is
//! outstanding, and if they never claim, the pre-armed refund reclaims our
//! escrow at its CSV maturity exactly as the live loop's tower side (which
//! runs regardless of phase) would. Only `Refunded` records are skipped: their
//! escrow exit is already chain-proven.

use std::path::Path;

use bitcoin::{OutPoint, Txid};

use crate::chain::{AuthoritativeChainView, SpendStatus};
use crate::settlement::refund::confirm_watchtower_handoff;
use crate::tx::backstop::{required_child_fee, ANCHOR_VOUT, MAX_BUMP_FEE_SATS};
use crate::wallet::backstop_driver::CpfpBumpRequest;
use crate::wallet::engine::SwapEngine;
use crate::wallet::ledger::BumpTarget;
use crate::wallet::runner::{hex32, register_settlement_output, resolve_target_feerate};
use crate::wallet::store::SwapPhase;
use crate::wallet::watchtower_driver::{
    refund_congestion_auto, refund_parent_meta, WatchtowerDriver, WatchtowerTick,
};
use crate::Result;

#[cfg(doc)]
use crate::settlement::refund::WatchtowerReceipt;
#[cfg(doc)]
use crate::wallet::engine::SwapContext;

/// Caller knobs for the watch loop. There is deliberately no `dry_run`: a
/// watch tick's purpose is to fire the dead-device refund.
pub struct WatchOptions {
    /// CPFP target feerate override (sat/vB); `None` = live estimate → the
    /// runner's fallback floor. Resolved FRESH on every stall.
    pub target_feerate_sat_vb: Option<u64>,
    /// Manual congestion signal for an ALREADY-RELAYED refund below the fee
    /// floor — the fallback for views with no live estimate (the CLI's
    /// `--assume-congested`); auto-detection runs regardless.
    pub refund_congested: bool,
    /// Gate on reserve-leasing bumps (the Task-E caller contract: lease/bump
    /// actions require a successful startup chain reconcile). `false` NEVER
    /// gates the refund FIRE — that is a pure chain action.
    pub allow_bump: bool,
}

/// One guarded swap: the armed tower plus the record-derived facts the
/// stall/stand-down handling needs. Built by [`arm_guards`] from the
/// persisted record ALONE — no live context, no session key.
pub struct WatchGuard {
    sid: [u8; 32],
    escrow: OutPoint,
    phase_at_arm: SwapPhase,
    driver: WatchtowerDriver,
    refund_bytes: Vec<u8>,
    /// Decoded refund txid (`None` if the bytes do not decode — the guard
    /// still arms; the fire path then errors cleanly instead of bumping).
    refund_txid: Option<Txid>,
    /// The record's pinned `escrow_amount` — fixes the refund's absolute fee.
    escrow_amount: u64,
    anchor_sats: u64,
}

impl WatchGuard {
    pub fn sid(&self) -> &[u8; 32] {
        &self.sid
    }
    pub fn escrow(&self) -> OutPoint {
        self.escrow
    }
    pub fn phase_at_arm(&self) -> SwapPhase {
        self.phase_at_arm
    }
}

/// What [`arm_guards`] found in the store.
pub struct WatchSet {
    /// One armed guard per guardable record.
    pub guards: Vec<WatchGuard>,
    /// Records that CANNOT be guarded (with why) — operator ALARMS, never
    /// silently skipped. In practice only a pre-funding record with no escrow
    /// outpoint lands here (the store's G2 rule forbids a funded escrow
    /// without its refund), which has nothing locked and nothing to guard.
    pub unguardable: Vec<([u8; 32], String)>,
    /// Unreadable record files from the store scan — operator ALARMS.
    pub unreadable: Vec<std::path::PathBuf>,
}

/// Arm one [`WatchGuard`] per guardable persisted swap: every record except
/// `Refunded` (its escrow exit is already chain-proven) whose escrow outpoint
/// and pre-armed refund are present. Arming performs this device's own G2
/// handoff acknowledgement (echo the refund fingerprint —
/// [`confirm_watchtower_handoff`]), the same receipt the negotiate path
/// demands. A per-record arm failure lands in `unguardable`, never aborts the
/// scan (the other swaps' deadlines must still be guarded).
pub fn arm_guards(engine: &SwapEngine) -> Result<WatchSet> {
    let (records, unreadable) = engine.store().list()?;
    let mut guards = Vec::new();
    let mut unguardable = Vec::new();
    for rec in records {
        if rec.phase == SwapPhase::Refunded {
            continue;
        }
        let sid = rec.swap_session_id;
        let Some(escrow) = rec.our_escrow_outpoint else {
            unguardable.push((sid, "record has no escrow outpoint to guard".into()));
            continue;
        };
        let Some(refund) = rec.pre_armed_refund else {
            // Unreachable through a legal put (G2: funded escrow ⇒ refund),
            // but a guard scan must fail loudly, not trust that.
            unguardable.push((sid, "record has a funded escrow but no pre-armed refund".into()));
            continue;
        };
        let refund_bytes = refund.tx_bytes().to_vec();
        let refund_txid =
            bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(&refund_bytes)
                .ok()
                .map(|t| t.compute_txid());
        let armed = confirm_watchtower_handoff(&refund, refund.fingerprint())
            .and_then(|receipt| WatchtowerDriver::arm(refund, escrow, &receipt));
        match armed {
            Ok(driver) => guards.push(WatchGuard {
                sid,
                escrow,
                phase_at_arm: rec.phase,
                driver,
                refund_bytes,
                refund_txid,
                escrow_amount: rec.params.escrow_amount_sats(),
                anchor_sats: rec.params.anchor_sats,
            }),
            Err(e) => unguardable.push((sid, format!("watchtower arm failed: {e}"))),
        }
    }
    Ok(WatchSet { guards, unguardable, unreadable })
}

/// The outcome of one [`watch_step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchStatus {
    /// The escrow's exit is not confirmed yet — keep polling.
    Guarding,
    /// The escrow's exit CONFIRMED (our refund, or a completion we stood down
    /// for): this guard is done. Carries the static reason.
    Resolved(&'static str),
}

/// One watchtower poll for one guarded swap. Idempotent and crash-safe: every
/// call re-reads chain state, so a restarted `watch` just re-evaluates.
///
/// Routing (the refund-only subset of the backstop, by design):
/// * `Idle` → keep polling.
/// * `FiredRefund` → the pre-armed refund went on the wire this tick (the
///   dead-device fire); keep polling until it confirms.
/// * `StandDown` → the escrow's spend CONFIRMED: if the spender is our own
///   refund, advance the record along the refund path and register the
///   reclaimed output; a completion win is logged and left for the owning
///   wallet's `recover`. Either way the guard resolves.
/// * `RefundStalledBelowFeeFloor` → the silent refund CPFP: bump from a
///   leasable reserve when one exists (and `opts.allow_bump`), else surface
///   the stall as a LOUD alarm and keep waiting — the CSV never expires.
pub fn watch_step(
    guard: &WatchGuard,
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    opts: &WatchOptions,
    log: &mut dyn FnMut(String),
) -> Result<WatchStatus> {
    let sid_hex = hex32(&guard.sid);
    // Congestion on an ALREADY-RELAYED refund: the manual flag, or the same
    // fully-gated auto-detect the live loop uses (fresh estimate only).
    let congested = opts.refund_congested
        || chain.estimated_feerate_sat_vb().is_some_and(|est| {
            refund_congestion_auto(chain, est, &guard.refund_bytes, guard.escrow_amount)
        });
    match guard.driver.tick(chain, congested)? {
        WatchtowerTick::Idle => Ok(WatchStatus::Guarding),
        WatchtowerTick::FiredRefund => {
            log(format!(
                "{sid_hex}: dead-device refund FIRED — the pre-armed refund is on the wire"
            ));
            Ok(WatchStatus::Guarding)
        }
        WatchtowerTick::StandDown => stand_down(guard, engine, chain, data_dir, log),
        WatchtowerTick::RefundStalledBelowFeeFloor => {
            bump_or_stall(guard, engine, chain, opts, log)?;
            Ok(WatchStatus::Guarding)
        }
    }
}

/// Drive every guard one pass, dropping the resolved ones. A per-guard error
/// is logged and the guard retried next pass — one failing swap must never
/// starve the others' deadlines (the recovery-scan discipline). Returns how
/// many guards remain.
pub fn watch_pass(
    guards: &mut Vec<WatchGuard>,
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    opts: &WatchOptions,
    log: &mut dyn FnMut(String),
) -> usize {
    let mut still = Vec::with_capacity(guards.len());
    for guard in guards.drain(..) {
        match watch_step(&guard, engine, chain, data_dir, opts, log) {
            Ok(WatchStatus::Guarding) => still.push(guard),
            Ok(WatchStatus::Resolved(reason)) => {
                log(format!("{}: guard resolved — {reason}", hex32(&guard.sid)));
            }
            Err(e) => {
                log(format!(
                    "{}: watch step failed (retrying next pass): {e}",
                    hex32(&guard.sid)
                ));
                still.push(guard);
            }
        }
    }
    *guards = still;
    guards.len()
}

/// The escrow's spend CONFIRMED — attribute it and resolve the guard.
fn stand_down(
    guard: &WatchGuard,
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    log: &mut dyn FnMut(String),
) -> Result<WatchStatus> {
    let sid_hex = hex32(&guard.sid);
    match chain.spend_txid(guard.escrow) {
        Some(seen) if Some(seen) == guard.refund_txid => {
            // Our own refund confirmed: advance the record along the refund
            // path (retried next pass if the store hiccups — the guard only
            // resolves once this succeeds) and register the reclaimed coin.
            advance_refund_terminal(engine, &guard.sid)?;
            register_settlement_output(engine, chain, data_dir, &guard.sid, &guard.refund_bytes, log);
            log(format!("{sid_hex}: pre-armed refund CONFIRMED — escrow reclaimed"));
            Ok(WatchStatus::Resolved("own pre-armed refund confirmed"))
        }
        Some(_) => {
            log(format!(
                "{sid_hex}: a completion confirmed against the escrow — standing down \
                 (completion-supersedes); run `recover` on the owning wallet to reconcile"
            ));
            Ok(WatchStatus::Resolved("a completion won — never fought"))
        }
        None => {
            // A view that cannot attribute the spender: the escrow is
            // resolved either way (nothing more a tower may do), but say so
            // honestly rather than claiming a completion.
            log(format!(
                "{sid_hex}: the escrow is confirmed-spent by an unattributable tx — standing \
                 down; run `recover` on the owning wallet to reconcile"
            ));
            Ok(WatchStatus::Resolved("escrow confirmed-spent (spender unattributable)"))
        }
    }
}

/// Advance a record whose OWN refund the chain confirmed to its `Refunded`
/// terminal, honoring the store transition table: every live phase passes
/// through `AbortRefund` first (the same route the live app and recovery
/// take). A `Completed` record is deliberately left untouched — its terminal
/// describes OUR settled leg; the refund reclaiming our own escrow afterwards
/// (a counterparty that never claimed) does not rewrite that history.
fn advance_refund_terminal(engine: &SwapEngine, sid: &[u8; 32]) -> Result<()> {
    let Some(mut rec) = engine.store().get(sid)? else {
        return Ok(());
    };
    if matches!(
        rec.phase,
        SwapPhase::Funding | SwapPhase::Signing | SwapPhase::Released | SwapPhase::Completing
    ) {
        rec.phase = SwapPhase::AbortRefund;
        engine.store().put(&rec)?;
    }
    if rec.phase == SwapPhase::AbortRefund {
        rec.phase = SwapPhase::Refunded;
        engine.store().put(&rec)?;
    }
    Ok(())
}

/// A matured refund below the current fee floor: CPFP it silently from a
/// leasable reserve, or surface the stall LOUDLY and keep waiting (the safe
/// no-reserve fallback — the CSV never expires).
fn bump_or_stall(
    guard: &WatchGuard,
    engine: &mut SwapEngine,
    chain: &impl AuthoritativeChainView,
    opts: &WatchOptions,
    log: &mut dyn FnMut(String),
) -> Result<()> {
    let sid_hex = hex32(&guard.sid);
    let (fee, vsize) = refund_parent_meta(&guard.refund_bytes, guard.escrow_amount)?;
    // Operator override → live node estimate → hardcoded floor, resolved
    // FRESH on every stall (the same rule as the runner's backstop pass).
    let live = chain.estimated_feerate_sat_vb();
    let (target, source) = resolve_target_feerate(opts.target_feerate_sat_vb, live);
    let child_fee = required_child_fee(target, fee, vsize);
    if child_fee == 0 || child_fee > MAX_BUMP_FEE_SATS {
        // Futile-bump short-circuit (same as the live executor): the refund
        // already meets the target, or no buildable child can — either way a
        // bump attempt is guaranteed NoBump, so don't burn a key index on it.
        log(format!(
            "{sid_hex}: ALARM — RefundStalledBelowFeeFloor: the matured refund cannot relay, \
             and a CPFP to {target} sat/vB ({source}) is futile (required child fee \
             {child_fee}); it fires unbumped once congestion clears (the CSV never expires) — \
             consider a higher --feerate"
        ));
        return Ok(());
    }
    if !opts.allow_bump {
        log(format!(
            "{sid_hex}: ALARM — RefundStalledBelowFeeFloor: reserve bumps are gated off (the \
             startup chain reconcile failed); the refund fires unbumped once congestion clears"
        ));
        return Ok(());
    }
    // F5 live heal, mirroring the live executor: a prior bump parks its
    // child's change PendingConfirm, and this heal is the only path back to a
    // leasable pool inside a long-lived process.
    engine.ledger_mut().heal_pending_reserve_changes(chain)?;
    if !engine.ledger().has_leasable_reserve(child_fee) {
        log(format!(
            "{sid_hex}: ALARM — RefundStalledBelowFeeFloor: the matured refund cannot relay \
             under congestion and NO leasable reserve exists on this watchtower device (the \
             bump needs {child_fee} sats); it fires unbumped once congestion clears — the CSV \
             never expires, so nothing is lost, but confirmation waits on the mempool. Onboard \
             a deposit on this device to arm the silent refund CPFP"
        ));
        return Ok(());
    }
    let Some(refund_txid) = guard.refund_txid else {
        log(format!(
            "{sid_hex}: ALARM — the pre-armed refund bytes do not decode; cannot CPFP (the \
             record is damaged — restore from a fresh backup bundle)"
        ));
        return Ok(());
    };
    // No second child on a bump already in flight: an equal-fee sibling is
    // refused by RBF/TRUC and would churn a key index + a lease cycle per
    // tick (the same gate the live auto-detect applies). A nonexistent anchor
    // (refund not yet relayed — the broadcast-time stall) reads Unspent.
    let anchor = OutPoint::new(refund_txid, ANCHOR_VOUT);
    if chain.spend_status(anchor) != SpendStatus::Unspent {
        log(format!(
            "{sid_hex}: refund bump child already in flight on the anchor — waiting for it"
        ));
        return Ok(());
    }
    let (change_key_index, _spk) = engine.issue_reserve_key()?;
    let outcome = engine.execute_cpfp_bump(
        chain,
        CpfpBumpRequest {
            target: BumpTarget::Refund,
            // A refund bump is SILENT by spec — no privacy is left to protect.
            linkage_ack: None,
            lessee: guard.sid,
            parent_bytes: &guard.refund_bytes,
            parent_anchor: anchor,
            anchor_value_sats: guard.anchor_sats,
            parent_fee_sats: fee,
            parent_vsize_vb: vsize,
            target_feerate_sat_vb: target,
            change_key_index,
        },
    )?;
    log(format!(
        "{sid_hex}: silent refund CPFP executed: {outcome:?} [feerate {target} sat/vB, {source}]"
    ));
    Ok(())
}
