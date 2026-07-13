//! Chain view abstraction + an in-process regtest-style simulator.
//!
//! The settlement layer depends only on the `ChainView` trait — it never talks
//! to a real node here (that is the network layer the deferred infra provides).
//! `SimChain` is a self-verifying stand-in with REAL physics that make the
//! failure-checklist rows meaningful:
//!   * an escrow output can be spent at most once (completion supersedes refund);
//!   * a relative-timelock (CSV) spend is rejected until the input has matured;
//!   * confirmations advance only when a block is mined.
//!
//! It is deliberately minimal — no full script validation — but the
//! ordering/timelock/double-spend rules are exactly the ones the settlement
//! safety argument rests on. The `policy` submodule adds the relay-POLICY
//! model (dust / ephemeral dust / TRUC / package relay / min-relay fee) a
//! real Core node applies before consensus ever sees a tx — the layer the
//! review packet's §4.98 fee-model critical lives in.

pub mod policy;

/// Real Bitcoin Core JSON-RPC backend (regtest/testnet) — feature `bitcoind`,
/// so the default build stays dependency-light (no HTTP client).
#[cfg(feature = "bitcoind")]
pub mod bitcoind;
#[cfg(feature = "bitcoind")]
pub use bitcoind::{BitcoinCoreChainView, HttpTransport, RpcClientError, RpcTransport};

use crate::{Error, Result};
use bitcoin::relative::LockTime;
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Map a policy rejection to the crate error type (static messages, mirroring
/// the reject-reason class a real node returns from `testmempoolaccept`).
fn policy_reject(v: policy::PolicyViolation) -> Error {
    use policy::PolicyViolation as V;
    match v {
        V::Dust { .. } => Error::Validation("policy: dust output"),
        V::FeeBelowMinRelay { .. } => Error::Deadline("policy: min relay fee not met"),
        V::NonStandardScript { .. } => Error::Validation("policy: non-standard scriptPubKey"),
        V::NonStandardVersion { .. } => Error::Validation("policy: non-standard tx version"),
        V::TrucTooLarge { .. } => Error::Validation("policy: TRUC tx too large"),
        V::TrucChildTooLarge { .. } => Error::Validation("policy: TRUC child too large"),
        V::TrucVersionMix => Error::Validation("policy: v3/non-v3 unconfirmed spend mix"),
        V::TrucTopology => Error::Validation("policy: TRUC 1-parent-1-child violated"),
        V::EphemeralDust(_) => Error::Validation("policy: ephemeral-dust conditions violated"),
        V::Package(_) => Error::Validation("policy: package shape invalid"),
    }
}

/// Status of an escrow output with respect to the tx that spends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendStatus {
    Unspent,
    InMempool,
    Confirmed(u32),
}

/// Tri-state verified funding read for the proceed-to-sign / encumbrance
/// gate. The point is to distinguish a source DISAGREEMENT (transient — the
/// self-verifying source holds the truth, so WAIT and re-poll) from a
/// genuine WRONG amount (a hostile escrow — abort). Collapsing both to
/// "not verified" lets a single lying non-authoritative source force a
/// terminal abort of an honestly-funded swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingReading {
    /// Not confirmed (on the agreement-required view).
    Unconfirmed,
    /// Confirmed at `height`; `amount` is Some when both sources agree on it,
    /// None when a source cannot report it.
    Confirmed { height: u32, amount: Option<u64> },
    /// Sources disagree, or the amount cannot be cross-verified. The
    /// self-verifying source is authoritative and can be re-polled — the
    /// caller must WAIT, never treat this as terminal.
    Unverifiable,
}

/// What the settlement layer needs from a chain. Read-only queries plus
/// broadcast; `&self` with interior mutability so it can be shared.
pub trait ChainView {
    fn tip_height(&self) -> u32;
    /// Confirmation height of a funding output, if confirmed.
    fn funding_height(&self, outpoint: OutPoint) -> Option<u32>;
    /// Confirmed output amount (sats) of a funding output, if known. Default
    /// `None` for views that don't track amounts; the deferred encumbrance
    /// check (escrow == exactly D+Δ_fee) needs this, so amount-bearing views
    /// (SimChain, a real filter client reading the funding tx) override it.
    fn funding_amount(&self, _outpoint: OutPoint) -> Option<u64> {
        None
    }
    /// Confirmed scriptPubKey of a funding output, if known. Default `None`
    /// for views that don't retain it; amount/tx-bearing views (SimChain, a
    /// real filter client reading the funding tx) override it. This is the
    /// input to the anti-substitution check: the counterparty escrow output
    /// must carry the agreed 2-of-2+CSV P2TR spk, not a same-amount output the
    /// counterparty solely controls. Like `funding_amount`, a dual-source view
    /// returns it only when both sources agree (never proceed on unverified
    /// escrow identity).
    fn funding_spk(&self, _outpoint: OutPoint) -> Option<ScriptBuf> {
        None
    }
    /// Status of whatever spends `escrow_outpoint`.
    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus;
    /// The txid currently spending `outpoint` (mempool or confirmed), if any.
    /// Lets the abort driver tell OUR refund from a counterparty completion.
    /// Default `None` for views that don't track it (the driver then treats
    /// an unknown spend conservatively as a winning completion).
    fn spend_txid(&self, _outpoint: OutPoint) -> Option<Txid> {
        None
    }
    /// Tri-state encumbrance read (see `FundingReading`). Default (a single
    /// source, which is its own authority and never disagrees with itself)
    /// composes height + amount and NEVER returns `Unverifiable`. A
    /// dual-source view overrides this to surface real disagreement so the
    /// caller waits instead of aborting.
    fn verified_funding_reading(&self, outpoint: OutPoint) -> FundingReading {
        match self.funding_height(outpoint) {
            None => FundingReading::Unconfirmed,
            Some(height) => FundingReading::Confirmed {
                height,
                amount: self.funding_amount(outpoint),
            },
        }
    }
    /// Funding height per the AUTHORITATIVE (self-verifying) source. Cannot be
    /// fooled into hiding or fabricating a confirmation, so it is the correct
    /// read for the no-show / abandon judgment (a genuinely-funded
    /// counterparty must never be declared a no-show because a lying explorer
    /// disagrees). NOT for proceed-to-sign, which stays agreement-required.
    /// Default = `funding_height` (a single source is its own authority).
    fn authoritative_funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        self.funding_height(outpoint)
    }
    /// The 64-byte taproot key-path signature in the witness of the tx
    /// spending `outpoint` (mempool OR confirmed), if that tx is a key-path
    /// spend. This is how SL observes Comp->SH's REVEALED final signature the
    /// instant it appears (mempool-first) — the input to extraction. Default
    /// `None` for views that don't retain witnesses.
    fn spending_witness_sig(&self, _outpoint: OutPoint) -> Option<[u8; 64]> {
        None
    }
    /// Broadcast a fully-signed tx to the mempool. Enforces funding existence,
    /// relative-timelock maturity, no-double-spend, and (on views that model
    /// it) real-node relay POLICY. Idempotent for a tx already accepted.
    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid>;
    /// Submit a 1P1C package (stalled parent + fee-bringing CPFP child),
    /// judged on the PACKAGE feerate/fee — the congestion-backstop path.
    /// Default: unsupported (views that cannot package-submit must say so
    /// loudly rather than silently broadcasting the parent alone).
    fn submit_package(&self, _parent_bytes: &[u8], _child_bytes: &[u8]) -> Result<(Txid, Txid)> {
        Err(Error::Unimplemented("package submission not supported by this chain view"))
    }
}

/// Marker for a [`ChainView`] whose readings are backed by at least one
/// SELF-VERIFYING source — the type-level half of the dual-source rule.
///
/// The wallet's fund-deciding entry points (`SwapApp`, `SwapDriver`,
/// `SwapEngine`'s settlement seams, `FundingDriver`, `RecoveryDriver`, the
/// backstop) require this bound, so a bare untrusted explorer client cannot
/// be wired into a fund decision BY CONSTRUCTION — it must be composed
/// through [`DualSourceChainView`] (whose constructor refuses a composition
/// with no self-verifying source) first. Implemented by:
/// - [`SimChain`]: it IS the chain — a direct view, not an explorer's claim
///   about one (and the reason tests need no changes);
/// - [`DualSourceChainView`]: `new` enforces ≥ 1 self-verifying source, and
///   its `ChainView` impl routes tip/spend reads to the authoritative source
///   while funding stays agreement-required.
///
/// Deliberately NOT implemented for arbitrary views: a real explorer-backed
/// `ChainView` (rank 8) must not receive this marker — pair it with a
/// BIP157/158 client inside a `DualSourceChainView` instead. The marker adds
/// no methods, so it changes no behavior — only what the compiler accepts.
pub trait AuthoritativeChainView: ChainView {}

impl AuthoritativeChainView for SimChain {}
impl<A: ChainSource, B: ChainSource> AuthoritativeChainView for DualSourceChainView<A, B> {}

#[derive(Clone)]
struct Inner {
    height: u32,
    /// funding outpoint -> (confirmation height, output amount in sats)
    funded: HashMap<OutPoint, (u32, u64)>,
    /// escrow outpoint -> (spending txid, confirmed height | None = mempool, fee)
    spends: HashMap<OutPoint, (Txid, Option<u32>, u64)>,
    /// Broadcast transactions, so a CONFIRMED tx's outputs become spendable
    /// outpoints (models real UTXO creation: Setup -> escrow -> completion),
    /// and an UNCONFIRMED tx's outputs are package/CPFP-spendable.
    txs: HashMap<Txid, Transaction>,
    /// Minimum fee (sats) a tx must pay to be relayed — the congestion knob.
    /// For a 1P1C package the PACKAGE total is compared against it (CPFP).
    congestion_min_fee: u64,
}

/// Outcome of the conflict/RBF check.
enum Acceptance {
    /// This exact txid is already known (mempool or confirmed) — idempotent
    /// no-op. (Notably, re-broadcasting a CONFIRMED tx must NOT demote it
    /// back to the mempool.)
    AlreadyKnown,
    /// Accept; evict these mempool incumbents first (RBF replacements).
    New(Vec<Txid>),
}

impl Inner {
    /// True iff `txid` is in the mempool (some spend entry not yet confirmed).
    fn is_unconfirmed(&self, txid: &Txid) -> bool {
        self.spends.values().any(|(t, conf, _)| t == txid && conf.is_none())
    }

    /// TRUC descendant probe: does the unconfirmed `parent` already have an
    /// in-mempool child other than `spender`? A child that conflicts with
    /// `spender` on some outpoint (i.e. is about to be RBF-evicted by it)
    /// does not count.
    fn has_other_unconfirmed_child(
        &self,
        parent: &Txid,
        spender: &Txid,
        spender_inputs: &[OutPoint],
    ) -> bool {
        self.spends.iter().any(|(op, (child, conf, _))| {
            op.txid == *parent
                && conf.is_none()
                && child != spender
                && !spender_inputs.iter().any(|si| {
                    self.spends
                        .get(si)
                        .map(|(t, c, _)| t == child && c.is_none())
                        .unwrap_or(false)
                })
        })
    }

    /// The number of DISTINCT unconfirmed ANCESTOR transactions of `tx`
    /// (transitive over inputs), for the TRUC ancestor-limit check. Counts
    /// ancestor TXS, not inputs: a tx spending two outputs of one unconfirmed
    /// parent has ONE ancestor, and a G→P→C chain has two. Confirmed prevouts
    /// (funding outputs or confirmed txs) end the walk.
    fn unconfirmed_ancestor_count(&self, tx: &Transaction) -> usize {
        let mut seen: std::collections::BTreeSet<Txid> = std::collections::BTreeSet::new();
        let mut stack: Vec<Txid> = tx.input.iter().map(|i| i.previous_output.txid).collect();
        while let Some(txid) = stack.pop() {
            if self.is_unconfirmed(&txid) && seen.insert(txid) {
                if let Some(parent) = self.txs.get(&txid) {
                    stack.extend(parent.input.iter().map(|i| i.previous_output.txid));
                }
            }
        }
        seen.len()
    }

    /// Resolve every input: total input value, CSV maturity, and the policy
    /// context (confirmed funding vs unconfirmed mempool parent). An input
    /// may spend a registered funding outpoint OR an output of an
    /// UNCONFIRMED broadcast tx (a mempool chain / package child).
    fn resolve_inputs(
        &self,
        tx: &Transaction,
        txid: &Txid,
    ) -> Result<(u64, Vec<policy::PrevoutCtx>)> {
        let tip = self.height;
        let spender_inputs: Vec<OutPoint> =
            tx.input.iter().map(|i| i.previous_output).collect();
        let mut total_in: u64 = 0;
        let mut ctxs = Vec::with_capacity(tx.input.len());
        for input in &tx.input {
            let op = input.previous_output;
            let (value, conf_height, ctx) = if let Some((h, amount)) = self.funded.get(&op) {
                (
                    *amount,
                    Some(*h),
                    policy::PrevoutCtx {
                        unconfirmed_parent: false,
                        parent_is_v3: false,
                        parent_has_other_child: false,
                    },
                )
            } else if let Some(parent) = self.txs.get(&op.txid) {
                if !self.is_unconfirmed(&op.txid) {
                    return Err(Error::Validation("broadcast: input spends an unfunded output"));
                }
                let out = parent
                    .output
                    .get(op.vout as usize)
                    .ok_or(Error::Validation("broadcast: input references a missing output"))?;
                (
                    out.value.to_sat(),
                    None,
                    policy::PrevoutCtx {
                        unconfirmed_parent: true,
                        parent_is_v3: parent.version.0 == 3,
                        parent_has_other_child: self.has_other_unconfirmed_child(
                            &op.txid,
                            txid,
                            &spender_inputs,
                        ),
                    },
                )
            } else {
                return Err(Error::Validation("broadcast: input spends an unfunded output"));
            };
            total_in = total_in.saturating_add(value);

            // Relative-timelock (CSV) maturity. An unconfirmed prevout has no
            // confirmation to measure from, so a CSV spend of it is immature.
            if let Some(lock) = input.sequence.to_relative_lock_time() {
                match lock {
                    LockTime::Blocks(h) => {
                        let matured = match conf_height {
                            Some(fh) => tip.saturating_sub(fh) >= h.value() as u32,
                            None => false,
                        };
                        if !matured {
                            return Err(Error::Deadline("broadcast: relative timelock not matured"));
                        }
                    }
                    LockTime::Time(_) => {
                        return Err(Error::Validation(
                            "broadcast: time-based locks unsupported in sim",
                        ));
                    }
                }
            }
            ctxs.push(ctx);
        }
        Ok((total_in, ctxs))
    }

    /// Conflict / double-spend handling with fee-based replacement (RBF): a
    /// strictly higher-fee replacement of an unconfirmed spend evicts the
    /// incumbent (and, transitively, the incumbent's descendants);
    /// equal-or-lower is refused; a confirmed spend is final.
    fn check_conflicts(&self, tx: &Transaction, txid: &Txid, fee: u64) -> Result<Acceptance> {
        if self.txs.contains_key(txid) {
            return Ok(Acceptance::AlreadyKnown);
        }
        let mut evict: Vec<Txid> = Vec::new();
        for input in &tx.input {
            match self.spends.get(&input.previous_output) {
                Some((_, Some(_), _)) => {
                    return Err(Error::Abort("broadcast: output already spent (confirmed)"))
                }
                Some((incumbent, None, old_fee)) => {
                    if fee <= *old_fee {
                        return Err(Error::Abort(
                            "broadcast: output already in mempool (fee too low to replace)",
                        ));
                    }
                    if !evict.contains(incumbent) {
                        evict.push(*incumbent);
                    }
                }
                None => {}
            }
        }
        Ok(Acceptance::New(evict))
    }

    /// Remove an UNCONFIRMED tx from the mempool: its spend entries, its
    /// body, and (transitively) any mempool descendants — a replaced or
    /// evicted parent must not leave orphaned children behind.
    fn remove_mempool_tx(&mut self, txid: &Txid) {
        if !self.is_unconfirmed(txid) {
            return; // confirmed (keep) or already gone
        }
        self.spends.retain(|_, v| !(v.0 == *txid && v.1.is_none()));
        if let Some(tx) = self.txs.remove(txid) {
            for vout in 0..tx.output.len() {
                let op = OutPoint::new(*txid, vout as u32);
                if let Some((child, None, _)) = self.spends.get(&op).copied() {
                    self.remove_mempool_tx(&child);
                }
            }
        }
    }

    /// Evict RBF incumbents, then insert the accepted tx into the mempool.
    fn insert_tx(&mut self, tx: Transaction, txid: Txid, fee: u64, evict: Vec<Txid>) {
        for e in evict {
            self.remove_mempool_tx(&e);
        }
        for input in &tx.input {
            self.spends.insert(input.previous_output, (txid, None, fee));
        }
        self.txs.insert(txid, tx);
    }
}

/// A shareable in-process chain (Send + Sync via Arc<Mutex<_>>).
#[derive(Clone)]
pub struct SimChain(Arc<Mutex<Inner>>);

impl SimChain {
    pub fn new(genesis_height: u32) -> Self {
        SimChain(Arc::new(Mutex::new(Inner {
            height: genesis_height,
            funded: HashMap::new(),
            spends: HashMap::new(),
            txs: HashMap::new(),
            congestion_min_fee: 0,
        })))
    }

    /// Record a confirmed funding output at the given height, with an
    /// unconstrained amount (fee checks always pass for spends of it).
    pub fn fund(&self, outpoint: OutPoint, height: u32) {
        self.0.lock().unwrap().funded.insert(outpoint, (height, u64::MAX));
    }

    /// Record a confirmed funding output with a specific amount, so spends of it
    /// have a meaningful fee (input amount − output total) for congestion tests.
    pub fn fund_with_amount(&self, outpoint: OutPoint, height: u32, amount_sats: u64) {
        self.0.lock().unwrap().funded.insert(outpoint, (height, amount_sats));
    }

    /// Record a confirmed funding output WITH its scriptPubKey, by synthesizing
    /// a creating tx so [`funding_spk`](ChainView::funding_spk) reports `spk`
    /// (a bare `fund`/`fund_with_amount` has no tx, so its spk reads `None`).
    /// For escrow-identity / CSV-binding tests that need a reportable spk without
    /// a full Setup broadcast.
    pub fn fund_with_spk(&self, outpoint: OutPoint, height: u32, amount_sats: u64, spk: ScriptBuf) {
        use bitcoin::{absolute, transaction::Version, Amount, TxOut};
        let mut g = self.0.lock().unwrap();
        g.funded.insert(outpoint, (height, amount_sats));
        let mut output: Vec<TxOut> = (0..outpoint.vout)
            .map(|_| TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::new() })
            .collect();
        output.push(TxOut { value: Amount::from_sat(amount_sats), script_pubkey: spk });
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output,
        };
        // Keyed by the outpoint's txid (funding_spk looks up outpoint.txid), so
        // the synthesized tx's own computed txid is irrelevant to the lookup.
        g.txs.insert(outpoint.txid, tx);
    }

    /// Set the minimum relay fee (congestion level). A tx paying less will not
    /// be accepted until it is fee-bumped or the congestion clears.
    pub fn set_congestion(&self, min_fee_sats: u64) {
        self.0.lock().unwrap().congestion_min_fee = min_fee_sats;
    }

    /// Mine one block: every mempool spend confirms at the new tip height, and
    /// each newly-confirmed transaction's outputs become spendable outpoints.
    pub fn mine(&self) {
        let mut g = self.0.lock().unwrap();
        g.height += 1;
        let h = g.height;
        let mut newly_confirmed = Vec::new();
        for (_op, (txid, conf, _fee)) in g.spends.iter_mut() {
            if conf.is_none() {
                *conf = Some(h);
                newly_confirmed.push(*txid);
            }
        }
        // Register the outputs of confirmed txs as fundable outpoints (a Setup's
        // escrow output, a completion's D output, etc.).
        for txid in newly_confirmed {
            if let Some(tx) = g.txs.get(&txid).cloned() {
                for (vout, out) in tx.output.iter().enumerate() {
                    g.funded
                        .entry(OutPoint::new(txid, vout as u32))
                        .or_insert((h, out.value.to_sat()));
                }
            }
        }
    }

    /// Advance the tip by `blocks` with no confirmations (time passing).
    pub fn advance(&self, blocks: u32) {
        self.0.lock().unwrap().height += blocks;
    }

    /// Evict an UNCONFIRMED (mempool) spend of `outpoint`, if any — models a
    /// low-fee tx dropping out of the mempool. The whole tx is evicted (all
    /// its spend entries) together with any mempool descendants. Confirmed
    /// spends are untouched.
    pub fn evict(&self, outpoint: OutPoint) {
        let mut g = self.0.lock().unwrap();
        if let Some((txid, None, _fee)) = g.spends.get(&outpoint).copied() {
            g.remove_mempool_tx(&txid);
        }
    }

    /// Submit a 1P1C package (`submitpackage` / opportunistic package relay):
    /// the parent may be below min-relay (even 0-fee, TRUC) or carry ONE
    /// ephemeral-dust output the child sweeps; acceptance is judged on the
    /// PACKAGE feerate (min-relay) and the package TOTAL fee (the congestion
    /// knob — CPFP). Atomic: either both txs enter the mempool or neither.
    pub fn submit_package(&self, parent_bytes: &[u8], child_bytes: &[u8]) -> Result<(Txid, Txid)> {
        let parent: Transaction = bitcoin::consensus::encode::deserialize(parent_bytes)
            .map_err(|_| Error::Validation("package: undecodable parent"))?;
        let child: Transaction = bitcoin::consensus::encode::deserialize(child_bytes)
            .map_err(|_| Error::Validation("package: undecodable child"))?;
        let parent_txid = parent.compute_txid();
        let child_txid = child.compute_txid();

        let mut g = self.0.lock().unwrap();
        // Work on a clone; commit only if the WHOLE package is accepted.
        let mut work = g.clone();

        let shape = policy::check_package_shape(&parent, &child).map_err(policy_reject)?;

        // --- Parent: policy (with package leniency) + physics ---------------
        let (p_in, p_ctx) = work.resolve_inputs(&parent, &parent_txid)?;
        let p_out: u64 = parent.output.iter().fold(0u64, |acc, o| acc.saturating_add(o.value.to_sat()));
        let p_fee = p_in.saturating_sub(p_out);
        let p_anc = work.unconfirmed_ancestor_count(&parent);
        policy::check_tx(&parent, p_fee, &p_ctx, p_anc, Some(shape)).map_err(policy_reject)?;
        match work.check_conflicts(&parent, &parent_txid, p_fee)? {
            Acceptance::New(evict) => work.insert_tx(parent.clone(), parent_txid, p_fee, evict),
            Acceptance::AlreadyKnown => {} // deduplicated, Core-style
        }

        // --- Child: resolves against the parent's outputs; no leniency ------
        let (c_in, c_ctx) = work.resolve_inputs(&child, &child_txid)?;
        let c_out: u64 = child.output.iter().fold(0u64, |acc, o| acc.saturating_add(o.value.to_sat()));
        let c_fee = c_in.saturating_sub(c_out);
        // The parent is already in `work`, so the child's ancestor set includes
        // it — a 1P1C child sees exactly 1 ancestor; a deeper chain, more.
        let c_anc = work.unconfirmed_ancestor_count(&child);
        policy::check_tx(&child, c_fee, &c_ctx, c_anc, None).map_err(policy_reject)?;

        // --- Package feerate + congestion (CPFP is judged on the package) ---
        if !policy::package_meets_feerate(
            &parent,
            p_fee,
            &child,
            c_fee,
            policy::MIN_RELAY_FEERATE_SAT_VB,
        ) {
            return Err(Error::Deadline("package: below min relay feerate"));
        }
        if p_fee.saturating_add(c_fee) < work.congestion_min_fee {
            return Err(Error::Deadline("package: fee below the current relay threshold"));
        }

        match work.check_conflicts(&child, &child_txid, c_fee)? {
            Acceptance::New(evict) => work.insert_tx(child, child_txid, c_fee, evict),
            Acceptance::AlreadyKnown => {}
        }

        *g = work;
        Ok((parent_txid, child_txid))
    }
}

impl ChainView for SimChain {
    fn tip_height(&self) -> u32 {
        self.0.lock().unwrap().height
    }

    fn funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        self.0.lock().unwrap().funded.get(&outpoint).map(|(h, _)| *h)
    }

    fn funding_amount(&self, outpoint: OutPoint) -> Option<u64> {
        self.0.lock().unwrap().funded.get(&outpoint).map(|(_, a)| *a)
    }

    fn funding_spk(&self, outpoint: OutPoint) -> Option<ScriptBuf> {
        // Only report the spk of a CONFIRMED funding output whose creating tx
        // we retain (a real Setup broadcast → mined). A synthetic `fund` /
        // `fund_with_amount` fixture has no tx, so its spk is unknown (None) —
        // exactly like a source that cannot report it, so the gate WAITs
        // rather than proceeding on an unverifiable escrow identity.
        let g = self.0.lock().unwrap();
        g.funded.get(&outpoint)?;
        let tx = g.txs.get(&outpoint.txid)?;
        tx.output
            .get(outpoint.vout as usize)
            .map(|o| o.script_pubkey.clone())
    }

    fn spend_txid(&self, outpoint: OutPoint) -> Option<Txid> {
        self.0.lock().unwrap().spends.get(&outpoint).map(|(t, _, _)| *t)
    }

    fn spending_witness_sig(&self, outpoint: OutPoint) -> Option<[u8; 64]> {
        let g = self.0.lock().unwrap();
        let (txid, _, _) = g.spends.get(&outpoint)?;
        let tx = g.txs.get(txid)?;
        // The Comp->SH completion is a taproot key-path spend: witness is a
        // single 64-byte schnorr signature on its first (only) input.
        let input = tx.input.iter().find(|i| i.previous_output == outpoint)?;
        let elem = input.witness.iter().next()?;
        elem.get(..64)?.try_into().ok()
    }

    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus {
        match self.0.lock().unwrap().spends.get(&escrow_outpoint) {
            None => SpendStatus::Unspent,
            Some((_, None, _)) => SpendStatus::InMempool,
            Some((_, Some(h), _)) => SpendStatus::Confirmed(*h),
        }
    }

    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid> {
        let tx: Transaction = bitcoin::consensus::encode::deserialize(tx_bytes)
            .map_err(|_| Error::Validation("broadcast: undecodable transaction"))?;
        let txid = tx.compute_txid();
        let mut g = self.0.lock().unwrap();

        // Physics: resolve inputs (funded or mempool-parent), CSV maturity,
        // fee (saturating so an unconstrained u64::MAX funding never
        // overflows). Also yields the policy context for each prevout.
        let (total_in, prevout_ctx) = g.resolve_inputs(&tx, &txid)?;
        let total_out: u64 = tx.output.iter().fold(0u64, |acc, o| acc.saturating_add(o.value.to_sat()));
        let fee = total_in.saturating_sub(total_out);

        match g.check_conflicts(&tx, &txid, fee)? {
            // Idempotent: already in the mempool or CONFIRMED (a rebroadcast
            // must never demote a confirmed tx back to the mempool).
            Acceptance::AlreadyKnown => Ok(txid),
            Acceptance::New(evict) => {
                // Relay policy — the gate a real Core node applies before
                // consensus ever sees the tx (dust / ephemeral dust / TRUC /
                // min-relay). Standalone submission: no package leniency.
                let anc = g.unconfirmed_ancestor_count(&tx);
                policy::check_tx(&tx, fee, &prevout_ctx, anc, None).map_err(policy_reject)?;

                // Congestion: a tx paying below the minimum relay fee will not
                // be accepted (it stalls until fee-bumped or congestion clears).
                if fee < g.congestion_min_fee {
                    return Err(Error::Deadline("broadcast: fee below the current relay threshold"));
                }
                g.insert_tx(tx, txid, fee, evict);
                Ok(txid)
            }
        }
    }

    fn submit_package(&self, parent_bytes: &[u8], child_bytes: &[u8]) -> Result<(Txid, Txid)> {
        SimChain::submit_package(self, parent_bytes, child_bytes)
    }
}

// ===== Self-verifying dual-source chain view (v3.13) =======================
//
// v3.13: "At least one of the two required chain-state sources must be
// self-verifying — BIP 157/158 compact-block filters checked against
// independently obtained headers — not merely a second trusted explorer.
// Disagreement resolves to wait-or-abort." This defeats a fully-eclipsed
// all-API path: a lying explorer cannot fabricate confirmation, because the
// self-verifying source validates PoW headers and will DISAGREE, and the gate
// then refuses to proceed on unverified state.

/// One chain-state source. A real deployment pairs a self-verifying BIP 157/158
/// client with an ordinary explorer; here a source wraps any `ChainView`.
pub trait ChainSource {
    fn tip_height(&self) -> u32;
    fn funding_height(&self, outpoint: OutPoint) -> Option<u32>;
    fn funding_amount(&self, _outpoint: OutPoint) -> Option<u64> {
        None
    }
    fn funding_spk(&self, _outpoint: OutPoint) -> Option<ScriptBuf> {
        None
    }
    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus;
    fn spend_txid(&self, _outpoint: OutPoint) -> Option<Txid> {
        None
    }
    fn spending_witness_sig(&self, _outpoint: OutPoint) -> Option<[u8; 64]> {
        None
    }
    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid>;
    /// 1P1C package submission (see `ChainView::submit_package`).
    fn submit_package(&self, _parent_bytes: &[u8], _child_bytes: &[u8]) -> Result<(Txid, Txid)> {
        Err(Error::Unimplemented("package submission not supported by this chain source"))
    }
    /// True iff this source validates compact-block filters against
    /// independently-obtained PoW headers — i.e. it cannot be made to lie about
    /// confirmation by an eclipse. At least one source of a pair must be this.
    fn is_self_verifying(&self) -> bool;
}

/// A [`ChainView`] that is SELF-VERIFYING at the SOURCE level: it validates
/// compact-block filters against independently-obtained PoW headers, so it
/// cannot be made to lie about a confirmation by an eclipse. This is the
/// honesty claim [`DualSourceChainView`] requires of at least one of its
/// sources — made a TYPE the compiler checks, never a caller-asserted bool.
///
/// Implemented ONLY by views that genuinely carry the property:
/// - [`SimChain`]: it IS the chain (the model's ground truth), not a remote
///   claim about one;
/// - a future BIP157/158 filter client (rank 8) — which must add its own
///   `impl SelfVerifyingSource for … {}`, a deliberate and reviewable act.
///
/// A block-explorer client must NOT implement this. Passing one as the
/// self-verifying half of a dual view is then a compile error (it lacks the
/// marker), instead of one unreviewable `true` at the construction seam.
pub trait SelfVerifyingSource: ChainView {}

impl SelfVerifyingSource for SimChain {}

/// A labeled source over a `ChainView`, tagged with whether it is the
/// self-verifying one. The tag is NOT a free bool: it can only be set true via
/// [`Source::self_verifying`], whose bound admits only a [`SelfVerifyingSource`].
pub struct Source<C: ChainView> {
    view: C,
    self_verifying: bool,
}

impl<C: ChainView> Source<C> {
    /// An UNTRUSTED source (e.g. a block explorer): the tag is false. Any
    /// `ChainView` qualifies — an untrusted view makes no honesty claim.
    pub fn untrusted(view: C) -> Self {
        Source { view, self_verifying: false }
    }

    /// A SELF-VERIFYING source: the tag is true. The `SelfVerifyingSource`
    /// bound is the whole point — only a view that carries the marker (SimChain;
    /// a future filter client) can be labeled self-verifying, so an explorer
    /// cannot slip through by asserting a bool.
    pub fn self_verifying(view: C) -> Self
    where
        C: SelfVerifyingSource,
    {
        Source { view, self_verifying: true }
    }
}

impl<C: ChainView> ChainSource for Source<C> {
    fn tip_height(&self) -> u32 {
        self.view.tip_height()
    }
    fn funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        self.view.funding_height(outpoint)
    }
    fn funding_amount(&self, outpoint: OutPoint) -> Option<u64> {
        self.view.funding_amount(outpoint)
    }
    fn funding_spk(&self, outpoint: OutPoint) -> Option<ScriptBuf> {
        self.view.funding_spk(outpoint)
    }
    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus {
        self.view.spend_status(escrow_outpoint)
    }
    fn spend_txid(&self, outpoint: OutPoint) -> Option<Txid> {
        self.view.spend_txid(outpoint)
    }
    fn spending_witness_sig(&self, outpoint: OutPoint) -> Option<[u8; 64]> {
        self.view.spending_witness_sig(outpoint)
    }
    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid> {
        self.view.broadcast(tx_bytes)
    }
    fn submit_package(&self, parent_bytes: &[u8], child_bytes: &[u8]) -> Result<(Txid, Txid)> {
        self.view.submit_package(parent_bytes, child_bytes)
    }
    fn is_self_verifying(&self) -> bool {
        self.self_verifying
    }
}

/// A chain view backed by TWO independent sources, at least one self-verifying.
/// Reads are cross-verified: the `verified_*` methods return `Err(Deadline)` on
/// disagreement so the settlement gate resolves to WAIT-OR-ABORT and never
/// proceeds on unverified state.
///
/// It also implements `ChainView` so it drops into every existing consumer: on
/// disagreement the reads collapse to the CONSERVATIVE value (fewer blocks
/// elapsed, funding not-yet-confirmed, spend still pending) so a caller that
/// ignores the distinction still never acts on unverified state — it simply
/// waits. Callers that want to distinguish "disagreement" from "not yet" use
/// the `verified_*` methods.
pub struct DualSourceChainView<A: ChainSource, B: ChainSource> {
    a: A,
    b: B,
}

impl<A: ChainSource, B: ChainSource> DualSourceChainView<A, B> {
    /// Requires at least one self-verifying source (else `Err`).
    pub fn new(a: A, b: B) -> Result<Self> {
        if !a.is_self_verifying() && !b.is_self_verifying() {
            return Err(Error::Validation(
                "dual-source chain view requires at least one self-verifying source",
            ));
        }
        Ok(DualSourceChainView { a, b })
    }

    /// Broadcast to the self-verifying source (the authoritative real chain);
    /// also to the other so an honest shared backing observes it.
    pub fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid> {
        // Prefer the self-verifying source as the authoritative broadcast target.
        let (primary, secondary) = if self.a.is_self_verifying() {
            (&self.a as &dyn ChainSource, &self.b as &dyn ChainSource)
        } else {
            (&self.b as &dyn ChainSource, &self.a as &dyn ChainSource)
        };
        let txid = primary.broadcast(tx_bytes)?;
        let _ = secondary.broadcast(tx_bytes); // best-effort; may be the same backing
        Ok(txid)
    }

    /// 1P1C package submission with the same primary/secondary fan-out as
    /// `broadcast` — packages must not silently bypass the dual view.
    pub fn submit_package(&self, parent_bytes: &[u8], child_bytes: &[u8]) -> Result<(Txid, Txid)> {
        let (primary, secondary) = if self.a.is_self_verifying() {
            (&self.a as &dyn ChainSource, &self.b as &dyn ChainSource)
        } else {
            (&self.b as &dyn ChainSource, &self.a as &dyn ChainSource)
        };
        let ids = primary.submit_package(parent_bytes, child_bytes)?;
        let _ = secondary.submit_package(parent_bytes, child_bytes); // best-effort
        Ok(ids)
    }

    /// Tip height, only if both sources agree. Disagreement => wait-or-abort.
    pub fn verified_tip_height(&self) -> Result<u32> {
        let (x, y) = (self.a.tip_height(), self.b.tip_height());
        if x == y {
            Ok(x)
        } else {
            Err(Error::Deadline("chain sources disagree on tip; wait-or-abort"))
        }
    }

    /// Funding confirmation height, only if both sources agree (including both
    /// agreeing it is unconfirmed). Disagreement => wait-or-abort.
    pub fn verified_funding_height(&self, outpoint: OutPoint) -> Result<Option<u32>> {
        let (x, y) = (self.a.funding_height(outpoint), self.b.funding_height(outpoint));
        if x == y {
            Ok(x)
        } else {
            Err(Error::Deadline(
                "chain sources disagree on funding confirmation; wait-or-abort (never proceed on unverified state)",
            ))
        }
    }

    /// Funding CONFIRMATION HEIGHT AND AMOUNT, only if both sources agree on
    /// both. This is the deferred-encumbrance-verification read (v3.14
    /// Phase 5): the counterparty escrow must be confirmed AND hold exactly
    /// D+Δ_fee before we sign. Disagreement (or a source that cannot report
    /// the amount) => Err, so we never sign against unverified funding.
    pub fn verified_funding(&self, outpoint: OutPoint) -> Result<Option<(u32, u64)>> {
        let (hx, hy) = (self.a.funding_height(outpoint), self.b.funding_height(outpoint));
        if hx != hy {
            return Err(Error::Deadline(
                "chain sources disagree on funding confirmation; wait-or-abort",
            ));
        }
        match hx {
            None => Ok(None),
            Some(h) => {
                let (ax, ay) = (self.a.funding_amount(outpoint), self.b.funding_amount(outpoint));
                match (ax, ay) {
                    (Some(x), Some(y)) if x == y => Ok(Some((h, x))),
                    (Some(_), Some(_)) => Err(Error::Deadline(
                        "chain sources disagree on funding amount; wait-or-abort",
                    )),
                    _ => Err(Error::Deadline(
                        "a chain source cannot report the funding amount; cannot verify encumbrance",
                    )),
                }
            }
        }
    }

    /// Funding scriptPubKey, only if both sources agree (the anti-substitution
    /// read). Disagreement, or a source that cannot report the spk, => Err so
    /// the gate waits rather than proceeding on an unverified escrow identity.
    pub fn verified_funding_spk(&self, outpoint: OutPoint) -> Result<Option<ScriptBuf>> {
        let (hx, hy) = (self.a.funding_height(outpoint), self.b.funding_height(outpoint));
        if hx != hy {
            return Err(Error::Deadline(
                "chain sources disagree on funding confirmation; wait-or-abort",
            ));
        }
        match hx {
            None => Ok(None),
            Some(_) => {
                let (sx, sy) = (self.a.funding_spk(outpoint), self.b.funding_spk(outpoint));
                match (sx, sy) {
                    (Some(x), Some(y)) if x == y => Ok(Some(x)),
                    (Some(_), Some(_)) => Err(Error::Deadline(
                        "chain sources disagree on funding scriptPubKey; wait-or-abort",
                    )),
                    _ => Err(Error::Deadline(
                        "a chain source cannot report the funding scriptPubKey; cannot verify escrow identity",
                    )),
                }
            }
        }
    }

    /// Spend status, only if both sources agree. Disagreement => wait-or-abort.
    pub fn verified_spend_status(&self, escrow_outpoint: OutPoint) -> Result<SpendStatus> {
        let (x, y) = (self.a.spend_status(escrow_outpoint), self.b.spend_status(escrow_outpoint));
        if x == y {
            Ok(x)
        } else {
            Err(Error::Deadline("chain sources disagree on spend status; wait-or-abort"))
        }
    }

    /// The self-verifying source (guaranteed present by `new`). If both are
    /// self-verifying, `a` is used (they must agree).
    fn sv(&self) -> &dyn ChainSource {
        if self.a.is_self_verifying() {
            &self.a
        } else {
            &self.b
        }
    }

    /// AUTHORITATIVE reading (v3.13/v3.14: "the self-verifying source is
    /// authoritative"). The self-verifying source validates PoW headers +
    /// compact filters, so a lying explorer can neither fabricate nor HIDE a
    /// confirmation. The refund/watchtower decision must act on timelocks and
    /// cannot wait forever on a disagreement, so it uses THIS — never the
    /// agreement-required `verified_*` (which is for the proceed-to-sign gate).
    pub fn authoritative_tip_height(&self) -> u32 {
        self.sv().tip_height()
    }
    pub fn authoritative_spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus {
        self.sv().spend_status(escrow_outpoint)
    }
}

impl<A: ChainSource, B: ChainSource> ChainView for DualSourceChainView<A, B> {
    // Tip and spend status use the AUTHORITATIVE self-verifying source, so a
    // lying source can never strand a matured refund or hide a completion (the
    // refund subroutine acts on timelocks and cannot wait forever). Funding
    // confirmation is the proceed-to-SIGN gate, which must NOT proceed on
    // unverified state, so it stays agreement-required (waits on disagreement).
    fn tip_height(&self) -> u32 {
        self.authoritative_tip_height()
    }
    fn funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        self.verified_funding_height(outpoint).unwrap_or(None)
    }
    fn funding_amount(&self, outpoint: OutPoint) -> Option<u64> {
        // Amount only when both sources agree on height AND amount.
        self.verified_funding(outpoint).ok().flatten().map(|(_, a)| a)
    }
    fn funding_spk(&self, outpoint: OutPoint) -> Option<ScriptBuf> {
        // Spk only when both sources agree; disagreement/absent collapses to
        // None so the anti-substitution gate waits, never proceeds unverified.
        self.verified_funding_spk(outpoint).ok().flatten()
    }
    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus {
        self.authoritative_spend_status(escrow_outpoint)
    }
    fn spend_txid(&self, outpoint: OutPoint) -> Option<Txid> {
        // Authoritative (self-verifying) source: a lying explorer must not be
        // able to misattribute a spend and trick us into "take the swap".
        self.sv().spend_txid(outpoint)
    }
    fn verified_funding_reading(&self, outpoint: OutPoint) -> FundingReading {
        // Real tri-state: a source disagreement (or an un-reportable amount)
        // becomes `Unverifiable` (wait, don't abort); genuine agreement gives
        // the confirmed amount.
        match self.verified_funding(outpoint) {
            Ok(None) => FundingReading::Unconfirmed,
            Ok(Some((height, amount))) => FundingReading::Confirmed { height, amount: Some(amount) },
            Err(_) => FundingReading::Unverifiable,
        }
    }
    fn authoritative_funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        self.sv().funding_height(outpoint)
    }
    fn spending_witness_sig(&self, outpoint: OutPoint) -> Option<[u8; 64]> {
        // The reveal must come from the authoritative source: a lying
        // explorer must not be able to feed us a bogus "final signature".
        self.sv().spending_witness_sig(outpoint)
    }
    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid> {
        DualSourceChainView::broadcast(self, tx_bytes)
    }
    fn submit_package(&self, parent_bytes: &[u8], child_bytes: &[u8]) -> Result<(Txid, Txid)> {
        DualSourceChainView::submit_package(self, parent_bytes, child_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn op(vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), vout)
    }

    /// A standard P2TR-shaped scriptPubKey (OP_1 <32 bytes>) — policy-valid
    /// fixture output. An EMPTY spk is non-standard on a real node and is now
    /// rejected here too, so fixtures must look like real outputs.
    fn p2tr_spk(seed: u8) -> ScriptBuf {
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[seed; 32]);
        ScriptBuf::from_bytes(v)
    }

    fn spend_tx(prev: OutPoint, sequence: Sequence) -> Vec<u8> {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: p2tr_spk(0x51) }],
        };
        bitcoin::consensus::encode::serialize(&tx)
    }

    #[test]
    fn double_spend_of_confirmed_output_is_rejected() {
        let chain = SimChain::new(100);
        chain.fund(op(0), 100);
        let a = spend_tx(op(0), Sequence::ENABLE_RBF_NO_LOCKTIME);
        assert!(chain.broadcast(&a).is_ok());
        chain.mine();
        assert!(matches!(chain.spend_status(op(0)), SpendStatus::Confirmed(101)));
        // A different tx spending the same confirmed output is refused.
        let b = spend_tx(op(0), Sequence::from_height(5));
        assert!(chain.broadcast(&b).is_err());
    }

    #[test]
    fn csv_spend_is_rejected_until_matured() {
        let chain = SimChain::new(100);
        chain.fund(op(1), 100);
        // CSV of 10 blocks; at tip 100 (0 elapsed) it is immature.
        let refund = spend_tx(op(1), Sequence::from_height(10));
        assert!(matches!(chain.broadcast(&refund), Err(Error::Deadline(_))));
        chain.advance(10); // tip 110, 10 elapsed
        assert!(chain.broadcast(&refund).is_ok());
    }

    #[test]
    fn unfunded_spend_is_rejected() {
        let chain = SimChain::new(100);
        let tx = spend_tx(op(9), Sequence::ENABLE_RBF_NO_LOCKTIME);
        assert!(chain.broadcast(&tx).is_err());
    }

    /// Build a spend of `prev` paying `out` sats (fee = funded_amount − out).
    fn spend_tx_out(prev: OutPoint, out: u64) -> Vec<u8> {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: p2tr_spk(0x52) }],
        };
        bitcoin::consensus::encode::serialize(&tx)
    }

    #[test]
    fn congestion_rejects_low_fee_and_accepts_bumped() {
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 10_000);
        chain.set_congestion(500); // require >= 500 sat fee
        // Output 9_600 -> fee 400 < 500: rejected.
        assert!(matches!(chain.broadcast(&spend_tx_out(op(0), 9_600)), Err(Error::Deadline(_))));
        // Output 9_400 -> fee 600 >= 500: accepted.
        assert!(chain.broadcast(&spend_tx_out(op(0), 9_400)).is_ok());
    }

    #[test]
    fn higher_fee_replaces_mempool_incumbent_lower_does_not() {
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 10_000);
        // Incumbent: fee 300.
        assert!(chain.broadcast(&spend_tx_out(op(0), 9_700)).is_ok());
        // Lower fee (200): refused.
        assert!(chain.broadcast(&spend_tx_out(op(0), 9_800)).is_err());
        // Higher fee (500): replaces the incumbent.
        assert!(chain.broadcast(&spend_tx_out(op(0), 9_500)).is_ok());
        assert!(matches!(chain.spend_status(op(0)), SpendStatus::InMempool));
    }

    // ----- Self-verifying dual-source chain view -----

    #[test]
    fn dual_source_requires_at_least_one_self_verifying() {
        let a = Source::untrusted(SimChain::new(100));
        let b = Source::untrusted(SimChain::new(100));
        assert!(DualSourceChainView::new(a, b).is_err());

        let a = Source::self_verifying(SimChain::new(100)); // self-verifying
        let b = Source::untrusted(SimChain::new(100));
        assert!(DualSourceChainView::new(a, b).is_ok());
    }

    #[test]
    fn agreeing_sources_pass_through() {
        // Both sources back the SAME chain (Arc clone) => always agree.
        let chain = SimChain::new(100);
        chain.fund(op(0), 100);
        let dual = DualSourceChainView::new(
            Source::self_verifying(chain.clone()),
            Source::untrusted(chain.clone()),
        )
        .unwrap();
        assert_eq!(dual.verified_tip_height().unwrap(), 100);
        assert_eq!(dual.verified_funding_height(op(0)).unwrap(), Some(100));
        assert_eq!(dual.verified_spend_status(op(0)).unwrap(), SpendStatus::Unspent);
        // ChainView adapter agrees too.
        assert_eq!(dual.funding_height(op(0)), Some(100));
    }

    #[test]
    fn disagreement_resolves_to_wait_or_abort() {
        // Two DIFFERENT chains that disagree on funding confirmation.
        let honest = SimChain::new(100); // op(0) NOT funded here
        let other = SimChain::new(100);
        other.fund(op(0), 100); // claims it IS funded
        let dual = DualSourceChainView::new(
            Source::self_verifying(honest), // self-verifying, says unconfirmed
            Source::untrusted(other), // explorer, says confirmed
        )
        .unwrap();
        // verified_* surfaces the disagreement explicitly.
        assert!(matches!(dual.verified_funding_height(op(0)), Err(Error::Deadline(_))));
        // ChainView adapter collapses to the conservative "not confirmed".
        assert_eq!(dual.funding_height(op(0)), None);
    }

    #[test]
    fn eclipse_all_api_path_is_defeated_by_the_self_verifying_source() {
        // A fully-eclipsed all-API attack: a LYING explorer fabricates a
        // confirmation to trick us into proceeding. The self-verifying source
        // (which validates PoW headers) cannot be fooled, so it disagrees, and
        // the gate refuses to proceed on unverified state — no theft.
        let self_verifying = SimChain::new(100); // truth: op(0) unfunded
        let lying_explorer = SimChain::new(100);
        lying_explorer.fund(op(0), 100); // the lie
        lying_explorer.mine(); // and pretends a spend confirmed, etc.

        let dual = DualSourceChainView::new(
            Source::self_verifying(self_verifying),
            Source::untrusted(lying_explorer),
        )
        .unwrap();

        // The gate never treats the escrow as confirmed on the strength of the
        // lying explorer alone.
        assert!(dual.verified_funding_height(op(0)).is_err());
        assert_eq!(dual.funding_height(op(0)), None, "eclipse must not yield a false confirmation");
    }

    #[test]
    fn lying_source_cannot_suppress_a_matured_refund() {
        // Honest self-verifying source: escrow funded, UNSPENT (a refund is due).
        let sv = SimChain::new(200);
        sv.fund(op(0), 100);
        // Lying source: claims a completion CONFIRMED, to trick us into "the
        // completion is winning, do not refund".
        let liar = SimChain::new(200);
        liar.fund(op(0), 100);
        liar.broadcast(&spend_tx(op(0), Sequence::ENABLE_RBF_NO_LOCKTIME)).unwrap();
        liar.mine();

        let dual =
            DualSourceChainView::new(Source::self_verifying(sv), Source::untrusted(liar)).unwrap();

        // The AUTHORITATIVE (self-verifying) reading is Unspent, so the refund
        // subroutine sees the truth and is not suppressed by the liar.
        assert_eq!(dual.authoritative_spend_status(op(0)), SpendStatus::Unspent);
        assert_eq!(
            dual.spend_status(op(0)),
            SpendStatus::Unspent,
            "a lying source must not strand a matured refund"
        );
        // The proceed-to-sign gate still sees the disagreement (funding path).
        assert!(dual.verified_spend_status(op(0)).is_err());
    }

    // ===== Relay-policy model (§4.98) =======================================

    fn p2a_out(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]),
        }
    }

    fn tx_bytes_of(version: Version, ins: &[(OutPoint, Sequence)], outs: Vec<TxOut>) -> Vec<u8> {
        let tx = Transaction {
            version,
            lock_time: absolute::LockTime::ZERO,
            input: ins
                .iter()
                .map(|(prev, seq)| TxIn {
                    previous_output: *prev,
                    script_sig: ScriptBuf::new(),
                    sequence: *seq,
                    witness: Witness::new(),
                })
                .collect(),
            output: outs,
        };
        bitcoin::consensus::encode::serialize(&tx)
    }

    /// THE §4.98 regression: the OLD contract shape — a POSITIVE-fee parent
    /// carrying a 0-VALUE P2A anchor — is rejected as dust, exactly as real
    /// Core 28–31 rejects it. This is the defect the sim could not previously
    /// surface; it must never relay again.
    #[test]
    fn old_shape_positive_fee_with_zero_value_anchor_is_rejected() {
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 1_005_000);
        let rbf = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let old_shape = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![
                TxOut { value: Amount::from_sat(1_000_000), script_pubkey: p2tr_spk(1) },
                p2a_out(0), // the 0-value ephemeral anchor on a positive-fee parent
            ],
        );
        assert!(
            matches!(chain.broadcast(&old_shape), Err(Error::Validation(_))),
            "the pre-scheme-(a) contract shape must be dust-rejected"
        );

        // The scheme-(a) shape — non-dust anchor, positive fee — relays.
        let new_shape = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![
                TxOut { value: Amount::from_sat(1_000_000), script_pubkey: p2tr_spk(1) },
                p2a_out(policy::DUST_P2A_SATS),
            ],
        );
        chain.broadcast(&new_shape).expect("scheme-(a) contract shape must relay standalone");
    }

    /// The other §4.98 half: a ZERO-fee Setup (whole coin into the escrow)
    /// can never relay standalone — 0-fee with ephemeral dust demands the
    /// package path, and without the dust it fails min-relay outright.
    #[test]
    fn zero_fee_parent_cannot_relay_standalone() {
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 1_005_000);
        let rbf = Sequence::ENABLE_RBF_NO_LOCKTIME;
        // Old-shape Setup: whole amount to the escrow + 0-value anchor, fee 0.
        let setup = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![
                TxOut { value: Amount::from_sat(1_005_000), script_pubkey: p2tr_spk(2) },
                p2a_out(0),
            ],
        );
        assert!(chain.broadcast(&setup).is_err(), "a 0-fee Setup must not relay standalone");
        // Without the anchor it fails min-relay instead.
        let no_anchor = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![TxOut { value: Amount::from_sat(1_005_000), script_pubkey: p2tr_spk(2) }],
        );
        assert!(
            matches!(chain.broadcast(&no_anchor), Err(Error::Deadline(_))),
            "a 0-fee tx fails min-relay"
        );
    }

    /// Ephemeral dust (Core 29+): a 0-fee parent with ONE 0-value anchor is
    /// accepted ONLY inside a 1P1C package whose child sweeps the dust — the
    /// scheme-(b) shape works on the package path, proving the policy model
    /// distinguishes the two §4.98 fixes rather than blanket-rejecting.
    #[test]
    fn zero_fee_ephemeral_dust_parent_relays_only_in_package() {
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 1_005_000);
        chain.fund_with_amount(op(9), 100, 50_000); // the fee reserve
        let rbf = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let parent = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![
                TxOut { value: Amount::from_sat(1_005_000), script_pubkey: p2tr_spk(3) },
                p2a_out(0),
            ],
        );
        let parent_txid: Txid = {
            let t: Transaction = bitcoin::consensus::encode::deserialize(&parent).unwrap();
            t.compute_txid()
        };
        // Standalone: refused.
        assert!(chain.broadcast(&parent).is_err());
        // Child sweeps the dust anchor + brings the fee from the reserve.
        let child = tx_bytes_of(
            Version(3), // TRUC: a v3 parent's child must be v3
            &[(OutPoint::new(parent_txid, 1), rbf), (op(9), rbf)],
            vec![TxOut { value: Amount::from_sat(48_000), script_pubkey: p2tr_spk(4) }],
        );
        let (p, c) = chain.submit_package(&parent, &child).expect("1P1C package accepted");
        assert_eq!(p, parent_txid);
        chain.mine();
        assert!(matches!(chain.spend_status(op(0)), SpendStatus::Confirmed(_)));
        assert!(matches!(chain.spend_status(OutPoint::new(p, 1)), SpendStatus::Confirmed(_)));
        let _ = c;
    }

    /// TRUC topology: a NON-v3 child of an unconfirmed v3 parent is rejected
    /// (version mix), and a CSV spend of an UNCONFIRMED output is immature.
    #[test]
    fn truc_version_mix_and_unconfirmed_csv_are_rejected() {
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 1_000_000);
        let rbf = Sequence::ENABLE_RBF_NO_LOCKTIME;
        // A v3 parent in the mempool (positive fee, non-dust anchor).
        let parent = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![
                TxOut { value: Amount::from_sat(990_000), script_pubkey: p2tr_spk(5) },
                p2a_out(policy::DUST_P2A_SATS),
            ],
        );
        let parent_txid = chain.broadcast(&parent).unwrap();
        // v2 child of the unconfirmed v3 parent: version mix — rejected.
        let bad_child = tx_bytes_of(
            Version::TWO,
            &[(OutPoint::new(parent_txid, 0), rbf)],
            vec![TxOut { value: Amount::from_sat(980_000), script_pubkey: p2tr_spk(6) }],
        );
        assert!(matches!(chain.broadcast(&bad_child), Err(Error::Validation(_))));
        // CSV spend of an unconfirmed output: immature.
        let csv_child = tx_bytes_of(
            Version(3),
            &[(OutPoint::new(parent_txid, 0), Sequence::from_height(1))],
            vec![TxOut { value: Amount::from_sat(980_000), script_pubkey: p2tr_spk(6) }],
        );
        assert!(matches!(chain.broadcast(&csv_child), Err(Error::Deadline(_))));
    }

    /// TRUC ancestor limit counts DISTINCT unconfirmed ancestor TXS, not
    /// inputs (review finding). (a) A v3 child spending TWO outputs of ONE
    /// unconfirmed parent has a single ancestor and must be ACCEPTED — the old
    /// per-input count wrongly saw two parents and rejected it. (b) A 3-deep
    /// v3 chain G→P→C has two ancestors at C and must be REJECTED — the old
    /// per-input count saw only the direct parent and wrongly accepted it.
    #[test]
    fn truc_ancestor_count_is_transitive_not_per_input() {
        let rbf = Sequence::ENABLE_RBF_NO_LOCKTIME;

        // (a) child spends two outputs of one unconfirmed v3 parent → accepted.
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 1_000_000);
        let parent = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![
                TxOut { value: Amount::from_sat(400_000), script_pubkey: p2tr_spk(10) },
                TxOut { value: Amount::from_sat(400_000), script_pubkey: p2tr_spk(11) },
            ],
        );
        let parent_txid = chain.broadcast(&parent).unwrap();
        let two_output_child = tx_bytes_of(
            Version(3),
            &[(OutPoint::new(parent_txid, 0), rbf), (OutPoint::new(parent_txid, 1), rbf)],
            vec![TxOut { value: Amount::from_sat(750_000), script_pubkey: p2tr_spk(12) }],
        );
        chain
            .broadcast(&two_output_child)
            .expect("a child spending two outputs of one parent is ONE ancestor, not two");

        // (b) 3-deep unconfirmed v3 chain: C has two ancestors → rejected.
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 1_000_000);
        let g = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![TxOut { value: Amount::from_sat(950_000), script_pubkey: p2tr_spk(13) }],
        );
        let g_txid = chain.broadcast(&g).unwrap();
        let p = tx_bytes_of(
            Version(3),
            &[(OutPoint::new(g_txid, 0), rbf)],
            vec![TxOut { value: Amount::from_sat(900_000), script_pubkey: p2tr_spk(14) }],
        );
        let p_txid = chain.broadcast(&p).expect("a 2-tx v3 chain (one ancestor) is allowed");
        let c = tx_bytes_of(
            Version(3),
            &[(OutPoint::new(p_txid, 0), rbf)],
            vec![TxOut { value: Amount::from_sat(850_000), script_pubkey: p2tr_spk(15) }],
        );
        assert!(
            matches!(chain.broadcast(&c), Err(Error::Validation(_))),
            "a 3-deep v3 chain (two ancestors) must be rejected as TRUC topology"
        );
    }

    /// Output standardness: Core's IsStandardTx rejects any nVersion outside
    /// 1..=3. A version-0 or version-4 tx never relays, regardless of fee.
    #[test]
    fn nonstandard_tx_version_is_rejected() {
        let rbf = Sequence::ENABLE_RBF_NO_LOCKTIME;
        for bad in [Version(0), Version(4)] {
            let chain = SimChain::new(100);
            chain.fund_with_amount(op(0), 100, 1_000_000);
            let tx = tx_bytes_of(
                bad,
                &[(op(0), rbf)],
                vec![TxOut { value: Amount::from_sat(900_000), script_pubkey: p2tr_spk(1) }],
            );
            assert!(
                matches!(chain.broadcast(&tx), Err(Error::Validation(_))),
                "tx version {} must be non-standard",
                bad.0
            );
        }
    }

    /// RBF-replacing a mempool parent evicts its descendants too — no
    /// orphaned children left behind; and re-broadcasting a CONFIRMED tx
    /// stays confirmed (idempotency must not demote it to the mempool).
    #[test]
    fn rbf_eviction_cascades_and_confirmed_rebroadcast_is_idempotent() {
        let chain = SimChain::new(100);
        chain.fund_with_amount(op(0), 100, 1_000_000);
        let rbf = Sequence::ENABLE_RBF_NO_LOCKTIME;
        let parent = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![
                TxOut { value: Amount::from_sat(990_000), script_pubkey: p2tr_spk(7) },
                p2a_out(policy::DUST_P2A_SATS),
            ],
        );
        let parent_txid = chain.broadcast(&parent).unwrap();
        // A v3 child rides on the parent's output.
        let child = tx_bytes_of(
            Version(3),
            &[(OutPoint::new(parent_txid, 0), rbf)],
            vec![TxOut { value: Amount::from_sat(980_000), script_pubkey: p2tr_spk(8) }],
        );
        chain.broadcast(&child).unwrap();
        assert!(matches!(
            chain.spend_status(OutPoint::new(parent_txid, 0)),
            SpendStatus::InMempool
        ));
        // Replace the parent (higher fee): the child must be evicted with it.
        let replacement = tx_bytes_of(
            Version(3),
            &[(op(0), rbf)],
            vec![
                TxOut { value: Amount::from_sat(985_000), script_pubkey: p2tr_spk(9) },
                p2a_out(policy::DUST_P2A_SATS),
            ],
        );
        let replacement_txid = chain.broadcast(&replacement).unwrap();
        assert_eq!(
            chain.spend_status(OutPoint::new(parent_txid, 0)),
            SpendStatus::Unspent,
            "the evicted parent's output no longer exists to be spent"
        );
        chain.mine();
        // Re-broadcasting the CONFIRMED replacement is a no-op, not a demote.
        assert!(matches!(chain.spend_status(op(0)), SpendStatus::Confirmed(_)));
        assert_eq!(chain.broadcast(&replacement).unwrap(), replacement_txid);
        assert!(
            matches!(chain.spend_status(op(0)), SpendStatus::Confirmed(_)),
            "rebroadcast must not demote a confirmed tx to the mempool"
        );
    }

    /// Pure-policy unit checks: dust thresholds by SPK type and the exact
    /// old-shape rejection reason.
    #[test]
    fn policy_dust_thresholds_and_reasons() {
        use policy::*;
        assert_eq!(dust_threshold(p2a_out(0).script_pubkey.as_script()), DUST_P2A_SATS);
        assert_eq!(dust_threshold(p2tr_spk(1).as_script()), DUST_P2TR_SATS);
        assert!(is_p2a(p2a_out(0).script_pubkey.as_script()));
        assert!(is_standard_spk(p2tr_spk(1).as_script()));
        assert!(!is_standard_spk(ScriptBuf::new().as_script()));

        // Old shape, checked at the policy layer directly: Dust.
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&tx_bytes_of(
            Version(3),
            &[(op(0), Sequence::ENABLE_RBF_NO_LOCKTIME)],
            vec![
                TxOut { value: Amount::from_sat(1_000_000), script_pubkey: p2tr_spk(1) },
                p2a_out(0),
            ],
        ))
        .unwrap();
        let ctx = [PrevoutCtx {
            unconfirmed_parent: false,
            parent_is_v3: false,
            parent_has_other_child: false,
        }];
        assert!(matches!(
            check_tx(&tx, 5_000, &ctx, 0, None),
            Err(PolicyViolation::Dust { vout: 1, value: 0, threshold: DUST_P2A_SATS })
        ));
        // Same tx with a 240-sat anchor: clean.
        let mut fixed = tx.clone();
        fixed.output[1].value = Amount::from_sat(DUST_P2A_SATS);
        assert!(check_tx(&fixed, 5_000, &ctx, 0, None).is_ok());
    }
}
