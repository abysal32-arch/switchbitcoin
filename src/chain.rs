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
//! It is deliberately minimal — no fees, no full script validation — but the
//! ordering/timelock/double-spend rules are exactly the ones the settlement
//! safety argument rests on.

use crate::{Error, Result};
use bitcoin::relative::LockTime;
use bitcoin::{OutPoint, Transaction, Txid};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Status of an escrow output with respect to the tx that spends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendStatus {
    Unspent,
    InMempool,
    Confirmed(u32),
}

/// What the settlement layer needs from a chain. Read-only queries plus
/// broadcast; `&self` with interior mutability so it can be shared.
pub trait ChainView {
    fn tip_height(&self) -> u32;
    /// Confirmation height of a funding output, if confirmed.
    fn funding_height(&self, outpoint: OutPoint) -> Option<u32>;
    /// Status of whatever spends `escrow_outpoint`.
    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus;
    /// Broadcast a fully-signed tx to the mempool. Enforces funding existence,
    /// relative-timelock maturity, and no-double-spend. Idempotent for a tx
    /// already accepted.
    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid>;
}

struct Inner {
    height: u32,
    /// funding outpoint -> (confirmation height, output amount in sats)
    funded: HashMap<OutPoint, (u32, u64)>,
    /// escrow outpoint -> (spending txid, confirmed height | None = mempool, fee)
    spends: HashMap<OutPoint, (Txid, Option<u32>, u64)>,
    /// Broadcast transactions, so a CONFIRMED tx's outputs become spendable
    /// outpoints (models real UTXO creation: Setup -> escrow -> completion).
    txs: HashMap<Txid, Transaction>,
    /// Minimum fee (sats) a tx must pay to be relayed — the congestion knob.
    congestion_min_fee: u64,
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
    /// low-fee tx dropping out of the mempool. Confirmed spends are untouched.
    pub fn evict(&self, outpoint: OutPoint) {
        let mut g = self.0.lock().unwrap();
        if let Some((_txid, None, _fee)) = g.spends.get(&outpoint) {
            g.spends.remove(&outpoint);
        }
    }
}

impl ChainView for SimChain {
    fn tip_height(&self) -> u32 {
        self.0.lock().unwrap().height
    }

    fn funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        self.0.lock().unwrap().funded.get(&outpoint).map(|(h, _)| *h)
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
        let tip = g.height;

        // Compute the fee (sum of input amounts − sum of outputs). Saturating so
        // an unconstrained (u64::MAX) funding input never overflows.
        let mut total_in: u64 = 0;
        for input in &tx.input {
            let op = input.previous_output;
            let (funding_height, amount) = *g
                .funded
                .get(&op)
                .ok_or(Error::Validation("broadcast: input spends an unfunded output"))?;
            total_in = total_in.saturating_add(amount);

            // Relative-timelock (CSV) maturity.
            if let Some(lock) = input.sequence.to_relative_lock_time() {
                match lock {
                    LockTime::Blocks(h) => {
                        let matured = tip.saturating_sub(funding_height) >= h.value() as u32;
                        if !matured {
                            return Err(Error::Deadline("broadcast: relative timelock not matured"));
                        }
                    }
                    LockTime::Time(_) => {
                        return Err(Error::Validation("broadcast: time-based locks unsupported in sim"));
                    }
                }
            }
        }
        let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        let fee = total_in.saturating_sub(total_out);

        // Congestion: a tx paying below the minimum relay fee will not be
        // accepted (it stalls until fee-bumped or congestion clears).
        if fee < g.congestion_min_fee {
            return Err(Error::Deadline("broadcast: fee below the current relay threshold"));
        }

        // Conflict / double-spend handling, with fee-based replacement (RBF).
        for input in &tx.input {
            let op = input.previous_output;
            // Replace-by-fee: a strictly higher-fee replacement of an unconfirmed
            // spend evicts the incumbent; equal-or-lower is refused.
            match g.spends.get(&op) {
                Some((existing, _, _)) if *existing == txid => {} // idempotent
                Some((_, Some(_), _)) => {
                    return Err(Error::Abort("broadcast: output already spent (confirmed)"))
                }
                Some((_, None, old_fee)) if fee <= *old_fee => {
                    return Err(Error::Abort(
                        "broadcast: output already in mempool (fee too low to replace)",
                    ))
                }
                Some((_, None, _)) => {} // higher fee: replace on insert below
                None => {}
            }
        }

        for input in &tx.input {
            g.spends.insert(input.previous_output, (txid, None, fee));
        }
        g.txs.insert(txid, tx);
        Ok(txid)
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
    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus;
    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid>;
    /// True iff this source validates compact-block filters against
    /// independently-obtained PoW headers — i.e. it cannot be made to lie about
    /// confirmation by an eclipse. At least one source of a pair must be this.
    fn is_self_verifying(&self) -> bool;
}

/// A labeled source over any `ChainView` (e.g. a `SimChain`). The label records
/// whether this source is the self-verifying one.
pub struct Source<C: ChainView> {
    view: C,
    self_verifying: bool,
}

impl<C: ChainView> Source<C> {
    pub fn new(view: C, self_verifying: bool) -> Self {
        Source { view, self_verifying }
    }
}

impl<C: ChainView> ChainSource for Source<C> {
    fn tip_height(&self) -> u32 {
        self.view.tip_height()
    }
    fn funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        self.view.funding_height(outpoint)
    }
    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus {
        self.view.spend_status(escrow_outpoint)
    }
    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid> {
        self.view.broadcast(tx_bytes)
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
    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus {
        self.authoritative_spend_status(escrow_outpoint)
    }
    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid> {
        DualSourceChainView::broadcast(self, tx_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn op(vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), vout)
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
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
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
            output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: ScriptBuf::new() }],
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
        let a = Source::new(SimChain::new(100), false);
        let b = Source::new(SimChain::new(100), false);
        assert!(DualSourceChainView::new(a, b).is_err());

        let a = Source::new(SimChain::new(100), true); // self-verifying
        let b = Source::new(SimChain::new(100), false);
        assert!(DualSourceChainView::new(a, b).is_ok());
    }

    #[test]
    fn agreeing_sources_pass_through() {
        // Both sources back the SAME chain (Arc clone) => always agree.
        let chain = SimChain::new(100);
        chain.fund(op(0), 100);
        let dual = DualSourceChainView::new(
            Source::new(chain.clone(), true),
            Source::new(chain.clone(), false),
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
            Source::new(honest, true), // self-verifying, says unconfirmed
            Source::new(other, false), // explorer, says confirmed
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
            Source::new(self_verifying, true),
            Source::new(lying_explorer, false),
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
            DualSourceChainView::new(Source::new(sv, true), Source::new(liar, false)).unwrap();

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
}
