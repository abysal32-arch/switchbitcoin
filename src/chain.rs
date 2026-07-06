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
    funded: HashMap<OutPoint, u32>,
    /// escrow outpoint -> (spending txid, confirmed height | None = mempool)
    spends: HashMap<OutPoint, (Txid, Option<u32>)>,
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
        })))
    }

    /// Record a confirmed funding output at the given height.
    pub fn fund(&self, outpoint: OutPoint, height: u32) {
        self.0.lock().unwrap().funded.insert(outpoint, height);
    }

    /// Mine one block: every mempool spend confirms at the new tip height.
    pub fn mine(&self) {
        let mut g = self.0.lock().unwrap();
        g.height += 1;
        let h = g.height;
        for (_op, (_txid, conf)) in g.spends.iter_mut() {
            if conf.is_none() {
                *conf = Some(h);
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
        if let Some((_txid, None)) = g.spends.get(&outpoint) {
            g.spends.remove(&outpoint);
        }
    }
}

impl ChainView for SimChain {
    fn tip_height(&self) -> u32 {
        self.0.lock().unwrap().height
    }

    fn funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        self.0.lock().unwrap().funded.get(&outpoint).copied()
    }

    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus {
        match self.0.lock().unwrap().spends.get(&escrow_outpoint) {
            None => SpendStatus::Unspent,
            Some((_, None)) => SpendStatus::InMempool,
            Some((_, Some(h))) => SpendStatus::Confirmed(*h),
        }
    }

    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid> {
        let tx: Transaction = bitcoin::consensus::encode::deserialize(tx_bytes)
            .map_err(|_| Error::Validation("broadcast: undecodable transaction"))?;
        let txid = tx.compute_txid();
        let mut g = self.0.lock().unwrap();
        let tip = g.height;

        // Validate every input before mutating (all-or-nothing acceptance).
        for input in &tx.input {
            let op = input.previous_output;
            let funding_height = *g
                .funded
                .get(&op)
                .ok_or(Error::Validation("broadcast: input spends an unfunded output"))?;

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

            // No double spend of a confirmed output; first-seen wins the mempool.
            match g.spends.get(&op) {
                Some((existing, _)) if *existing == txid => {} // idempotent re-broadcast
                Some((_, Some(_))) => {
                    return Err(Error::Abort("broadcast: output already spent (confirmed)"))
                }
                Some((_, None)) => {
                    return Err(Error::Abort("broadcast: output already in mempool (conflict)"))
                }
                None => {}
            }
        }

        for input in &tx.input {
            g.spends.insert(input.previous_output, (txid, None));
        }
        Ok(txid)
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
}
