//! Swap orchestrator (wallet rank 4): the wallet's decision loop OVER the
//! already-built settlement core. It adds NO cryptography — it sequences
//! funding, verifies encumbrance, and routes failures, driving the reviewed
//! seams (`await_funded`, `run_adaptor_exchange`, `refund::run`) and
//! persisting through the `SwapStore` + `Ledger`.
//!
//! Two poll-driven decision machines, both pure (clock/chain in, action out)
//! so the outer event loop stays testable and crash-re-enterable:
//!
//!   * `FundingCoordinator::next_funding_action` — v3.14 Phase 4. Fixes the
//!     funding ORDER by canonical session-pubkey sort (coordinator-free
//!     agreement — the SAME sort KeyAgg/role_seed use), gates the second
//!     funder on DEFERRED ENCUMBRANCE VERIFICATION of the first escrow
//!     (confirmed AND holding exactly the tier escrow amount, read through the dual-source
//!     `verified_funding` rule), enforces the co-funding window and the
//!     Block-X wallet-policy deadline, and applies per-party funding jitter.
//!
//!   * `AbortDriver::next_abort_action` — the re-enterable failure sink
//!     (v3.13 Operational State Machine). Completion-supersedes FIRST (never
//!     fight a winning completion — take the swap), else broadcast the
//!     pre-armed refund at CSV maturity, else wait; terminal reconciliation
//!     to Refunded/Completed. Idempotent: re-evaluates chain state on every
//!     entry, so a crash mid-abort just re-runs.
//!
//! OPEN QUESTION FOR THE CRYPTOGRAPHER (flagged in the review packet): the
//! spec says "SL-first funding minimizes the funded party's exposure", but
//! roles derive from the two confirmed txids + S only AFTER both escrows
//! confirm — so which party is SL is unknowable at funding time. This
//! coordinator fixes the order by canonical session-pubkey sort (the only
//! coordinator-free, both-wallets-agree option pre-role) and bounds exposure
//! symmetrically. Whether the spec intends a stronger SL-specifically-first
//! guarantee (which would need role pre-commitment) is a spec-resolution
//! item, not a code bug.

use crate::chain::{ChainView, SpendStatus};
use crate::crypto::ValidatedPoint;
use crate::settlement::params::Params;
use crate::settlement::refund::PreArmedRefund;
use crate::wallet::manifest::SignedManifest;
use crate::{Error, Result};
use bitcoin::OutPoint;

/// Which side of the canonical order we are — this fixes funding sequence,
/// NOT the settlement role (SH/SL derive later from txids+S).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingOrder {
    /// Canonically-smaller session pubkey: broadcasts its Setup first.
    First,
    /// Canonically-larger: funds only after verifying the first escrow.
    Second,
}

/// The coordinator's decision for this poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingAction {
    /// Broadcast our Setup now (order + jitter + any encumbrance precondition
    /// all satisfied).
    BroadcastOurSetup,
    /// Nothing to do yet: jitter still pending, our confirmation pending, or
    /// (second funder) the counterparty escrow not yet verified.
    Wait,
    /// Both escrows confirmed, within the window, before Block X, and the
    /// counterparty escrow holds exactly the tier escrow amount: proceed to `await_funded`
    /// and the exchange.
    Proceed { our_height: u32, their_height: u32, s_height: u32 },
    /// Abort to refunds and discard session state: Block-X deadline passed,
    /// co-funding window exceeded, or the counterparty escrow is not at
    /// D+Δ_fee (wrong/absent encumbrance).
    Abort(&'static str),
}

/// Immutable per-swap funding policy derived from the signed manifest.
pub struct FundingCoordinator {
    params: Params,
    /// Per-party jitter bound (blocks), from the manifest. Our own delay is
    /// sampled once in [0, jitter_max] and passed in as `jitter_ready`.
    cofunding_jitter_max: u32,
}

impl FundingCoordinator {
    pub fn from_manifest(manifest: &SignedManifest) -> Self {
        FundingCoordinator {
            params: manifest.params().clone(),
            cofunding_jitter_max: manifest.cofunding_jitter_max(),
        }
    }

    pub fn jitter_max(&self) -> u32 {
        self.cofunding_jitter_max
    }

    /// Canonical funding order from the two session pubkeys — the SAME
    /// lexicographic sort role_seed / KeyAgg use, so both wallets agree with
    /// no coordinator. Equal pubkeys are rejected (as everywhere else).
    pub fn funding_order(
        ours: &ValidatedPoint,
        theirs: &ValidatedPoint,
    ) -> Result<FundingOrder> {
        let (o, t) = (ours.to_bytes(), theirs.to_bytes());
        if o == t {
            return Err(Error::Validation("both parties presented the same session pubkey"));
        }
        Ok(if o < t { FundingOrder::First } else { FundingOrder::Second })
    }

    /// The escrow amount every tier participant funds: exactly
    /// D + Δ_fee − setup_cost (scheme (a) — the Setup pays its baked fee and
    /// anchor out of the pre-encumbrance coin). The encumbrance check
    /// compares the counterparty escrow against THIS. Checked arithmetic:
    /// hostile params get Err, never a wrapped amount.
    pub fn expected_escrow_amount(&self) -> Result<u64> {
        let pre = self
            .params
            .tier_d_sats
            .checked_add(self.params.delta_fee_sats)
            .ok_or(Error::Validation("tier overflow"))?;
        pre.checked_sub(self.params.setup_cost_sats())
            .ok_or(Error::Validation("setup cost exceeds the funding unit"))
    }

    /// Poll: decide the next funding action. Pure — all mutable state
    /// (whether our Setup is on the wire, whether our jitter has elapsed)
    /// comes in as arguments the outer loop tracks against the `SwapStore`.
    ///
    /// `chain` MUST be the dual-source view (or a single self-verifying
    /// source): `funding_height`/`funding_amount` already collapse to the
    /// verified reading, so a lying source cannot fabricate the encumbrance.
    #[allow(clippy::too_many_arguments)]
    pub fn next_funding_action(
        &self,
        chain: &dyn ChainView,
        order: FundingOrder,
        our_escrow: OutPoint,
        their_escrow: OutPoint,
        our_setup_broadcast: bool,
        jitter_ready: bool,
        block_x: u32,
    ) -> Result<FundingAction> {
        use crate::chain::FundingReading;
        let expected = self.expected_escrow_amount()?;
        let tip = chain.tip_height();

        // Block-X no-show judgment uses the AUTHORITATIVE (self-verifying)
        // funding heights: a lying non-authoritative source can DELAY but must
        // never be able to declare a genuinely-funded counterparty a no-show
        // (which would irreversibly abort an honest swap). The self-verifying
        // source cannot be fooled into hiding a confirmation.
        let our_auth = chain.authoritative_funding_height(our_escrow);
        let their_auth = chain.authoritative_funding_height(their_escrow);
        if tip >= block_x && !(our_auth.is_some() && their_auth.is_some()) {
            return Ok(FundingAction::Abort("Block X funding deadline passed; abandon to refunds"));
        }

        // Tri-state encumbrance read of the counterparty escrow. Only a
        // GENUINE wrong amount (both sources agree it is != the tier escrow amount) is a
        // hostile escrow that warrants a terminal Abort. A mere source
        // DISAGREEMENT (`Unverifiable`) or an un-reportable amount must NOT
        // abort — the self-verifying source holds the truth and we re-poll.
        let their_reading = chain.verified_funding_reading(their_escrow);
        if let FundingReading::Confirmed { amount: Some(a), .. } = their_reading {
            if a != expected {
                return Ok(FundingAction::Abort(
                    "counterparty escrow is not exactly the tier escrow amount; abort",
                ));
            }
        }
        // The counterparty escrow is VERIFIED-encumbered iff both sources
        // agree it is confirmed at exactly D+Δ_fee.
        let their_encumbrance_ok = matches!(
            their_reading,
            FundingReading::Confirmed { amount: Some(a), .. } if a == expected
        );

        // Have we funded yet?
        if !our_setup_broadcast {
            if !jitter_ready {
                return Ok(FundingAction::Wait);
            }
            return Ok(match order {
                // First funder broadcasts as soon as jitter elapses.
                FundingOrder::First => FundingAction::BroadcastOurSetup,
                // Second funder funds only after the first escrow is VERIFIED
                // at exactly D+Δ_fee.
                FundingOrder::Second => {
                    if their_encumbrance_ok {
                        FundingAction::BroadcastOurSetup
                    } else {
                        FundingAction::Wait
                    }
                }
            });
        }

        // We have funded; the proceed-to-sign gate stays AGREEMENT-REQUIRED
        // (never proceed on unverified state): wait for both confirmations on
        // the cross-verified reading.
        let (Some(oh), Some(th)) = (chain.funding_height(our_escrow), chain.funding_height(their_escrow))
        else {
            return Ok(FundingAction::Wait);
        };

        // Both confirmed: enforce the co-funding window.
        if oh.abs_diff(th) > self.params.cofunding_window {
            return Ok(FundingAction::Abort("co-funding window exceeded; abandon to refunds"));
        }
        // Final encumbrance gate: proceed only when VERIFIED at D+Δ_fee. If it
        // is merely unverifiable (source disagreement), WAIT — never abort an
        // honestly-funded swap on a single lying source. (A persistent liar
        // degrades to refund-at-maturity, a delay, never theft.)
        if !their_encumbrance_ok {
            return Ok(FundingAction::Wait);
        }
        Ok(FundingAction::Proceed {
            our_height: oh,
            their_height: th,
            s_height: oh.max(th),
        })
    }
}

/// The abort/refund driver's decision for this poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortAction {
    /// A counterparty completion is WINNING against our escrow (in mempool or
    /// confirmed): do NOT refund. If we are SL, take the swap
    /// (restore→extract→claim); if we are SH, our leg already resolved.
    TakeTheSwap,
    /// Our refund CSV has matured and no completion is winning: broadcast the
    /// pre-armed refund.
    BroadcastRefund,
    /// Neither yet — refund immature and no completion present: wait.
    Wait,
    /// Terminal: our refund confirmed (funds reclaimed).
    Refunded,
    /// Terminal: a completion confirmed against our escrow (swap went through
    /// / was superseded).
    Completed,
}

/// The wallet-level abort/refund subroutine. Wraps the settlement
/// `completion-supersedes` rule with terminal reconciliation and makes it
/// re-enterable from a persisted `SwapRecord` (chain state re-read every
/// entry — crash-safe by construction).
pub struct AbortDriver;

impl AbortDriver {
    /// Decide the next action for a swap that has entered the abort path.
    /// `our_escrow` is the outpoint OUR pre-armed refund would spend (the
    /// escrow we funded). `refund` supplies the CSV maturity height.
    ///
    /// Ordering mirrors `refund::should_refund` but adds the two TERMINAL
    /// states the wallet must reconcile to (the settlement `run` returns
    /// Err/Ok; the wallet needs to know when to stop polling):
    ///   1. our escrow spent+confirmed by a completion  → Completed
    ///      (unless it is OUR OWN refund that confirmed  → Refunded)
    ///   2. completion in mempool / confirmed-by-them    → TakeTheSwap
    ///   3. refund matured, escrow unspent               → BroadcastRefund
    ///   4. otherwise                                    → Wait
    pub fn next_abort_action(
        chain: &dyn ChainView,
        our_escrow: OutPoint,
        refund: &PreArmedRefund,
        our_refund_txid: Option<bitcoin::Txid>,
    ) -> AbortAction {
        match chain.spend_status(our_escrow) {
            SpendStatus::Confirmed(_) => {
                // Someone swept our escrow and it confirmed. If it was our
                // own refund, we are Refunded; otherwise a completion won.
                match (our_refund_txid, spend_txid(chain, our_escrow)) {
                    (Some(mine), Some(seen)) if mine == seen => AbortAction::Refunded,
                    _ => AbortAction::Completed,
                }
            }
            // A completion is in flight against our escrow: never fight it.
            SpendStatus::InMempool => {
                // If the in-mempool spend is OUR OWN refund (we broadcast it
                // and it hasn't confirmed), keep waiting for it; otherwise a
                // counterparty completion is winning → take the swap.
                match (our_refund_txid, spend_txid(chain, our_escrow)) {
                    (Some(mine), Some(seen)) if mine == seen => AbortAction::Wait,
                    _ => AbortAction::TakeTheSwap,
                }
            }
            SpendStatus::Unspent => {
                if chain.tip_height() >= refund.csv_maturity_height() {
                    AbortAction::BroadcastRefund
                } else {
                    AbortAction::Wait
                }
            }
        }
    }
}

/// The txid currently spending an outpoint (mempool or confirmed), if any.
/// Used only to distinguish OUR refund from a counterparty completion; a
/// view that cannot report it collapses to "not ours" (conservative: we then
/// treat an unknown spend as a winning completion and take the swap rather
/// than double-spend).
fn spend_txid(chain: &dyn ChainView, outpoint: OutPoint) -> Option<bitcoin::Txid> {
    chain.spend_txid(outpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::SimChain;

    fn vp(seed: u8) -> ValidatedPoint {
        // A valid point: (seed+1) * G, serialized and re-validated.
        let mut b = [0u8; 32];
        b[31] = seed + 1; // nonzero scalar
        let s = secp::Scalar::from_slice(&b).unwrap();
        ValidatedPoint::from_bytes(&(s * secp::G).serialize()).unwrap()
    }

    fn op(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b)), 0)
    }

    fn coord() -> FundingCoordinator {
        FundingCoordinator {
            params: Params::testnet_provisional(),
            cofunding_jitter_max: 6,
        }
    }

    fn unit() -> u64 {
        // The ESCROW amount the encumbrance gate expects (scheme (a)).
        Params::testnet_provisional().escrow_amount_sats()
    }

    #[test]
    fn funding_order_is_canonical_and_agreed() {
        let a = vp(1);
        let b = vp(2);
        let (oa, ob) = (
            FundingCoordinator::funding_order(&a, &b).unwrap(),
            FundingCoordinator::funding_order(&b, &a).unwrap(),
        );
        assert_ne!(oa, ob, "the two wallets must derive opposite roles");
        assert!(matches!((oa, ob), (FundingOrder::First, FundingOrder::Second) | (FundingOrder::Second, FundingOrder::First)));
        // Equal pubkeys rejected.
        assert!(FundingCoordinator::funding_order(&a, &a).is_err());
    }

    #[test]
    fn first_funder_waits_for_jitter_then_broadcasts() {
        let c = coord();
        let chain = SimChain::new(1_000);
        // jitter not ready → Wait.
        assert_eq!(
            c.next_funding_action(&chain, FundingOrder::First, op(1), op(2), false, false, 2_000)
                .unwrap(),
            FundingAction::Wait
        );
        // jitter ready, nothing funded → broadcast ours first.
        assert_eq!(
            c.next_funding_action(&chain, FundingOrder::First, op(1), op(2), false, true, 2_000)
                .unwrap(),
            FundingAction::BroadcastOurSetup
        );
    }

    #[test]
    fn second_funder_gates_on_verified_encumbrance() {
        let c = coord();
        let chain = SimChain::new(1_000);
        // Counterparty escrow not yet confirmed → Wait even with jitter ready.
        assert_eq!(
            c.next_funding_action(&chain, FundingOrder::Second, op(1), op(2), false, true, 2_000)
                .unwrap(),
            FundingAction::Wait
        );
        // Counterparty escrow confirmed but at the WRONG amount → Abort.
        chain.fund_with_amount(op(2), 1_001, unit() - 1);
        assert_eq!(
            c.next_funding_action(&chain, FundingOrder::Second, op(1), op(2), false, true, 2_000)
                .unwrap(),
            FundingAction::Abort("counterparty escrow is not exactly the tier escrow amount; abort")
        );
    }

    #[test]
    fn second_funder_broadcasts_once_encumbrance_verified() {
        let c = coord();
        let chain = SimChain::new(1_000);
        chain.fund_with_amount(op(2), 1_001, unit()); // theirs, exactly D+fee
        assert_eq!(
            c.next_funding_action(&chain, FundingOrder::Second, op(1), op(2), false, true, 2_000)
                .unwrap(),
            FundingAction::BroadcastOurSetup
        );
    }

    #[test]
    fn block_x_deadline_aborts_a_stalled_funding() {
        let c = coord();
        let chain = SimChain::new(2_000); // tip == block_x
        // Only ours confirmed; theirs never came, past Block X → Abort.
        chain.fund_with_amount(op(1), 1_999, unit());
        assert_eq!(
            c.next_funding_action(&chain, FundingOrder::First, op(1), op(2), true, true, 2_000)
                .unwrap(),
            FundingAction::Abort("Block X funding deadline passed; abandon to refunds")
        );
    }

    #[test]
    fn proceed_only_within_window_and_at_correct_encumbrance() {
        let c = coord();
        let cw = Params::testnet_provisional().cofunding_window;

        // Within window → Proceed with S = later height.
        let chain = SimChain::new(1_000);
        chain.fund_with_amount(op(1), 1_000, unit());
        chain.fund_with_amount(op(2), 1_000 + cw, unit());
        assert_eq!(
            c.next_funding_action(&chain, FundingOrder::First, op(1), op(2), true, true, 5_000)
                .unwrap(),
            FundingAction::Proceed { our_height: 1_000, their_height: 1_000 + cw, s_height: 1_000 + cw }
        );

        // Skew beyond the window → Abort.
        let chain = SimChain::new(1_000);
        chain.fund_with_amount(op(1), 1_000, unit());
        chain.fund_with_amount(op(2), 1_000 + cw + 1, unit());
        assert_eq!(
            c.next_funding_action(&chain, FundingOrder::First, op(1), op(2), true, true, 5_000)
                .unwrap(),
            FundingAction::Abort("co-funding window exceeded; abandon to refunds")
        );
    }

    // ----- AbortDriver -----

    fn refund(maturity: u32) -> PreArmedRefund {
        PreArmedRefund::from_signed_tx(vec![0xab; 64], maturity).unwrap()
    }

    #[test]
    fn abort_waits_until_refund_matures_then_broadcasts() {
        let chain = SimChain::new(500);
        chain.fund(op(1), 500);
        let r = refund(600);
        // Immature, escrow unspent → Wait.
        assert_eq!(
            AbortDriver::next_abort_action(&chain, op(1), &r, None),
            AbortAction::Wait
        );
        // Matured, still unspent → BroadcastRefund.
        while chain.tip_height() < 600 {
            chain.mine();
        }
        assert_eq!(
            AbortDriver::next_abort_action(&chain, op(1), &r, None),
            AbortAction::BroadcastRefund
        );
    }

    #[test]
    fn abort_never_fights_a_winning_completion() {
        let chain = SimChain::new(500);
        chain.fund_with_amount(op(1), 500, unit());
        // A counterparty completion appears in the mempool against our escrow.
        let comp = spend_of(op(1), unit() - 200);
        chain.broadcast(&comp).unwrap();
        let r = refund(600);
        // Even past maturity, a winning completion means TAKE THE SWAP.
        while chain.tip_height() < 700 {
            chain.mine();
        }
        // (mining confirms the completion → Completed terminal.)
        assert_eq!(
            AbortDriver::next_abort_action(&chain, op(1), &r, None),
            AbortAction::Completed
        );
    }

    #[test]
    fn abort_reconciles_terminal_states_by_who_spent() {
        // Our own refund confirmed → Refunded (not Completed).
        let chain = SimChain::new(500);
        chain.fund(op(1), 500);
        while chain.tip_height() < 600 {
            chain.mine();
        }
        // A REAL refund tx spending our escrow (so the sim gives it a txid).
        let refund_bytes = spend_of(op(1), 400);
        let r = PreArmedRefund::from_signed_tx(refund_bytes.clone(), 600).unwrap();
        let refund_txid = chain.broadcast(r.tx_bytes()).unwrap();
        assert_eq!(
            AbortDriver::next_abort_action(&chain, op(1), &r, Some(refund_txid)),
            AbortAction::Wait,
            "our refund is in the mempool; keep waiting for it"
        );
        chain.mine();
        assert_eq!(
            AbortDriver::next_abort_action(&chain, op(1), &r, Some(refund_txid)),
            AbortAction::Refunded
        );
    }

    #[test]
    fn abort_in_mempool_completion_is_take_the_swap_not_wait() {
        let chain = SimChain::new(500);
        chain.fund_with_amount(op(1), 500, unit());
        let comp = spend_of(op(1), unit() - 200);
        let _ = chain.broadcast(&comp).unwrap();
        let r = refund(600);
        // Their completion pends in mempool; we never broadcast a refund
        // (our_refund_txid = None) → the mempool spend is theirs → take the
        // swap, do not passively wait.
        assert_eq!(
            AbortDriver::next_abort_action(&chain, op(1), &r, None),
            AbortAction::TakeTheSwap
        );
        // And if it were OUR refund in the mempool, we'd Wait for it instead.
        assert_eq!(
            AbortDriver::next_abort_action(&chain, op(1), &r, Some(txid_of(&comp))),
            AbortAction::Wait
        );
    }

    /// A standard P2TR-shaped scriptPubKey (`OP_1 <32 bytes>`). The relay-policy
    /// gate rejects an empty (non-standard) spk, so fixtures must look real.
    fn std_p2tr_spk() -> bitcoin::ScriptBuf {
        let mut v = vec![0x51u8, 0x20];
        v.extend_from_slice(&[0x77u8; 32]);
        bitcoin::ScriptBuf::from_bytes(v)
    }

    // Build a minimal signed spend of `outpoint` paying `out` sats to a
    // standard scriptpubkey, so the SimChain sees a spend with a real txid.
    fn spend_of(outpoint: OutPoint, out: u64) -> Vec<u8> {
        use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: std_p2tr_spk() }],
        };
        bitcoin::consensus::encode::serialize(&tx)
    }

    fn txid_of(tx_bytes: &[u8]) -> bitcoin::Txid {
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(tx_bytes).unwrap();
        tx.compute_txid()
    }
}
