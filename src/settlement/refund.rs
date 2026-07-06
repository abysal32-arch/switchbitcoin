//! Refund / abort subroutine — completion-supersedes (v3.14 §Operational State
//! Machine). The safe sink for EVERY failure path. Idempotent; safe to re-enter
//! after a crash.
//!
//! It is invoked whenever anything returns `Error::Abort` (or on deadline). The
//! golden rule: before broadcasting a refund, RE-CHECK whether the counterparty's
//! completion is winning; if it is, DON'T fight it — take the successful swap.
//! A needless refund wastes fees AND reveals the script leaf (privacy loss).

use crate::{Error, Result};
use bitcoin::hashes::{sha256, Hash};

/// A refund transaction signed and stored BEFORE any completion is broadcast
/// (v3.13 pre-armed refunds). The watchtower can broadcast it even if this device
/// is dead — this is what makes gate G2 crash-safe. Pays the owner's own address.
///
/// Constructed from a FULLY-SIGNED transaction: `arm` (the tx-layer fill point)
/// builds and signs it; `from_signed_tx` wraps bytes the tx layer produced.
/// This module does not re-verify the signature — that is the tx layer's job at
/// construction; what G2 needs from this type is existence-before-broadcast.
#[derive(Clone, Debug)]
pub struct PreArmedRefund {
    signed_tx: Vec<u8>,
    csv_maturity_height: u32,
}

impl PreArmedRefund {
    /// Build and sign the refund NOW, before broadcasting any completion (G2).
    ///
    /// Script-path spend of the escrow's CSV leaf: build the refund tx (input
    /// nSequence = the leaf's relative CSV), sign the BIP341 script-path sighash
    /// with the funder's own key, attach the `[sig, leaf, control_block]`
    /// witness, and store the fully-signed bytes. The stored tx is broadcastable
    /// by the watchtower the moment `S + csv_blocks` is reached — this is what
    /// makes gate G2 crash-safe.
    pub fn arm(
        escrow: &crate::tx::escrow::Escrow,
        funding_outpoint: bitcoin::OutPoint,
        escrow_amount_sats: u64,
        funder_seckey: &secp::Scalar,
        dest_spk: bitcoin::ScriptBuf,
        out_amount_sats: u64,
        s_height: u32,
    ) -> Result<Self> {
        let spend = crate::tx::txbuild::build_refund(
            escrow,
            funding_outpoint,
            escrow_amount_sats,
            dest_spk,
            out_amount_sats,
        )?;
        let sig = crate::tx::txbuild::sign_schnorr_single(funder_seckey.serialize(), spend.sighash)?;
        let signed = crate::tx::txbuild::finalize_refund(spend, escrow, sig)?;
        let csv_maturity_height = s_height
            .checked_add(escrow.csv_blocks() as u32)
            .ok_or(Error::Deadline("refund CSV maturity overflows the height field"))?;
        PreArmedRefund::from_signed_tx(signed, csv_maturity_height)
    }

    /// Wrap an already fully-signed refund transaction produced by the tx layer.
    pub fn from_signed_tx(signed_tx: Vec<u8>, csv_maturity_height: u32) -> Result<Self> {
        if signed_tx.is_empty() {
            return Err(Error::Validation("refund tx must not be empty"));
        }
        Ok(PreArmedRefund { signed_tx, csv_maturity_height })
    }

    pub fn csv_maturity_height(&self) -> u32 {
        self.csv_maturity_height
    }

    pub fn tx_bytes(&self) -> &[u8] {
        &self.signed_tx
    }

    /// Stable identifier for handoff acknowledgement: SHA-256 of the signed tx.
    pub fn fingerprint(&self) -> [u8; 32] {
        sha256::Hash::hash(&self.signed_tx).to_byte_array()
    }
}

/// Witness that an armed watchtower holds THIS pre-armed refund (gate G2's
/// second half). Non-constructible except via `confirm_watchtower_handoff`,
/// which demands the watchtower echo the refund's fingerprint back — a caller
/// cannot conjure one by passing `true` somewhere. Non-`Clone`: one receipt per
/// handoff.
#[derive(Debug)]
pub struct WatchtowerReceipt {
    refund_fingerprint: [u8; 32],
}

impl WatchtowerReceipt {
    pub fn matches(&self, refund: &PreArmedRefund) -> bool {
        self.refund_fingerprint == refund.fingerprint()
    }
}

/// Complete the watchtower handoff: the watchtower proves receipt by echoing
/// the refund fingerprint (over the authenticated watchtower channel — the
/// channel itself is infrastructure the tx/network layer provides). Wrong echo
/// => no receipt => `broadcast_completion` stays locked (G2).
pub fn confirm_watchtower_handoff(
    refund: &PreArmedRefund,
    ack_fingerprint: [u8; 32],
) -> Result<WatchtowerReceipt> {
    if ack_fingerprint != refund.fingerprint() {
        return Err(Error::Deadline(
            "watchtower ack does not match the pre-armed refund; G2 not satisfied",
        ));
    }
    Ok(WatchtowerReceipt { refund_fingerprint: ack_fingerprint })
}

/// What the chain view told us about the counterparty's completion.
pub enum CompletionStatus {
    Confirmed,
    InMempool,
    Absent,
}

/// The completion-supersedes decision. Call BEFORE broadcasting any refund.
/// Returns Ok(()) meaning "refund broadcast is appropriate"; Err(Abort(..)) with
/// a "completion winning" reason meaning "do NOT refund, follow the swap path".
///
/// NOTE for the `run` fill: `InMempool` must route to the EXTRACTION path, not
/// to passive waiting — a visible completion exposes s_final, so the correct
/// response is to extract and complete our own leg (a counterparty who parks a
/// low-fee completion in the mempool is handing us the secret, not delaying us).
pub fn should_refund(status: CompletionStatus, refund_matured: bool) -> Result<()> {
    match status {
        CompletionStatus::Confirmed | CompletionStatus::InMempool => {
            // Do NOT fight a winning completion.
            Err(Error::Abort("counterparty completion is winning; take the swap, do not refund"))
        }
        CompletionStatus::Absent if refund_matured => Ok(()),
        CompletionStatus::Absent => Err(Error::Deadline("refund not yet matured")),
    }
}

/// Map the chain's view of our escrow output to a completion status. Because
/// `run` is called BEFORE we broadcast our own refund, any spend of the escrow
/// is necessarily the counterparty's completion.
fn completion_status_of(
    chain: &impl crate::chain::ChainView,
    escrow_outpoint: bitcoin::OutPoint,
) -> CompletionStatus {
    match chain.spend_status(escrow_outpoint) {
        crate::chain::SpendStatus::Confirmed(_) => CompletionStatus::Confirmed,
        crate::chain::SpendStatus::InMempool => CompletionStatus::InMempool,
        crate::chain::SpendStatus::Unspent => CompletionStatus::Absent,
    }
}

/// Run the refund subroutine against a chain view. Idempotent and crash-safe:
/// re-checking status on every entry means a crash mid-refund simply
/// re-evaluates on restart.
///
/// Completion-supersedes: if the counterparty's completion is winning
/// (confirmed or in mempool), this returns `Err(Abort("...take the swap..."))`
/// — do NOT fight it (extraction, not refund, is the response). Otherwise, once
/// the CSV has matured, broadcast the pre-armed refund. The chain view enforces
/// the relative timelock and the no-double-spend rule, so a completion that
/// confirms first wins deterministically.
pub fn run(
    refund: &PreArmedRefund,
    chain: &impl crate::chain::ChainView,
    escrow_outpoint: bitcoin::OutPoint,
) -> Result<()> {
    let matured = chain.tip_height() >= refund.csv_maturity_height();
    let status = completion_status_of(chain, escrow_outpoint);
    // May return Err(Abort) meaning "completion winning; take the swap".
    should_refund(status, matured)?;
    // Appropriate to refund: broadcast it. The chain view rejects it if the CSV
    // is somehow not yet matured or the output was spent out from under us
    // (either => a completion is winning, so surfacing the error is correct).
    chain.broadcast(refund.tx_bytes())?;
    Ok(())
}

/// A watchtower holding a pre-armed refund on the owner's behalf. It can fire
/// the refund even if the owner's device is dead (gate G2 crash-safety), and it
/// respects completion-supersedes so it never fights a winning completion.
pub struct Watchtower {
    refund: PreArmedRefund,
    escrow_outpoint: bitcoin::OutPoint,
}

impl Watchtower {
    /// Arm the watchtower with a refund whose fingerprint the owner acknowledged
    /// (the same `WatchtowerReceipt` that satisfies gate G2).
    pub fn arm(
        refund: PreArmedRefund,
        escrow_outpoint: bitcoin::OutPoint,
        receipt: &WatchtowerReceipt,
    ) -> Result<Self> {
        if !receipt.matches(&refund) {
            return Err(Error::Deadline("watchtower receipt does not cover this refund"));
        }
        Ok(Watchtower { refund, escrow_outpoint })
    }

    /// Poll the chain and fire the refund if (and only if) it is both matured
    /// and not superseded by a winning completion. Returns Ok(true) if the
    /// refund was broadcast this poll, Ok(false) if there is nothing to do yet,
    /// Err(Abort) if a completion is winning (owner should take the swap).
    pub fn poll(&self, chain: &impl crate::chain::ChainView) -> Result<bool> {
        match run(&self.refund, chain, self.escrow_outpoint) {
            Ok(()) => Ok(true),
            // "not yet matured" is a normal not-yet-actionable state, not an error.
            Err(Error::Deadline(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_supersedes_decision_table() {
        assert!(should_refund(CompletionStatus::Absent, true).is_ok());
        assert!(matches!(
            should_refund(CompletionStatus::Absent, false),
            Err(Error::Deadline(_))
        ));
        assert!(matches!(
            should_refund(CompletionStatus::Confirmed, true),
            Err(Error::Abort(_))
        ));
        assert!(matches!(
            should_refund(CompletionStatus::InMempool, true),
            Err(Error::Abort(_))
        ));
    }

    #[test]
    fn arm_produces_a_signed_script_path_refund() {
        let mut rng = rand::rng();
        let sk = secp::Scalar::random(&mut rng);
        let other = secp::Scalar::random(&mut rng);
        let mut keys = [sk * secp::G, other * secp::G];
        keys.sort_by_key(|p| p.serialize());
        let ctx = musig2::KeyAggContext::new(keys).unwrap();
        let internal: secp::Point = ctx.aggregated_pubkey_untweaked();
        let funder = sk * secp::G;
        let escrow = crate::tx::escrow::Escrow::new(&internal, &funder, 144).unwrap();
        let outpoint =
            bitcoin::OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), 0);
        let dest = escrow.funding_script_pubkey().clone();

        let refund =
            PreArmedRefund::arm(&escrow, outpoint, 1_005_000, &sk, dest, 1_000_000, 800_000).unwrap();
        assert_eq!(refund.csv_maturity_height(), 800_000 + 144);

        // The stored bytes are a real, version-2 tx with the CSV relative lock
        // and a complete 3-element script-path witness.
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(refund.tx_bytes()).unwrap();
        assert_eq!(tx.version, bitcoin::transaction::Version::TWO);
        assert!(tx.input[0].sequence.is_relative_lock_time());
        assert_eq!(tx.input[0].witness.len(), 3);
    }

    #[test]
    fn watchtower_receipt_requires_matching_echo() {
        let refund = PreArmedRefund::from_signed_tx(vec![1, 2, 3], 100).unwrap();
        assert!(confirm_watchtower_handoff(&refund, [0u8; 32]).is_err());
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
        assert!(receipt.matches(&refund));
        let other = PreArmedRefund::from_signed_tx(vec![9, 9], 100).unwrap();
        assert!(!receipt.matches(&other));
    }
}
