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
    /// TX-LAYER FILL POINT: needs escrow outpoint, own key, CSV height, params.
    pub fn arm(/* escrow, own key, csv height, params */) -> Result<Self> {
        Err(Error::Unimplemented("PreArmedRefund::arm: sign script-path refund up front (tx layer)"))
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

/// Run the refund subroutine. Idempotent and crash-safe: re-checking status on
/// every entry means a crash mid-refund simply re-evaluates on restart.
/// CHAIN-LAYER FILL POINT (needs the dual-source chain view + Tor broadcast).
pub fn run(_refund: &PreArmedRefund /*, chain view, watchtower */) -> Result<()> {
    // IMPLEMENT:
    //   loop-ish (event driven):
    //     let status = dual_source_completion_status();   // self-verifying
    //     should_refund(status, matured)?;                // may say "take the swap"
    //     broadcast pre-armed refund over dedicated Tor circuit;
    //     if it stalls -> escalate via anchor+reserve backstop (silent for refunds);
    //   if completion appears after we broadcast: CSV ordering decides; never
    //   double-spend against ourselves; reconcile to whichever confirms.
    Err(Error::Unimplemented("refund::run: completion-supersedes, Tor broadcast, deterministic reconciliation"))
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
    fn watchtower_receipt_requires_matching_echo() {
        let refund = PreArmedRefund::from_signed_tx(vec![1, 2, 3], 100).unwrap();
        assert!(confirm_watchtower_handoff(&refund, [0u8; 32]).is_err());
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
        assert!(receipt.matches(&refund));
        let other = PreArmedRefund::from_signed_tx(vec![9, 9], 100).unwrap();
        assert!(!receipt.matches(&other));
    }
}
