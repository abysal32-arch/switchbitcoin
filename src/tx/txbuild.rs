//! Completion / refund transaction construction and BIP341 sighashes.
//!
//! Completion legs (Comp->SH, Comp->SL) are KEY-PATH spends of the escrow (the
//! MuSig2 aggregate, taproot-tweaked). Refund legs are SCRIPT-PATH spends of the
//! CSV leaf. The 32-byte sighashes produced here are exactly the messages the
//! MuSig2 signer signs — they replace the placeholder sighashes the crypto-core
//! tests use.

use crate::tx::escrow::Escrow;
use crate::{Error, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSig;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{absolute, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// A spend transaction plus the 32-byte sighash the signer must sign.
#[derive(Clone)]
pub struct SpendTx {
    pub tx: Transaction,
    pub sighash: [u8; 32],
}

/// TRUC / BIP431 topology version. Every contract transaction (Setup,
/// Completion, Refund) is version 3 for its RBF-pinning protection (v3.13).
const TRUC_VERSION: Version = Version(3);

/// The ephemeral anchor output (P2A, BIP336): `OP_1 <0x4e73>`, 0 value. Every
/// contract tx carries one so a CPFP child can bump it ONLY under a genuine fee
/// spike beyond the baked-in Δ_fee — a congestion-only, opt-in backstop
/// (v3.13). On the happy path it is left unspent, so it adds no external link.
fn ephemeral_anchor() -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]),
    }
}

fn escrow_prevout(escrow: &Escrow, escrow_amount_sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(escrow_amount_sats),
        script_pubkey: escrow.funding_script_pubkey().clone(),
    }
}

/// Build a COMPLETION transaction (key-path spend of the escrow) and its
/// BIP341 key-spend sighash. `dest_spk` receives exactly `out_amount_sats`
/// (the swap output D); the fee is `escrow_amount - out_amount`.
///
/// The completion input is RBF-enabled with no relative timelock (it must be
/// spendable as soon as the escrow confirms).
pub fn build_completion(
    escrow: &Escrow,
    escrow_outpoint: OutPoint,
    escrow_amount_sats: u64,
    dest_spk: ScriptBuf,
    out_amount_sats: u64,
) -> Result<SpendTx> {
    let tx = Transaction {
        version: TRUC_VERSION,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: escrow_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        // Output 0 is exactly D to the fresh destination; output 1 is the
        // 0-value ephemeral anchor (congestion-only backstop). No change output.
        output: vec![
            TxOut { value: Amount::from_sat(out_amount_sats), script_pubkey: dest_spk },
            ephemeral_anchor(),
        ],
    };
    let prevout = escrow_prevout(escrow, escrow_amount_sats);
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
        .map_err(|_| Error::Abort("completion key-spend sighash"))?
        .to_byte_array();
    Ok(SpendTx { tx, sighash })
}

/// Build a REFUND transaction (script-path spend of the CSV leaf) and its
/// BIP341 script-spend sighash. The input's nSequence encodes the SAME relative
/// CSV as the leaf, so the spend is only valid once `csv_blocks` have elapsed
/// since the escrow confirmed.
pub fn build_refund(
    escrow: &Escrow,
    escrow_outpoint: OutPoint,
    escrow_amount_sats: u64,
    dest_spk: ScriptBuf,
    out_amount_sats: u64,
) -> Result<SpendTx> {
    let tx = Transaction {
        version: TRUC_VERSION,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: escrow_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(escrow.csv_blocks()),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut { value: Amount::from_sat(out_amount_sats), script_pubkey: dest_spk },
            ephemeral_anchor(),
        ],
    };
    let prevout = escrow_prevout(escrow, escrow_amount_sats);
    let leaf_hash = TapLeafHash::from_script(escrow.refund_leaf().as_script(), LeafVersion::TapScript);
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|_| Error::Abort("refund script-spend sighash"))?
        .to_byte_array();
    Ok(SpendTx { tx, sighash })
}

/// Sign a script-path (single-key) BIP340 schnorr signature over `sighash` with
/// the refund key. Deterministic (no aux randomness) so re-arming is stable.
/// The keypair's x-only pubkey must equal the refund leaf's key (both derive
/// from the same scalar), so the CHECKSIG verifies.
pub fn sign_schnorr_single(seckey_bytes: [u8; 32], sighash: [u8; 32]) -> Result<[u8; 64]> {
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_slice(&secp, &seckey_bytes)
        .map_err(|_| Error::Validation("invalid refund secret key"))?;
    let msg = Message::from_digest(sighash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    Ok(out)
}

/// Attach the taproot KEY-PATH witness (a single 64-byte signature) to a
/// completion and serialize the fully-signed transaction, ready to broadcast.
pub fn finalize_key_spend(mut spend: SpendTx, sig64: [u8; 64]) -> Vec<u8> {
    let mut w = Witness::new();
    w.push(sig64);
    spend.tx.input[0].witness = w;
    bitcoin::consensus::encode::serialize(&spend.tx)
}

/// Attach the script-path refund witness `[sig, leaf_script, control_block]` and
/// serialize the fully-signed transaction (consensus encoding). This is what the
/// watchtower can broadcast even if the owner's device is dead (G2 crash-safety).
pub fn finalize_refund(mut spend: SpendTx, escrow: &Escrow, sig64: [u8; 64]) -> Result<Vec<u8>> {
    let control_block = escrow.refund_control_block()?;
    let mut w = Witness::new();
    w.push(sig64);
    w.push(escrow.refund_leaf().as_bytes());
    w.push(control_block.serialize());
    spend.tx.input[0].witness = w;
    Ok(bitcoin::consensus::encode::serialize(&spend.tx))
}

/// Independent spendability proof, computed on the BITCOIN side (secp256k1 0.29):
/// verify a 64-byte BIP340 signature against the escrow's taproot OUTPUT key and
/// the given sighash. If this passes, the completion signature the MuSig2 stack
/// produced is a valid taproot key-path witness for the funded UTXO — i.e. the
/// output is genuinely spendable, proven across the crypto/tx version boundary.
pub fn verify_taproot_key_spend(
    output_key_xonly: [u8; 32],
    sighash: [u8; 32],
    sig64: &[u8; 64],
) -> Result<()> {
    let secp = Secp256k1::verification_only();
    let sig = SchnorrSig::from_slice(sig64)
        .map_err(|_| Error::Verification("malformed schnorr signature"))?;
    let msg = Message::from_digest(sighash);
    let key = XOnlyPublicKey::from_slice(&output_key_xonly)
        .map_err(|_| Error::Verification("invalid output key"))?;
    secp.verify_schnorr(&sig, &msg, &key)
        .map_err(|_| Error::Verification("taproot key-spend signature does not verify"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_outpoint() -> OutPoint {
        OutPoint::new(bitcoin::Txid::all_zeros(), 0)
    }

    #[test]
    fn completion_and_refund_sighashes_differ_and_are_stable() {
        // Build a minimal escrow to spend.
        let mut rng = rand::rng();
        let sk_a = secp::Scalar::random(&mut rng);
        let sk_b = secp::Scalar::random(&mut rng);
        let internal: secp::Point = crate::settlement::state_machine::canonical_internal_key(
            sk_a * secp::G,
            sk_b * secp::G,
        )
        .unwrap();
        let escrow = Escrow::new(&internal, &(sk_a * secp::G), 216).unwrap();

        let dest = escrow.funding_script_pubkey().clone(); // any spk
        let c = build_completion(&escrow, dummy_outpoint(), 1_005_000, dest.clone(), 1_000_000).unwrap();
        let r = build_refund(&escrow, dummy_outpoint(), 1_005_000, dest, 1_000_000).unwrap();

        // Key-path and script-path sighashes over the same spend must differ.
        assert_ne!(c.sighash, r.sighash);
        // Deterministic: same inputs, same sighash.
        let c2 = build_completion(
            &escrow, dummy_outpoint(), 1_005_000,
            escrow.funding_script_pubkey().clone(), 1_000_000,
        )
        .unwrap();
        assert_eq!(c.sighash, c2.sighash);
        // Refund input carries the CSV relative-timelock.
        assert!(r.tx.input[0].sequence.is_relative_lock_time());
    }
}
