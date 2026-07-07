//! Phase 1 pre-encumbrance address + Phase 4 Setup transaction (v3.13).
//!
//! Onboarding pre-sizes each pre-encumbrance UTXO to exactly D + Δ_fee in a
//! Taproot single-sig address the depositor controls alone. The Setup spends
//! that UTXO WHOLE into the 2-of-2 MuSig2 escrow — single input, single escrow
//! output, NO change — so swap funding needs no change output and the escrow is
//! exactly equal for everyone in the tier (the on-chain privacy linchpin). The
//! Setup is TRUC/v3 and carries the ephemeral anchor; it pays no baked fee (the
//! whole D + Δ_fee lands in the escrow), so its fee is a congestion-only CPFP
//! from the anchor, exactly like a completion/refund.

use crate::tx::escrow::Escrow;
use crate::tx::txbuild::{ephemeral_anchor, finalize_key_spend, SpendTx, TRUC_VERSION};
use crate::{Error, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{absolute, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// The Phase-1 pre-encumbrance scriptPubKey: a Taproot single-sig (key-path
/// only, no script tree) to the funder's own key. On-chain it is an ordinary
/// Taproot receive of exactly D + Δ_fee, identical across all tier users.
pub fn pre_encumbrance_spk(funder_xonly: [u8; 32]) -> Result<ScriptBuf> {
    let secp = Secp256k1::verification_only();
    let key = XOnlyPublicKey::from_slice(&funder_xonly)
        .map_err(|_| Error::Validation("invalid pre-encumbrance key"))?;
    Ok(ScriptBuf::new_p2tr(&secp, key, None))
}

/// Sign a Taproot KEY-PATH (single-sig) spend of a no-script-tree output: the
/// key is tweaked by the empty merkle root (BIP341), so signing uses the
/// tweaked keypair. Deterministic (no aux randomness).
fn sign_key_path_tweaked(seckey_bytes: [u8; 32], sighash: [u8; 32]) -> Result<[u8; 64]> {
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_slice(&secp, &seckey_bytes)
        .map_err(|_| Error::Validation("invalid pre-encumbrance secret key"))?;
    let tweaked = kp.tap_tweak(&secp, None); // key-path-only: empty merkle root
    let msg = Message::from_digest(sighash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    Ok(out)
}

/// Build and sign the Setup: spend the whole D + Δ_fee pre-encumbrance UTXO into
/// the escrow with NO change (single input, escrow output + ephemeral anchor),
/// TRUC/v3. Returns the fully-signed tx bytes and the escrow OUTPOINT it creates
/// (setup_txid:0). `pre_amount_sats` must equal the escrow amount (D + Δ_fee).
pub fn build_setup(
    pre_outpoint: OutPoint,
    pre_amount_sats: u64,
    escrow: &Escrow,
    funder_seckey: &secp::Scalar,
) -> Result<(Vec<u8>, OutPoint)> {
    let funder_xonly = (*funder_seckey * secp::G).serialize_xonly();
    let pre_spk = pre_encumbrance_spk(funder_xonly)?;

    let tx = Transaction {
        version: TRUC_VERSION,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: pre_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        // Whole-UTXO into the escrow (no change) + the 0-value ephemeral anchor.
        output: vec![
            TxOut {
                value: Amount::from_sat(pre_amount_sats),
                script_pubkey: escrow.funding_script_pubkey().clone(),
            },
            ephemeral_anchor(),
        ],
    };

    // Key-path sighash of the pre-encumbrance spend.
    let prevout = TxOut { value: Amount::from_sat(pre_amount_sats), script_pubkey: pre_spk };
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
        .map_err(|_| Error::Abort("setup key-spend sighash"))?
        .to_byte_array();
    let sig = sign_key_path_tweaked(funder_seckey.serialize(), sighash)?;

    let signed = finalize_key_spend(SpendTx { tx, sighash }, sig);
    let setup_tx: Transaction = bitcoin::consensus::encode::deserialize(&signed)
        .map_err(|_| Error::Abort("setup re-decode"))?;
    Ok((signed, OutPoint::new(setup_tx.compute_txid(), 0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::txbuild::verify_taproot_key_spend;

    #[test]
    fn setup_is_zero_change_and_signs_the_pre_encumbrance() {
        // 2-of-2 escrow (internal key from a canonical aggregate).
        let mut rng = rand::rng();
        let sk_funder = secp::Scalar::random(&mut rng);
        let sk_other = secp::Scalar::random(&mut rng);
        let internal =
            crate::settlement::state_machine::canonical_internal_key(sk_funder * secp::G, sk_other * secp::G)
                .unwrap();
        let escrow = Escrow::new(&internal, &(sk_funder * secp::G), 216).unwrap();

        let d_plus_fee = 1_005_000u64; // D + Δ_fee
        let pre_outpoint =
            OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), 0);
        let (signed, escrow_op) =
            build_setup(pre_outpoint, d_plus_fee, &escrow, &sk_funder).unwrap();

        let tx: Transaction = bitcoin::consensus::encode::deserialize(&signed).unwrap();
        // TRUC/v3, single input, escrow output + anchor, NO change.
        assert_eq!(tx.version, TRUC_VERSION);
        assert_eq!(tx.input.len(), 1, "whole-UTXO spend, single input");
        assert_eq!(tx.output.len(), 2, "escrow output + ephemeral anchor, no change");
        assert_eq!(tx.output[0].value.to_sat(), d_plus_fee, "escrow gets the whole D + Δ_fee");
        assert!(escrow.funding_script_pubkey() == &tx.output[0].script_pubkey);
        assert_eq!(escrow_op, OutPoint::new(tx.compute_txid(), 0));

        // The key-path signature verifies against the pre-encumbrance OUTPUT key
        // (funder key tweaked by the empty merkle root) — proven bitcoin-side.
        let funder_xonly = (sk_funder * secp::G).serialize_xonly();
        let secp = Secp256k1::verification_only();
        let internal_key = XOnlyPublicKey::from_slice(&funder_xonly).unwrap();
        let output_key = internal_key.tap_tweak(&secp, None).0.to_x_only_public_key().serialize();
        let prevout = TxOut {
            value: Amount::from_sat(d_plus_fee),
            script_pubkey: pre_encumbrance_spk(funder_xonly).unwrap(),
        };
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
            .unwrap()
            .to_byte_array();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&tx.input[0].witness[0][..64]);
        verify_taproot_key_spend(output_key, sighash, &sig).expect("setup sig must verify");
    }
}
