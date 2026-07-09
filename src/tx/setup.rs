//! Phase 1 pre-encumbrance address + Phase 4 Setup transaction (v3.13).
//!
//! Onboarding pre-sizes each pre-encumbrance UTXO to exactly D + Δ_fee in a
//! Taproot single-sig address the depositor controls alone. The Setup spends
//! that UTXO WHOLE into the 2-of-2 MuSig2 escrow — single input, escrow
//! output + P2A anchor, NO change — so swap funding needs no change output
//! and the escrow is exactly equal for everyone in the tier (the on-chain
//! privacy linchpin). The Setup is TRUC/v3; under the scheme-(a) fee model
//! (§4.98 resolution) it pays a real baked `setup_fee` (so it relays
//! STANDALONE on real Core policy — a 0-fee tx cannot), the anchor carries a
//! standard non-dust value, and the escrow receives
//! `D + Δ_fee − setup_fee − anchor = Params::escrow_amount_sats()`. The
//! anchor CPFP remains a congestion-only backstop, exactly like a
//! completion/refund.

use crate::tx::escrow::Escrow;
use crate::tx::txbuild::{anchor_output, finalize_key_spend, SpendTx, TRUC_VERSION};
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
/// tweaked keypair (odd-Y internal keys are negated by `tap_tweak` per
/// BIP341, so every derived key signs correctly). Deterministic (no aux
/// randomness). pub(crate): `wallet::keys` routes single-sig signing through
/// here so key material stays behind the `KeySource` seam.
pub(crate) fn sign_key_path_tweaked(seckey_bytes: [u8; 32], sighash: [u8; 32]) -> Result<[u8; 64]> {
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

/// Build and sign the Setup: spend the whole D + Δ_fee pre-encumbrance UTXO
/// into the escrow with NO change (single input, escrow output + P2A anchor),
/// TRUC/v3, paying `pre_amount − escrow_amount − anchor = setup_fee` as a
/// real standalone-relayable fee. Returns the fully-signed tx bytes and the
/// escrow OUTPOINT it creates (setup_txid:0). Callers pass
/// `Params::escrow_amount_sats()` / `Params::anchor_sats`; the conservation
/// guard refuses any split that pays no (or negative) fee.
pub fn build_setup(
    pre_outpoint: OutPoint,
    pre_amount_sats: u64,
    escrow_amount_sats: u64,
    anchor_sats: u64,
    escrow: &Escrow,
    funder_seckey: &secp::Scalar,
) -> Result<(Vec<u8>, OutPoint)> {
    // Conservation: escrow + anchor strictly below the pre-encumbrance coin,
    // the remainder being the Setup's baked fee (§4.98 scheme (a) — a 0-fee
    // Setup cannot relay standalone on real Core policy).
    if escrow_amount_sats
        .checked_add(anchor_sats)
        .is_none_or(|t| t >= pre_amount_sats)
    {
        return Err(Error::Validation("setup: escrow + anchor must leave a positive fee"));
    }
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
        // Whole-UTXO spend, no change: escrow output + the non-dust anchor.
        output: vec![
            TxOut {
                value: Amount::from_sat(escrow_amount_sats),
                script_pubkey: escrow.funding_script_pubkey().clone(),
            },
            anchor_output(anchor_sats),
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

/// Build and sign the Phase-1 ONBOARDING SPLIT: spend the whole deposit UTXO
/// into `outputs` (k pre-encumbrance outputs of exactly D + Δ_fee each, plus
/// at most one unencumbered change output that absorbs ALL rounding — v3.13
/// Phase 1). The deposit is an ordinary Taproot single-sig receive
/// (`pre_encumbrance_spk` of the deposit key), spent key-path.
///
/// Unlike the contract transactions (Setup/Completion/Refund), the split is
/// an ORDINARY wallet transaction: version 2, no ephemeral anchor, and it
/// pays its own fee (`fee_sats`) like any normal wallet spend — the
/// history-terminating tx should look like ordinary wallet activity, not
/// like protocol traffic ("no fee side-channel").
///
/// Conservation is enforced: `sum(outputs) + fee_sats == deposit_amount_sats`
/// exactly, and the fee must be positive. The LEDGER decides the output list
/// (tier arithmetic, dust folding); this function only refuses to sign
/// anything that does not conserve the deposit.
pub fn build_onboarding_split(
    deposit_outpoint: OutPoint,
    deposit_amount_sats: u64,
    deposit_seckey: &secp::Scalar,
    outputs: &[(ScriptBuf, u64)],
    fee_sats: u64,
) -> Result<(Vec<u8>, bitcoin::Txid)> {
    let deposit_xonly = (*deposit_seckey * secp::G).serialize_xonly();
    let spend = unsigned_onboarding_split(
        deposit_outpoint,
        deposit_amount_sats,
        deposit_xonly,
        outputs,
        fee_sats,
    )?;
    let sig = sign_key_path_tweaked(deposit_seckey.serialize(), spend.sighash)?;
    let signed = finalize_key_spend(spend, sig);
    let split_tx: Transaction = bitcoin::consensus::encode::deserialize(&signed)
        .map_err(|_| Error::Abort("split re-decode"))?;
    Ok((signed, split_tx.compute_txid()))
}

/// The unsigned half of the onboarding split: build the transaction and its
/// key-spend sighash without touching key material, so callers can route the
/// signature through the enclave seam (`KeySource::sign_key_path`) and
/// finalize with `txbuild::finalize_key_spend`.
pub fn unsigned_onboarding_split(
    deposit_outpoint: OutPoint,
    deposit_amount_sats: u64,
    deposit_xonly: [u8; 32],
    outputs: &[(ScriptBuf, u64)],
    fee_sats: u64,
) -> Result<SpendTx> {
    if outputs.is_empty() {
        return Err(Error::Validation("split: no outputs"));
    }
    if fee_sats == 0 {
        return Err(Error::Validation("split: fee must be positive"));
    }
    let out_total: u64 = outputs
        .iter()
        .try_fold(0u64, |acc, (_, a)| acc.checked_add(*a))
        .ok_or(Error::Validation("split: output total overflows"))?;
    if out_total
        .checked_add(fee_sats)
        .is_none_or(|t| t != deposit_amount_sats)
    {
        return Err(Error::Validation(
            "split: outputs + fee must equal the deposit exactly",
        ));
    }

    let deposit_spk = pre_encumbrance_spk(deposit_xonly)?;

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: deposit_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs
            .iter()
            .map(|(spk, amount)| TxOut {
                value: Amount::from_sat(*amount),
                script_pubkey: spk.clone(),
            })
            .collect(),
    };

    let prevout = TxOut {
        value: Amount::from_sat(deposit_amount_sats),
        script_pubkey: deposit_spk,
    };
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
        .map_err(|_| Error::Abort("split key-spend sighash"))?
        .to_byte_array();
    Ok(SpendTx { tx, sighash })
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

        let p = crate::settlement::params::Params::testnet_provisional();
        let d_plus_fee = p.pre_encumbrance_sats(); // D + Δ_fee
        let pre_outpoint =
            OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), 0);
        let (signed, escrow_op) = build_setup(
            pre_outpoint,
            d_plus_fee,
            p.escrow_amount_sats(),
            p.anchor_sats,
            &escrow,
            &sk_funder,
        )
        .unwrap();

        let tx: Transaction = bitcoin::consensus::encode::deserialize(&signed).unwrap();
        // TRUC/v3, single input, escrow output + anchor, NO change.
        assert_eq!(tx.version, TRUC_VERSION);
        assert_eq!(tx.input.len(), 1, "whole-UTXO spend, single input");
        assert_eq!(tx.output.len(), 2, "escrow output + P2A anchor, no change");
        assert_eq!(
            tx.output[0].value.to_sat(),
            p.escrow_amount_sats(),
            "escrow gets D + Δ_fee − setup_cost (scheme (a))"
        );
        assert_eq!(tx.output[1].value.to_sat(), p.anchor_sats, "non-dust anchor");
        // The Setup pays its baked fee — standalone-relayable (§4.98).
        let fee = d_plus_fee - tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
        assert_eq!(fee, p.setup_fee_sats);
        assert!(escrow.funding_script_pubkey() == &tx.output[0].script_pubkey);
        assert_eq!(escrow_op, OutPoint::new(tx.compute_txid(), 0));
        // A 0-fee split (the old shape) is rejected at construction.
        assert!(build_setup(pre_outpoint, d_plus_fee, d_plus_fee, 0, &escrow, &sk_funder).is_err());

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
