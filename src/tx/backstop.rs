//! Congestion-only CPFP fee backstop (v3.13).
//!
//! Every contract tx (Setup/Completion/Refund) carries a 0-value ephemeral
//! P2A anchor. On the happy path it is left unspent (no external link). ONLY
//! under a genuine fee spike beyond the baked-in Δ_fee does a wallet spend
//! the anchor with a CPFP child that pulls the parent up to a relayable
//! feerate — funded from a RESERVE coin so no swap-path coin is touched.
//!
//! The child is TRUC/v3 (a v3 parent admits exactly one v3 child), spends
//! `[parent anchor (keyless P2A, empty witness), reserve UTXO (P2TR
//! single-sig)]`, and pays the whole bump fee, leaving a single change output
//! to a fresh address. The reserve input is signed through the enclave seam
//! (`KeySource::sign_key_path`) — this module only builds the unsigned tx +
//! its sighash and finalizes the witnesses.
//!
//! PRIVACY NOTE (why this is opt-in for completions): the child co-spends the
//! parent anchor and a reserve coin, so on-chain it LINKS the reserve's
//! provenance to that swap. For a refund this is free (a refund already
//! revealed its leaf — no privacy left), so the backstop fires SILENTLY. For
//! a completion the link is a real privacy loss, so the wallet layer gates it
//! behind an explicit consent (`LinkageAck`) and records the taint.

use crate::tx::setup::pre_encumbrance_spk;
use crate::tx::txbuild::{ephemeral_anchor, TRUC_VERSION};
use crate::{Error, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{absolute, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// P2TR dust threshold (sats) for the child's change output.
const DUST_SATS: u64 = 330;

/// An unsigned CPFP bump: the child tx plus the sighash to sign for its
/// reserve input (input 1). Input 0 is the keyless anchor (empty witness).
pub struct CpfpBump {
    tx: Transaction,
    pub reserve_sighash: [u8; 32],
}

impl CpfpBump {
    pub fn child_output_sats(&self) -> u64 {
        self.tx.output[0].value.to_sat()
    }
}

/// Build the anchor+reserve CPFP child that bumps `parent_anchor` (the
/// parent's `(txid, anchor_vout)`), paying `child_fee_sats` of fee out of the
/// reserve coin. Returns the unsigned child + the reserve-input sighash to
/// sign. Total; refuses a fee that would leave a dust/negative change.
pub fn build_cpfp_bump(
    parent_anchor: OutPoint,
    reserve_outpoint: OutPoint,
    reserve_amount_sats: u64,
    reserve_xonly: [u8; 32],
    child_fee_sats: u64,
    dest_spk: ScriptBuf,
) -> Result<CpfpBump> {
    if child_fee_sats == 0 {
        return Err(Error::Validation("bump fee must be positive"));
    }
    let child_out = reserve_amount_sats
        .checked_sub(child_fee_sats)
        .ok_or(Error::Validation("bump fee exceeds the reserve amount"))?;
    if child_out < DUST_SATS {
        return Err(Error::Validation("bump would leave a dust/empty change output"));
    }

    // Prevouts, in input order: [P2A anchor (0 value), reserve (P2TR)].
    let anchor_prevout = ephemeral_anchor();
    let reserve_spk = pre_encumbrance_spk(reserve_xonly)?;
    let reserve_prevout = TxOut {
        value: Amount::from_sat(reserve_amount_sats),
        script_pubkey: reserve_spk,
    };

    let tx = Transaction {
        version: TRUC_VERSION, // a v3 parent admits exactly one v3 child
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            // Input 0: the parent's keyless P2A anchor — empty witness.
            TxIn {
                previous_output: parent_anchor,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            // Input 1: the reserve UTXO — key-path signed below.
            TxIn {
                previous_output: reserve_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut { value: Amount::from_sat(child_out), script_pubkey: dest_spk }],
    };

    let prevouts = [anchor_prevout, reserve_prevout];
    let reserve_sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(1, &Prevouts::All(&prevouts), TapSighashType::Default)
        .map_err(|_| Error::Abort("cpfp reserve key-spend sighash"))?
        .to_byte_array();

    Ok(CpfpBump { tx, reserve_sighash })
}

/// Attach the witnesses and serialize the fully-signed child: input 0 (the
/// P2A anchor) is spent with an EMPTY witness; input 1 (the reserve) carries
/// the single 64-byte key-path signature.
pub fn finalize_cpfp_bump(mut bump: CpfpBump, reserve_sig: [u8; 64]) -> Vec<u8> {
    // Input 0 stays empty (keyless anchor).
    let mut w = Witness::new();
    w.push(reserve_sig);
    bump.tx.input[1].witness = w;
    bitcoin::consensus::encode::serialize(&bump.tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::setup::pre_encumbrance_spk;
    use crate::tx::txbuild::verify_taproot_key_spend;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
    use bitcoin::Txid;

    fn op(seed: u8, vout: u32) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b)), vout)
    }

    #[test]
    fn cpfp_child_is_well_formed_and_the_reserve_sig_verifies() {
        // A reserve key.
        let mut rng = rand::rng();
        let reserve_sk = secp::Scalar::random(&mut rng);
        let reserve_xonly = (reserve_sk * secp::G).serialize_xonly();
        let reserve_amount = 100_000u64;
        let child_fee = 8_000u64;
        let dest = pre_encumbrance_spk([2u8; 32]).unwrap();

        let bump = build_cpfp_bump(
            op(0xA0, 1), // parent anchor at vout 1
            op(0xB0, 0), // reserve UTXO
            reserve_amount,
            reserve_xonly,
            child_fee,
            dest,
        )
        .unwrap();
        assert_eq!(bump.child_output_sats(), reserve_amount - child_fee);

        // Sign the reserve input through the same tweaked-key path the wallet
        // uses, then verify bitcoin-side against the reserve OUTPUT key.
        let sig = crate::tx::setup::sign_key_path_tweaked(reserve_sk.serialize(), bump.reserve_sighash)
            .unwrap();
        let secp = Secp256k1::verification_only();
        let internal = XOnlyPublicKey::from_slice(&reserve_xonly).unwrap();
        let output_key = internal.tap_tweak(&secp, None).0.to_x_only_public_key().serialize();
        verify_taproot_key_spend(output_key, bump.reserve_sighash, &sig)
            .expect("reserve key-spend must verify");

        // Finalize: 2 inputs, input 0 empty (anchor), input 1 = the sig.
        let raw = finalize_cpfp_bump(bump, sig);
        let tx: Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
        assert_eq!(tx.version, TRUC_VERSION);
        assert_eq!(tx.input.len(), 2);
        assert!(tx.input[0].witness.is_empty(), "P2A anchor spent with empty witness");
        assert_eq!(tx.input[1].witness.len(), 1);
        assert_eq!(tx.input[1].witness.iter().next().unwrap().len(), 64);
        assert_eq!(tx.output.len(), 1);
    }

    #[test]
    fn rejects_dust_and_over_fee() {
        let mut rng = rand::rng();
        let xonly = (secp::Scalar::random(&mut rng) * secp::G).serialize_xonly();
        let dest = pre_encumbrance_spk((secp::Scalar::random(&mut rng) * secp::G).serialize_xonly())
            .unwrap();
        // Fee exceeds reserve.
        assert!(build_cpfp_bump(op(1, 1), op(2, 0), 1_000, xonly, 2_000, dest.clone()).is_err());
        // Fee leaves sub-dust change.
        assert!(build_cpfp_bump(op(1, 1), op(2, 0), 1_000, xonly, 800, dest.clone()).is_err());
        // Zero fee.
        assert!(build_cpfp_bump(op(1, 1), op(2, 0), 1_000, xonly, 0, dest).is_err());
    }
}
