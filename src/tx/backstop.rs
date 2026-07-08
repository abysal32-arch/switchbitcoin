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
/// Absurd-fee ceiling for a single bump child (defense against a buggy fee
/// estimate burning a whole reserve coin as fee — finding #12). Generous
/// headroom over any realistic CPFP; a real bump is a few thousand sats.
const MAX_BUMP_FEE_SATS: u64 = 200_000;

/// Anchor-output invariant, shared with `tx::txbuild`: every contract tx
/// carries its ephemeral anchor as its LAST output. The completion/refund/
/// setup builders all place it at vout 1.
pub const ANCHOR_VOUT: u32 = 1;

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

/// The child vsize a caller uses to size the fee: 2 inputs (a keyless P2A
/// anchor with an empty witness, and one P2TR key-path input ≈ 57.5 vB) plus
/// one P2TR output, TRUC v3. ≈ 111 vB; rounded up for the caller's headroom.
pub const CHILD_VSIZE_VB: u64 = 120;

/// The child fee a caller must pay so the PARENT+CHILD PACKAGE clears
/// `target_feerate_sat_vb` — CPFP acceptance is on the package feerate, not
/// the child's own (finding #8). `parent_fee_sats`/`parent_vsize_vb` describe
/// the stalled parent. Total; saturates rather than under/overflowing.
pub fn required_child_fee(
    target_feerate_sat_vb: u64,
    parent_fee_sats: u64,
    parent_vsize_vb: u64,
) -> u64 {
    let package_vsize = parent_vsize_vb.saturating_add(CHILD_VSIZE_VB);
    let needed_total = target_feerate_sat_vb.saturating_mul(package_vsize);
    needed_total.saturating_sub(parent_fee_sats)
}

/// Build the anchor+reserve CPFP child that bumps `parent_anchor` (the
/// parent's `(txid, ANCHOR_VOUT)`), paying `child_fee_sats` out of the reserve
/// coin. `anchor_value_sats` MUST equal the parent anchor output's real value
/// (0 under the current ephemeral-anchor stand-in; the future standard anchor
/// carries a non-dust value — see the fee-model note in `tx::txbuild`) so the
/// prevout the sighash commits to matches consensus (finding #6). The anchor
/// value is added to the child's input total. Total; refuses an absurd fee, a
/// non-anchor vout, or a fee that would leave dust/negative change.
pub fn build_cpfp_bump(
    parent_anchor: OutPoint,
    anchor_value_sats: u64,
    reserve_outpoint: OutPoint,
    reserve_amount_sats: u64,
    reserve_xonly: [u8; 32],
    child_fee_sats: u64,
    dest_spk: ScriptBuf,
) -> Result<CpfpBump> {
    // The anchor is always the parent's LAST output; a wrong vout would
    // reference a non-existent/other output and yield a consensus-invalid
    // child that fails only at broadcast.
    if parent_anchor.vout != ANCHOR_VOUT {
        return Err(Error::Validation("cpfp: parent anchor must be the last (anchor) output"));
    }
    if child_fee_sats == 0 {
        return Err(Error::Validation("bump fee must be positive"));
    }
    if child_fee_sats > MAX_BUMP_FEE_SATS {
        return Err(Error::Validation("bump fee exceeds the absurd-fee ceiling"));
    }
    // Input total = anchor value + reserve; child pays the fee out of it.
    let input_total = anchor_value_sats
        .checked_add(reserve_amount_sats)
        .ok_or(Error::Validation("cpfp: input total overflow"))?;
    let child_out = input_total
        .checked_sub(child_fee_sats)
        .ok_or(Error::Validation("bump fee exceeds the reserve amount"))?;
    if child_out < DUST_SATS {
        return Err(Error::Validation("bump would leave a dust/empty change output"));
    }

    // Prevouts, in input order: [P2A anchor (its real value), reserve (P2TR)].
    let mut anchor_prevout = ephemeral_anchor();
    anchor_prevout.value = Amount::from_sat(anchor_value_sats);
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

        let anchor_value = 330u64; // exercise a real (non-zero) anchor value
        let bump = build_cpfp_bump(
            op(0xA0, ANCHOR_VOUT), // parent anchor at the last output
            anchor_value,
            op(0xB0, 0), // reserve UTXO
            reserve_amount,
            reserve_xonly,
            child_fee,
            dest,
        )
        .unwrap();
        assert_eq!(bump.child_output_sats(), reserve_amount + anchor_value - child_fee);

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
    fn rejects_dust_over_fee_absurd_fee_and_wrong_vout() {
        let mut rng = rand::rng();
        let xonly = (secp::Scalar::random(&mut rng) * secp::G).serialize_xonly();
        let dest = pre_encumbrance_spk((secp::Scalar::random(&mut rng) * secp::G).serialize_xonly())
            .unwrap();
        // Fee exceeds reserve (+anchor 0).
        assert!(build_cpfp_bump(op(1, ANCHOR_VOUT), 0, op(2, 0), 1_000, xonly, 2_000, dest.clone()).is_err());
        // Fee leaves sub-dust change.
        assert!(build_cpfp_bump(op(1, ANCHOR_VOUT), 0, op(2, 0), 1_000, xonly, 800, dest.clone()).is_err());
        // Zero fee.
        assert!(build_cpfp_bump(op(1, ANCHOR_VOUT), 0, op(2, 0), 1_000, xonly, 0, dest.clone()).is_err());
        // Absurd fee (over the ceiling), even with a huge reserve.
        assert!(build_cpfp_bump(op(1, ANCHOR_VOUT), 0, op(2, 0), 10_000_000, xonly, 300_000, dest.clone()).is_err());
        // Wrong vout (anchor is always the last output).
        assert!(build_cpfp_bump(op(1, 0), 0, op(2, 0), 100_000, xonly, 5_000, dest).is_err());
    }

    #[test]
    fn required_child_fee_covers_the_package_shortfall() {
        // Parent 150 vB paid 300 sat (2 sat/vB); we want 10 sat/vB.
        // package = 150 + 120 = 270 vB; needed = 2700; child pays 2700 - 300.
        assert_eq!(required_child_fee(10, 300, 150), 2_400);
        // Parent already over target → child pays nothing extra.
        assert_eq!(required_child_fee(1, 10_000, 150), 0);
    }
}
