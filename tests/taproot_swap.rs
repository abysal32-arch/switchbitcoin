//! End-to-end TAPROOT swap at the transaction level (no chain / no network).
//!
//! This is the definitive spendability proof for the tx layer: the two-party
//! adaptor exchange signs the REAL BIP341 completion sighashes under the
//! taproot-tweaked MuSig2 key, and each completed 64-byte signature is verified
//! on the BITCOIN side (secp256k1 0.29) against the escrow's funded OUTPUT key.
//! If these verifications pass, the outputs are genuinely spendable — proven
//! across the crypto(0.31)/tx(0.29) version boundary.
//!
//! Escrow orientation (the timelock composition):
//!   * Comp->SH spends the SL-funded escrow (refund CSV = delta_early).
//!   * Comp->SL spends the SH-funded escrow (refund CSV = delta_late).

use bitcoin::OutPoint;
use musig2::KeyAggContext;
use newkey::crypto::adaptor::AdaptorSecret;
use newkey::crypto::{ValidatedFinalSig, ValidatedPoint};
use newkey::settlement::params::Params;
use newkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use newkey::settlement::state_machine::{
    ExchangeInputs, Funding, PeerSession, Possessing, Role, Transport,
};
use newkey::tx::escrow::Escrow;
use newkey::tx::txbuild::{build_completion, verify_taproot_key_spend};
use newkey::{Error, Result};
use secp::{Point, Scalar};
use std::sync::mpsc;

struct ChannelTransport {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}
impl Transport for ChannelTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.tx.send(bytes.to_vec()).map_err(|_| Error::Abort("peer hung up"))
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        self.rx.recv().map_err(|_| Error::Abort("peer hung up"))
    }
}
fn duplex() -> (ChannelTransport, ChannelTransport) {
    let (tx_a, rx_b) = mpsc::channel();
    let (tx_b, rx_a) = mpsc::channel();
    (ChannelTransport { tx: tx_a, rx: rx_a }, ChannelTransport { tx: tx_b, rx: rx_b })
}

fn keypair() -> (Scalar, Point) {
    let mut rng = rand::rng();
    let sk = Scalar::random(&mut rng);
    (sk, sk * secp::G)
}

/// The 2-of-2 aggregate internal key under the canonical (sorted) key order —
/// must match `settlement::canonical_key_agg`.
fn aggregate_internal(sh_pub: Point, sl_pub: Point) -> Point {
    let mut keys = [sh_pub, sl_pub];
    keys.sort_by_key(|p| p.serialize());
    KeyAggContext::new(keys).expect("keys").aggregated_pubkey_untweaked()
}

#[test]
fn taproot_swap_both_legs_are_spendable_on_the_bitcoin_side() {
    let (sh_sk, sh_pub) = keypair();
    let (sl_sk, sl_pub) = keypair();
    let params = Params::testnet_provisional();
    assert!(params.validate().is_ok());
    let s_height = 800_000u32;
    let escrow_amount = params.tier_d_sats + params.delta_fee_sats; // funds D + fee
    let d = params.tier_d_sats; // completion output is exactly D

    // Shared 2-of-2 internal key.
    let internal = aggregate_internal(sh_pub, sl_pub);

    // SL-funded escrow (SH sweeps via Comp->SH): early refund, funder = SL.
    let escrow_comp_sh = Escrow::new(&internal, &sl_pub, params.delta_early).expect("escrow sh");
    // SH-funded escrow (SL sweeps via Comp->SL): late refund, funder = SH.
    let delta_late = u32::try_from(params.delta_late()).unwrap();
    let escrow_comp_sl = Escrow::new(&internal, &sh_pub, delta_late).expect("escrow sl");

    // Funding outpoints (a real funding tx would produce these).
    let op_sh = OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), 0);
    let op_sl = OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), 1);

    // Real BIP341 completion sighashes. Destination spk is illustrative (its
    // bytes are committed by the sighash; spendability of the DESTINATION is out
    // of scope — what we prove is the ESCROW spend is valid).
    let dest_sh = escrow_comp_sh.funding_script_pubkey().clone();
    let dest_sl = escrow_comp_sl.funding_script_pubkey().clone();
    let comp_sh_tx = build_completion(&escrow_comp_sh, op_sh, escrow_amount, dest_sh, d).unwrap();
    let comp_sl_tx = build_completion(&escrow_comp_sl, op_sl, escrow_amount, dest_sl, d).unwrap();
    let msg_comp_sh = comp_sh_tx.sighash;
    let msg_comp_sl = comp_sl_tx.sighash;
    let root_sh = escrow_comp_sh.merkle_root();
    let root_sl = escrow_comp_sl.merkle_root();
    let outkey_sh = escrow_comp_sh.output_key_xonly();
    let outkey_sl = escrow_comp_sl.output_key_xonly();

    let swap_id = [0x77u8; 32];
    let store = tempfile::tempdir().expect("store");
    let lease_sh = tempfile::tempdir().expect("lease sh");
    let lease_sl = tempfile::tempdir().expect("lease sl");

    // SH thread: exchange, then G2-gated completion of Comp->SH.
    let (io_sh, io_sl) = duplex();
    let sh_params = params.clone();
    let sh = std::thread::spawn(move || -> Result<[u8; 64]> {
        let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + delta_late)?;
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
        let (t_secret, _) = AdaptorSecret::generate()?;
        let peer = PeerSession::new(swap_id, Box::new(io_sh));
        let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
        let possessing = funded.run_adaptor_exchange(ExchangeInputs {
            our_seckey: sh_sk,
            their_pubkey: ValidatedPoint::from_bytes(&sl_pub.serialize())?,
            msg_comp_sh,
            msg_comp_sl,
            pre_armed_refund: refund,
            adaptor_secret: Some(t_secret),
            lease_dir: Some(lease_sh.path().to_path_buf()),
            possession_store: None,
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
        })?;
        let sig = possessing.broadcast_completion(s_height + 10, &receipt)?;
        Ok(sig.0)
    });

    // SL side: exchange, then extract t from SH's completion and claim Comp->SL.
    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .expect("funded");
    let sl_possessing: Possessing = funded
        .run_adaptor_exchange(ExchangeInputs {
            our_seckey: sl_sk,
            their_pubkey: ValidatedPoint::from_bytes(&sh_pub.serialize()).unwrap(),
            msg_comp_sh,
            msg_comp_sl,
            pre_armed_refund: PreArmedRefund::from_signed_tx(vec![0xbb; 64], s_height + params.delta_early).unwrap(),
            adaptor_secret: None,
            lease_dir: Some(lease_sl.path().to_path_buf()),
            possession_store: Some(store.path().to_path_buf()),
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
        })
        .expect("SL exchange");

    let sh_completion = sh.join().expect("SH thread").expect("SH side");

    // PROOF 1: SH's Comp->SH signature is a valid taproot key-path spend of the
    // SL-funded escrow — verified on the bitcoin side against its output key.
    verify_taproot_key_spend(outkey_sh, msg_comp_sh, &sh_completion)
        .expect("Comp->SH must be a valid taproot key-path spend of the funded output");

    // SL observes SH's completion, extracts t, completes its own leg.
    let observed = ValidatedFinalSig::from_bytes(&sh_completion).expect("well-formed");
    let plan = sl_possessing
        .claim_after_reveal(&observed, s_height + 12)
        .expect("extract + claim");

    // PROOF 2: SL's Comp->SL signature is a valid taproot key-path spend of the
    // SH-funded escrow — again verified on the bitcoin side.
    verify_taproot_key_spend(outkey_sl, msg_comp_sl, &plan.comp_sl_final.0)
        .expect("Comp->SL must be a valid taproot key-path spend of the funded output");

    // Claim delay respects the timelock bound (review item #5).
    assert!(
        (s_height + 12) as u64 + plan.delay_blocks as u64 + params.claim_confirm_allowance as u64
            <= s_height as u64 + params.delta_late()
    );
}
