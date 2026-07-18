//! Claim scheduler integration (wallet rank 5): drive SL's randomized,
//! posture-bounded claim end-to-end on the SimChain, observing Comp→SH's
//! reveal from the MEMPOOL (mempool-first), and prove the hard bound —
//! even at the sampled delay, SL confirms strictly before the swept escrow's
//! late refund matures.

use bitcoin::OutPoint;
use switchbitcoin::chain::{ChainView, SimChain, SpendStatus};
use switchbitcoin::crypto::adaptor::AdaptorSecret;
use switchbitcoin::crypto::ValidatedPoint;
use switchbitcoin::settlement::params::Params;
use switchbitcoin::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use switchbitcoin::settlement::state_machine::{
    ExchangeInputs, Funding, PeerSession, Role, Transport,
};
use switchbitcoin::tx::escrow::Escrow;
use switchbitcoin::tx::txbuild::{build_completion, finalize_key_spend};
use switchbitcoin::wallet::claim_scheduler::{ClaimBroadcast, ClaimScheduler};
use switchbitcoin::wallet::manifest::{ClaimDelayPosture, SignedManifest};
use switchbitcoin::{Error, Result};
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

#[derive(Clone, Copy)]
struct Party {
    sk: Scalar,
    pk: Point,
}
fn keypair() -> Party {
    let mut rng = rand::rng();
    let sk = Scalar::random(&mut rng);
    Party { sk, pk: sk * secp::G }
}

fn txid_from(seed: u8) -> bitcoin::Txid {
    let mut b = [0u8; 32];
    b[0] = seed;
    bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b))
}

#[test]
fn sl_claim_is_posture_delayed_reveal_observed_and_bound_holds() {
    let manifest = SignedManifest::compose(
        1,
        Params::testnet_provisional(),
        ClaimDelayPosture::Aggressive, // widest band — stresses the bound
        [(0, 6), (6, 36), (12, 72)],
        6,
        3,
    )
    .unwrap();
    let params = manifest.params().clone();
    let scheduler = ClaimScheduler::from_manifest(&manifest);
    let s_height = 800_000u32;
    let escrow_amount = params.escrow_amount_sats(); // scheme (a)
    let d = params.tier_d_sats;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let sh = keypair();
    let sl = keypair();
    let internal =
        switchbitcoin::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap(); // E_sl
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).unwrap(); // E_sh
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // E_sl (SH sweeps)
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // E_sh (SL sweeps)

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, escrow_amount, dest.clone(), d, params.anchor_sats).unwrap();
    let comp_sl_spend =
        build_completion(&escrow_comp_sl, op_comp_sl, escrow_amount, dest, d, params.anchor_sats).unwrap();
    let msg_sh = comp_sh_spend.sighash;
    let msg_sl = comp_sl_spend.sighash;
    let root_sh = escrow_comp_sh.merkle_root();
    let root_sl = escrow_comp_sl.merkle_root();
    let ok_sh = escrow_comp_sh.output_key_xonly();
    let ok_sl = escrow_comp_sl.output_key_xonly();

    let swap_id = [0x51u8; 32];
    let lease_sh = tempfile::tempdir().unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    // SH runs the exchange and broadcasts Comp→SH (revealing s_final).
    let sh_params = params.clone();
    let sh_chain = chain.clone();
    let comp_sh_for_sh = comp_sh_spend.clone();
    let sh_handle = std::thread::spawn(move || -> Result<()> {
        let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + delta_late)?;
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
        let (t, _) = AdaptorSecret::generate()?;
        let peer = PeerSession::new(swap_id, Box::new(io_sh));
        let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
        let possessing = funded.run_adaptor_exchange(ExchangeInputs {
            our_seckey: sh.sk,
            their_pubkey: ValidatedPoint::from_bytes(&sl.pk.serialize())?,
            msg_comp_sh: msg_sh,
            msg_comp_sl: msg_sl,
            pre_armed_refund: refund,
            adaptor_secret: Some(t),
            lease_dir: Some(lease_sh.path().to_path_buf()),
            possession_store: None,
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
            taproot_output_comp_sh: Some(ok_sh),
            taproot_output_comp_sl: Some(ok_sl),
        })?;
        let sig = possessing.broadcast_completion(s_height + 10, &receipt)?;
        // SH broadcasts Comp→SH to the MEMPOOL (does not mine it).
        let final_tx = finalize_key_spend(comp_sh_for_sh, sig.0);
        sh_chain.broadcast(&final_tx).expect("Comp->SH to mempool");
        Ok(())
    });

    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .unwrap();
    let sl_possessing = funded
        .run_adaptor_exchange(ExchangeInputs {
            our_seckey: sl.sk,
            their_pubkey: ValidatedPoint::from_bytes(&sh.pk.serialize()).unwrap(),
            msg_comp_sh: msg_sh,
            msg_comp_sl: msg_sl,
            pre_armed_refund: PreArmedRefund::from_signed_tx(vec![0xbb; 64], s_height + params.delta_early)
                .unwrap(),
            adaptor_secret: None,
            lease_dir: Some(lease_sl.path().to_path_buf()),
            possession_store: Some((
                store.path().to_path_buf(),
                switchbitcoin::crypto::storage::platform_secure_key(),
            )),
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
            taproot_output_comp_sh: Some(ok_sh),
            taproot_output_comp_sl: Some(ok_sl),
        })
        .unwrap();
    sh_handle.join().unwrap().expect("SH side");

    // ===== SL's scheduler loop. =====
    // Comp→SH is in the MEMPOOL (unconfirmed): mempool-first reveal detection
    // must already surface the final signature.
    assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::InMempool));
    let reveal = ClaimScheduler::observe_reveal(&chain, op_comp_sh)
        .expect("reveal observed from the mempool before confirmation");

    let reveal_height = chain.tip_height();
    let schedule = scheduler
        .schedule_claim(&sl_possessing, &reveal, reveal_height)
        .expect("extract + schedule");

    // THE BOUND: even at this sampled (aggressive-posture) delay, the claim
    // confirms strictly before the SWEPT escrow's late refund matures.
    let claim_confirm_height = schedule.broadcast_at_height as u64 + 1; // +1 block to confirm
    let refund_maturity = s_height as u64 + params.delta_late(); // sweep anchor == S here (manual)
    assert!(
        claim_confirm_height + params.claim_confirm_allowance as u64 <= refund_maturity,
        "sampled delay would breach the late-refund maturity"
    );

    // Before the delay elapses: Wait.
    if schedule.delay_blocks > 0 {
        assert_eq!(
            ClaimScheduler::next_broadcast(&chain, op_comp_sl, &schedule, None),
            ClaimBroadcast::Wait
        );
    }
    // Advance to the broadcast height.
    while chain.tip_height() < schedule.broadcast_at_height {
        chain.mine();
    }
    assert_eq!(
        ClaimScheduler::next_broadcast(&chain, op_comp_sl, &schedule, None),
        ClaimBroadcast::Broadcast
    );

    // Broadcast the claim; it confirms.
    let comp_sl_final = finalize_key_spend(comp_sl_spend, schedule.comp_sl_final.0);
    let claim_txid = chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
    // Still in mempool → Wait; after mining → Done.
    assert_eq!(
        ClaimScheduler::next_broadcast(&chain, op_comp_sl, &schedule, Some(claim_txid)),
        ClaimBroadcast::Wait
    );
    chain.mine();
    assert!(matches!(chain.spend_status(op_comp_sl), SpendStatus::Confirmed(_)));
    assert_eq!(
        ClaimScheduler::next_broadcast(&chain, op_comp_sl, &schedule, Some(claim_txid)),
        ClaimBroadcast::Won
    );
}
