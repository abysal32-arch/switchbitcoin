//! The full two-party adaptor exchange over a REAL TCP socket (Task 04).
//!
//! Mirrors `taproot_swap.rs` — the definitive tx-level spendability proof —
//! but replaces the in-process `ChannelTransport` with `TcpTransport` on a
//! loopback connection: two threads, one TCP pair, full exchange. If this
//! passes, the wire protocol survives real socket semantics (length framing,
//! partial reads, kernel buffering) end-to-end, and both completion legs are
//! verified spendable on the bitcoin side.

use bitcoin::OutPoint;
use swapkey::crypto::adaptor::AdaptorSecret;
use swapkey::crypto::{ValidatedFinalSig, ValidatedPoint};
use swapkey::settlement::params::Params;
use swapkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use swapkey::settlement::state_machine::{
    ExchangeInputs, Funding, PeerSession, Possessing, Role, Transport,
};
use swapkey::tx::escrow::Escrow;
use swapkey::tx::txbuild::{build_completion, verify_taproot_key_spend};
use swapkey::wallet::transport::TcpTransport;
use swapkey::Result;
use secp::{Point, Scalar};
use std::net::TcpListener;

/// Loopback TCP pair: connect completes via the listener backlog, so no
/// helper thread is needed for the handshake.
fn tcp_pair() -> (TcpTransport, TcpTransport) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = TcpTransport::connect(addr).expect("connect");
    let server = TcpTransport::accept(&listener).expect("accept");
    (client, server)
}

fn keypair() -> (Scalar, Point) {
    let mut rng = rand::rng();
    let sk = Scalar::random(&mut rng);
    (sk, sk * secp::G)
}

fn aggregate_internal(sh_pub: Point, sl_pub: Point) -> Point {
    swapkey::settlement::state_machine::canonical_internal_key(sh_pub, sl_pub).expect("keys")
}

#[test]
fn adaptor_exchange_over_tcp_both_legs_spendable() {
    let (sh_sk, sh_pub) = keypair();
    let (sl_sk, sl_pub) = keypair();
    let params = Params::testnet_provisional();
    assert!(params.validate().is_ok());
    let s_height = 800_000u32;
    let escrow_amount = params.escrow_amount_sats();
    let d = params.tier_d_sats;

    let internal = aggregate_internal(sh_pub, sl_pub);
    let escrow_comp_sh = Escrow::new(&internal, &sl_pub, params.delta_early).expect("escrow sh");
    let delta_late = u32::try_from(params.delta_late()).unwrap();
    let escrow_comp_sl = Escrow::new(&internal, &sh_pub, delta_late).expect("escrow sl");

    let op_sh = OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), 0);
    let op_sl = OutPoint::new(bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), 1);

    let dest_sh = escrow_comp_sh.funding_script_pubkey().clone();
    let dest_sl = escrow_comp_sl.funding_script_pubkey().clone();
    let comp_sh_tx =
        build_completion(&escrow_comp_sh, op_sh, escrow_amount, dest_sh, d, params.anchor_sats)
            .unwrap();
    let comp_sl_tx =
        build_completion(&escrow_comp_sl, op_sl, escrow_amount, dest_sl, d, params.anchor_sats)
            .unwrap();
    let msg_comp_sh = comp_sh_tx.sighash;
    let msg_comp_sl = comp_sl_tx.sighash;
    let root_sh = escrow_comp_sh.merkle_root();
    let root_sl = escrow_comp_sl.merkle_root();
    let outkey_sh = escrow_comp_sh.output_key_xonly();
    let outkey_sl = escrow_comp_sl.output_key_xonly();

    let swap_id = [0x74u8; 32]; // 't' for transport
    let store = tempfile::tempdir().expect("store");
    let lease_sh = tempfile::tempdir().expect("lease sh");
    let lease_sl = tempfile::tempdir().expect("lease sl");

    // The only difference from taproot_swap.rs: a real socket pair.
    let (io_sh, io_sl) = tcp_pair();

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
            taproot_output_comp_sh: Some(outkey_sh),
            taproot_output_comp_sl: Some(outkey_sl),
        })?;
        let sig = possessing.broadcast_completion(s_height + 10, &receipt)?;
        Ok(sig.0)
    });

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
            pre_armed_refund: PreArmedRefund::from_signed_tx(
                vec![0xbb; 64],
                s_height + params.delta_early,
            )
            .unwrap(),
            adaptor_secret: None,
            lease_dir: Some(lease_sl.path().to_path_buf()),
            possession_store: Some((
                store.path().to_path_buf(),
                swapkey::crypto::storage::platform_secure_key(),
            )),
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
            taproot_output_comp_sh: Some(outkey_sh),
            taproot_output_comp_sl: Some(outkey_sl),
        })
        .expect("SL exchange over TCP");

    let sh_completion = sh.join().expect("SH thread").expect("SH side over TCP");

    // PROOF 1: Comp->SH is a valid taproot key-path spend, exchanged over TCP.
    verify_taproot_key_spend(outkey_sh, msg_comp_sh, &sh_completion)
        .expect("Comp->SH must be a valid taproot key-path spend");

    // SL observes SH's completion, extracts t, completes its own leg.
    let observed = ValidatedFinalSig::from_bytes(&sh_completion).expect("well-formed");
    let plan = sl_possessing
        .claim_after_reveal(&observed, s_height + 12)
        .expect("extract + claim");

    // PROOF 2: Comp->SL is a valid taproot key-path spend.
    verify_taproot_key_spend(outkey_sl, msg_comp_sl, &plan.comp_sl_final.0)
        .expect("Comp->SL must be a valid taproot key-path spend");

    // Claim delay respects the timelock bound (parity with taproot_swap.rs).
    assert!(
        (s_height + 12) as u64 + plan.delay_blocks as u64 + params.claim_confirm_allowance as u64
            <= s_height as u64 + params.delta_late()
    );
}

/// Task 05 envelope gate over the REAL transport: a frame sealed for one
/// session must not open for another (cross-session splice), and a frame
/// carrying a foreign wire version must be rejected — both surviving actual
/// TCP framing byte-identically.
#[test]
fn cross_session_and_wrong_version_envelopes_rejected_over_tcp() {
    use swapkey::wire::{open_message, seal_message, Message, WIRE_VERSION};

    let (mut a, mut b) = tcp_pair();
    let sid = [0xAAu8; 32];
    let other_sid = [0xBBu8; 32];
    let m = Message::NonceCommitment([0x77u8; 32]);

    // Sanity: the sealed frame crosses TCP intact and opens under its session.
    a.send(&seal_message(&sid, &m)).expect("send sealed");
    let frame = b.recv().expect("recv sealed");
    assert_eq!(open_message(&sid, &frame).expect("own session must open"), m);

    // Cross-session splice: the same valid bytes, expected by another session.
    a.send(&seal_message(&sid, &m)).expect("send sealed");
    let frame = b.recv().expect("recv sealed");
    assert!(
        open_message(&other_sid, &frame).is_err(),
        "frame sealed for session A must not open for session B"
    );

    // Wrong wire version: rejected before any field parses.
    let mut forged = seal_message(&sid, &m);
    forged[0] = WIRE_VERSION.wrapping_add(1);
    a.send(&forged).expect("send forged");
    let frame = b.recv().expect("recv forged");
    assert!(open_message(&sid, &frame).is_err(), "foreign wire version must be rejected");
}
