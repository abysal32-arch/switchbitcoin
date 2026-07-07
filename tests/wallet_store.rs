//! Wallet-layer crash-safety integration tests (wallet rank 1).
//!
//! These prove the two crash stories END TO END, from the persisted record
//! alone — no in-memory state survives the "crash" in either test:
//!
//!   1. Crash AFTER SL releases (post-G1): the SwapStore record points at the
//!      sealed possession record; a fresh process restores, extracts t from
//!      the observed reveal, and claims on the SimChain.
//!   2. Crash DURING a signing session (INV-2): reopen routes the swap to
//!      ABORT_REFUND, and the pre-armed refund persisted INSIDE the record
//!      reclaims the funds at CSV maturity — the record alone is a complete
//!      exit.

use bitcoin::{OutPoint, Txid};
use newkey::chain::{ChainView, SimChain, SpendStatus};
use newkey::crypto::adaptor::AdaptorSecret;
use newkey::crypto::{ValidatedFinalSig, ValidatedPoint};
use newkey::settlement::params::Params;
use newkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use newkey::settlement::state_machine::{
    swap_session_id, ExchangeInputs, Funding, PeerSession, Possessing, Role, Transport,
};
use newkey::tx::escrow::Escrow;
use newkey::tx::txbuild::{build_completion, finalize_key_spend};
use newkey::wallet::{ModeledEnclave, RecoveryAction, SwapPhase, SwapRecord, SwapStore};
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

fn txid_from(seed: u8) -> Txid {
    let mut b = [0u8; 32];
    b[0] = seed;
    Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b))
}

fn hex32(id: &[u8; 32]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Crash story 1: SL releases (G1 satisfied, possession record + SwapRecord
/// persisted), the process dies, and a FRESH process finishes the swap using
/// nothing but the wallet store.
#[test]
fn sl_crash_after_release_recovers_from_store_and_claims() {
    let sh = keypair();
    let sl = keypair();
    let params = Params::testnet_provisional();
    let s_height = 700_000u32;
    let escrow_amount = params.tier_d_sats + params.delta_fee_sats;
    let d = params.tier_d_sats;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let internal =
        newkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).expect("E_sl");
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).expect("E_sh");
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // SL-funded
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // SH-funded

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, escrow_amount, dest.clone(), d).unwrap();
    let comp_sl_spend =
        build_completion(&escrow_comp_sl, op_comp_sl, escrow_amount, dest.clone(), d).unwrap();
    let msg_comp_sh = comp_sh_spend.sighash;
    let msg_comp_sl = comp_sl_spend.sighash;
    let root_sh = escrow_comp_sh.merkle_root();
    let root_sl = escrow_comp_sl.merkle_root();
    let outkey_sh = escrow_comp_sh.output_key_xonly();
    let outkey_sl = escrow_comp_sl.output_key_xonly();

    // SL's REAL pre-armed refund of its own escrow (E_sl, early leaf).
    let sl_refund = PreArmedRefund::arm(
        &escrow_comp_sh,
        op_comp_sh,
        escrow_amount,
        &sl.sk,
        dest.clone(),
        d,
        s_height,
    )
    .expect("arm SL refund");

    let swap_id = [0x77u8; 32];
    let lease_sh = tempfile::tempdir().unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    let sh_params = params.clone();
    let sh_handle = std::thread::spawn(move || -> Result<(Vec<u8>, [u8; 64])> {
        let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + delta_late)?;
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
        let (t_secret, _) = AdaptorSecret::generate()?;
        let peer = PeerSession::new(swap_id, Box::new(io_sh));
        let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
        let possessing = funded.run_adaptor_exchange(ExchangeInputs {
            our_seckey: sh.sk,
            their_pubkey: ValidatedPoint::from_bytes(&sl.pk.serialize())?,
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
        let final_tx = finalize_key_spend(comp_sh_spend, sig.0);
        Ok((final_tx, sig.0))
    });

    // SL side: walk the wallet record through the REAL lifecycle as the
    // (future rank-4) orchestrator will: Funding -> Signing -> Released.
    let sid = swap_session_id(sl.pk, sh.pk).expect("sid");
    let (store, actions) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
    assert!(actions.is_empty());
    let mut rec = SwapRecord {
        swap_session_id: sid,
        role: Role::SecretLearner,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height,
        sweep_escrow_height: s_height,
        our_escrow_outpoint: Some(op_comp_sh),
        their_escrow_outpoint: Some(op_comp_sl),
        pre_armed_refund: Some(sl_refund.clone()),
        possession_record: None,
    };
    store.put(&rec).unwrap();
    rec.phase = SwapPhase::Signing;
    store.put(&rec).unwrap();

    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .expect("funded");
    let sl_possessing = funded
        .run_adaptor_exchange(ExchangeInputs {
            our_seckey: sl.sk,
            their_pubkey: ValidatedPoint::from_bytes(&sh.pk.serialize()).unwrap(),
            msg_comp_sh,
            msg_comp_sl,
            pre_armed_refund: sl_refund,
            adaptor_secret: None,
            lease_dir: Some(lease_sl.path().to_path_buf()),
            possession_store: Some(possession_store.path().to_path_buf()),
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
            taproot_output_comp_sh: Some(outkey_sh),
            taproot_output_comp_sl: Some(outkey_sl),
        })
        .expect("SL exchange");

    // G1 satisfied: record the release with the possession-record path.
    let possession_path =
        possession_store.path().join(format!("{}.possession", hex32(&sid)));
    assert!(possession_path.exists(), "possession record not persisted");
    rec.phase = SwapPhase::Released;
    rec.possession_record = Some(possession_path);
    store.put(&rec).unwrap();

    let (comp_sh_final, comp_sh_sig) = sh_handle.join().unwrap().expect("SH side");

    // ===== CRASH: all SL in-memory state dies. =====
    drop(sl_possessing);
    drop(store);

    // SH's completion lands while SL is down.
    chain.broadcast(&comp_sh_final).expect("Comp->SH accepted");
    chain.mine();
    assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::Confirmed(_)));

    // ===== FRESH PROCESS: the wallet store is ALL that survives. =====
    let (store, actions) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
    assert!(actions.is_empty(), "Released must not be force-aborted: {actions:?}");
    let rec = store.get(&sid).unwrap().expect("record survived");
    assert_eq!(rec.phase, SwapPhase::Released);

    let restored = Possessing::restore_secret_learner(
        rec.possession_record.as_ref().expect("path"),
        &rec.swap_session_id,
    )
    .expect("restore from possession record");

    let observed = ValidatedFinalSig::from_bytes(&comp_sh_sig).unwrap();
    let plan = restored
        .claim_after_reveal(&observed, chain.tip_height())
        .expect("extract + claim after restore");
    let comp_sl_final = finalize_key_spend(comp_sl_spend, plan.comp_sl_final.0);
    chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
    chain.mine();
    assert!(matches!(chain.spend_status(op_comp_sl), SpendStatus::Confirmed(_)));

    // Close out the record: Completing -> Completed.
    let mut rec = rec;
    rec.phase = SwapPhase::Completing;
    store.put(&rec).unwrap();
    rec.phase = SwapPhase::Completed;
    store.put(&rec).unwrap();
}

/// Crash story 2: the process dies MID-SIGNING. INV-2 routes the swap to
/// ABORT_REFUND on reopen, and the pre-armed refund persisted inside the
/// record reclaims the escrow at CSV maturity — no other state needed.
#[test]
fn crash_mid_signing_reclaims_via_persisted_refund() {
    let sh = keypair();
    let sl = keypair();
    let params = Params::testnet_provisional();
    let s_height = 500_000u32;
    let escrow_amount = params.tier_d_sats + params.delta_fee_sats;
    let d = params.tier_d_sats;

    let internal =
        newkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    // SL's escrow (E_sl): early refund leaf keyed to SL.
    let escrow = Escrow::new(&internal, &sl.pk, params.delta_early).expect("E_sl");
    let op = OutPoint::new(txid_from(9), 0);

    let chain = SimChain::new(s_height);
    chain.fund(op, s_height);

    let dest = escrow.funding_script_pubkey().clone();
    let refund =
        PreArmedRefund::arm(&escrow, op, escrow_amount, &sl.sk, dest, d, s_height).expect("arm");
    let maturity = refund.csv_maturity_height();

    let sid = swap_session_id(sl.pk, sh.pk).expect("sid");
    let wallet_dir = tempfile::tempdir().unwrap();
    {
        let (store, _) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
        let mut rec = SwapRecord {
            swap_session_id: sid,
            role: Role::SecretLearner,
            phase: SwapPhase::Funding,
            params: params.clone(),
            s_height,
            sweep_escrow_height: 0,
            our_escrow_outpoint: Some(op),
            their_escrow_outpoint: None,
            pre_armed_refund: Some(refund),
            possession_record: None,
        };
        store.put(&rec).unwrap();
        rec.phase = SwapPhase::Signing;
        store.put(&rec).unwrap();
        // ===== CRASH mid-session: nonces die with the process. =====
    }

    // Fresh process: INV-2.
    let (store, actions) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
    assert_eq!(actions, vec![RecoveryAction::AbortedLiveSigning { swap_session_id: sid }]);
    let rec = store.get(&sid).unwrap().expect("record");
    assert_eq!(rec.phase, SwapPhase::AbortRefund);
    let refund = rec.pre_armed_refund.as_ref().expect("refund persisted");

    // Too early: the CSV leaf is not mature — the chain refuses it.
    assert!(
        chain.broadcast(refund.tx_bytes()).is_err(),
        "immature refund must be rejected"
    );

    // Mine to maturity; the persisted bytes alone reclaim the funds.
    while chain.tip_height() < refund.csv_maturity_height() {
        chain.mine();
    }
    assert_eq!(maturity, refund.csv_maturity_height());
    chain.broadcast(refund.tx_bytes()).expect("mature refund accepted");
    chain.mine();
    assert!(matches!(chain.spend_status(op), SpendStatus::Confirmed(_)));

    // Ledger closes out: AbortRefund -> Refunded.
    let mut rec = rec;
    rec.phase = SwapPhase::Refunded;
    store.put(&rec).unwrap();
}
