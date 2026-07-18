//! Wallet-layer crash-safety integration tests (wallet rank 1).
//!
//! These prove the two crash stories END TO END, from the persisted record
//! alone — no in-memory state survives the "crash" in either test:
//!
//!   1. Crash INSIDE the G1 window — after the exchange persisted the
//!      possession record but BEFORE the orchestrator's put(Released) (the
//!      critical from the adversarial review): open() must route the swap to
//!      Released by G1 evidence, and a fresh process restores, extracts t
//!      from the observed reveal, and claims on the SimChain.
//!   2. Crash DURING a signing session before anything was persisted
//!      (INV-2): reopen routes the swap to ABORT_REFUND, and the pre-armed
//!      refund persisted INSIDE the record reclaims the funds at CSV
//!      maturity — the record alone is a complete exit.
//!
//! Both tests follow the orchestrator write-ordering contract from
//! `wallet::mod`: put(Funding) before money moves, the possession pointer
//! registered at put(Signing), the completion tx persisted at
//! put(Completing) before broadcast.

use bitcoin::{OutPoint, Txid};
use switchbitcoin::chain::{ChainView, SimChain, SpendStatus};
use switchbitcoin::crypto::adaptor::AdaptorSecret;
use switchbitcoin::crypto::{ValidatedFinalSig, ValidatedPoint};
use switchbitcoin::settlement::params::Params;
use switchbitcoin::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use switchbitcoin::settlement::state_machine::{
    swap_session_id, ExchangeInputs, Funding, PeerSession, Possessing, Role, Transport,
};
use switchbitcoin::tx::escrow::Escrow;
use switchbitcoin::tx::txbuild::{build_completion, finalize_key_spend};
use switchbitcoin::wallet::{ModeledEnclave, RecoveryAction, SwapPhase, SwapRecord, SwapStore};
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

/// Crash story 1 — THE adversarial-review critical: SL's process dies inside
/// the G1 window (possession record persisted by the exchange; the enabling
/// partial possibly on the wire; put(Released) never reached). The wallet
/// record still says Signing. A fresh process must NOT refund-strand: open()
/// routes to Released by G1 evidence and the swap completes from the store
/// alone.
#[test]
fn sl_crash_in_g1_window_recovers_from_store_and_claims() {
    let sh = keypair();
    let sl = keypair();
    let params = Params::testnet_provisional();
    let s_height = 700_000u32;
    let escrow_amount = params.escrow_amount_sats(); // scheme (a)
    let d = params.tier_d_sats;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let internal =
        switchbitcoin::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).expect("E_sl");
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).expect("E_sh");
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // SL-funded
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // SH-funded

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, escrow_amount, dest.clone(), d, params.anchor_sats).unwrap();
    let comp_sl_spend =
        build_completion(&escrow_comp_sl, op_comp_sl, escrow_amount, dest.clone(), d, params.anchor_sats).unwrap();
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
        params.anchor_sats,
        s_height,
    )
    .expect("arm SL refund");

    let swap_id = [0x77u8; 32];
    let lease_sh = tempfile::tempdir().unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    // Ordering contract rule 1: the record exists BEFORE money moves.
    let sid = swap_session_id(sl.pk, sh.pk).expect("sid");
    let (store, actions) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
    assert!(actions.is_empty());
    let mut rec = SwapRecord {
        swap_session_id: sid,
        role: Role::SecretLearner,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height: 0,
        sweep_escrow_height: 0,
        our_escrow_outpoint: Some(op_comp_sh),
        their_escrow_outpoint: Some(op_comp_sl),
        pre_armed_refund: Some(sl_refund.clone()),
        completion_tx: None,
        setup_tx: None,
        possession_record: None,
    };
    store.put(&rec).unwrap();

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    // Ordering contract rule 2: the (deterministic) possession pointer is
    // registered at put(Signing), BEFORE the exchange runs.
    let possession_path =
        possession_store.path().join(format!("{}.possession", hex32(&sid)));
    rec.phase = SwapPhase::Signing;
    rec.s_height = s_height;
    rec.sweep_escrow_height = s_height;
    rec.possession_record = Some(possession_path.clone());
    store.put(&rec).unwrap();

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
            possession_store: Some((
                possession_store.path().to_path_buf(),
                switchbitcoin::crypto::storage::platform_secure_key(),
            )),
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
            taproot_output_comp_sh: Some(outkey_sh),
            taproot_output_comp_sl: Some(outkey_sl),
        })
        .expect("SL exchange");
    assert!(possession_path.exists(), "possession record not persisted");

    let (comp_sh_final, comp_sh_sig) = sh_handle.join().unwrap().expect("SH side");

    // ===== CRASH — inside the G1 window: the exchange persisted the
    // possession record and (from SH's completed run) the enabling partial
    // WAS delivered, but put(Released) never happened. The on-disk phase is
    // still Signing. All SL in-memory state dies.
    drop(sl_possessing);
    drop(store);

    // SH's completion lands while SL is down: the exact branch that was
    // fund-loss before the fix (refund would be stranded; extraction is the
    // only path to SL's funds).
    chain.broadcast(&comp_sh_final).expect("Comp->SH accepted");
    chain.mine();
    assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::Confirmed(_)));

    // ===== FRESH PROCESS: the wallet store is ALL that survives. =====
    let (store, actions) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
    // G1 evidence routing: possession record exists + authenticates =>
    // Released (restore-and-extract), NOT AbortRefund.
    assert_eq!(actions, vec![RecoveryAction::RestoredPostRelease { swap_session_id: sid }]);
    let rec = store.get(&sid).unwrap().expect("record survived");
    assert_eq!(rec.phase, SwapPhase::Released);

    let restored = Possessing::restore_secret_learner(
        rec.possession_record.as_ref().expect("path"),
        &rec.swap_session_id,
        &switchbitcoin::crypto::storage::platform_secure_key(),
    )
    .expect("restore from possession record");

    let observed = ValidatedFinalSig::from_bytes(&comp_sh_sig).unwrap();
    let plan = restored
        .claim_after_reveal(&observed, chain.tip_height())
        .expect("extract + claim after restore");
    let comp_sl_final = finalize_key_spend(comp_sl_spend, plan.comp_sl_final.0);

    // Ordering contract rule 3: persist the finalized claim BEFORE broadcast.
    let mut rec = rec;
    rec.phase = SwapPhase::Completing;
    rec.completion_tx = Some(comp_sl_final.clone());
    store.put(&rec).unwrap();

    chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
    chain.mine();
    assert!(matches!(chain.spend_status(op_comp_sl), SpendStatus::Confirmed(_)));

    rec.phase = SwapPhase::Completed;
    store.put(&rec).unwrap();

    // And the Completing record really is self-sufficient: a fresh process
    // could have rebroadcast the persisted bytes verbatim.
    let reread = store.get(&sid).unwrap().unwrap();
    assert_eq!(reread.completion_tx.as_deref(), Some(comp_sl_final.as_slice()));
}

/// Crash story 2: the process dies MID-SIGNING before the exchange persisted
/// anything (no possession record). INV-2 routes the swap to ABORT_REFUND on
/// reopen, and the pre-armed refund persisted inside the record reclaims the
/// escrow at CSV maturity — no other state needed.
#[test]
fn crash_mid_signing_reclaims_via_persisted_refund() {
    let sh = keypair();
    let sl = keypair();
    let params = Params::testnet_provisional();
    let s_height = 500_000u32;
    let escrow_amount = params.escrow_amount_sats(); // scheme (a)
    let d = params.tier_d_sats;

    let internal =
        switchbitcoin::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    // SL's escrow (E_sl): early refund leaf keyed to SL.
    let escrow = Escrow::new(&internal, &sl.pk, params.delta_early).expect("E_sl");
    let op = OutPoint::new(txid_from(9), 0);
    let op_theirs = OutPoint::new(txid_from(8), 0);

    let dest = escrow.funding_script_pubkey().clone();
    let refund =
        PreArmedRefund::arm(&escrow, op, escrow_amount, &sl.sk, dest, d, params.anchor_sats, s_height).expect("arm");
    let maturity = refund.csv_maturity_height();

    let sid = swap_session_id(sl.pk, sh.pk).expect("sid");
    let wallet_dir = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    {
        let (store, _) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
        let mut rec = SwapRecord {
            swap_session_id: sid,
            role: Role::SecretLearner,
            phase: SwapPhase::Funding,
            params: params.clone(),
            s_height: 0,
            sweep_escrow_height: 0,
            our_escrow_outpoint: Some(op),
            their_escrow_outpoint: Some(op_theirs),
            pre_armed_refund: Some(refund),
            completion_tx: None,
            setup_tx: None,
            possession_record: None,
        };
        store.put(&rec).unwrap();
        rec.phase = SwapPhase::Signing;
        rec.s_height = s_height;
        rec.possession_record = Some(
            possession_store.path().join(format!("{}.possession", hex32(&sid))),
        );
        store.put(&rec).unwrap();
        // ===== CRASH mid-session: nonces die with the process; the
        // possession record was never written (no G1 evidence). =====
    }

    let chain = SimChain::new(s_height);
    chain.fund(op, s_height);

    // Fresh process: INV-2 — no G1 evidence => ABORT_REFUND.
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
