//! SoftwareKeyStore drop-in integration (Task 06): the SAME complete two-party
//! swap `tests/engine.rs` drives with the modeled key doubles, driven instead
//! with the real software keystore serving BOTH seams (`EnclaveKeyProvider`
//! for ledger/store sealing + `KeySource` for ledger signing) — proving the
//! store is a drop-in, end to end: onboarding split, escrow, exchange,
//! completion, and ledger reconcile all under seed-derived keys. Plus the
//! custody-specific lifecycle: sealed files created under a keystore reopen
//! under a REOPENED keystore (same dir + passphrase), and do NOT open under a
//! different key root.

use bitcoin::OutPoint;
use switchbitcoin::chain::{ChainView, SimChain, SpendStatus};
use switchbitcoin::crypto::adaptor::AdaptorSecret;
use switchbitcoin::crypto::ValidatedPoint;
use switchbitcoin::settlement::params::Params;
use switchbitcoin::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use switchbitcoin::settlement::state_machine::{
    swap_session_id, ExchangeInputs, Funding, PeerSession, Role, Transport,
};
use switchbitcoin::tx::escrow::Escrow;
use switchbitcoin::tx::txbuild::{build_completion, finalize_key_spend};
use switchbitcoin::wallet::engine::{SwapContext, SwapEngine, SwapOutcome};
use switchbitcoin::wallet::keys::{KeyPurpose, KeySource};
use switchbitcoin::wallet::keystore::SoftwareKeyStore;
use switchbitcoin::wallet::ledger::{acknowledge_phase0, CoinState, Ledger, WalletClock, PHASE0_WARNING};
use switchbitcoin::wallet::manifest::ModeledTrustRoot;
use switchbitcoin::wallet::store::{ModeledEnclave, SwapPhase, SwapStore};
use switchbitcoin::{Error, Result};
use secp::{Point, Scalar};
use std::sync::mpsc;

/// Low PBKDF2 work factor so the suite stays fast; production uses
/// `SoftwareKeyStore::create` (600k).
const TEST_ITERS: u32 = 16;

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
struct FixedClock(u64);
impl WalletClock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// Onboard one mature, leasable pre-encumbrance coin into the SL wallet's
/// ledger — every key (deposit spk, split signing, change) drawn from the
/// SOFTWARE keystore, and the ledger file sealed under its platform key.
fn onboard_one_coin(
    dir: &std::path::Path,
    pre_enc: u64,
    lessee: [u8; 32],
    ks: &SoftwareKeyStore,
) -> OutPoint {
    let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
    let mut ledger = Ledger::create(dir, ks, ack).unwrap();
    let params = Params::testnet_provisional();
    let (idx, spk) = ledger.next_deposit_address(ks).unwrap();
    let dep = OutPoint::new(txid_from(0xDD), 0);
    ledger
        .register_deposit(
            dep,
            pre_enc + 2_000,
            100,
            idx,
            &spk,
            ks,
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .unwrap();
    let plan = ledger.split_deposit(dep, &params, 2_000, ks).unwrap();
    ledger.confirm_split(plan.txid, 150, &FixedClock(1_000)).unwrap();
    let coin = ledger
        .lease_pre_encumbrance(pre_enc, &FixedClock(u64::MAX), u32::MAX, lessee)
        .unwrap()
        .expect("a mature pre-encumbrance coin");
    coin.outpoint
}

/// The engine e2e from `tests/engine.rs`, with `SoftwareKeyStore` substituted
/// for BOTH `ModeledEnclave` and `ModeledKeySource`: a complete swap producing
/// a valid escrow, pre-armed refund handoff, and completion.
#[test]
fn full_swap_driven_with_the_software_keystore() {
    let params = Params::testnet_provisional();
    let unit = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let s_height = 700_000u32;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let sh = keypair();
    let sl = keypair();
    let internal =
        switchbitcoin::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap(); // E_sl
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).unwrap(); // E_sh
    let op_comp_sh = OutPoint::new(txid_from(2), 0);
    let op_comp_sl = OutPoint::new(txid_from(1), 0);

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, unit, dest.clone(), d, params.anchor_sats)
            .unwrap();
    let comp_sl_spend =
        build_completion(&escrow_comp_sl, op_comp_sl, unit, dest, d, params.anchor_sats).unwrap();
    let msg_sh = comp_sh_spend.sighash;
    let msg_sl = comp_sl_spend.sighash;
    let root_sh = escrow_comp_sh.merkle_root();
    let root_sl = escrow_comp_sl.merkle_root();
    let ok_sh = escrow_comp_sh.output_key_xonly();
    let ok_sl = escrow_comp_sl.output_key_xonly();

    let swap_id = [0xE9u8; 32];
    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let lease_sh = tempfile::tempdir().unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    // The REAL keystore: created once, then REOPENED from disk for the engine
    // (the reopen is the custody path a restarted wallet takes).
    let (ks_created, _mnemonic) =
        SoftwareKeyStore::create_with_iters(wallet_dir.path(), "pre-alpha passphrase", TEST_ITERS)
            .unwrap();
    let funding_coin =
        onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid, &ks_created);
    drop(ks_created);
    let ks = SoftwareKeyStore::open(wallet_dir.path(), "pre-alpha passphrase").unwrap();

    let (mut engine, actions) = SwapEngine::open(
        wallet_dir.path(),
        &ks,
        Box::new(ks.clone()),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(actions.is_empty(), "fresh wallet has no recovery actions");

    let dest2 = escrow_comp_sh.funding_script_pubkey().clone();
    let sl_refund = PreArmedRefund::arm(
        &escrow_comp_sh, op_comp_sh, unit, &sl.sk, dest2, d, params.anchor_sats, s_height,
    )
    .unwrap();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // SH runs the exchange raw + broadcasts Comp->SH to the mempool.
    let sh_params = params.clone();
    let sh_chain = chain.clone();
    let comp_sh_for_sh = comp_sh_spend.clone();
    let sh_handle = std::thread::spawn(move || -> Result<[u8; 64]> {
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
        sh_chain
            .broadcast(&finalize_key_spend(comp_sh_for_sh, sig.0))
            .expect("Comp->SH to mempool");
        Ok(sig.0)
    });

    // SL side, ENTIRELY through the engine over software-keystore custody.
    engine
        .record_funding(
            &make_ctx(
                sl.sk, sh.pk, op_comp_sh, op_comp_sl, unit, msg_sh, msg_sl,
                sl_refund.clone(), None, root_sh, root_sl, ok_sh, ok_sl,
                lease_sl.path().to_path_buf(), possession_store.path().to_path_buf(),
                confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap(),
                funding_coin,
            ),
            Role::SecretLearner,
            params.clone(),
        )
        .unwrap();
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Funding);

    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .unwrap();
    let mut ctx = make_ctx(
        sl.sk, sh.pk, op_comp_sh, op_comp_sl, unit, msg_sh, msg_sl, sl_refund, None,
        root_sh, root_sl, ok_sh, ok_sl, lease_sl.path().to_path_buf(),
        possession_store.path().to_path_buf(), sl_receipt, funding_coin,
    );

    let possessing = engine.run_exchange(funded, &mut ctx, &chain).unwrap();
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Released);

    sh_handle.join().unwrap().expect("SH side");
    assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::InMempool));

    match engine.settle(&possessing, &ctx, &chain).unwrap() {
        SwapOutcome::Completed { our_final_sig, .. } => {
            let comp_sl_final = finalize_key_spend(comp_sl_spend, our_final_sig);
            chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
            chain.mine();
            assert!(matches!(chain.spend_status(op_comp_sl), SpendStatus::Confirmed(_)));
        }
        other => panic!("expected Completed, got {other:?}"),
    }

    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Completed);
    let coin = engine.ledger().find(&funding_coin).expect("funding coin tracked");
    assert_eq!(coin.state, CoinState::Spent, "the engine marked the funding coin spent");
}

/// The custody lifecycle around restarts: ledger + swap store sealed under a
/// keystore's platform key reopen under a REOPENED keystore, keys re-derive
/// identically, and a DIFFERENT key root (the modeled enclave) is rejected.
#[test]
fn sealed_wallet_files_survive_a_keystore_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (ks, _) = SoftwareKeyStore::create_with_iters(dir.path(), "pw", TEST_ITERS).unwrap();

    // Create + seal a ledger and a swap store under the keystore.
    let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
    let mut ledger = Ledger::create(dir.path(), &ks, ack).unwrap();
    let (idx, spk) = ledger.next_deposit_address(&ks).unwrap();
    drop(ledger);
    let store = SwapStore::open(dir.path(), &ks).unwrap();
    drop(store);
    let xonly = ks.derive_xonly(KeyPurpose::Deposit, idx).unwrap();
    drop(ks);

    // Reopen the keystore from disk: sealed files must open, keys must match.
    let ks2 = SoftwareKeyStore::open(dir.path(), "pw").unwrap();
    let mut ledger = Ledger::open(dir.path(), &ks2).expect("sealed ledger reopens");
    assert_eq!(ks2.derive_xonly(KeyPurpose::Deposit, idx).unwrap(), xonly);
    // The persisted (index -> spk) binding still verifies against the
    // RE-DERIVED key: register_deposit re-checks the derivation, so this
    // passing proves the index-only disk model survives a keystore reopen.
    ledger
        .register_deposit(
            OutPoint::new(txid_from(0xD1), 0),
            50_000,
            100,
            idx,
            &spk,
            &ks2,
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .expect("spk issued before the reopen still binds to the re-derived key");
    drop(ledger);
    SwapStore::open(dir.path(), &ks2).expect("sealed swap store reopens");

    // A different key root must NOT open the sealed ledger (the platform key
    // is load-bearing, not decorative). The swap store is per-RECORD sealed —
    // wrong-key behavior there is quarantine-on-scan, covered by the store's
    // own unit tests — so the whole-file-sealed ledger is the hard gate here.
    assert!(Ledger::open(dir.path(), &ModeledEnclave).is_err());
}

#[allow(clippy::too_many_arguments)]
fn make_ctx(
    our_seckey: Scalar,
    their_pk: Point,
    our_escrow_op: OutPoint,
    their_escrow_op: OutPoint,
    escrow_amount: u64,
    msg_comp_sh: [u8; 32],
    msg_comp_sl: [u8; 32],
    pre_armed_refund: PreArmedRefund,
    adaptor_secret: Option<AdaptorSecret>,
    root_sh: [u8; 32],
    root_sl: [u8; 32],
    ok_sh: [u8; 32],
    ok_sl: [u8; 32],
    lease_dir: std::path::PathBuf,
    possession_store: std::path::PathBuf,
    watchtower_receipt: switchbitcoin::settlement::refund::WatchtowerReceipt,
    funding_coin: OutPoint,
) -> SwapContext {
    SwapContext {
        our_seckey,
        their_pubkey: ValidatedPoint::from_bytes(&their_pk.serialize()).unwrap(),
        our_escrow_op,
        their_escrow_op,
        reveal_escrow_op: our_escrow_op,
        escrow_amount,
        msg_comp_sh,
        msg_comp_sl,
        pre_armed_refund,
        adaptor_secret,
        taproot_root_comp_sh: root_sh,
        taproot_root_comp_sl: root_sl,
        taproot_output_comp_sh: ok_sh,
        taproot_output_comp_sl: ok_sl,
        lease_dir,
        possession_store,
        watchtower_receipt,
        funding_coin,
    }
}
