//! `Wallet::open` + startup wiring (Task 07): the one-call composition of
//! config → keystore → engine → `SwapApp::startup` over a single data dir.
//!
//! * first run mints the keystore + (ack-gated) ledger, reopen is `Ready`;
//! * both onboarding acknowledgements are demanded, and an interrupted
//!   first run resumes (keystore present, ledger absent, mnemonic gone);
//! * passphrase policy (empty refused; wrong = clean re-promptable Err);
//! * torn / missing keystore states are routed with explicit advice;
//! * the dir-lock refuses a second concurrent open;
//! * startup over a `SimChain` drives a seeded recovery record's tick (the
//!   Task-B/E startup shape, entered through `Wallet` instead of raw seams).
//!
//! NOTE: every `Wallet::open` pays the PRODUCTION 600k-iteration PBKDF2 (the
//! keystore's test-only low-iteration path is deliberately not reachable
//! from `Wallet`), so these tests each cost a few hundred ms of KDF.

use bitcoin::OutPoint;
use secp::{Point, Scalar};
use switchbitcoin::chain::{ChainView, SimChain};
use switchbitcoin::settlement::refund::PreArmedRefund;
use switchbitcoin::settlement::state_machine::{canonical_internal_key, Role};
use switchbitcoin::tx::escrow::Escrow;
use switchbitcoin::tx::setup::build_setup;
use switchbitcoin::wallet::config::{Network, WalletConfig};
use switchbitcoin::wallet::ledger::PHASE0_WARNING;
use switchbitcoin::wallet::recovery_driver::RecoveryTick;
use switchbitcoin::wallet::runtime::{FirstRunError, OpenedWallet, Wallet};
use switchbitcoin::wallet::store::{SwapPhase, SwapRecord};

const PASS: &str = "task-07 test passphrase";

fn cfg(dir: &std::path::Path) -> WalletConfig {
    WalletConfig::new(dir, Network::Regtest)
}

/// Drive a fresh dir through the full first-run flow to a running Wallet.
fn first_run(dir: &std::path::Path) -> Wallet {
    let OpenedWallet::FirstRun(fr) = Wallet::open(cfg(dir), PASS).unwrap() else {
        panic!("fresh dir must route to FirstRun");
    };
    let words = fr.mnemonic().expect("fresh first run carries the mnemonic").to_string();
    fr.complete(PHASE0_WARNING, Some(&words)).unwrap()
}

fn keypair() -> (Scalar, Point) {
    let mut rng = rand::rng();
    let sk = Scalar::random(&mut rng);
    (sk, sk * secp::G)
}

fn txid_from(seed: u8) -> bitcoin::Txid {
    let mut b = [0u8; 32];
    b[0] = seed;
    bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b))
}

#[test]
fn first_run_creates_the_stores_and_reopen_is_ready() {
    let dir = tempfile::tempdir().unwrap();

    let wallet = first_run(dir.path());
    // The composed stores exist under the one data dir.
    // (No manifest.current: that file first appears when a SIGNED manifest
    // is ingested — until then the store serves the compiled baseline.)
    for file in ["keystore.bin", "ledger.bin", ".store.lock", ".manifest.lock"] {
        assert!(dir.path().join(file).exists(), "{file} missing after first run");
    }
    assert!(wallet.open_actions().is_empty());
    // Post-open params are the manifest's (== the compiled baseline here).
    assert_eq!(*wallet.params(), wallet.config().params);
    drop(wallet);

    // Reopen: same passphrase, straight to Ready.
    match Wallet::open(cfg(dir.path()), PASS).unwrap() {
        OpenedWallet::Ready(w) => assert!(w.open_actions().is_empty()),
        OpenedWallet::FirstRun(_) => panic!("existing wallet must reopen Ready"),
    }

    // Wrong passphrase: clean Err (no state change — still Ready after).
    assert!(Wallet::open(cfg(dir.path()), "not the passphrase").is_err());
    assert!(matches!(Wallet::open(cfg(dir.path()), PASS).unwrap(), OpenedWallet::Ready(_)));
}

/// Extract the returned `FirstRun` from a `Refused`, failing the test on any
/// other outcome.
fn expect_refused(
    result: Result<Wallet, FirstRunError>,
) -> Box<switchbitcoin::wallet::runtime::FirstRun> {
    match result {
        Err(FirstRunError::Refused { first_run, .. }) => first_run,
        Err(FirstRunError::Fatal(e)) => panic!("expected Refused, got Fatal({e:?})"),
        Ok(_) => panic!("a bad acknowledgement echo must not complete onboarding"),
    }
}

#[test]
fn ack_typos_are_refused_and_retryable_with_the_same_first_run() {
    let dir = tempfile::tempdir().unwrap();
    let OpenedWallet::FirstRun(fr) = Wallet::open(cfg(dir.path()), PASS).unwrap() else {
        panic!("fresh dir must route to FirstRun");
    };
    let words = fr.mnemonic().unwrap().to_string();

    // Bad mnemonic echo: Refused — the SAME FirstRun comes back, the words
    // are still displayable, and nothing durable was created (one typo must
    // not burn the one-shot mnemonic or waive the backup ack).
    let fr = expect_refused(fr.complete(PHASE0_WARNING, Some("wrong words")));
    assert_eq!(fr.mnemonic(), Some(words.as_str()));
    assert!(!dir.path().join("ledger.bin").exists());

    // Bad Phase-0 echo (mnemonic echo correct): Refused again, still whole.
    let fr = expect_refused(fr.complete("not the warning copy", Some(&words)));
    assert_eq!(fr.mnemonic(), Some(words.as_str()));
    assert!(!dir.path().join("ledger.bin").exists());

    // Retry with both echoes right: completes, and the backup ack was
    // genuinely enforced on this same instance.
    let wallet = fr.complete(PHASE0_WARNING, Some(&words)).unwrap();
    drop(wallet);
    assert!(matches!(Wallet::open(cfg(dir.path()), PASS).unwrap(), OpenedWallet::Ready(_)));
}

#[test]
fn an_interrupted_first_run_resumes_without_the_mnemonic() {
    let dir = tempfile::tempdir().unwrap();
    // Simulate a crash after keystore create, before complete().
    let OpenedWallet::FirstRun(fr) = Wallet::open(cfg(dir.path()), PASS).unwrap() else {
        panic!("fresh dir must route to FirstRun");
    };
    drop(fr);

    // Resume: keystore present, ledger absent, no engine artifacts — and the
    // mnemonic is GONE (unrecoverable from the seed).
    let OpenedWallet::FirstRun(fr) = Wallet::open(cfg(dir.path()), PASS).unwrap() else {
        panic!("interrupted first run must resume as FirstRun");
    };
    assert!(fr.mnemonic().is_none());
    let wallet = fr.complete(PHASE0_WARNING, None).unwrap();
    assert!(dir.path().join("ledger.bin").exists());
    drop(wallet);
    assert!(matches!(Wallet::open(cfg(dir.path()), PASS).unwrap(), OpenedWallet::Ready(_)));
}

/// The established-wallet guards: once the engine has run, a lost file must
/// FAIL CLOSED with restore advice — never reroute to onboarding, which
/// would silently reset the coin memory (missing ledger) or mint a seed that
/// quarantines every live swap record (missing keystore).
#[test]
fn an_established_wallet_never_reroutes_to_onboarding() {
    let dir = tempfile::tempdir().unwrap();
    drop(first_run(dir.path()));

    // ledger.bin lost, everything else intact: fail closed, not FirstRun.
    std::fs::remove_file(dir.path().join("ledger.bin")).unwrap();
    let err = Wallet::open(cfg(dir.path()), PASS).unwrap_err();
    assert!(err.to_string().contains("restore ledger.bin"), "{err}");

    // keystore.bin ALSO lost (locks/artifacts remain): refuse a fresh seed.
    std::fs::remove_file(dir.path().join("keystore.bin")).unwrap();
    let err = Wallet::open(cfg(dir.path()), PASS).unwrap_err();
    assert!(err.to_string().contains("restore keystore.bin"), "{err}");

    // Externally damaged keystore.bin on an established wallet: DAMAGE
    // advice — never the interrupted-create delete advice.
    let dir = tempfile::tempdir().unwrap();
    drop(first_run(dir.path()));
    std::fs::write(dir.path().join("keystore.bin"), b"externally mangled").unwrap();
    let err = Wallet::open(cfg(dir.path()), PASS).unwrap_err();
    assert!(err.to_string().contains("do NOT delete"), "{err}");
    assert!(!err.to_string().contains("interrupted create"), "{err}");
}

#[test]
fn passphrase_policy_is_enforced_at_the_wallet_seam() {
    let dir = tempfile::tempdir().unwrap();
    // Empty passphrase refused BEFORE any file is created (binary-owned
    // policy — the keystore itself would accept it).
    assert!(Wallet::open(cfg(dir.path()), "").is_err());
    assert!(!dir.path().join("keystore.bin").exists());
}

#[test]
fn torn_and_missing_keystore_states_are_routed_with_advice() {
    // Torn keystore (crash mid-create / foreign file): explicit
    // delete-to-recreate advice, NOT a wrong-passphrase loop.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("keystore.bin"), b"torn by a crash").unwrap();
    let err = Wallet::open(cfg(dir.path()), PASS).unwrap_err();
    assert!(err.to_string().contains("torn keystore"), "{err}");

    // Keystore missing but wallet data present: refuse to mint a fresh seed
    // over sealed state it could never read.
    let dir = tempfile::tempdir().unwrap();
    let wallet = first_run(dir.path());
    drop(wallet);
    std::fs::remove_file(dir.path().join("keystore.bin")).unwrap();
    let err = Wallet::open(cfg(dir.path()), PASS).unwrap_err();
    assert!(err.to_string().contains("restore keystore.bin"), "{err}");
}

#[test]
fn a_second_concurrent_open_is_refused_by_the_dir_lock() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = first_run(dir.path());

    let err = Wallet::open(cfg(dir.path()), PASS).unwrap_err();
    assert!(err.to_string().contains("another process"), "{err}");

    // Releasing the first instance frees the locks.
    drop(wallet);
    assert!(matches!(Wallet::open(cfg(dir.path()), PASS).unwrap(), OpenedWallet::Ready(_)));
}

#[test]
fn a_loaded_config_file_opens_the_wallet_it_points_at() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("wallet-data");
    let config_path = dir.path().join("switchbitcoin.toml");
    // Single-quoted literal string: Windows backslashes pass through.
    std::fs::write(
        &config_path,
        format!("network = \"regtest\"\ndata_dir = '{}'\n", data_dir.display()),
    )
    .unwrap();

    let config = WalletConfig::load(&config_path).unwrap();
    assert_eq!(config.data_dir, data_dir);
    assert!(config.node.is_none());

    let OpenedWallet::FirstRun(fr) = Wallet::open(config, PASS).unwrap() else {
        panic!("fresh data dir must route to FirstRun");
    };
    let words = fr.mnemonic().unwrap().to_string();
    let wallet = fr.complete(PHASE0_WARNING, Some(&words)).unwrap();
    assert!(data_dir.join("keystore.bin").exists());
    assert_eq!(wallet.config().network, Network::Regtest);
}

/// The Task-B/E startup shape entered through `Wallet`: a `Funding` record
/// whose escrow is CONFIRMED on chain must surface its standing pre-armed
/// refund in the recovery scan, and the reconcile outcome rides alongside.
#[test]
fn startup_over_a_sim_chain_drives_a_seeded_recovery_record() {
    let dir = tempfile::tempdir().unwrap();
    let mut wallet = first_run(dir.path());
    let params = wallet.params().clone();
    let base = 750_000u32;
    let chain = SimChain::new(base);

    // A real Setup on chain: pre-coin conjured, escrow confirmed.
    let ((sk1, pk1), (_sk2, pk2)) = (keypair(), keypair());
    let internal = canonical_internal_key(pk1, pk2).unwrap();
    let escrow = Escrow::new(&internal, &pk1, params.delta_early).unwrap();
    let pre_op = OutPoint::new(txid_from(0xC2), 0);
    chain.fund_with_amount(pre_op, base, params.pre_encumbrance_sats());
    let (setup, escrow_op) = build_setup(
        pre_op,
        params.pre_encumbrance_sats(),
        params.escrow_amount_sats(),
        params.anchor_sats,
        &escrow,
        &sk1,
    )
    .unwrap();
    chain.broadcast(&setup).unwrap();
    chain.mine();
    let funded_at = chain.funding_height(escrow_op).unwrap();
    let refund = PreArmedRefund::arm(
        &escrow,
        escrow_op,
        params.escrow_amount_sats(),
        &sk1,
        escrow.funding_script_pubkey().clone(),
        params.tier_d_sats,
        params.anchor_sats,
        funded_at,
    )
    .unwrap();

    // Seed the crash artifact: a persisted `Funding` record for the funded
    // escrow (the in-memory app state did not survive).
    let sid = [0x5Bu8; 32];
    wallet
        .engine()
        .store()
        .put(&SwapRecord {
            swap_session_id: sid,
            role: Role::SecretHolder,
            phase: SwapPhase::Funding,
            params: params.clone(),
            s_height: 0,
            sweep_escrow_height: 0,
            our_escrow_outpoint: Some(escrow_op),
            their_escrow_outpoint: Some(OutPoint::new(txid_from(0xC3), 0)),
            pre_armed_refund: Some(refund),
            completion_tx: None,
            setup_tx: None,
            possession_record: None,
        })
        .unwrap();

    // Steps 2+3 through the Wallet handle.
    let (reconcile, scan) = wallet.startup(&chain).unwrap();
    let reconcile = reconcile.expect("reconcile succeeds on a writable ledger");
    assert!(reconcile.reserves_swept.is_empty());

    assert!(scan.unreadable.is_empty() && scan.failed.is_empty());
    assert_eq!(scan.ticks.len(), 1);
    assert_eq!(scan.ticks[0].0, sid);
    assert!(
        matches!(scan.ticks[0].1, RecoveryTick::Funding { refund: Some(_) }),
        "funded Funding record must surface its refund, got {:?}",
        scan.ticks[0].1
    );
}
