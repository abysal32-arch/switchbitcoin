//! Backup & restore (Task 17): the wallet-portability story, end to end.
//!
//! * `backup_restore_round_trip_drives_an_inflight_swap_to_its_terminal` —
//!   the headline: a wallet with a swap parked in `AbortRefund` is backed up
//!   (refused while the engine runs, snapshotted once stopped), the data dir
//!   is WIPED, the bundle restores byte-identically into the empty path, and
//!   the recover path (startup reconcile + recovery ticks + refund babysit)
//!   drives the restored swap to `Refunded` on the same SimChain. The key
//!   index provably survives (issuance continues, never rewinds).
//! * `restore_refuses_corrupt_and_hostile_bundles_cleanly` — negative-first:
//!   truncation, bit flips, bad magic, path traversal, duplicate members,
//!   incomplete member sets, a torn keystore member, understated counts, and
//!   occupied destinations are all clean `Err`s that leave NO partial dir
//!   and NO staging leftovers.
//! * `mnemonic_only_restore_with_a_raised_floor_prevents_index_reuse` — the
//!   dead-device path: seed from words + fresh ledger + `raise_key_index_floor`
//!   resumes issuance PAST every index the lost wallet used; the floor is
//!   monotonic and persists.
//!
//! Fixtures mirror tests/runner.rs (test crates cannot share modules) but run
//! under REAL `SoftwareKeyStore` custody — a backup of the modeled enclave
//! would have no keystore.bin to carry.

use std::sync::mpsc;
use std::time::Duration;

use bitcoin::OutPoint;
use secp::{Point, Scalar};
use swapkey::chain::{ChainView, SimChain, SpendStatus};
use swapkey::crypto::ValidatedPoint;
use swapkey::settlement::params::Params;
use swapkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use swapkey::settlement::state_machine::{canonical_internal_key, PeerSession, Transport};
use swapkey::tx::escrow::Escrow;
use swapkey::tx::setup::build_setup;
use swapkey::tx::txbuild::build_completion;
use swapkey::wallet::backup::{backup_data_dir, restore_data_dir, BACKUP_MAGIC};
use swapkey::wallet::engine::{SwapContext, SwapEngine};
use swapkey::wallet::ledger::{
    acknowledge_phase0, CoinClass, CoinState, Ledger, WalletClock, PHASE0_WARNING,
};
use swapkey::wallet::manifest::ModeledTrustRoot;
use swapkey::wallet::runner::{
    apply_recovery_tick, hex32, persist_artifacts, refund_babysit_step, swap_step, RunOptions,
    SwapArtifacts, SwapOutcome, SwapRunState, SwapStepOutcome,
};
use swapkey::wallet::store::SwapPhase;
use swapkey::wallet::{AppTick, SoftwareKeyStore, SwapApp};
use swapkey::{Error, Result};

/// Low KDF work factor so the suite stays fast (the keystore module's own
/// precedent); production is DEFAULT_PBKDF2_ITERS.
const TEST_ITERS: u32 = 16;
const PASS: &str = "backup test passphrase";

// ---------- fixture helpers (mirrors tests/runner.rs, keystore-backed) ------

struct ChannelTransport {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}
impl Transport for ChannelTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.tx.send(bytes.to_vec()).map_err(|_| Error::Abort("peer hung up"))
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        self.rx.recv_timeout(Duration::from_secs(60)).map_err(|_| Error::Abort("peer hung up"))
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
fn vp(p: &Point) -> ValidatedPoint {
    ValidatedPoint::from_bytes(&p.serialize()).unwrap()
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

/// The on-disk path of a bundle member name (`/`-separated) under `dir`.
fn member_path(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    name.split('/').fold(dir.to_path_buf(), |p, c| p.join(c))
}

/// Serialize an arbitrary bundle with a VALID trailing hash — the hostile-
/// bundle constructor (a real attacker can always produce a well-hashed
/// bundle; the hash gates corruption, the allowlist gates hostility).
fn craft(files: &[(&str, &[u8])]) -> Vec<u8> {
    use bitcoin::hashes::{sha256, Hash};
    let mut v = Vec::new();
    v.extend_from_slice(BACKUP_MAGIC);
    v.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for (name, data) in files {
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&(data.len() as u64).to_le_bytes());
        v.extend_from_slice(data);
    }
    let d = sha256::Hash::hash(&v).to_byte_array();
    v.extend_from_slice(&d);
    v
}

/// Recompute a tampered bundle's trailing hash so only the STRUCTURAL gate
/// under test fires, never the integrity hash.
fn reseal(mut bytes: Vec<u8>) -> Vec<u8> {
    use bitcoin::hashes::{sha256, Hash};
    bytes.truncate(bytes.len() - 32);
    let d = sha256::Hash::hash(&bytes).to_byte_array();
    bytes.extend_from_slice(&d);
    bytes
}

// ============================================================================
// The headline round trip: fund → abort → backup → wipe → restore → recover.
// ============================================================================

#[test]
fn backup_restore_round_trip_drives_an_inflight_swap_to_its_terminal() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 600_000u32;

    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("wallet");
    std::fs::create_dir_all(&dir).unwrap();
    let bundle = root.path().join("wallet.skbak");

    // Real keystore custody: the round trip must carry keystore.bin too.
    let (ks, _words) = SoftwareKeyStore::create_with_iters(&dir, PASS, TEST_ITERS).unwrap();

    // Onboard one deposit through the real pipeline (register → split →
    // confirm), leaving the pre-encumbrance coin unleased for now.
    let sl_pre = {
        let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
        let mut ledger = Ledger::create(&dir, &ks, ack).unwrap();
        let (idx, spk) = ledger.next_deposit_address(&ks).unwrap();
        let dep = OutPoint::new(txid_from(0xD1), 0);
        ledger
            .register_deposit(
                dep,
                params.pre_encumbrance_sats() + 2_000,
                100,
                idx,
                &spk,
                &ks,
                Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
            )
            .unwrap();
        let plan = ledger.split_deposit(dep, &params, 2_000, &ks).unwrap();
        ledger.confirm_split(plan.txid, 150, &FixedClock(1_000)).unwrap();
        ledger
            .coins()
            .iter()
            .find(|c| c.class == CoinClass::PreEncumbrance && c.state == CoinState::Unspent)
            .expect("split minted a pre-encumbrance coin")
            .outpoint
    };

    // Escrow pair + our Setup + hostile counterparty — the funded-abort shape
    // from tests/runner.rs. First funder = smaller pubkey (our Setup leads).
    let (sh, sl) = loop {
        let a = keypair();
        let b = keypair();
        if vp(&a.pk).to_bytes() < vp(&b.pk).to_bytes() {
            break (b, a);
        } else if vp(&b.pk).to_bytes() < vp(&a.pk).to_bytes() {
            break (a, b);
        }
    };
    let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
    let e_ours = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let e_theirs = Escrow::new(&internal, &sh.pk, params.delta_early).unwrap();

    let chain = SimChain::new(base);
    let unit = params.pre_encumbrance_sats();
    chain.fund_with_amount(sl_pre, base, unit);
    let (sl_setup, our_op) =
        build_setup(sl_pre, unit, escrow_amt, params.anchor_sats, &e_ours, &sl.sk).unwrap();
    let their_pre = OutPoint::new(txid_from(0xB0), 0);
    chain.fund_with_amount(their_pre, base, unit);
    let (_sh_setup, their_op) =
        build_setup(their_pre, unit, escrow_amt, params.anchor_sats, &e_theirs, &sh.sk).unwrap();

    let dest = e_ours.funding_script_pubkey().clone();
    let comp =
        build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund = PreArmedRefund::arm(
        &e_ours, our_op, escrow_amt, &sl.sk, dest.clone(), d, params.anchor_sats, base,
    )
    .unwrap();
    let refund_bytes = refund.tx_bytes().to_vec();
    let refund_txid: bitcoin::Txid = {
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(refund.tx_bytes()).unwrap();
        tx.compute_txid()
    };
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let ctx = SwapContext {
        our_seckey: sl.sk,
        their_pubkey: vp(&sh.pk),
        our_escrow_op: our_op,
        their_escrow_op: their_op,
        reveal_escrow_op: our_op,
        escrow_amount: escrow_amt,
        msg_comp_sh: comp.sighash,
        msg_comp_sl: comp.sighash,
        pre_armed_refund: refund,
        adaptor_secret: None,
        taproot_root_comp_sh: e_ours.merkle_root(),
        taproot_root_comp_sl: e_theirs.merkle_root(),
        taproot_output_comp_sh: e_ours.output_key_xonly(),
        taproot_output_comp_sl: e_theirs.output_key_xonly(),
        // The runner's real layout: leases + possession records live under
        // the data dir, so the bundle can carry them.
        lease_dir: dir.join("leases"),
        possession_store: dir.clone(),
        watchtower_receipt: receipt,
        funding_coin: sl_pre,
    };
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let sid_hex = hex32(&sid);

    // Lease under the REAL sid (the negotiated path's shape) so the restored
    // startup reconcile sees a lease matching the live record.
    {
        let mut ledger = Ledger::open(&dir, &ks).unwrap();
        let coin = ledger
            .lease_pre_encumbrance(unit, &FixedClock(u64::MAX), u32::MAX, sid)
            .unwrap()
            .expect("a mature pre-encumbrance coin");
        assert_eq!(coin.outpoint, sl_pre);
    }
    // A crash-left single-signer tombstone (INV-3 burn evidence): the bundle
    // must carry it — a restored store must keep refusing to re-sign that sid.
    std::fs::create_dir_all(dir.join("leases")).unwrap();
    std::fs::write(dir.join("leases").join(&sid_hex), b"").unwrap();

    let mut engine =
        SwapEngine::open(&dir, &ks, Box::new(ks.clone()), &ModeledTrustRoot).unwrap().0;
    let (dead, _keep) = duplex();
    let peer = PeerSession::new([0u8; 32], Box::new(dead));
    let mut app = SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

    let artifacts = SwapArtifacts {
        session_id: sid,
        setup_tx: sl_setup.clone(),
        comp_sh: comp.clone(),
        comp_sl: comp.clone(),
        refund_tx: refund_bytes,
        dest_key_index: 0,
        dest_spk: dest.clone(),
    };
    // The real negotiation sidecars the templates before the Setup can ever
    // broadcast; mirror that — the sidecar is exactly what must ride a backup.
    persist_artifacts(&dir, &artifacts).unwrap();

    let opts = RunOptions::default();
    let mut log = |_line: String| {};
    let mut state = SwapRunState::new();
    match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log).unwrap()
    {
        SwapStepOutcome::Continue(AppTick::BroadcastSetup) => {}
        other => panic!("expected the Setup broadcast step, got {other:?}"),
    }
    // Hostile counterparty escrow: one sat short → funded abort → Refunding.
    chain.fund_with_amount(their_op, base + 1, escrow_amt - 1);
    chain.mine();
    let outcome = loop {
        match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
            .unwrap()
        {
            SwapStepOutcome::Continue(_) => {}
            SwapStepOutcome::Holding { .. } => chain.mine(),
            SwapStepOutcome::Done(o) => break o,
        }
    };
    assert!(matches!(outcome, SwapOutcome::Refunding { .. }), "got {outcome:?}");
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::AbortRefund);

    // Key-index continuity marker: one more issuance goes into the snapshot.
    let (idx_before, _spk) = engine.issue_deposit_address().unwrap();

    // (1) A RUNNING wallet refuses to back up (the engine holds the locks).
    assert!(
        backup_data_dir(&dir, &bundle).is_err(),
        "backup under a live engine must refuse — a copy from under a writer can tear"
    );

    drop(app);
    drop(engine);

    // (2) Stopped: the snapshot succeeds and names the whole durable set.
    let summary = backup_data_dir(&dir, &bundle).unwrap();
    let names: Vec<&str> = summary.files.iter().map(|(n, _)| n.as_str()).collect();
    for expect in [
        "keystore.bin".to_string(),
        "ledger.bin".into(),
        format!("{sid_hex}.swap"),
        format!("{sid_hex}.artifacts"),
        format!("leases/{sid_hex}"),
    ] {
        assert!(names.iter().any(|n| **n == expect), "{expect} missing from bundle: {names:?}");
    }
    assert!(
        names.iter().all(|n| !n.ends_with(".lock") && !n.ends_with(".tmp")),
        "locks/transients must never ride a bundle: {names:?}"
    );

    // Byte-faithful capture for the post-restore equality assert.
    let pre: std::collections::BTreeMap<String, Vec<u8>> = summary
        .files
        .iter()
        .map(|(name, _)| (name.clone(), std::fs::read(member_path(&dir, name)).unwrap()))
        .collect();

    // (3) An existing bundle is never overwritten.
    assert!(backup_data_dir(&dir, &bundle).is_err());

    // (4) Disk loss.
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!dir.exists());

    // (5) Restore: byte-identical, and a second restore over it is refused.
    let restored = restore_data_dir(&bundle, &dir).unwrap();
    assert_eq!(restored.files.len(), summary.files.len());
    for (name, bytes) in &pre {
        assert_eq!(
            &std::fs::read(member_path(&dir, name)).unwrap(),
            bytes,
            "{name} must restore byte-identically"
        );
    }
    assert!(restore_data_dir(&bundle, &dir).is_err(), "an established dir is never overwritten");

    // (6) Reopen from the restored dir ALONE and recover: startup reconcile +
    // recovery ticks re-enter the in-flight swap; babysit drives it terminal.
    let ks2 = SoftwareKeyStore::open(&dir, PASS).unwrap();
    let mut engine2 =
        SwapEngine::open(&dir, &ks2, Box::new(ks2.clone()), &ModeledTrustRoot).unwrap().0;
    let (reconcile, scan) = SwapApp::startup(&mut engine2, &chain).unwrap();
    assert!(reconcile.is_ok(), "chain reconcile after restore must succeed");
    assert!(scan.unreadable.is_empty(), "no restored record may be unreadable");
    assert!(scan.failed.is_empty(), "no restored record may fail re-entry");
    assert!(scan.ticks.iter().any(|(s, _)| s == &sid), "the in-flight swap must re-enter");
    for (s, tick) in &scan.ticks {
        apply_recovery_tick(&mut engine2, &chain, &dir, s, tick, &opts, &mut log).unwrap();
    }

    // Mature the CSV; the babysit step broadcasts the pre-armed refund, a
    // confirmation advances the record to its terminal.
    while chain.tip_height() < base + 250 {
        chain.mine();
    }
    assert_eq!(refund_babysit_step(&mut engine2, &chain, &dir, &sid, &opts, &mut log).unwrap(), None);
    assert!(
        matches!(chain.spend_status(our_op), SpendStatus::InMempool),
        "the restored wallet must broadcast the pre-armed refund at maturity"
    );
    assert_eq!(chain.spend_txid(our_op), Some(refund_txid));
    chain.mine();
    assert_eq!(
        refund_babysit_step(&mut engine2, &chain, &dir, &sid, &opts, &mut log).unwrap(),
        Some(SwapPhase::Refunded)
    );
    assert_eq!(engine2.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Refunded);

    // (7) The key index survived: issuance CONTINUES past the snapshot.
    let (idx_after, _spk) = engine2.issue_deposit_address().unwrap();
    assert_eq!(idx_after, idx_before + 1, "restored issuance must never rewind");
}

// ============================================================================
// Negative-first: hostile/corrupt bundles are clean Errs, never partial dirs.
// ============================================================================

#[test]
fn restore_refuses_corrupt_and_hostile_bundles_cleanly() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("w");
    std::fs::create_dir_all(&dir).unwrap();
    {
        let (ks, _) = SoftwareKeyStore::create_with_iters(&dir, PASS, TEST_ITERS).unwrap();
        let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
        let _ledger = Ledger::create(&dir, &ks, ack).unwrap();
    }
    let bundle = root.path().join("w.skbak");
    backup_data_dir(&dir, &bundle).unwrap();
    let good = std::fs::read(&bundle).unwrap();

    let mut case = 0usize;
    let mut attempt = |bytes: &[u8], tag: &str| {
        case += 1;
        let path = root.path().join(format!("bad{case}.skbak"));
        std::fs::write(&path, bytes).unwrap();
        let target = root.path().join(format!("t{case}"));
        assert!(restore_data_dir(&path, &target).is_err(), "{tag}: must be refused");
        assert!(!target.exists(), "{tag}: no partial dir may be created");
        assert!(
            !root.path().join(format!("t{case}.restore-tmp")).exists(),
            "{tag}: staging leftovers must be cleaned up"
        );
    };

    // Corruption: the integrity/magic gates.
    attempt(&good[..good.len() - 10], "truncated tail");
    attempt(&good[..20], "beheaded");
    let mut bad = good.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x01;
    attempt(&bad, "bit flip");
    let mut bad = good.clone();
    bad[0] ^= 0xff;
    attempt(&bad, "bad magic");

    // Hostility: well-hashed bundles that violate the member rules.
    let sid = "ab".repeat(32);
    attempt(
        &craft(&[("../evil.swap", b"x"), ("keystore.bin", b"k"), ("ledger.bin", b"l")]),
        "path traversal",
    );
    attempt(
        &craft(&[
            (format!("leases\\{sid}").as_str(), b"x"),
            ("keystore.bin", b"k"),
            ("ledger.bin", b"l"),
        ]),
        "backslash separator",
    );
    attempt(
        &craft(&[("keystore.bin", b"k"), ("keystore.bin", b"k"), ("ledger.bin", b"l")]),
        "duplicate member",
    );
    attempt(&craft(&[("ledger.bin", b"l")]), "missing keystore");
    attempt(&craft(&[("swapkey.toml", b"cfg"), ("keystore.bin", b"k"), ("ledger.bin", b"l")]), "foreign member");
    // Structurally valid, but the keystore member itself is torn: the staged
    // pre-KDF probe must refuse BEFORE any dir exists at the destination.
    attempt(&craft(&[("keystore.bin", b"garbage"), ("ledger.bin", b"l")]), "torn keystore member");
    // Understated count with a recomputed hash → trailing garbage.
    let mut bad = good.clone();
    let count_at = BACKUP_MAGIC.len();
    let n = u32::from_le_bytes(bad[count_at..count_at + 4].try_into().unwrap());
    bad[count_at..count_at + 4].copy_from_slice(&(n - 1).to_le_bytes());
    attempt(&reseal(bad), "understated count");

    // A VALID bundle still refuses an occupied destination, untouched.
    let occupied = root.path().join("occupied");
    std::fs::create_dir_all(&occupied).unwrap();
    std::fs::write(occupied.join("precious.txt"), b"do not clobber").unwrap();
    assert!(restore_data_dir(&bundle, &occupied).is_err());
    assert_eq!(std::fs::read(occupied.join("precious.txt")).unwrap(), b"do not clobber");

    // And the same good bundle restores fine into a fresh path (the negative
    // cases above failed for their OWN reasons, not a broken fixture).
    let fresh = root.path().join("fresh");
    restore_data_dir(&bundle, &fresh).unwrap();
    assert!(fresh.join("keystore.bin").exists() && fresh.join("ledger.bin").exists());
}

// ============================================================================
// Backup preconditions.
// ============================================================================

#[test]
fn backup_refuses_an_incomplete_wallet_and_a_destination_inside_the_data_dir() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("w");
    std::fs::create_dir_all(&dir).unwrap();

    // Keystore alone = an unfinished first run: its backup is the mnemonic,
    // not a bundle (and a bundle without a ledger could never restore-open).
    let (ks, _) = SoftwareKeyStore::create_with_iters(&dir, PASS, TEST_ITERS).unwrap();
    assert!(backup_data_dir(&dir, &root.path().join("x.skbak")).is_err());

    {
        let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
        let _ledger = Ledger::create(&dir, &ks, ack).unwrap();
    }
    // A bundle INSIDE the data dir would pollute the wallet's home.
    assert!(backup_data_dir(&dir, &dir.join("x.skbak")).is_err());
    // Outside: fine.
    backup_data_dir(&dir, &root.path().join("x.skbak")).unwrap();
}

// ============================================================================
// Mnemonic-only restore: the floor is what stands between issuance and reuse.
// ============================================================================

#[test]
fn mnemonic_only_restore_with_a_raised_floor_prevents_index_reuse() {
    let root = tempfile::tempdir().unwrap();
    let old_dir = root.path().join("old");
    std::fs::create_dir_all(&old_dir).unwrap();
    let (ks, words) = SoftwareKeyStore::create_with_iters(&old_dir, PASS, TEST_ITERS).unwrap();
    let mut old_spks = Vec::new();
    {
        let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
        let mut ledger = Ledger::create(&old_dir, &ks, ack).unwrap();
        for expect in 0u32..5 {
            let (idx, spk) = ledger.next_deposit_address(&ks).unwrap();
            assert_eq!(idx, expect);
            old_spks.push(spk);
        }
    }

    // Dead device: only the words survive. `restore` pays the production KDF
    // once — deliberate; it IS the real path.
    let new_dir = root.path().join("new");
    std::fs::create_dir_all(&new_dir).unwrap();
    let ks2 = SoftwareKeyStore::restore(&new_dir, &words, "a different passphrase").unwrap();
    let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
    let mut ledger2 = Ledger::create(&new_dir, &ks2, ack).unwrap();

    // The fresh ledger rewound issuance to 0 — the floor is the fix.
    ledger2.raise_key_index_floor(5).unwrap();
    let (idx, spk) = ledger2.next_deposit_address(&ks2).unwrap();
    assert_eq!(idx, 5, "issuance must resume past the floor");
    assert!(
        old_spks.iter().all(|old| old != &spk),
        "the fresh address must not reuse any spk the lost wallet issued"
    );

    // Monotonic: a floor at-or-below the counter is a no-op, never a rewind.
    ledger2.raise_key_index_floor(2).unwrap();
    let (idx, _) = ledger2.next_deposit_address(&ks2).unwrap();
    assert_eq!(idx, 6);

    // The floor persists like any ledger mutation.
    drop(ledger2);
    let mut ledger3 = Ledger::open(&new_dir, &ks2).unwrap();
    let (idx, _) = ledger3.next_deposit_address(&ks2).unwrap();
    assert_eq!(idx, 7);
}
