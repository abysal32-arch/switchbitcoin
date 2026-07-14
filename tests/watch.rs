//! Standalone watchtower mode (Task 19): the `watch` run mode drives the
//! dead-device refund guard from the PERSISTED record alone — no live
//! `SwapContext`, no transport, no session key (the fixture drops everything
//! but the data dir before the watch loop runs).
//!
//! * `watch_fires_the_pre_armed_refund_from_the_persisted_record_alone` — the
//!   headline: a funded swap's record, primary absent, fires the refund at
//!   CSV maturity, confirms it, advances the record to `Refunded`, and
//!   registers the reclaimed output in the ledger.
//! * `watch_stands_down_on_a_winning_completion_and_never_fires` — a
//!   completion that lands first makes the watchtower stand down (it never
//!   fights it), and the record is left for the owning wallet's `recover`.
//! * `watch_no_reserve_stall_is_loud_then_fires_when_congestion_clears` — the
//!   no-reserve case: the fee-floor stall surfaces as a LOUD alarm (never a
//!   silent failure), and the refund fires unbumped once congestion clears.
//! * `watch_reserve_case_executes_the_silent_refund_cpfp` — with a leasable
//!   reserve the stalled refund is CPFP-bumped silently (1P1C package).
//! * `two_watchtowers_do_not_double_spend_and_double_broadcast_is_idempotent`
//!   — a live primary and a watchtower (or two watchtowers) firing the same
//!   refund is a no-op, never a double-spend or a grief.
//! * Negative-first coverage: empty stores, unguardable records, and hostile
//!   (undecodable) refund bytes are clean errors/alarms, never panics.

use bitcoin::{
    absolute, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use secp::{Point, Scalar};
use swapkey::chain::{ChainView, SimChain, SpendStatus};
use swapkey::settlement::params::Params;
use swapkey::settlement::refund::PreArmedRefund;
use swapkey::settlement::state_machine::{canonical_internal_key, Role};
use swapkey::tx::escrow::Escrow;
use swapkey::tx::txbuild::build_completion;
use swapkey::wallet::engine::SwapEngine;
use swapkey::wallet::keys::ModeledKeySource;
use swapkey::wallet::ledger::{
    acknowledge_phase0, CoinClass, CoinState, Ledger, WalletClock, PHASE0_WARNING,
};
use swapkey::wallet::manifest::ModeledTrustRoot;
use swapkey::wallet::runner::{persist_artifacts, SwapArtifacts};
use swapkey::wallet::store::{ModeledEnclave, SwapPhase, SwapRecord};
use swapkey::wallet::watch::{arm_guards, watch_pass, watch_step, WatchOptions, WatchStatus};

// ---------- fixture helpers (mirrors tests/runner.rs / tests/backstop_bump.rs) ----------

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

struct FixedClock(u64);
impl WalletClock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

fn open_engine(dir: &std::path::Path) -> SwapEngine {
    SwapEngine::open(
        dir,
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap()
    .0
}

/// A counterparty completion shape: a no-timelock v3 spend of `outpoint`.
fn completion_of(outpoint: OutPoint, out: u64) -> Vec<u8> {
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&[0x77u8; 32]);
    let tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: ScriptBuf::from_bytes(spk) }],
    };
    bitcoin::consensus::encode::serialize(&tx)
}

fn record(
    sid: [u8; 32],
    phase: SwapPhase,
    params: &Params,
    our_escrow: Option<OutPoint>,
    their_escrow: Option<OutPoint>,
    refund: Option<PreArmedRefund>,
) -> SwapRecord {
    SwapRecord {
        swap_session_id: sid,
        role: Role::SecretHolder,
        phase,
        params: params.clone(),
        s_height: 0,
        sweep_escrow_height: 0,
        our_escrow_outpoint: our_escrow,
        their_escrow_outpoint: their_escrow,
        pre_armed_refund: refund,
        completion_tx: None,
        setup_tx: None,
        possession_record: None,
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    chain: SimChain,
    sid: [u8; 32],
    escrow_op: OutPoint,
    refund_bytes: Vec<u8>,
    refund_txid: Txid,
    maturity: u32,
    /// The split-carved reserve, when the fixture onboarded a deposit.
    reserve: Option<(OutPoint, u64)>,
}

/// Build a guarded Funding-phase record in a fresh wallet dir: a real escrow,
/// a real signed pre-armed refund (the negotiate-time shape, paying a
/// wallet-issued `SwapDestination`), and the `.artifacts` sidecar for output
/// registration — then DROP the engine and every key. What remains is exactly
/// the delegation packet's content: the data dir. The session scalar dies
/// with this function, so the tests provably drive from persisted artifacts
/// alone.
fn guarded_wallet(base: u32, seed: u8, onboard_reserve: bool) -> Fixture {
    let params = Params::testnet_provisional();
    let dir = tempfile::tempdir().unwrap();

    // The ledger: empty, or with one real onboarded deposit whose split
    // carves the dedicated CPFP reserve (the production provisioning path).
    let mut reserve = None;
    {
        let mut ledger = Ledger::create(
            dir.path(),
            &ModeledEnclave,
            acknowledge_phase0(PHASE0_WARNING).unwrap(),
        )
        .unwrap();
        if onboard_reserve {
            let keys = ModeledKeySource::new(&ModeledEnclave);
            let unit = params.pre_encumbrance_sats();
            let deposit_op = OutPoint::new(txid_from(seed ^ 0x11), 0);
            let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
            ledger
                .register_deposit(
                    deposit_op,
                    unit + 80_000 + 1_000,
                    100,
                    idx,
                    &spk,
                    &keys,
                    Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
                )
                .unwrap();
            let plan = ledger.split_deposit(deposit_op, &params, 1_000, &keys).unwrap();
            ledger.confirm_split(plan.txid, 105, &FixedClock(1_000)).unwrap();
            let reserve_op =
                OutPoint::new(plan.txid, plan.reserve_vout.expect("split carves the reserve"));
            reserve = Some((reserve_op, ledger.find(&reserve_op).unwrap().amount_sats));
        }
    }

    let chain = SimChain::new(base);
    let mut engine = open_engine(dir.path());
    let (dest_idx, dest_spk) = engine.issue_swap_destination().unwrap();

    let a = keypair();
    let b = keypair();
    let internal = canonical_internal_key(a.pk, b.pk).unwrap();
    let e_ours = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let escrow_op = OutPoint::new(txid_from(seed), 0);
    chain.fund_with_amount(escrow_op, base, params.escrow_amount_sats());
    if let Some((reserve_op, amount)) = reserve {
        chain.fund_with_amount(reserve_op, base, amount);
    }

    let refund = PreArmedRefund::arm(
        &e_ours,
        escrow_op,
        params.escrow_amount_sats(),
        &a.sk,
        dest_spk.clone(),
        params.tier_d_sats,
        params.anchor_sats,
        base,
    )
    .unwrap();
    let refund_bytes = refund.tx_bytes().to_vec();
    let refund_txid = bitcoin::consensus::encode::deserialize::<Transaction>(&refund_bytes)
        .unwrap()
        .compute_txid();
    let maturity = base + params.delta_early;

    let sid = [seed; 32];
    engine
        .store()
        .put(&record(
            sid,
            SwapPhase::Funding,
            &params,
            Some(escrow_op),
            Some(OutPoint::new(txid_from(seed ^ 0xFF), 0)),
            Some(refund),
        ))
        .unwrap();

    let comp = build_completion(
        &e_ours,
        escrow_op,
        params.escrow_amount_sats(),
        dest_spk.clone(),
        params.tier_d_sats,
        params.anchor_sats,
    )
    .unwrap();
    persist_artifacts(
        dir.path(),
        &SwapArtifacts {
            session_id: sid,
            setup_tx: vec![0xEE],
            comp_sh: comp.clone(),
            comp_sl: comp,
            refund_tx: refund_bytes.clone(),
            dest_key_index: dest_idx,
            dest_spk,
        },
    )
    .unwrap();

    drop(engine); // ← the "primary" dies here; only the data dir survives
    Fixture { dir, chain, sid, escrow_op, refund_bytes, refund_txid, maturity, reserve }
}

fn default_opts() -> WatchOptions {
    WatchOptions { target_feerate_sat_vb: None, refund_congested: false, allow_bump: true }
}

// ============================================================================
// negative-first: hostile/degenerate inputs are clean, never panics
// ============================================================================

#[test]
fn arm_guards_on_an_empty_store_finds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    drop(
        Ledger::create(dir.path(), &ModeledEnclave, acknowledge_phase0(PHASE0_WARNING).unwrap())
            .unwrap(),
    );
    let engine = open_engine(dir.path());
    let set = arm_guards(&engine).unwrap();
    assert!(set.guards.is_empty());
    assert!(set.unguardable.is_empty());
    assert!(set.unreadable.is_empty());
}

#[test]
fn a_record_with_nothing_to_guard_is_an_alarm_not_a_guard() {
    let dir = tempfile::tempdir().unwrap();
    drop(
        Ledger::create(dir.path(), &ModeledEnclave, acknowledge_phase0(PHASE0_WARNING).unwrap())
            .unwrap(),
    );
    let engine = open_engine(dir.path());
    // A pre-funding record with no escrow outpoint (and, per the store's G2
    // rule, therefore legally no refund): nothing locked, nothing to guard —
    // but the scan must SAY so, never silently skip.
    let params = Params::testnet_provisional();
    engine
        .store()
        .put(&record([0x01; 32], SwapPhase::Funding, &params, None, None, None))
        .unwrap();
    let set = arm_guards(&engine).unwrap();
    assert!(set.guards.is_empty());
    assert_eq!(set.unguardable.len(), 1);
    assert!(set.unguardable[0].1.contains("no escrow outpoint"));
}

#[test]
fn hostile_refund_bytes_error_cleanly_and_the_guard_is_retained() {
    let dir = tempfile::tempdir().unwrap();
    drop(
        Ledger::create(dir.path(), &ModeledEnclave, acknowledge_phase0(PHASE0_WARNING).unwrap())
            .unwrap(),
    );
    let engine = open_engine(dir.path());
    let params = Params::testnet_provisional();
    let base = 500_000u32;
    let escrow_op = OutPoint::new(txid_from(0x66), 0);
    let chain = SimChain::new(base);
    chain.fund_with_amount(escrow_op, base, params.escrow_amount_sats());
    // Undecodable refund bytes (the store only requires non-empty).
    let garbage = PreArmedRefund::from_signed_tx(vec![1, 2, 3], base + 144).unwrap();
    engine
        .store()
        .put(&record(
            [0x66; 32],
            SwapPhase::Funding,
            &params,
            Some(escrow_op),
            Some(OutPoint::new(txid_from(0x67), 0)),
            Some(garbage),
        ))
        .unwrap();

    let mut engine = engine;
    let set = arm_guards(&engine).unwrap();
    assert_eq!(set.guards.len(), 1, "arming stays best-effort on undecodable bytes");
    let mut guards = set.guards;
    while chain.tip_height() < base + 144 {
        chain.mine();
    }
    let mut lines = Vec::new();
    // The fire attempt maps to a stall, whose sizing then errors CLEANLY (the
    // bytes do not decode) — an Err, never a panic; the pass keeps the guard.
    let err = watch_step(
        &guards[0],
        &mut engine,
        &chain,
        dir.path(),
        &default_opts(),
        &mut |l| lines.push(l),
    );
    assert!(err.is_err(), "hostile bytes must be a clean Err");
    let remaining = watch_pass(
        &mut guards,
        &mut engine,
        &chain,
        dir.path(),
        &default_opts(),
        &mut |l| lines.push(l),
    );
    assert_eq!(remaining, 1, "a failing guard is retried, never dropped");
    assert!(lines.iter().any(|l| l.contains("watch step failed")));
}

// ============================================================================
// the headline: dead-device fire from persisted artifacts alone
// ============================================================================

#[test]
fn watch_fires_the_pre_armed_refund_from_the_persisted_record_alone() {
    let base = 700_000u32;
    let fx = guarded_wallet(base, 0xA1, false);
    // A FRESH engine over the surviving data dir: no live ctx, no session key
    // (the ephemeral scalar died with the fixture), no transport.
    let mut engine = open_engine(fx.dir.path());
    let set = arm_guards(&engine).unwrap();
    assert_eq!(set.guards.len(), 1);
    assert!(set.unguardable.is_empty());
    let mut guards = set.guards;
    assert_eq!(guards[0].escrow(), fx.escrow_op);
    let opts = default_opts();
    let mut lines = Vec::new();

    // Pre-maturity: guarding, nothing broadcast.
    let st = watch_step(&guards[0], &mut engine, &fx.chain, fx.dir.path(), &opts, &mut |l| {
        lines.push(l)
    })
    .unwrap();
    assert_eq!(st, WatchStatus::Guarding);
    assert!(matches!(fx.chain.spend_status(fx.escrow_op), SpendStatus::Unspent));

    // At CSV maturity, owner absent: the watchtower fires the refund itself.
    while fx.chain.tip_height() < fx.maturity {
        fx.chain.mine();
    }
    let st = watch_step(&guards[0], &mut engine, &fx.chain, fx.dir.path(), &opts, &mut |l| {
        lines.push(l)
    })
    .unwrap();
    assert_eq!(st, WatchStatus::Guarding, "fired but not yet confirmed");
    assert!(matches!(fx.chain.spend_status(fx.escrow_op), SpendStatus::InMempool));
    assert_eq!(fx.chain.spend_txid(fx.escrow_op), Some(fx.refund_txid));
    assert!(lines.iter().any(|l| l.contains("FIRED")));

    // Confirm: the guard resolves, the record advances to Refunded, and the
    // reclaimed output is registered in this device's ledger.
    fx.chain.mine();
    let remaining = watch_pass(&mut guards, &mut engine, &fx.chain, fx.dir.path(), &opts, &mut |l| {
        lines.push(l)
    });
    assert_eq!(remaining, 0, "escrow exit confirmed ⇒ nothing left to guard");
    assert_eq!(engine.store().get(&fx.sid).unwrap().unwrap().phase, SwapPhase::Refunded);
    let reclaimed = OutPoint::new(fx.refund_txid, 0);
    let coin = engine.ledger().find(&reclaimed).expect("reclaimed output registered");
    assert_eq!(coin.class, CoinClass::Swapped);
    assert_eq!(coin.amount_sats, Params::testnet_provisional().tier_d_sats);
}

// ============================================================================
// completion-supersedes: a watchtower never fights a winning completion
// ============================================================================

#[test]
fn watch_stands_down_on_a_winning_completion_and_never_fires() {
    let base = 640_000u32;
    let fx = guarded_wallet(base, 0xB2, false);
    let mut engine = open_engine(fx.dir.path());
    let mut guards = arm_guards(&engine).unwrap().guards;
    assert_eq!(guards.len(), 1);

    // The counterparty's completion confirms against the escrow first.
    fx.chain.broadcast(&completion_of(fx.escrow_op, 995_000)).unwrap();
    fx.chain.mine();
    let completion_txid = fx.chain.spend_txid(fx.escrow_op).unwrap();
    assert_ne!(completion_txid, fx.refund_txid);

    // Even well past maturity the watchtower stands down — it never fights.
    while fx.chain.tip_height() < fx.maturity + 10 {
        fx.chain.mine();
    }
    let mut lines = Vec::new();
    let st = watch_step(
        &guards[0],
        &mut engine,
        &fx.chain,
        fx.dir.path(),
        &default_opts(),
        &mut |l| lines.push(l),
    )
    .unwrap();
    assert!(matches!(st, WatchStatus::Resolved(_)));
    assert!(lines.iter().any(|l| l.contains("standing down")));
    // The chain still shows the completion as the only spender.
    assert_eq!(fx.chain.spend_txid(fx.escrow_op), Some(completion_txid));
    // The record is NOT rewritten — reconciling a forward-resolved swap is
    // the owning wallet's `recover`, not the watchtower's.
    assert_eq!(engine.store().get(&fx.sid).unwrap().unwrap().phase, SwapPhase::Funding);
    // And the pass drops the guard.
    let remaining = watch_pass(
        &mut guards,
        &mut engine,
        &fx.chain,
        fx.dir.path(),
        &default_opts(),
        &mut |l| lines.push(l),
    );
    assert_eq!(remaining, 0);
}

// ============================================================================
// reserve provisioning: the no-reserve stall is LOUD; a reserve bumps silently
// ============================================================================

#[test]
fn watch_no_reserve_stall_is_loud_then_fires_when_congestion_clears() {
    let base = 660_000u32;
    let fx = guarded_wallet(base, 0xC3, false); // empty ledger: NO reserve
    let mut engine = open_engine(fx.dir.path());
    let guards = arm_guards(&engine).unwrap().guards;

    // Congestion above the refund's baked fee: the fire attempt cannot relay.
    fx.chain.set_congestion(50_000);
    while fx.chain.tip_height() < fx.maturity {
        fx.chain.mine();
    }
    // A target feerate that would demand a real CPFP child — but there is no
    // reserve on this device: the stall must be a LOUD alarm, never silent.
    let opts = WatchOptions {
        target_feerate_sat_vb: Some(100),
        refund_congested: false,
        allow_bump: true,
    };
    let mut lines = Vec::new();
    let st = watch_step(&guards[0], &mut engine, &fx.chain, fx.dir.path(), &opts, &mut |l| {
        lines.push(l)
    })
    .unwrap();
    assert_eq!(st, WatchStatus::Guarding);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("RefundStalledBelowFeeFloor") && l.contains("NO leasable reserve")),
        "the no-reserve stall must be loud: {lines:?}"
    );
    assert!(matches!(fx.chain.spend_status(fx.escrow_op), SpendStatus::Unspent));

    // Congestion clears: the refund fires unbumped (the CSV never expired).
    fx.chain.set_congestion(0);
    let st = watch_step(&guards[0], &mut engine, &fx.chain, fx.dir.path(), &opts, &mut |l| {
        lines.push(l)
    })
    .unwrap();
    assert_eq!(st, WatchStatus::Guarding);
    assert_eq!(fx.chain.spend_txid(fx.escrow_op), Some(fx.refund_txid));
    fx.chain.mine();
    let st = watch_step(&guards[0], &mut engine, &fx.chain, fx.dir.path(), &opts, &mut |l| {
        lines.push(l)
    })
    .unwrap();
    assert_eq!(st, WatchStatus::Resolved("own pre-armed refund confirmed"));
    assert_eq!(engine.store().get(&fx.sid).unwrap().unwrap().phase, SwapPhase::Refunded);
}

#[test]
fn watch_reserve_case_executes_the_silent_refund_cpfp() {
    let base = 680_000u32;
    let fx = guarded_wallet(base, 0xD4, true); // onboarded: reserve carved
    let (reserve_op, _amount) = fx.reserve.expect("fixture onboarded a reserve");
    let mut engine = open_engine(fx.dir.path());
    let guards = arm_guards(&engine).unwrap().guards;

    // Congestion above the refund's baked fee, below what the 1P1C package
    // pays at the target feerate — the exact silent-CPFP case.
    fx.chain.set_congestion(9_000);
    while fx.chain.tip_height() < fx.maturity {
        fx.chain.mine();
    }
    let opts = WatchOptions {
        target_feerate_sat_vb: Some(40),
        refund_congested: false,
        allow_bump: true,
    };
    let mut lines = Vec::new();
    let st = watch_step(&guards[0], &mut engine, &fx.chain, fx.dir.path(), &opts, &mut |l| {
        lines.push(l)
    })
    .unwrap();
    assert_eq!(st, WatchStatus::Guarding);
    // The package went on the wire: the refund spends the escrow, the child
    // spends the refund's anchor, and the ledger marked the reserve spent.
    assert!(matches!(fx.chain.spend_status(fx.escrow_op), SpendStatus::InMempool));
    assert_eq!(fx.chain.spend_txid(fx.escrow_op), Some(fx.refund_txid));
    assert!(matches!(
        fx.chain.spend_status(OutPoint::new(fx.refund_txid, 1)),
        SpendStatus::InMempool
    ));
    assert_eq!(engine.ledger().find(&reserve_op).unwrap().state, CoinState::Spent);
    assert!(lines.iter().any(|l| l.contains("silent refund CPFP executed")));

    // Confirm and resolve.
    fx.chain.mine();
    let st = watch_step(&guards[0], &mut engine, &fx.chain, fx.dir.path(), &opts, &mut |l| {
        lines.push(l)
    })
    .unwrap();
    assert_eq!(st, WatchStatus::Resolved("own pre-armed refund confirmed"));
    assert_eq!(engine.store().get(&fx.sid).unwrap().unwrap().phase, SwapPhase::Refunded);
}

// ============================================================================
// interplay: two devices guarding the same swap cannot double-spend or grief
// ============================================================================

#[test]
fn two_watchtowers_do_not_double_spend_and_double_broadcast_is_idempotent() {
    let base = 720_000u32;
    let fx = guarded_wallet(base, 0xE5, false);
    // Device B = the delegation story: the same record content restored into
    // a second, independent data dir (its own store/ledger — the per-dir
    // locks make cross-device contention structurally impossible).
    let dir_b = tempfile::tempdir().unwrap();
    drop(
        Ledger::create(dir_b.path(), &ModeledEnclave, acknowledge_phase0(PHASE0_WARNING).unwrap())
            .unwrap(),
    );
    let mut engine_a = open_engine(fx.dir.path());
    let mut engine_b = open_engine(dir_b.path());
    engine_b
        .store()
        .put(&engine_a.store().get(&fx.sid).unwrap().unwrap())
        .unwrap();

    let guards_a = arm_guards(&engine_a).unwrap().guards;
    let guards_b = arm_guards(&engine_b).unwrap().guards;
    assert_eq!(guards_a.len(), 1);
    assert_eq!(guards_b.len(), 1);

    while fx.chain.tip_height() < fx.maturity {
        fx.chain.mine();
    }
    let opts = default_opts();
    let mut sink = |_l: String| {};

    // A fires; B sees the in-mempool refund and does nothing (no fight).
    let st_a =
        watch_step(&guards_a[0], &mut engine_a, &fx.chain, fx.dir.path(), &opts, &mut sink)
            .unwrap();
    assert_eq!(st_a, WatchStatus::Guarding);
    assert_eq!(fx.chain.spend_txid(fx.escrow_op), Some(fx.refund_txid));
    let st_b =
        watch_step(&guards_b[0], &mut engine_b, &fx.chain, dir_b.path(), &opts, &mut sink)
            .unwrap();
    assert_eq!(st_b, WatchStatus::Guarding);

    // The worst case — both devices broadcast the SAME signed refund "at
    // once": the second submission is an idempotent no-op (same txid), never
    // a double-spend.
    assert!(fx.chain.broadcast(&fx.refund_bytes).is_ok());
    assert_eq!(fx.chain.spend_txid(fx.escrow_op), Some(fx.refund_txid));

    // Confirm: both devices resolve, each advancing its own record copy.
    fx.chain.mine();
    let st_a =
        watch_step(&guards_a[0], &mut engine_a, &fx.chain, fx.dir.path(), &opts, &mut sink)
            .unwrap();
    let st_b =
        watch_step(&guards_b[0], &mut engine_b, &fx.chain, dir_b.path(), &opts, &mut sink)
            .unwrap();
    assert_eq!(st_a, WatchStatus::Resolved("own pre-armed refund confirmed"));
    assert_eq!(st_b, WatchStatus::Resolved("own pre-armed refund confirmed"));
    assert_eq!(engine_a.store().get(&fx.sid).unwrap().unwrap().phase, SwapPhase::Refunded);
    assert_eq!(engine_b.store().get(&fx.sid).unwrap().unwrap().phase, SwapPhase::Refunded);
}
