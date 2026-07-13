//! Runner-module integration (Task 08): the tick→broadcast run loop and the
//! two-party pre-swap negotiation, driven over `SimChain` + an in-process
//! transport — the unit-testable core the `swapkey-cli` binary composes.
//!
//! * `swap_step_drives_a_full_swap_to_completed` — the headline app-test
//!   fixture, but the SL side is driven ENTIRELY through `swap_step`: the
//!   Setup broadcast + early-record confirm and the final completion
//!   broadcast are performed by the runner, and the completion is asserted ON
//!   CHAIN (the engine-boundary mapping, not just the tick).
//! * `swap_step_funded_abort_babysits_to_refunded` — a funded abort surfaces
//!   as `Refunding`, and `refund_babysit_step` carries the persisted record
//!   through Wait → BroadcastRefund (on chain) → Refunded.
//! * `negotiate_swap_two_parties_agree_and_close_forward_or_refund` — two
//!   independent wallets negotiate over a duplex transport and run the swap
//!   end-to-end. The role↔CSV pre-commitment is the deferred stop-gate, so
//!   the expected terminal is branched on the POST-CONFIRMATION derived role:
//!   convention-matching roles must complete BOTH legs; mismatching roles
//!   must refuse at the CSV-binding guard and close through BOTH refunds —
//!   forward-or-refund either way.
//! * `negotiate_swap_rejects_a_network_mismatch` / `_requires_a_coin` —
//!   handshake refusals happen before anything is at stake.

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use bitcoin::OutPoint;
use swapkey::chain::{ChainView, SimChain, SpendStatus};
use swapkey::crypto::adaptor::AdaptorSecret;
use swapkey::crypto::ValidatedPoint;
use swapkey::settlement::params::Params;
use swapkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund, WatchtowerReceipt};
use swapkey::settlement::state_machine::{
    canonical_internal_key, swap_session_id, ExchangeInputs, Funding, PeerSession, Role, Transport,
};
use swapkey::tx::escrow::Escrow;
use swapkey::tx::setup::build_setup;
use swapkey::tx::txbuild::{build_completion, finalize_key_spend};
use swapkey::wallet::config::Network;
use swapkey::wallet::engine::{SwapContext, SwapEngine};
use swapkey::wallet::keys::ModeledKeySource;
use swapkey::wallet::ledger::{acknowledge_phase0, CoinClass, CoinState, Ledger, WalletClock, PHASE0_WARNING};
use swapkey::wallet::manifest::ModeledTrustRoot;
use swapkey::wallet::runner::{
    completion_babysit_step, negotiate_swap, refund_babysit_step, swap_step, RunOptions,
    SwapArtifacts, SwapOutcome, SwapRunState, SwapStepOutcome,
};
use swapkey::wallet::store::{ModeledEnclave, SwapPhase};
use swapkey::wallet::AppTick;
use swapkey::{Error, Result};
use secp::{Point, Scalar};

// ---------- shared fixture helpers (mirrors tests/app.rs) ----------

struct ChannelTransport {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}
impl Transport for ChannelTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.tx.send(bytes.to_vec()).map_err(|_| Error::Abort("peer hung up"))
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        // Bounded so a test bug fails instead of hanging the suite forever.
        self.rx
            .recv_timeout(Duration::from_secs(60))
            .map_err(|_| Error::Abort("peer hung up"))
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

/// Onboard one deposit through the REAL pipeline (register → split →
/// confirm), leaving the pre-encumbrance coin UNLEASED (negotiation leases it
/// under the real session id). Returns the pre-encumbrance outpoint.
///
/// `dep_seed` must DIFFER between two wallets sharing one SimChain: both test
/// wallets run the same `ModeledEnclave` (same derived keys), so an identical
/// deposit outpoint can shuffle into byte-identical split txs — and two
/// "different" wallets would then own the SAME pre-encumbrance outpoint.
fn onboard_unleased(dir: &std::path::Path, params: &Params, dep_seed: u8) -> OutPoint {
    let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
    let mut ledger = Ledger::create(dir, &ModeledEnclave, ack).unwrap();
    let keys = ModeledKeySource::new(&ModeledEnclave);
    let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
    let dep = OutPoint::new(txid_from(dep_seed), 0);
    ledger
        .register_deposit(
            dep,
            params.pre_encumbrance_sats() + 2_000,
            100,
            idx,
            &spk,
            &keys,
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .unwrap();
    let plan = ledger.split_deposit(dep, params, 2_000, &keys).unwrap();
    ledger.confirm_split(plan.txid, 150, &FixedClock(1_000)).unwrap();
    ledger
        .coins()
        .iter()
        .find(|c| c.class == CoinClass::PreEncumbrance && c.state == CoinState::Unspent)
        .expect("split minted a pre-encumbrance coin")
        .outpoint
}

/// Onboard AND lease the coin under `lessee` (the fixture-test shape, where
/// the ctx is hand-built rather than negotiated).
fn onboard_leased(dir: &std::path::Path, params: &Params, lessee: [u8; 32]) -> OutPoint {
    let pre = onboard_unleased(dir, params, 0xDD);
    let mut ledger = Ledger::open(dir, &ModeledEnclave).unwrap();
    let coin = ledger
        .lease_pre_encumbrance(params.pre_encumbrance_sats(), &FixedClock(u64::MAX), u32::MAX, lessee)
        .unwrap()
        .expect("a mature pre-encumbrance coin");
    assert_eq!(coin.outpoint, pre);
    pre
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
    watchtower_receipt: WatchtowerReceipt,
    funding_coin: OutPoint,
) -> SwapContext {
    SwapContext {
        our_seckey,
        their_pubkey: vp(&their_pk),
        our_escrow_op,
        their_escrow_op,
        reveal_escrow_op: our_escrow_op, // SL fixture: the reveal spends OUR escrow
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

fn build_real_setup(
    chain: &SimChain,
    params: &Params,
    pre_op: OutPoint,
    base_height: u32,
    escrow: &Escrow,
    sk: &Scalar,
) -> (Vec<u8>, OutPoint) {
    let unit = params.pre_encumbrance_sats();
    chain.fund_with_amount(pre_op, base_height, unit);
    build_setup(pre_op, unit, params.escrow_amount_sats(), params.anchor_sats, escrow, sk).unwrap()
}

fn derived_role(
    chain: &SimChain,
    params: &Params,
    our_op: OutPoint,
    their_op: OutPoint,
    our_pk: &Point,
    their_pk: &Point,
) -> Role {
    let (dead, _drop) = duplex();
    let peer = PeerSession::new([0u8; 32], Box::new(dead));
    Funding::new(params.clone(), peer)
        .await_funded(chain, our_op, their_op, &vp(our_pk), &vp(their_pk))
        .unwrap()
        .role()
}

fn no_log() -> impl FnMut(String) {
    |_line: String| {}
}

// ============================================================================
// swap_step: full swap to Completed, all broadcasts performed by the runner.
// ============================================================================

#[test]
fn swap_step_drives_a_full_swap_to_completed() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 900_000u32;
    let s_height = base + 1;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_leased(wallet_dir.path(), &params, [0xAAu8; 32]);
    let sh_pre = OutPoint::new(txid_from(0xB0), 0);

    // Grind keypairs until the runner-driven side derives SecretLearner (the
    // same fixture-self-consistency trick as tests/app.rs).
    let (sh, sl, escrow_e_sl, escrow_e_sh, sl_setup, sh_setup, sl_escrow_op, sh_escrow_op) = loop {
        let sh = keypair();
        let sl = keypair();
        let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
        let e_sl = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
        let e_sh = Escrow::new(&internal, &sh.pk, delta_late).unwrap();

        let probe = SimChain::new(base);
        let (sl_setup, sl_op) = build_real_setup(&probe, &params, sl_pre, base, &e_sl, &sl.sk);
        let (sh_setup, sh_op) = build_real_setup(&probe, &params, sh_pre, base, &e_sh, &sh.sk);
        probe.broadcast(&sl_setup).unwrap();
        probe.broadcast(&sh_setup).unwrap();
        probe.mine();

        if derived_role(&probe, &params, sl_op, sh_op, &sl.pk, &sh.pk) == Role::SecretLearner {
            break (sh, sl, e_sl, e_sh, sl_setup, sh_setup, sl_op, sh_op);
        }
    };

    let chain = SimChain::new(base);
    chain.fund_with_amount(sl_pre, base, params.pre_encumbrance_sats());
    chain.fund_with_amount(sh_pre, base, params.pre_encumbrance_sats());
    chain.broadcast(&sl_setup).unwrap();
    chain.broadcast(&sh_setup).unwrap();
    chain.mine();

    let dest = escrow_e_sl.funding_script_pubkey().clone();
    let comp_sh =
        build_completion(&escrow_e_sl, sl_escrow_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let comp_sl =
        build_completion(&escrow_e_sh, sh_escrow_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let (msg_sh, msg_sl) = (comp_sh.sighash, comp_sl.sighash);
    let (root_sh, root_sl) = (escrow_e_sl.merkle_root(), escrow_e_sh.merkle_root());
    let (ok_sh, ok_sl) = (escrow_e_sl.output_key_xonly(), escrow_e_sh.output_key_xonly());

    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let lease_sh = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    let sl_refund = PreArmedRefund::arm(
        &escrow_e_sl, sl_escrow_op, escrow_amt, &sl.sk, dest.clone(), d, params.anchor_sats, s_height,
    )
    .unwrap();
    let sl_refund_bytes = sl_refund.tx_bytes().to_vec();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // Live SH counterparty (raw settlement thread), as in tests/app.rs.
    let sh_params = params.clone();
    let sh_chain = chain.clone();
    let comp_sh_for_sh = comp_sh.clone();
    let sh_handle = std::thread::spawn(move || -> Result<[u8; 64]> {
        let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + delta_late)?;
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
        let (t, _) = AdaptorSecret::generate()?;
        let peer = PeerSession::new([0xE9u8; 32], Box::new(io_sh));
        let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
        let possessing = funded.run_adaptor_exchange(ExchangeInputs {
            our_seckey: sh.sk,
            their_pubkey: vp(&sl.pk),
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

    let mut engine = open_engine(wallet_dir.path());
    let ctx = make_ctx(
        sl.sk, sh.pk, sl_escrow_op, sh_escrow_op, escrow_amt, msg_sh, msg_sl, sl_refund, None,
        root_sh, root_sl, ok_sh, ok_sl, lease_sl.path().to_path_buf(),
        possession_store.path().to_path_buf(), sl_receipt, sl_pre,
    );
    let peer = PeerSession::new([0xE9u8; 32], Box::new(io_sl));
    let mut app = swapkey::wallet::SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

    let artifacts = SwapArtifacts {
        session_id: sid,
        setup_tx: sl_setup.clone(),
        comp_sh: comp_sh.clone(),
        comp_sl: comp_sl.clone(),
        refund_tx: sl_refund_bytes,
        dest_key_index: 0,
        dest_spk: dest.clone(),
    };
    let opts = RunOptions::default();
    let mut log = no_log();
    let mut state = SwapRunState::new();

    // Drive ENTIRELY through swap_step: it performs the Setup broadcast (and
    // the early-record confirm) and finally broadcasts OUR completion.
    let mut saw_setup_broadcast = false;
    let mut outcome = None;
    for _ in 0..24 {
        match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
            .unwrap()
        {
            SwapStepOutcome::Continue(AppTick::BroadcastSetup) => {
                saw_setup_broadcast = true;
                // The runner confirmed the broadcast → the early record exists.
                assert_eq!(
                    engine.store().get(&sid).unwrap().unwrap().phase,
                    SwapPhase::Funding,
                    "swap_step must call setup_broadcast after broadcasting"
                );
            }
            SwapStepOutcome::Continue(_) => {}
            SwapStepOutcome::Done(o) => {
                outcome = Some(o);
                break;
            }
        }
        if sh_handle.is_finished() {
            // reveal is up; keep polling to extraction
        }
    }
    let _sh_sig = sh_handle.join().unwrap().expect("SH side");
    if outcome.is_none() {
        for _ in 0..8 {
            if let SwapStepOutcome::Done(o) =
                swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
                    .unwrap()
            {
                outcome = Some(o);
                break;
            }
        }
    }
    assert!(saw_setup_broadcast, "the runner must have performed our Setup broadcast");
    assert!(state.setup_on_wire, "the run state must record the fund exposure");
    assert!(!state.record_pending(), "the early record persisted on the healthy path");
    let completion_txid = match outcome.expect("swap must settle") {
        SwapOutcome::Completed { completion_txid } => completion_txid,
        other => panic!("expected Completed, got {other:?}"),
    };

    // THE point of the runner: our completion is ON CHAIN without any manual
    // finalize/broadcast by the caller.
    assert!(
        matches!(chain.spend_status(sh_escrow_op), SpendStatus::InMempool | SpendStatus::Confirmed(_)),
        "swap_step must have broadcast our finalized completion"
    );
    assert_eq!(chain.spend_txid(sh_escrow_op), Some(completion_txid));
    chain.mine();
    assert!(matches!(chain.spend_status(sh_escrow_op), SpendStatus::Confirmed(_)));
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Completed);
    assert_eq!(engine.ledger().find(&sl_pre).unwrap().state, CoinState::Spent);
}

// ============================================================================
// swap_step → Refunding, then refund_babysit_step to the Refunded terminal.
// ============================================================================

#[test]
fn swap_step_funded_abort_babysits_to_refunded() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 600_000u32;

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_leased(wallet_dir.path(), &params, [0xAAu8; 32]);

    // First funder (smaller pubkey) so our Setup is broadcast before the abort.
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
    let (sl_setup, our_op) = build_real_setup(&chain, &params, sl_pre, base, &e_ours, &sl.sk);
    let (_sh_setup, their_op) =
        build_real_setup(&chain, &params, OutPoint::new(txid_from(0xB0), 0), base, &e_theirs, &sh.sk);

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest.clone(), d, params.anchor_sats, base)
            .unwrap();
    let refund_bytes = refund.tx_bytes().to_vec();
    let refund_txid: bitcoin::Txid = {
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(refund.tx_bytes()).unwrap();
        tx.compute_txid()
    };
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let mut engine = open_engine(wallet_dir.path());
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let (dead, _keep) = duplex();
    let peer = PeerSession::new([0u8; 32], Box::new(dead));
    let mut app = swapkey::wallet::SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

    let artifacts = SwapArtifacts {
        session_id: sid,
        setup_tx: sl_setup.clone(),
        comp_sh: comp.clone(),
        comp_sl: comp.clone(),
        refund_tx: refund_bytes,
        dest_key_index: 0,
        dest_spk: dest.clone(),
    };
    let opts = RunOptions::default();
    let mut log = no_log();
    let mut state = SwapRunState::new();

    // Step 1: the runner broadcasts our Setup + persists the early record.
    match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log).unwrap()
    {
        SwapStepOutcome::Continue(AppTick::BroadcastSetup) => {}
        other => panic!("expected the Setup broadcast step, got {other:?}"),
    }
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Funding);

    // Hostile counterparty escrow: one sat short → funded abort → Refunding.
    chain.fund_with_amount(their_op, base + 1, escrow_amt - 1);
    chain.mine();
    let outcome = loop {
        match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
            .unwrap()
        {
            SwapStepOutcome::Continue(_) => {}
            SwapStepOutcome::Done(o) => break o,
        }
    };
    assert!(matches!(outcome, SwapOutcome::Refunding { .. }), "got {outcome:?}");
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::AbortRefund);

    // Babysit: immature → no broadcast, no terminal.
    let dir = wallet_dir.path();
    assert_eq!(refund_babysit_step(&mut engine, &chain, dir, &sid, &opts, &mut log).unwrap(), None);
    assert!(matches!(chain.spend_status(our_op), SpendStatus::Unspent));

    // Mature the CSV; the babysit step broadcasts the pre-armed refund.
    while chain.tip_height() < base + 250 {
        chain.mine();
    }
    assert_eq!(refund_babysit_step(&mut engine, &chain, dir, &sid, &opts, &mut log).unwrap(), None);
    assert!(
        matches!(chain.spend_status(our_op), SpendStatus::InMempool),
        "the babysit step must broadcast the refund at maturity"
    );
    assert_eq!(chain.spend_txid(our_op), Some(refund_txid));

    // Confirm it; the babysit step advances the record to its terminal.
    chain.mine();
    assert_eq!(
        refund_babysit_step(&mut engine, &chain, dir, &sid, &opts, &mut log).unwrap(),
        Some(SwapPhase::Refunded)
    );
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Refunded);
}

// ============================================================================
// negotiate_swap: two independent wallets, end to end, forward-or-refund.
// ============================================================================

struct SideResult {
    sid: [u8; 32],
    our_pk: Point,
    our_escrow_op: OutPoint,
    their_escrow_op: OutPoint,
    msg_comp_sh: [u8; 32],
    msg_comp_sl: [u8; 32],
    outcome: SwapOutcome,
    /// Whether the ledger tracks a `Swapped` coin after the terminal — the
    /// registered settlement output (completion OR refund pays our fresh
    /// SwapDestination key).
    has_swapped_coin: bool,
}

/// One party's whole life: negotiate over `io`, begin, drive `swap_step` to a
/// terminal. Runs on its own thread against the SHARED SimChain.
#[allow(clippy::too_many_arguments)]
fn run_party(
    label: &'static str,
    dir: std::path::PathBuf,
    chain: SimChain,
    io: ChannelTransport,
    session_sk: Scalar,
    block_x: u32,
    done: Arc<AtomicUsize>,
) -> Result<SideResult> {
    let mut io = io;
    let mut engine = open_engine(&dir);
    let clock = FixedClock(u64::MAX);
    let negotiated = negotiate_swap(
        &mut io,
        &mut engine,
        &chain,
        &clock,
        Network::Regtest,
        &dir,
        session_sk,
    )?;
    let sid = negotiated.artifacts.session_id;
    let our_pk = session_sk * secp::G;
    let our_escrow_op = negotiated.ctx.our_escrow_op;
    let their_escrow_op = negotiated.ctx.their_escrow_op;
    let msg_comp_sh = negotiated.ctx.msg_comp_sh;
    let msg_comp_sl = negotiated.ctx.msg_comp_sl;

    let peer = PeerSession::new(sid, Box::new(io));
    let mut app = swapkey::wallet::SwapApp::begin(&engine, negotiated.ctx, peer, block_x, 0)?;
    let artifacts = negotiated.artifacts;
    let opts = RunOptions::default();
    // Printed only on test failure (libtest captures output) — diagnostics.
    let mut log = |line: String| eprintln!("[{label}] {line}");
    let mut state = SwapRunState::new();

    let mut outcome = None;
    for step in 0..4_000 {
        match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
            .map_err(|e| {
                eprintln!("[{label}] swap_step {step} failed: {e}");
                e
            })? {
            SwapStepOutcome::Continue(_) => std::thread::sleep(Duration::from_millis(5)),
            SwapStepOutcome::Done(o) => {
                outcome = Some(o);
                break;
            }
        }
    }
    let outcome = outcome.ok_or(Error::Abort("party never reached a terminal"))?;
    eprintln!("[{label}] terminal: {outcome:?}");

    // Babysit to a CONFIRMED terminal — completion and refund alike (the
    // miner keeps mining while we loop; failed steps retry like the binary).
    let mut settled = false;
    for _ in 0..4_000 {
        let step = match &outcome {
            SwapOutcome::Completed { .. } => {
                completion_babysit_step(&mut engine, &chain, &dir, &sid, &opts, &mut log)
                    .map(|o| o.map(|_| ()))
            }
            SwapOutcome::Refunding { .. } => {
                refund_babysit_step(&mut engine, &chain, &dir, &sid, &opts, &mut log)
                    .map(|o| o.map(|_| ()))
            }
            SwapOutcome::Aborted { .. } => Ok(Some(())),
        };
        match step {
            Ok(Some(())) => {
                settled = true;
                break;
            }
            Ok(None) => {}
            Err(e) => log(format!("babysit step failed (retrying): {e}")),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !settled {
        return Err(Error::Abort("babysit never terminated"));
    }
    let has_swapped_coin =
        engine.ledger().coins().iter().any(|c| c.class == CoinClass::Swapped);

    done.fetch_add(1, AtomicOrdering::SeqCst);
    Ok(SideResult {
        sid,
        our_pk,
        our_escrow_op,
        their_escrow_op,
        msg_comp_sh,
        msg_comp_sl,
        outcome,
        has_swapped_coin,
    })
}

/// The per-attempt outcome of the two-party negotiate→swap flow: the branch
/// predictor and the terminal it produced, plus the forward-or-refund closure
/// facts the flow asserts on chain. Returned by [`run_role_csv_attempt`].
struct AttemptFacts {
    /// The interim convention (A = smaller session pubkey = presumed
    /// SecretLearner) matched the POST-CONFIRMATION derived role — the branch
    /// predictor for which terminal is CORRECT.
    predicted_match: bool,
    /// Both parties reached `SwapOutcome::Completed` (else both `Refunding`).
    completed: bool,
    /// Both escrows were swept/reclaimed on chain (completions or refunds).
    escrows_closed: bool,
    /// Both ledgers registered the received `Swapped` coin.
    swapped_registered: bool,
}

/// ONE attempt of the shared two-party flow: two independent wallets, each with
/// one REAL onboarded coin, negotiate over a duplex transport and run the swap
/// end to end against a fresh shared `SimChain`. Asserts cross-side agreement,
/// the strong outcome==prediction property (the deferred role↔CSV stop-gate
/// decides which terminal is CORRECT), and forward-or-refund closure — then
/// returns the facts.
///
/// Fresh tempdirs, fresh onboarded coins, and fresh random session keys make
/// each call independent, so `measure_role_csv_refund_rate` can run N of them.
fn run_role_csv_attempt() -> AttemptFacts {
    let params = Params::testnet_provisional();
    let base = 500_000u32;
    let chain = SimChain::new(base);

    // Two independent wallets, each with one REAL onboarded coin whose split
    // output is then made visible on the shared chain.
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let pre_a = onboard_unleased(dir_a.path(), &params, 0xDA);
    let pre_b = onboard_unleased(dir_b.path(), &params, 0xDB);
    assert_ne!(pre_a, pre_b, "the two wallets must fund from distinct coins");
    chain.fund_with_amount(pre_a, base, params.pre_encumbrance_sats());
    chain.fund_with_amount(pre_b, base, params.pre_encumbrance_sats());

    let sk_a = Scalar::random(&mut rand::rng());
    let sk_b = Scalar::random(&mut rand::rng());
    let block_x = base + 400;
    let (io_a, io_b) = duplex();
    let done = Arc::new(AtomicUsize::new(0));

    let ha = {
        let (dir, chain, done) = (dir_a.path().to_path_buf(), chain.clone(), done.clone());
        std::thread::spawn(move || run_party("A", dir, chain, io_a, sk_a, block_x, done))
    };
    let hb = {
        let (dir, chain, done) = (dir_b.path().to_path_buf(), chain.clone(), done.clone());
        std::thread::spawn(move || run_party("B", dir, chain, io_b, sk_b, block_x, done))
    };

    // Miner: keep the chain advancing (setup confirmations, CSV maturity for
    // the refund branch) until both parties report terminal.
    let miner = {
        let (chain, done) = (chain.clone(), done.clone());
        std::thread::spawn(move || {
            for _ in 0..3_000 {
                if done.load(AtomicOrdering::SeqCst) >= 2 {
                    break;
                }
                chain.mine();
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };

    let ra = ha.join().unwrap().expect("party A");
    let rb = hb.join().unwrap().expect("party B");
    miner.join().unwrap();

    // Cross-side agreement: same session, mirrored escrows, IDENTICAL
    // completion sighashes (the co-signed messages must match or Phase A
    // could never have verified).
    assert_eq!(ra.sid, rb.sid, "both sides must derive the same session id");
    assert_eq!(ra.our_escrow_op, rb.their_escrow_op);
    assert_eq!(ra.their_escrow_op, rb.our_escrow_op);
    assert_eq!(ra.msg_comp_sh, rb.msg_comp_sh);
    assert_eq!(ra.msg_comp_sl, rb.msg_comp_sl);

    // The deferred role↔CSV stop-gate decides which terminal is CORRECT: the
    // convention presumes A (smaller pubkey) = SecretLearner; the derived
    // role either agrees (both legs complete) or the CSV-binding guard
    // refuses and both sides exit through their refunds.
    let role_a =
        derived_role(&chain, &params, ra.our_escrow_op, ra.their_escrow_op, &ra.our_pk, &rb.our_pk);
    let a_is_smaller = vp(&ra.our_pk).to_bytes() < vp(&rb.our_pk).to_bytes();
    let convention_matched = (role_a == Role::SecretLearner) == a_is_smaller;
    let completed = matches!(ra.outcome, SwapOutcome::Completed { .. })
        && matches!(rb.outcome, SwapOutcome::Completed { .. });

    if convention_matched {
        assert!(
            matches!(ra.outcome, SwapOutcome::Completed { .. })
                && matches!(rb.outcome, SwapOutcome::Completed { .. }),
            "convention-matching roles must COMPLETE both legs, got A={:?} B={:?}",
            ra.outcome,
            rb.outcome
        );
        // Both escrows swept on chain by the completions.
        chain.mine();
        assert!(matches!(chain.spend_status(ra.our_escrow_op), SpendStatus::Confirmed(_)));
        assert!(matches!(chain.spend_status(rb.our_escrow_op), SpendStatus::Confirmed(_)));
    } else {
        assert!(
            matches!(ra.outcome, SwapOutcome::Refunding { .. })
                && matches!(rb.outcome, SwapOutcome::Refunding { .. }),
            "mismatching roles must refuse at the CSV guard and refund, got A={:?} B={:?}",
            ra.outcome,
            rb.outcome
        );
        // Forward-or-refund CLOSED: both escrows reclaimed by their refunds
        // (the babysit loops only returned once the records were terminal).
        chain.mine();
        assert!(matches!(chain.spend_status(ra.our_escrow_op), SpendStatus::Confirmed(_)));
        assert!(matches!(chain.spend_status(rb.our_escrow_op), SpendStatus::Confirmed(_)));
    }
    // Either exit pays our fresh SwapDestination key, and the babysit
    // terminal must have REGISTERED the received coin in each ledger.
    assert!(ra.has_swapped_coin, "A's settlement output must be ledger-tracked");
    assert!(rb.has_swapped_coin, "B's settlement output must be ledger-tracked");

    let escrows_closed = matches!(chain.spend_status(ra.our_escrow_op), SpendStatus::Confirmed(_))
        && matches!(chain.spend_status(rb.our_escrow_op), SpendStatus::Confirmed(_));
    let swapped_registered = ra.has_swapped_coin && rb.has_swapped_coin;
    AttemptFacts {
        predicted_match: convention_matched,
        completed,
        escrows_closed,
        swapped_registered,
    }
}

#[test]
fn negotiate_swap_two_parties_agree_and_close_forward_or_refund() {
    // One attempt of the shared flow; the helper makes every assertion this
    // test always made (cross-side agreement, outcome==prediction, and forward-
    // or-refund closure). `measure_role_csv_refund_rate` runs N of these.
    run_role_csv_attempt();
}

/// N-attempt empirical measurement of the role↔CSV refund rate: run the SAME
/// two-wallet flow N times (env `SWAPKEY_RATE_ATTEMPTS`, default 32), tally the
/// completed/refunded split, and print a machine-greppable summary. Ignored by
/// default (minutes of wall clock — each refund attempt mines 216+ SimChain
/// blocks at the 10 ms miner tick). Run with:
///   cargo test --test runner measure_role_csv_refund_rate -- --ignored --nocapture
#[test]
#[ignore = "N-attempt role↔CSV refund-rate measurement; run with --ignored --nocapture"]
fn measure_role_csv_refund_rate() {
    let n: usize = std::env::var("SWAPKEY_RATE_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(32);

    let mut completed = 0usize;
    let mut mismatches = 0usize;
    for attempt in 0..n {
        let facts = run_role_csv_attempt();
        // The strong property: the terminal MUST equal the convention predictor
        // (predicted_match ⇒ both Completed; !predicted_match ⇒ both Refunding).
        // run_role_csv_attempt already asserts this; count here too so the tally
        // printed below is a real number, not a tautology.
        if facts.completed != facts.predicted_match {
            mismatches += 1;
        }
        assert_eq!(
            facts.completed, facts.predicted_match,
            "attempt {attempt}: terminal (completed={}) disagreed with the convention \
             prediction (match={})",
            facts.completed, facts.predicted_match
        );
        // Forward-or-refund closure — the same facts the existing test asserts.
        assert!(facts.escrows_closed, "attempt {attempt}: both escrows must close on chain");
        assert!(
            facts.swapped_registered,
            "attempt {attempt}: both ledgers must register the Swapped coin"
        );
        if facts.completed {
            completed += 1;
        }
        eprintln!(
            "ROLE-CSV attempt {}/{n}: {} (predicted {})",
            attempt + 1,
            if facts.completed { "completed" } else { "refunded" },
            if facts.predicted_match { "completed" } else { "refunded" },
        );
    }

    let refunded = n - completed;
    let pct = 100.0 * completed as f64 / n as f64;
    // 3σ sanity bound around the p=0.5 expectation — catches a broken-coin
    // regression that would skew the split, NOT a substitute for the per-attempt
    // prediction assertion above (that is the strong check).
    let bound = 1.5 * (n as f64).sqrt();
    let deviation = (completed as f64 - n as f64 / 2.0).abs();
    println!(
        "ROLE-CSV RATE (SimChain): completed {completed}/{n} ({pct:.1}%), refunded {refunded}/{n}, \
         prediction-mismatches {mismatches}"
    );
    println!(
        "ROLE-CSV BOUND (SimChain): |completed - N/2| = {deviation:.2}, allowed <= 1.5*sqrt(N) = {bound:.2}"
    );
    assert_eq!(mismatches, 0, "every attempt's terminal must equal its convention prediction");
    assert!(
        deviation <= bound,
        "completed {completed}/{n} deviates {deviation:.2} from N/2, exceeding the ~3σ bound \
         {bound:.2} (suspect a broken-coin regression, not the p=0.5 role split)"
    );
}

// ============================================================================
// negotiate_swap refusals: before anything is at stake.
// ============================================================================

#[test]
fn negotiate_swap_rejects_a_network_mismatch() {
    let params = Params::testnet_provisional();
    let chain = SimChain::new(100);
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    onboard_unleased(dir_a.path(), &params, 0xDA);
    onboard_unleased(dir_b.path(), &params, 0xDB);
    let (mut io_a, mut io_b) = duplex();

    let hb = {
        let (dir, chain) = (dir_b.path().to_path_buf(), chain.clone());
        std::thread::spawn(move || {
            let mut engine = open_engine(&dir);
            negotiate_swap(
                &mut io_b,
                &mut engine,
                &chain,
                &FixedClock(u64::MAX),
                Network::Testnet, // peer disagrees on the network
                &dir,
                Scalar::random(&mut rand::rng()),
            )
            .map(|_| ())
        })
    };
    let mut engine = open_engine(dir_a.path());
    let ra = negotiate_swap(
        &mut io_a,
        &mut engine,
        &chain,
        &FixedClock(u64::MAX),
        Network::Regtest,
        dir_a.path(),
        Scalar::random(&mut rand::rng()),
    );
    assert!(ra.is_err(), "a network mismatch must refuse the handshake");
    assert!(hb.join().unwrap().is_err(), "the peer must refuse symmetrically");
}

#[test]
fn negotiate_swap_requires_an_onboarded_coin() {
    // A wallet with NO mature pre-encumbrance coin refuses after hello, and
    // the peer's failure is a clean transport abort, not a hang.
    let params = Params::testnet_provisional();
    let chain = SimChain::new(100);
    let dir_a = tempfile::tempdir().unwrap(); // no coins at all
    {
        let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
        Ledger::create(dir_a.path(), &ModeledEnclave, ack).unwrap();
    }
    let dir_b = tempfile::tempdir().unwrap();
    onboard_unleased(dir_b.path(), &params, 0xDB);
    let (mut io_a, mut io_b) = duplex();

    let hb = {
        let (dir, chain) = (dir_b.path().to_path_buf(), chain.clone());
        std::thread::spawn(move || {
            let mut engine = open_engine(&dir);
            negotiate_swap(
                &mut io_b,
                &mut engine,
                &chain,
                &FixedClock(u64::MAX),
                Network::Regtest,
                &dir,
                Scalar::random(&mut rand::rng()),
            )
            .map(|_| ())
        })
    };
    let mut engine = open_engine(dir_a.path());
    let ra = negotiate_swap(
        &mut io_a,
        &mut engine,
        &chain,
        &FixedClock(u64::MAX),
        Network::Regtest,
        dir_a.path(),
        Scalar::random(&mut rand::rng()),
    );
    match ra {
        Err(Error::Validation(msg)) => assert!(msg.contains("pre-encumbrance"), "{msg}"),
        Err(other) => panic!("expected the no-coin refusal, got {other:?}"),
        Ok(_) => panic!("negotiation must refuse without a mature coin"),
    }
    // Hang up our side; the peer's pending offer-recv fails immediately as a
    // clean transport abort, not a hang.
    drop(io_a);
    assert!(hb.join().unwrap().is_err());
}
