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

use std::net::TcpListener;
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
use swapkey::wallet::manifest::{ClaimDelayPosture, ModeledTrustRoot};
use swapkey::wallet::runner::{
    completion_babysit_step, negotiate_swap, refund_babysit_step, swap_step, RunOptions,
    SwapArtifacts, SwapOutcome, SwapRunState, SwapStepOutcome,
};
use swapkey::wallet::store::{ModeledEnclave, SwapPhase};
use swapkey::wallet::ticket::{maker_rendezvous, taker_rendezvous, Ticket};
use swapkey::wallet::transport::TcpTransport;
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
            // The default (Moderate) posture holds the SL claim; this loop
            // never mines otherwise, so mine the hold out here so the next
            // poll broadcasts.
            SwapStepOutcome::Holding { broadcast_at_height } => {
                while chain.tip_height() < broadcast_at_height {
                    chain.mine();
                }
            }
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
            match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
                .unwrap()
            {
                SwapStepOutcome::Done(o) => {
                    outcome = Some(o);
                    break;
                }
                SwapStepOutcome::Holding { broadcast_at_height } => {
                    while chain.tip_height() < broadcast_at_height {
                        chain.mine();
                    }
                }
                SwapStepOutcome::Continue(_) => {}
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
            // This swap aborts to refund (never settles as SL), so a hold is
            // not expected here; mine anyway so it would elapse (no miner runs).
            SwapStepOutcome::Holding { .. } => chain.mine(),
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
    /// Task-13 hold telemetry: the FIRST observed SL claim hold (`None` for a
    /// side that never held — SH always, and any refunding SL).
    hold: Option<HoldObs>,
    /// Tip height at which a `Done(Completed)` returned (`None` otherwise) —
    /// used to assert the claim was broadcast AT/AFTER the hold target.
    completed_tip: Option<u32>,
    /// Count of `Holding` steps observed by this side.
    held_steps: usize,
}

/// One SL claim-hold observation captured by [`run_party`] at the FIRST
/// `Holding` step (Task 13 telemetry).
#[derive(Clone, Copy)]
struct HoldObs {
    /// The posture target height the SL held for.
    broadcast_at_height: u32,
    /// Chain tip at the first `Holding` observation (must be strictly below
    /// `broadcast_at_height` — the claim is NOT broadcast before its target).
    tip_at_first_obs: u32,
    /// Whether the swept escrow (the counterparty escrow the SL sweeps) still
    /// read `Unspent` at the first `Holding` observation.
    swept_unspent_at_first_obs: bool,
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
    posture: Option<ClaimDelayPosture>,
) -> Result<SideResult> {
    let mut io = io;
    let mut engine = open_engine(&dir);
    // Task 13: apply the operator posture override right after the engine
    // opens (mirrors the CLI); `None` leaves the manifest's active posture.
    engine.set_claim_posture(posture);
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
    let mut hold: Option<HoldObs> = None;
    let mut held_steps = 0usize;
    let mut completed_tip: Option<u32> = None;
    for step in 0..4_000 {
        match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
            .map_err(|e| {
                eprintln!("[{label}] swap_step {step} failed: {e}");
                e
            })? {
            SwapStepOutcome::Continue(_) => std::thread::sleep(Duration::from_millis(5)),
            // Under run_role_csv_attempt's background miner, treat Holding like
            // Continue (sleep) but RECORD the first observation (Task 13); the
            // miner advances the chain past broadcast_at_height so the hold
            // elapses on its own.
            SwapStepOutcome::Holding { broadcast_at_height } => {
                held_steps += 1;
                if hold.is_none() {
                    hold = Some(HoldObs {
                        broadcast_at_height,
                        tip_at_first_obs: chain.tip_height(),
                        swept_unspent_at_first_obs: matches!(
                            chain.spend_status(their_escrow_op),
                            SpendStatus::Unspent
                        ),
                    });
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            SwapStepOutcome::Done(o) => {
                if matches!(o, SwapOutcome::Completed { .. }) {
                    completed_tip = Some(chain.tip_height());
                }
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
        hold,
        completed_tip,
        held_steps,
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

/// The full result of one attempt: the summary facts PLUS the two per-side
/// results and the shared chain, so a caller (Task-13's hold test) can inspect
/// the SL claim-hold telemetry and reach `funding_height` for the ceiling
/// assertion.
struct AttemptResult {
    facts: AttemptFacts,
    ra: SideResult,
    rb: SideResult,
    chain: SimChain,
}

/// The no-posture attempt (manifest active posture on both sides) — the shape
/// the existing tests use. Delegates to [`run_role_csv_attempt_with`].
fn run_role_csv_attempt() -> AttemptFacts {
    run_role_csv_attempt_with(None).facts
}

/// ONE attempt of the shared two-party flow: two independent wallets, each with
/// one REAL onboarded coin, negotiate over a duplex transport and run the swap
/// end to end against a fresh shared `SimChain`. Asserts cross-side agreement,
/// the strong outcome==prediction property (the deferred role↔CSV stop-gate
/// decides which terminal is CORRECT), and forward-or-refund closure — then
/// returns the facts, both side results, and the chain.
///
/// `posture` is applied to BOTH parties' engines (Task 13); `None` leaves the
/// manifest's active posture. Fresh tempdirs, fresh onboarded coins, and fresh
/// random session keys make each call independent, so `measure_role_csv_refund_rate`
/// can run N of them.
fn run_role_csv_attempt_with(posture: Option<ClaimDelayPosture>) -> AttemptResult {
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
        std::thread::spawn(move || run_party("A", dir, chain, io_a, sk_a, block_x, done, posture))
    };
    let hb = {
        let (dir, chain, done) = (dir_b.path().to_path_buf(), chain.clone(), done.clone());
        std::thread::spawn(move || run_party("B", dir, chain, io_b, sk_b, block_x, done, posture))
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
    AttemptResult {
        facts: AttemptFacts {
            predicted_match: convention_matched,
            completed,
            escrows_closed,
            swapped_registered,
        },
        ra,
        rb,
        chain,
    }
}

#[test]
fn negotiate_swap_two_parties_agree_and_close_forward_or_refund() {
    // One attempt of the shared flow; the helper makes every assertion this
    // test always made (cross-side agreement, outcome==prediction, and forward-
    // or-refund closure). `measure_role_csv_refund_rate` runs N of these.
    run_role_csv_attempt();
}

/// Task 13 — the SL claim-delay privacy posture wired end-to-end through the
/// two-party run loop. With `Aggressive` (min band 12) the SL ALWAYS holds, so
/// a hold is observable; the SH is unaffected. The role↔CSV convention refunds
/// ~half of attempts by design, so retry until one COMPLETES (the negotiate flow
/// can't pre-grind the derived role the way
/// `swap_step_drives_a_full_swap_to_completed` does, so a bounded retry stands
/// in for that deterministic-completion discipline).
#[test]
fn sl_claim_hold_delays_broadcast_and_respects_ceiling() {
    let params = Params::testnet_provisional();
    let delta_late = params.delta_late();
    let allowance = params.claim_confirm_allowance as u64;

    // ~half of attempts refund by design; retry (cap 12 ⇒ all-refund flake
    // ≈ 0.5^12 ≈ 0.02%) until one completes and a hold is observable. A
    // completed attempt can also — very rarely — consume its whole hold window
    // against the 10 ms miner before the SL's first `Holding` poll (an OS
    // stall between the engine's schedule and the runner's first poll; Fable
    // review, LOW), or read the telemetry tip late for the same reason. Both
    // are timing degeneracies of THIS harness, not hold regressions, so they
    // retry like a refunded attempt; an implementation that never holds fails
    // EVERY attempt and dies at the expect below.
    let mut result = None;
    for attempt in 0..12 {
        let r = run_role_csv_attempt_with(Some(ClaimDelayPosture::Aggressive));
        if !r.facts.completed {
            eprintln!("attempt {attempt}: refunded (role↔CSV mismatch by design); retrying");
            continue;
        }
        // BOTH sides holding is a hard bug (the SH must never hold) — never a
        // timing artifact, so it fails immediately rather than retrying.
        assert!(
            !(r.ra.held_steps > 0 && r.rb.held_steps > 0),
            "both sides held a claim — the SecretHolder must never hold"
        );
        let first_hold = if r.ra.held_steps > 0 { r.ra.hold } else { r.rb.hold };
        match first_hold {
            Some(h) if h.tip_at_first_obs < h.broadcast_at_height => {
                result = Some(r);
                break;
            }
            _ => eprintln!(
                "attempt {attempt}: completed but the hold window raced the miner \
                 (timing degeneracy); retrying"
            ),
        }
    }
    let AttemptResult { ra, rb, chain, .. } = result.expect(
        "at least one of 12 attempts must complete WITH an observable hold \
         (p≈0.5 completion each; a raced hold window is ~1e-5)",
    );

    // Exactly ONE side — the SL — observed a hold; the SH never did (a
    // SecretHolder swap is unaffected by the claim posture).
    assert!(
        (ra.held_steps > 0) ^ (rb.held_steps > 0),
        "exactly one side must hold, got A.held={} B.held={}",
        ra.held_steps,
        rb.held_steps
    );
    let (sl, sh) = if ra.held_steps > 0 { (&ra, &rb) } else { (&rb, &ra) };
    assert_eq!(sh.held_steps, 0, "the SecretHolder side must never hold");
    assert!(sh.hold.is_none(), "the SecretHolder side records no hold");

    let hold = sl.hold.expect("the SL recorded a hold");
    // Not broadcast BEFORE the target: the first hold is observed at a tip
    // strictly below broadcast_at_height.
    assert!(
        hold.tip_at_first_obs < hold.broadcast_at_height,
        "first hold tip {} must be strictly below the target {}",
        hold.tip_at_first_obs,
        hold.broadcast_at_height
    );
    // The swept escrow was still Unspent while the SL held its claim.
    assert!(
        hold.swept_unspent_at_first_obs,
        "the swept escrow must read Unspent while the SL holds its claim"
    );
    // Broadcast AT/AFTER the target: the completion tip is >= broadcast_at.
    let completed_tip = sl.completed_tip.expect("the SL reached a completion");
    assert!(
        completed_tip >= hold.broadcast_at_height,
        "SL completed at tip {} but must not broadcast before the hold target {}",
        completed_tip,
        hold.broadcast_at_height
    );

    // Ceiling respected END-TO-END: the held broadcast still confirms (within
    // the allowance) strictly before the swept escrow's late refund matures.
    // swept_op = the escrow the SL sweeps (its completion template's input).
    let swept_op = sl.their_escrow_op;
    let swept_funding_h = chain
        .funding_height(swept_op)
        .expect("the swept escrow is funded on chain") as u64;
    // broadcast_at + allowance + 1 <= swept_funding + delta_late; the strict `<`
    // form is the clippy-clean equivalent of that (confirm STRICTLY before the
    // swept escrow's late refund matures).
    assert!(
        hold.broadcast_at_height as u64 + allowance < swept_funding_h + delta_late,
        "broadcast_at {} + allowance {} + 1 exceeds swept funding {} + delta_late {}",
        hold.broadcast_at_height,
        allowance,
        swept_funding_h,
        delta_late
    );
    // Both records reached confirmed terminals + escrows closed — already
    // asserted inside run_role_csv_attempt_with for a completed attempt.
}

// ============================================================================
// swap_step: the hold's RACE arms (Fable review, MEDIUM — previously untested).
// A foreign mempool spend of the swept escrow abandons the hold and FIGHTS
// (Done(Completed) before the target height); a foreign CONFIRMED spend is a
// loud LOSS (`Err`), never reported as success.
// ============================================================================

/// A well-formed foreign spend of `outpoint` paying a standard P2TR output —
/// the shape of SH's late refund racing our held claim. (SimChain does not
/// enforce CSV maturity on relay, which is exactly the hostile shape the hold
/// must react to.)
fn foreign_spend_of(outpoint: OutPoint, out_sats: u64) -> Vec<u8> {
    use bitcoin::{
        absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&[0x77u8; 32]);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_sats),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }],
    };
    bitcoin::consensus::encode::serialize(&tx)
}

/// The driven SL swap parked at its FIRST `Holding` step, ready for a race to
/// be injected against the swept escrow. Tempdirs ride along so the stores
/// under the engine/ctx stay alive.
struct HeldSwap {
    app: swapkey::wallet::SwapApp,
    engine: SwapEngine,
    chain: SimChain,
    artifacts: SwapArtifacts,
    state: SwapRunState,
    /// The escrow the SL's held claim sweeps (the completion's input).
    swept_op: OutPoint,
    broadcast_at_height: u32,
    _wallet_dir: tempfile::TempDir,
    _lease_sl: tempfile::TempDir,
    _possession_store: tempfile::TempDir,
}

/// Drive the deterministic SL fixture (the same role-grind as
/// `swap_step_drives_a_full_swap_to_completed`) to its FIRST `Holding` step.
/// The posture is forced `Aggressive` (min delay 12) and NO miner thread runs,
/// so the hold cannot elapse on its own — the runner is parked mid-hold,
/// polling `next_broadcast` against the swept escrow, deterministically.
fn drive_sl_swap_to_first_hold() -> HeldSwap {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 910_000u32;
    let s_height = base + 1;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_leased(wallet_dir.path(), &params, [0xAAu8; 32]);
    let sh_pre = OutPoint::new(txid_from(0xB0), 0);

    // Grind keypairs until the runner-driven side derives SecretLearner (the
    // fixture-self-consistency trick shared with the full-swap test).
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
        build_completion(&escrow_e_sl, sl_escrow_op, escrow_amt, dest.clone(), d, params.anchor_sats)
            .unwrap();
    let comp_sl =
        build_completion(&escrow_e_sh, sh_escrow_op, escrow_amt, dest.clone(), d, params.anchor_sats)
            .unwrap();
    let (msg_sh, msg_sl) = (comp_sh.sighash, comp_sl.sighash);
    let (root_sh, root_sl) = (escrow_e_sl.merkle_root(), escrow_e_sh.merkle_root());
    let (ok_sh, ok_sl) = (escrow_e_sl.output_key_xonly(), escrow_e_sh.output_key_xonly());

    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let lease_sh = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    let sl_refund = PreArmedRefund::arm(
        &escrow_e_sl, sl_escrow_op, escrow_amt, &sl.sk, dest.clone(), d, params.anchor_sats,
        s_height,
    )
    .unwrap();
    let sl_refund_bytes = sl_refund.tx_bytes().to_vec();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // Live SH counterparty (raw settlement thread), as in the full-swap test.
    let sh_params = params.clone();
    let sh_chain = chain.clone();
    let comp_sh_for_sh = comp_sh.clone();
    let lease_sh_path = lease_sh.path().to_path_buf();
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
            lease_dir: Some(lease_sh_path),
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
    // Aggressive ⇒ the sampled delay is >= 12 (the ceiling is ample this close
    // to funding), so with no miner the first Completed tick MUST hold.
    engine.set_claim_posture(Some(ClaimDelayPosture::Aggressive));
    let ctx = make_ctx(
        sl.sk, sh.pk, sl_escrow_op, sh_escrow_op, escrow_amt, msg_sh, msg_sl, sl_refund, None,
        root_sh, root_sl, ok_sh, ok_sl, lease_sl.path().to_path_buf(),
        possession_store.path().to_path_buf(), sl_receipt, sl_pre,
    );
    let peer = PeerSession::new([0xE9u8; 32], Box::new(io_sl));
    let mut app = swapkey::wallet::SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

    let artifacts = SwapArtifacts {
        session_id: sid,
        setup_tx: sl_setup,
        comp_sh,
        comp_sl,
        refund_tx: sl_refund_bytes,
        dest_key_index: 0,
        dest_spk: dest,
    };
    let opts = RunOptions::default();
    let mut log = no_log();
    let mut state = SwapRunState::new();

    // Drive to the first Holding. The Phase-A exchange blocks inside one poll;
    // after joining the SH thread the reveal is guaranteed in the mempool, so
    // the very next step schedules and holds.
    let mut held_at = None;
    for _ in 0..24 {
        match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
            .unwrap()
        {
            SwapStepOutcome::Holding { broadcast_at_height } => {
                held_at = Some(broadcast_at_height);
                break;
            }
            SwapStepOutcome::Continue(_) => {}
            SwapStepOutcome::Done(o) => panic!("swap terminated before the hold: {o:?}"),
        }
    }
    sh_handle.join().unwrap().expect("SH side");
    if held_at.is_none() {
        for _ in 0..8 {
            match swap_step(&mut app, &mut engine, &chain, &artifacts, &mut state, &opts, &mut log)
                .unwrap()
            {
                SwapStepOutcome::Holding { broadcast_at_height } => {
                    held_at = Some(broadcast_at_height);
                    break;
                }
                SwapStepOutcome::Continue(_) => {}
                SwapStepOutcome::Done(o) => panic!("swap terminated before the hold: {o:?}"),
            }
        }
    }
    let broadcast_at_height =
        held_at.expect("the Aggressive posture must hold (no miner runs in this fixture)");
    assert!(
        chain.tip_height() < broadcast_at_height,
        "the fixture must park strictly inside the hold window"
    );

    HeldSwap {
        app,
        engine,
        chain,
        artifacts,
        state,
        swept_op: sh_escrow_op,
        broadcast_at_height,
        _wallet_dir: wallet_dir,
        _lease_sl: lease_sl,
        _possession_store: possession_store,
    }
}

/// Task 14 step 3: the baked fee params validated against the MEASURED vsizes
/// of the three ACTUAL signed transactions (not the doc-comment estimates) —
/// Setup and the pre-armed Refund straight from the artifacts sidecar, the
/// Completion reassembled exactly the way the runner broadcasts it
/// (`finalize_key_spend(template, final_sig)`). The floor is bitcoind's stock
/// `minrelaytxfee` of 1 sat/vB (testnet4 and mainnet defaults agree); the
/// baked fees must clear it with at least 3x margin so a mildly raised relay
/// floor never strands a pre-signed tx whose fee can't be renegotiated. vsize
/// is network-independent, so this regtest-shaped measurement is the testnet
/// number (cross-checked on-chain by the Task 14 testnet run).
#[test]
fn task14_baked_fees_clear_the_relay_floor_with_margin() {
    let held = drive_sl_swap_to_first_hold();
    let params = Params::testnet_provisional();
    let decode = |bytes: &[u8]| -> bitcoin::Transaction {
        bitcoin::consensus::encode::deserialize(bytes).expect("a signed tx from the fixture")
    };

    let setup = decode(&held.artifacts.setup_tx);
    let refund = decode(&held.artifacts.refund_tx);
    let rec = held
        .engine
        .store()
        .get(&held.artifacts.session_id)
        .unwrap()
        .expect("the held swap has a persisted record");
    let sig: [u8; 64] = rec
        .completion_tx
        .as_deref()
        .expect("a held SL swap has its FINALIZED 64-byte completion sig persisted")
        .try_into()
        .unwrap();
    let completion = decode(&finalize_key_spend(held.artifacts.comp_sl.clone(), sig));

    // Fees measured from the actual outputs against the params-known input
    // values (Setup spends the pre-encumbrance; both exits spend the escrow).
    let out_sum = |tx: &bitcoin::Transaction| {
        tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>()
    };
    let setup_fee = params.pre_encumbrance_sats() - out_sum(&setup);
    let completion_fee = params.escrow_amount_sats() - out_sum(&completion);
    let refund_fee = params.escrow_amount_sats() - out_sum(&refund);
    assert_eq!(setup_fee, params.setup_fee_sats, "Setup pays exactly the baked setup fee");
    assert_eq!(completion_fee, params.settlement_fee_sats(), "Completion pays the settlement fee");
    assert_eq!(refund_fee, params.settlement_fee_sats(), "Refund pays the settlement fee");

    // The relay-floor margin: fee >= 3 sat/vB * measured vsize (3x the 1 sat/vB
    // default floor). Printed so a `--nocapture` run documents the numbers.
    for (name, tx, fee) in
        [("setup", &setup, setup_fee), ("completion", &completion, completion_fee), ("refund", &refund, refund_fee)]
    {
        let vsize = tx.vsize() as u64;
        println!(
            "measured {name}: {vsize} vB, baked fee {fee} sats = {} sat/vB (floor margin {}x)",
            fee / vsize,
            fee / vsize
        );
        assert!(
            fee >= vsize * 3,
            "{name}: baked fee {fee} sats must clear 3 sat/vB over its measured {vsize} vB"
        );
    }
}

/// Task 13 (Fable review, MEDIUM): a foreign spend racing the swept escrow in
/// the MEMPOOL during the hold must ABANDON the hold and fight immediately —
/// `Done(Completed)` strictly before the posture target height, never a
/// stand-down `Holding`.
#[test]
fn sl_hold_abandons_to_fight_a_racing_foreign_mempool_spend() {
    let mut hs = drive_sl_swap_to_first_hold();
    let escrow_amt = Params::testnet_provisional().escrow_amount_sats();
    hs.chain
        .broadcast(&foreign_spend_of(hs.swept_op, escrow_amt.saturating_sub(20_000)))
        .expect("the foreign racing spend relays");
    assert!(hs.chain.tip_height() < hs.broadcast_at_height);

    let mut log = no_log();
    let out = swap_step(
        &mut hs.app, &mut hs.engine, &hs.chain, &hs.artifacts, &mut hs.state,
        &RunOptions::default(), &mut log,
    )
    .unwrap();
    match out {
        SwapStepOutcome::Done(SwapOutcome::Completed { .. }) => {}
        other => panic!("a racing foreign spend must abandon the hold and fight, got {other:?}"),
    }
    assert!(
        hs.chain.tip_height() < hs.broadcast_at_height,
        "the fight must have happened BEFORE the posture target height"
    );
}

/// Task 13 (Fable review, MEDIUM): a foreign spend that CONFIRMS on the swept
/// escrow while we hold is a lost claim race — `swap_step` must surface a loud
/// `Err`, NEVER `Done(Completed)` (the scheduler contract: a loss is never
/// reported as a success).
#[test]
fn sl_hold_reports_a_confirmed_foreign_spend_as_lost_never_success() {
    let mut hs = drive_sl_swap_to_first_hold();
    let escrow_amt = Params::testnet_provisional().escrow_amount_sats();
    hs.chain
        .broadcast(&foreign_spend_of(hs.swept_op, escrow_amt.saturating_sub(20_000)))
        .expect("the foreign racing spend relays");
    hs.chain.mine(); // ...and CONFIRMS while we hold (still inside the window).
    assert!(hs.chain.tip_height() < hs.broadcast_at_height);

    let mut log = no_log();
    let err = swap_step(
        &mut hs.app, &mut hs.engine, &hs.chain, &hs.artifacts, &mut hs.state,
        &RunOptions::default(), &mut log,
    )
    .expect_err("a confirmed foreign spend of the swept escrow must be a loud loss");
    assert!(
        matches!(err, Error::Abort(m) if m.contains("claim race lost")),
        "the loss must surface as Abort(claim race lost ...), got {err:?}"
    );
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

// ============================================================================
// Task 15: swap ticket end-to-end — maker mints a ticket carrying its REAL
// ephemeral address, taker decodes+validates+dials it, both run the nonce
// rendezvous, then the UNCHANGED negotiate_swap runs over a loopback
// TcpTransport and BOTH derive the same session id (the ticket only got the
// two parties to a connected transport; it is a convenience, not a trust
// anchor — negotiate_swap re-checks network + params itself).
// ============================================================================

#[test]
fn ticket_rendezvous_then_negotiate_over_tcp_loopback() {
    let params = Params::testnet_provisional();
    let base = 500_000u32;
    let chain = SimChain::new(base);

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let pre_a = onboard_unleased(dir_a.path(), &params, 0xDA);
    let pre_b = onboard_unleased(dir_b.path(), &params, 0xDB);
    assert_ne!(pre_a, pre_b, "the two wallets must fund from distinct coins");
    chain.fund_with_amount(pre_a, base, params.pre_encumbrance_sats());
    chain.fund_with_amount(pre_b, base, params.pre_encumbrance_sats());

    // Maker binds FIRST so the ticket carries the REAL bound port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let ticket = Ticket::mint(Network::Regtest, &params, "127.0.0.1", port).unwrap();
    let ticket_str = ticket.encode();
    let maker_nonce = ticket.nonce;

    // Maker: accept, maker-half rendezvous, then negotiate.
    let maker = {
        let (dir, chain) = (dir_a.path().to_path_buf(), chain.clone());
        std::thread::spawn(move || -> Result<[u8; 32]> {
            let mut t = TcpTransport::accept_timeout(&listener, Duration::from_secs(10))?;
            maker_rendezvous(&mut t, &maker_nonce)?;
            let mut engine = open_engine(&dir);
            let negotiated = negotiate_swap(
                &mut t,
                &mut engine,
                &chain,
                &FixedClock(u64::MAX),
                Network::Regtest,
                &dir,
                Scalar::random(&mut rand::rng()),
            )?;
            Ok(negotiated.artifacts.session_id)
        })
    };

    // Taker: decode + validate BEFORE dialing (a mismatch is a clean refusal,
    // not a hung socket), then dial, taker-half rendezvous, then negotiate.
    let decoded = Ticket::decode(&ticket_str).expect("taker decodes the pasted ticket");
    decoded
        .validate(Network::Regtest, &params)
        .expect("taker's local network + params match the ticket");
    assert_eq!(decoded.addr(), format!("127.0.0.1:{port}"));
    let mut t = TcpTransport::connect(decoded.addr()).expect("taker dials the ticket's address");
    taker_rendezvous(&mut t, &decoded.nonce).expect("taker rendezvous");
    let mut engine_b = open_engine(dir_b.path());
    let taker_sid = negotiate_swap(
        &mut t,
        &mut engine_b,
        &chain,
        &FixedClock(u64::MAX),
        Network::Regtest,
        dir_b.path(),
        Scalar::random(&mut rand::rng()),
    )
    .expect("taker negotiate over the socket")
    .artifacts
    .session_id;

    let maker_sid = maker.join().unwrap().expect("maker side");
    assert_eq!(maker_sid, taker_sid, "both sides must derive the same session id");
}

// ============================================================================
// Task 16: TWO concurrent swaps over ONE shared wallet/ledger — the serve
// model (a single thread interleaving both swaps' steps), against two
// independent peer wallets. The crux is shared-resource correctness: the two
// negotiations must lease DISTINCT pre-encumbrance coins (keyed by sid), both
// swaps must close forward-or-refund, and the shared ledger must end with no
// stranded lease and BOTH received coins registered.
// ============================================================================

/// Onboard ONE deposit sized for TWO pre-encumbrance units (the concurrent-
/// swap wallet), leaving both UNLEASED. Returns both outpoints.
fn onboard_two_unleased(dir: &std::path::Path, params: &Params, dep_seed: u8) -> Vec<OutPoint> {
    let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
    let mut ledger = Ledger::create(dir, &ModeledEnclave, ack).unwrap();
    let keys = ModeledKeySource::new(&ModeledEnclave);
    let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
    let dep = OutPoint::new(txid_from(dep_seed), 0);
    // Sized so the split carves its reserve AND still divides into two full
    // units (the reserve is carved BEFORE the k-unit division).
    ledger
        .register_deposit(
            dep,
            2 * params.pre_encumbrance_sats() + params.cpfp_reserve_sats + 2_000,
            100,
            idx,
            &spk,
            &keys,
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .unwrap();
    let plan = ledger.split_deposit(dep, params, 2_000, &keys).unwrap();
    assert_eq!(plan.pre_encumbrance_count, 2, "the deposit must split into TWO units");
    ledger.confirm_split(plan.txid, 150, &FixedClock(1_000)).unwrap();
    let pres: Vec<OutPoint> = ledger
        .coins()
        .iter()
        .filter(|c| c.class == CoinClass::PreEncumbrance && c.state == CoinState::Unspent)
        .map(|c| c.outpoint)
        .collect();
    assert_eq!(pres.len(), 2);
    pres
}

/// One interleaved babysit tick for a terminal swap; `true` once the record
/// is terminal (errors retry like the binary's loops).
fn babysit_once(
    engine: &mut SwapEngine,
    chain: &SimChain,
    dir: &std::path::Path,
    sid: &[u8; 32],
    outcome: &SwapOutcome,
    opts: &RunOptions,
) -> bool {
    let mut log = no_log();
    match outcome {
        SwapOutcome::Completed { .. } => {
            completion_babysit_step(engine, chain, dir, sid, opts, &mut log)
                .map(|o| o.is_some())
                .unwrap_or(false)
        }
        SwapOutcome::Refunding { .. } => refund_babysit_step(engine, chain, dir, sid, opts, &mut log)
            .map(|o| o.is_some())
            .unwrap_or(false),
        SwapOutcome::Aborted { .. } => true,
    }
}

#[test]
fn two_concurrent_swaps_share_one_ledger_without_collisions() {
    let params = Params::testnet_provisional();
    let base = 500_000u32;
    let chain = SimChain::new(base);

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_c = tempfile::tempdir().unwrap();
    let pres_a = onboard_two_unleased(dir_a.path(), &params, 0xA7);
    let pre_b = onboard_unleased(dir_b.path(), &params, 0xB7);
    let pre_c = onboard_unleased(dir_c.path(), &params, 0xC7);
    for op in pres_a.iter().copied().chain([pre_b, pre_c]) {
        chain.fund_with_amount(op, base, params.pre_encumbrance_sats());
    }

    let block_x = base + 400;
    let done = Arc::new(AtomicUsize::new(0));
    let (io1_a, io1_b) = duplex();
    let (io2_a, io2_c) = duplex();
    let sk_b = Scalar::random(&mut rand::rng());
    let sk_c = Scalar::random(&mut rand::rng());

    let hb = {
        let (dir, chain, done) = (dir_b.path().to_path_buf(), chain.clone(), done.clone());
        std::thread::spawn(move || run_party("B", dir, chain, io1_b, sk_b, block_x, done, None))
    };
    let hc = {
        let (dir, chain, done) = (dir_c.path().to_path_buf(), chain.clone(), done.clone());
        std::thread::spawn(move || run_party("C", dir, chain, io2_c, sk_c, block_x, done, None))
    };
    let miner = {
        let (chain, done) = (chain.clone(), done.clone());
        std::thread::spawn(move || {
            for _ in 0..4_000 {
                if done.load(AtomicOrdering::SeqCst) >= 3 {
                    break;
                }
                chain.mine();
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };

    // ---- wallet A: ONE engine, TWO interleaved swaps (the serve model) ----
    let mut engine = open_engine(dir_a.path());
    let clock = FixedClock(u64::MAX);
    let mut io1_a = io1_a;
    let mut io2_a = io2_a;
    let sk_a1 = Scalar::random(&mut rand::rng());
    let sk_a2 = Scalar::random(&mut rand::rng());
    let n1 = negotiate_swap(
        &mut io1_a, &mut engine, &chain, &clock, Network::Regtest, dir_a.path(), sk_a1,
    )
    .expect("negotiate swap 1");
    let n2 = negotiate_swap(
        &mut io2_a, &mut engine, &chain, &clock, Network::Regtest, dir_a.path(), sk_a2,
    )
    .expect("negotiate swap 2");
    let sid1 = n1.artifacts.session_id;
    let sid2 = n2.artifacts.session_id;
    assert_ne!(sid1, sid2);

    // THE lease crux: the two negotiations took two DISTINCT coins, each
    // tagged with its own sid — the transactional Unspent→Leased flip can
    // never hand one coin to two swaps.
    {
        let leased: Vec<(OutPoint, Option<[u8; 32]>)> = engine
            .ledger()
            .coins()
            .iter()
            .filter(|c| c.state == CoinState::Leased)
            .map(|c| (c.outpoint, c.lessee))
            .collect();
        assert_eq!(leased.len(), 2, "exactly the two negotiated leases");
        assert_ne!(leased[0].0, leased[1].0, "two swaps must never share a coin");
        let lessees: Vec<[u8; 32]> = leased.iter().map(|(_, l)| l.unwrap()).collect();
        assert!(lessees.contains(&sid1) && lessees.contains(&sid2));
    }

    let peer1 = PeerSession::new(sid1, Box::new(io1_a));
    let peer2 = PeerSession::new(sid2, Box::new(io2_a));
    let mut app1 =
        swapkey::wallet::SwapApp::begin(&engine, n1.ctx, peer1, block_x, 0).expect("begin 1");
    let mut app2 =
        swapkey::wallet::SwapApp::begin(&engine, n2.ctx, peer2, block_x, 0).expect("begin 2");
    let art1 = n1.artifacts;
    let art2 = n2.artifacts;
    let opts = RunOptions::default();
    let mut log1 = |l: String| eprintln!("[A/1] {l}");
    let mut log2 = |l: String| eprintln!("[A/2] {l}");
    let mut st1 = SwapRunState::new();
    let mut st2 = SwapRunState::new();
    let (mut out1, mut out2) = (None, None);
    for _ in 0..8_000 {
        if out1.is_none() {
            if let SwapStepOutcome::Done(o) =
                swap_step(&mut app1, &mut engine, &chain, &art1, &mut st1, &opts, &mut log1)
                    .expect("swap 1 step")
            {
                out1 = Some(o);
            }
        }
        if out2.is_none() {
            if let SwapStepOutcome::Done(o) =
                swap_step(&mut app2, &mut engine, &chain, &art2, &mut st2, &opts, &mut log2)
                    .expect("swap 2 step")
            {
                out2 = Some(o);
            }
        }
        if out1.is_some() && out2.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let out1 = out1.expect("swap 1 reached a terminal");
    let out2 = out2.expect("swap 2 reached a terminal");

    // Interleaved babysit of BOTH swaps to confirmed record terminals over
    // the one shared engine.
    let (mut settled1, mut settled2) = (false, false);
    for _ in 0..8_000 {
        if !settled1 {
            settled1 = babysit_once(&mut engine, &chain, dir_a.path(), &sid1, &out1, &opts);
        }
        if !settled2 {
            settled2 = babysit_once(&mut engine, &chain, dir_a.path(), &sid2, &out2, &opts);
        }
        if settled1 && settled2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(settled1 && settled2, "both swaps must settle");
    done.fetch_add(1, AtomicOrdering::SeqCst);

    let rb = hb.join().unwrap().expect("party B");
    let rc = hc.join().unwrap().expect("party C");
    miner.join().unwrap();

    // Per-swap cross-side agreement.
    assert_eq!(rb.sid, sid1);
    assert_eq!(rc.sid, sid2);
    assert_eq!(
        matches!(out1, SwapOutcome::Completed { .. }),
        matches!(rb.outcome, SwapOutcome::Completed { .. }),
        "swap 1's two sides must agree on the terminal"
    );
    assert_eq!(
        matches!(out2, SwapOutcome::Completed { .. }),
        matches!(rc.outcome, SwapOutcome::Completed { .. }),
        "swap 2's two sides must agree on the terminal"
    );
    // Forward-or-refund closure for BOTH swaps: all four escrows spent.
    chain.mine();
    for op in [rb.our_escrow_op, rb.their_escrow_op, rc.our_escrow_op, rc.their_escrow_op] {
        assert!(
            matches!(chain.spend_status(op), SpendStatus::Confirmed(_)),
            "every escrow must be closed by a completion or a refund"
        );
    }
    // A's SHARED ledger closed clean: both received coins registered (each
    // exit pays a fresh SwapDestination)...
    assert_eq!(
        engine.ledger().coins().iter().filter(|c| c.class == CoinClass::Swapped).count(),
        2,
        "both swaps' settlement outputs must be ledger-tracked"
    );
    // ...and after the chain-aware lease reconcile (the heal serve runs on
    // failures and every startup), NO lease survives two terminal swaps: both
    // funding coins are confirmed-spent by their Setups → swept to Spent.
    engine.reconcile_leases_with_chain(&chain).unwrap();
    let coins = engine.ledger().coins();
    assert!(coins.iter().all(|c| c.state != CoinState::Leased), "no stranded lease");
    assert_eq!(
        coins.iter().filter(|c| c.class == CoinClass::PreEncumbrance && c.state == CoinState::Spent).count(),
        2,
        "both funding coins closed as Spent, exactly once each"
    );
}

// ============================================================================
// Task 16: the shared-ledger primitives under concurrent swaps — the lease
// picker cannot double-assign, and the orphan heal's keep-set protects the
// record-less negotiate→Setup-broadcast window.
// ============================================================================

#[test]
fn concurrent_negotiations_lease_distinct_coins_and_reconcile_keeps_the_live_set() {
    let params = Params::testnet_provisional();
    let dir = tempfile::tempdir().unwrap();
    let pres = onboard_two_unleased(dir.path(), &params, 0xE1);
    let mut ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
    let sid1 = [0x11u8; 32];
    let sid2 = [0x22u8; 32];
    let c1 = ledger
        .lease_pre_encumbrance(params.pre_encumbrance_sats(), &FixedClock(u64::MAX), u32::MAX, sid1)
        .unwrap()
        .expect("first lease");
    let c2 = ledger
        .lease_pre_encumbrance(params.pre_encumbrance_sats(), &FixedClock(u64::MAX), u32::MAX, sid2)
        .unwrap()
        .expect("second lease");
    assert_ne!(c1.outpoint, c2.outpoint, "the picker must never double-assign a coin");
    assert!(pres.contains(&c1.outpoint) && pres.contains(&c2.outpoint));
    // Pool exhausted: a THIRD concurrent negotiation is a clean None (the
    // no-coin refusal), never a shared coin.
    assert!(ledger
        .lease_pre_encumbrance(
            params.pre_encumbrance_sats(),
            &FixedClock(u64::MAX),
            u32::MAX,
            [0x33u8; 32]
        )
        .unwrap()
        .is_none());
    // The reconcile keep-set: with only sid1 live, sid2's orphan releases and
    // sid1's lease SURVIVES — the exact contract the serve heal relies on.
    let released = ledger.reconcile_leases(&[sid1]).unwrap();
    assert_eq!(released, vec![c2.outpoint]);
    assert_eq!(ledger.find(&c1.outpoint).unwrap().state, CoinState::Leased);
    assert_eq!(ledger.find(&c2.outpoint).unwrap().state, CoinState::Unspent);
}

#[test]
fn orphan_heal_keeps_the_record_less_sibling_lease() {
    // The Task-16 hazard: a sibling swap's coin leases at negotiate time but
    // its store record only lands with the Setup broadcast — the funding-order
    // waiter sits record-less for many ticks. A store-only heal (run for a
    // DIFFERENT failed attempt) would release that live lease into a later
    // double-lease; the keep-set variant must hold it.
    let params = Params::testnet_provisional();
    let dir = tempfile::tempdir().unwrap();
    let pres = onboard_two_unleased(dir.path(), &params, 0xE2);
    let chain = SimChain::new(500_000);
    for op in &pres {
        chain.fund_with_amount(*op, 500_000, params.pre_encumbrance_sats());
    }
    let mut engine = open_engine(dir.path());
    let sibling = [0x77u8; 32];
    let coin = engine
        .ledger_mut()
        .lease_pre_encumbrance(
            params.pre_encumbrance_sats(),
            &FixedClock(u64::MAX),
            chain.tip_height(),
            sibling,
        )
        .unwrap()
        .expect("sibling lease");
    // The keep-set heal holds the record-less sibling's lease...
    engine.reconcile_leases_with_chain_keeping(&chain, &[sibling]).unwrap();
    assert_eq!(engine.ledger().find(&coin.outpoint).unwrap().state, CoinState::Leased);
    // ...and the store-only shape (empty keep-set) releases it — the exact
    // hazard the keeping variant exists to close.
    engine.reconcile_leases_with_chain_keeping(&chain, &[]).unwrap();
    assert_eq!(engine.ledger().find(&coin.outpoint).unwrap().state, CoinState::Unspent);
}
