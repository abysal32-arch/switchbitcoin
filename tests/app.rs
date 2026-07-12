//! `SwapApp` end-to-end integration (the top-level run-loop): the four
//! orchestration drivers composed into ONE re-enterable "run a swap" entry
//! point, driven over a real `SimChain`.
//!
//! * `swap_app_runs_a_full_swap_to_completed` — the headline: a COMPLETE swap
//!   for the SL party driven entirely through `SwapApp` — real Setups on chain
//!   (pre-funding poll loop), the `Proceed` handoff into the settlement spine,
//!   and settlement to a persisted `Completed` — against a live SH counterparty
//!   thread. Proves the seams actually wire end-to-end, not just in isolation.
//! * `swap_app_routes_to_refunding_when_phase_a_fails` — the cross into
//!   settlement with a dead transport aborts to the pre-armed refund
//!   (`AppTick::Refunding`, `AbortRefund` persisted), our escrow funded.
//! * `swap_app_block_x_abort_is_clean_and_sticky` — a pre-funding Block-X abort
//!   with our Setup never broadcast is a clean `Aborted` (nothing locked), and
//!   the terminal is sticky/idempotent.
//! * `swap_app_funded_abort_routes_to_refunding` — a wrong-amount counterparty
//!   escrow AFTER we funded ours is `Refunding` (the funded-abort branch).
//! * `swap_app_backstop_tick_is_idle_pre_record_then_delegates` — the
//!   congestion backstop is `Idle` before the first durable record and
//!   delegates to the `BackstopDriver` classifier afterwards.
//! * `swap_app_recover_delegates_to_recovery_driver` — whole-wallet crash
//!   re-entry delegates to `RecoveryDriver::reenter_all`.

use bitcoin::OutPoint;
use swapkey::chain::{ChainView, DualSourceChainView, FundingReading, SimChain, Source, SpendStatus};
use swapkey::crypto::adaptor::AdaptorSecret;
use swapkey::crypto::ValidatedPoint;
use swapkey::settlement::params::Params;
use swapkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund, WatchtowerReceipt};
use swapkey::settlement::state_machine::{
    canonical_internal_key, swap_session_id, ExchangeInputs, Funding, PeerSession, Role, Transport,
};
use swapkey::tx::escrow::Escrow;
use swapkey::tx::setup::build_setup;
use swapkey::tx::txbuild::{build_completion, finalize_key_spend, sign_schnorr_single};
use swapkey::wallet::app::{AppTick, BackstopRun, SwapApp};
use swapkey::wallet::backstop_driver::{BackstopTick, BumpOutcome};
use swapkey::wallet::engine::{SwapContext, SwapEngine};
use swapkey::wallet::keys::ModeledKeySource;
use swapkey::wallet::ledger::{acknowledge_phase0, BumpTarget, Ledger, WalletClock, PHASE0_WARNING};
use swapkey::wallet::ledger::CoinState;
use swapkey::wallet::manifest::ModeledTrustRoot;
use swapkey::wallet::orchestrator::AbortAction;
use swapkey::wallet::recovery_driver::{RecoveryDriver, RecoveryTick};
use swapkey::wallet::store::{ModeledEnclave, SwapPhase, SwapRecord};
use swapkey::{Error, Result};
use secp::{Point, Scalar};
use std::sync::mpsc;

// ---------- transport ----------

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

/// A transport that errors on any I/O — the pre-funding half never touches it,
/// and Phase A over it fails (→ the abort/refund path).
struct DeadEnd;
impl Transport for DeadEnd {
    fn send(&mut self, _bytes: &[u8]) -> Result<()> {
        Err(Error::Abort("dead transport"))
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        Err(Error::Abort("dead transport"))
    }
}

// ---------- keys / misc ----------

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
/// Onboard one mature, leasable pre-encumbrance coin and return its outpoint
/// (the swap's funding coin). Deterministic + independent of the swap keys.
fn onboard_one_coin(dir: &std::path::Path, pre_enc: u64, lessee: [u8; 32]) -> OutPoint {
    let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
    let mut ledger = Ledger::create(dir, &ModeledEnclave, ack).unwrap();
    let keys = ModeledKeySource::new(&ModeledEnclave);
    let params = Params::testnet_provisional();
    let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
    let dep = OutPoint::new(txid_from(0xDD), 0);
    ledger
        .register_deposit(
            dep,
            pre_enc + 2_000,
            100,
            idx,
            &spk,
            &keys,
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .unwrap();
    let plan = ledger.split_deposit(dep, &params, 2_000, &keys).unwrap();
    ledger.confirm_split(plan.txid, 150, &FixedClock(1_000)).unwrap();
    let coin = ledger
        .lease_pre_encumbrance(pre_enc, &FixedClock(u64::MAX), u32::MAX, lessee)
        .unwrap()
        .expect("a mature pre-encumbrance coin");
    coin.outpoint
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
        reveal_escrow_op: our_escrow_op, // SL: SH's Comp->SH spends OUR escrow (E_sl)
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

/// Fund `pre_op` with a pre-encumbrance coin at `base_height`, then build +
/// return the party's REAL Setup and its escrow outpoint (setup_txid:0).
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

/// The role the party with `our_op`/`our_pk` derives via the production
/// `await_funded` formula, given both escrows confirmed on `chain`. Used to
/// grind keys so the SL-driven side is deterministically `SecretLearner`.
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

// ============================================================================
// Headline: a full swap driven end-to-end through SwapApp.
// ============================================================================

#[test]
fn swap_app_runs_a_full_swap_to_completed() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 900_000u32;
    let s_height = base + 1; // both escrows confirm one block after the pre-coins
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    // SL's funding coin is deterministic + key-independent; onboard it once.
    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);
    let sh_pre = OutPoint::new(txid_from(0xB0), 0);

    // Grind keypairs until the SL-driven side derives SecretLearner for the REAL
    // Setup txids (role = f(txids, S, pubkeys)). Both escrows are built at the
    // funding-time CSVs the two roles use (E_sl: delta_early+sl.pk; E_sh:
    // delta_late+sh.pk), so the winning keys make the fixture self-consistent.
    let (sh, sl, escrow_e_sl, escrow_e_sh, sl_setup, sh_setup, sl_escrow_op, sh_escrow_op) = loop {
        let sh = keypair();
        let sl = keypair();
        let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
        let e_sl = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap(); // SL funds, SH sweeps
        let e_sh = Escrow::new(&internal, &sh.pk, delta_late).unwrap(); // SH funds, SL sweeps

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

    // The REAL chain both parties observe.
    let chain = SimChain::new(base);
    // Re-fund the pre-coins on this chain and land both escrows at s_height.
    chain.fund_with_amount(sl_pre, base, params.pre_encumbrance_sats());
    chain.fund_with_amount(sh_pre, base, params.pre_encumbrance_sats());
    chain.broadcast(&sl_setup).unwrap();
    chain.broadcast(&sh_setup).unwrap();
    chain.mine();
    assert_eq!(chain.funding_height(sl_escrow_op), Some(s_height));
    assert_eq!(chain.funding_height(sh_escrow_op), Some(s_height));

    // Settlement fixture (mirrors the engine full-stack test): completions,
    // sighashes, taproot data, and SL's pre-armed refund of its own escrow.
    let dest = escrow_e_sl.funding_script_pubkey().clone();
    let comp_sh = build_completion(&escrow_e_sl, sl_escrow_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let comp_sl = build_completion(&escrow_e_sh, sh_escrow_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let (msg_sh, msg_sl) = (comp_sh.sighash, comp_sl.sighash);
    let (root_sh, root_sl) = (escrow_e_sl.merkle_root(), escrow_e_sh.merkle_root());
    let (ok_sh, ok_sl) = (escrow_e_sl.output_key_xonly(), escrow_e_sh.output_key_xonly());

    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let lease_sh = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    let sl_refund =
        PreArmedRefund::arm(&escrow_e_sl, sl_escrow_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, s_height)
            .unwrap();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // SH counterparty — a raw settlement thread (a separate node in production),
    // funded_manual(SecretHolder, S) since the grind fixed SL on our side.
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

    // SL side, ENTIRELY through SwapApp.
    let (mut engine, actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(actions.is_empty(), "onboarded wallet has no crashed swaps");

    let ctx = make_ctx(
        sl.sk, sh.pk, sl_escrow_op, sh_escrow_op, escrow_amt, msg_sh, msg_sl, sl_refund, None,
        root_sh, root_sl, ok_sh, ok_sl, lease_sl.path().to_path_buf(),
        possession_store.path().to_path_buf(), sl_receipt, sl_pre,
    );
    let peer = PeerSession::new([0xE9u8; 32], Box::new(io_sl));

    let our_final_sig = {
        let mut app = SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

        // Pre-funding: both escrows already confirmed, so the loop just re-broadcasts
        // our (idempotent) Setup and Proceeds. The `Proceed` poll crosses the handoff
        // and BLOCKS in the Phase-A exchange (rendezvous with the SH thread), then
        // takes the first settlement step.
        let mut settled: Option<[u8; 64]> = None;
        for _ in 0..12 {
            match app.poll(&mut engine, &chain).unwrap() {
                AppTick::BroadcastSetup => {
                    chain.broadcast(&sl_setup).expect("idempotent re-broadcast");
                    app.setup_broadcast(&engine, &sl_setup).unwrap();
                }
                AppTick::Wait => {}
                AppTick::AwaitingReveal => {
                    // Phase A is done; make sure the SH thread has revealed, then
                    // the next poll extracts + completes.
                    if sh_handle.is_finished() {
                        // fall through to re-poll
                    }
                }
                AppTick::Completed { our_final_sig } => {
                    settled = Some(our_final_sig);
                    break;
                }
                other => panic!("unexpected tick before completion: {other:?}"),
            }
            if app.is_terminal() {
                break;
            }
        }
        // Ensure SH has broadcast Comp->SH (the reveal), then drive to Completed.
        let _sh_sig = sh_handle.join().unwrap().expect("SH side");
        assert!(matches!(chain.spend_status(sl_escrow_op), SpendStatus::InMempool | SpendStatus::Confirmed(_)));
        if settled.is_none() {
            for _ in 0..6 {
                match app.poll(&mut engine, &chain).unwrap() {
                    AppTick::Completed { our_final_sig } => {
                        settled = Some(our_final_sig);
                        break;
                    }
                    AppTick::AwaitingReveal => continue,
                    other => panic!("unexpected tick awaiting completion: {other:?}"),
                }
            }
        }
        settled.expect("SwapApp settled SL's leg to Completed")
    };

    // Engine boundary: the caller finalizes + broadcasts OUR completion tx.
    let comp_sl_final = finalize_key_spend(comp_sl, our_final_sig);
    chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
    chain.mine();
    assert!(matches!(chain.spend_status(sh_escrow_op), SpendStatus::Confirmed(_)));

    // The full lifecycle persisted through SwapApp, and the ledger reconciled.
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Completed);
    let coin = engine.ledger().find(&sl_pre).expect("funding coin tracked");
    assert_eq!(coin.state, CoinState::Spent, "SwapApp marked the funding coin spent");
}

// ============================================================================
// Cross into settlement with a dead transport → Refunding (our escrow funded).
// ============================================================================

#[test]
fn swap_app_routes_to_refunding_when_phase_a_fails() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 800_000u32;
    let s_height = base + 1;

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);
    let sh_pre = OutPoint::new(txid_from(0xC0), 0);

    let sh = keypair();
    let sl = keypair();
    let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
    // Both escrows at delta_early (the funding gate admits either CSV candidate);
    // the exchange dies on the dead transport before role-specific crypto matters.
    let e_ours = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let e_theirs = Escrow::new(&internal, &sh.pk, params.delta_early).unwrap();

    let chain = SimChain::new(base);
    let (sl_setup, our_op) = build_real_setup(&chain, &params, sl_pre, base, &e_ours, &sl.sk);
    let (sh_setup, their_op) = build_real_setup(&chain, &params, sh_pre, base, &e_theirs, &sh.sk);
    chain.broadcast(&sl_setup).unwrap();
    chain.broadcast(&sh_setup).unwrap();
    chain.mine();

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, s_height).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();

    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let peer = PeerSession::new([0xDEu8; 32], Box::new(DeadEnd));

    let mut app = SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();
    let mut outcome = None;
    for _ in 0..8 {
        match app.poll(&mut engine, &chain).unwrap() {
            AppTick::BroadcastSetup => {
                chain.broadcast(&sl_setup).unwrap();
                app.setup_broadcast(&engine, &sl_setup).unwrap();
            }
            AppTick::Wait => {}
            AppTick::Refunding(reason) => {
                outcome = Some(reason);
                break;
            }
            other => panic!("unexpected tick: {other:?}"),
        }
    }
    assert!(outcome.is_some(), "a dead-transport Phase A must route to Refunding");
    // The engine persisted the refund exit; the pre-armed refund is the sink.
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::AbortRefund);
    // Sticky + idempotent.
    assert!(matches!(app.poll(&mut engine, &chain).unwrap(), AppTick::Refunding(_)));
    assert!(app.is_terminal());
}

// ============================================================================
// Pre-funding Block-X abort, our Setup never broadcast → clean Aborted.
// ============================================================================

#[test]
fn swap_app_block_x_abort_is_clean_and_sticky() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 700_000u32;

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);

    let sh = keypair();
    let sl = keypair();
    let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
    let e_ours = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let e_theirs = Escrow::new(&internal, &sh.pk, params.delta_early).unwrap();
    let our_op = OutPoint::new(txid_from(0x11), 0);
    let their_op = OutPoint::new(txid_from(0x22), 0);

    let chain = SimChain::new(base);
    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let peer = PeerSession::new([0u8; 32], Box::new(DeadEnd));

    // Never broadcast our Setup; let Block X pass with neither escrow funded.
    let block_x = base + 3;
    let mut app = SwapApp::begin(&engine, ctx, peer, block_x, 0).unwrap();
    while chain.tip_height() < block_x {
        chain.mine();
    }
    match app.poll(&mut engine, &chain).unwrap() {
        AppTick::Aborted(reason) => assert!(reason.contains("Block X")),
        other => panic!("expected clean Aborted, got {other:?}"),
    }
    // Nothing was ever persisted (the first record is written at Proceed).
    assert!(engine.store().get(&sid).unwrap().is_none());
    // Sticky.
    assert!(matches!(app.poll(&mut engine, &chain).unwrap(), AppTick::Aborted(_)));
    assert!(app.is_terminal());
}

// ============================================================================
// Funded then aborted (wrong-amount counterparty escrow) → Refunding.
// ============================================================================

#[test]
fn swap_app_funded_abort_routes_to_refunding() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 600_000u32;

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);

    // Deterministically be the First funder (our pubkey canonically smaller), so
    // we broadcast BEFORE the wrong-amount abort fires (funded → Refunding).
    let (sh, sl) = loop {
        let a = keypair();
        let b = keypair();
        if vp(&a.pk).to_bytes() < vp(&b.pk).to_bytes() {
            break (b, a); // sl = a (smaller = First)
        } else if vp(&b.pk).to_bytes() < vp(&a.pk).to_bytes() {
            break (a, b); // sl = b
        }
    };
    let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
    let e_ours = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let e_theirs = Escrow::new(&internal, &sh.pk, params.delta_early).unwrap();

    let chain = SimChain::new(base);
    let (sl_setup, our_op) = build_real_setup(&chain, &params, sl_pre, base, &e_ours, &sl.sk);
    let (_sh_setup, their_op) = build_real_setup(&chain, &params, OutPoint::new(txid_from(0xB0), 0), base, &e_theirs, &sh.sk);

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let peer = PeerSession::new([0u8; 32], Box::new(DeadEnd));
    let mut app = SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();
    assert_eq!(app.funding_order(), Some(swapkey::wallet::orchestrator::FundingOrder::First));

    // Broadcast ours (fund E_ours), then the counterparty funds its escrow at the
    // WRONG amount → a funded abort → Refunding.
    assert_eq!(app.poll(&mut engine, &chain).unwrap(), AppTick::BroadcastSetup);
    chain.broadcast(&sl_setup).unwrap();
    app.setup_broadcast(&engine, &sl_setup).unwrap();
    // The early Funding record is durable the moment our Setup is on the wire.
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::Funding,
        "setup_broadcast persists the early Funding record"
    );
    chain.fund_with_amount(their_op, base + 1, escrow_amt - 1); // hostile: 1 sat short
    chain.mine();

    match app.poll(&mut engine, &chain).unwrap() {
        AppTick::Refunding(_) => {}
        other => panic!("a funded abort must be Refunding, got {other:?}"),
    }
    assert!(app.is_terminal());

    // The funded abort advanced the early record to AbortRefund, so a crash
    // here is re-entered by recover() as the refund decision (escrow funded,
    // refund immature → Wait).
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::AbortRefund);
    let scan = SwapApp::recover(&engine, &chain).unwrap();
    assert!(scan.unreadable.is_empty() && scan.failed.is_empty());
    let ticks = scan.ticks;
    assert_eq!(ticks.len(), 1);
    assert_eq!(ticks[0].0, sid);
    assert!(
        matches!(ticks[0].1, RecoveryTick::Refund(AbortAction::Wait)),
        "recover drives the funded abort's refund decision, got {:?}",
        ticks[0].1
    );

    // And the live backstop still fires the dead-device refund at CSV maturity
    // (now via the record path — same tower, same outcome).
    assert_eq!(
        app.backstop_tick(&engine, &chain, false, false).unwrap(),
        BackstopTick::Idle,
        "before CSV maturity the tower is idle"
    );
    while chain.tip_height() < base + 200 {
        chain.mine();
    }
    assert_eq!(
        app.backstop_tick(&engine, &chain, false, false).unwrap(),
        BackstopTick::FiredRefund,
        "the funded escrow's refund fires at maturity"
    );
}

// ============================================================================
// AwaitingVerification escalation: a persistent stall cannot wait forever.
// ============================================================================

/// The persistent-liar stall, escalated: both escrows are authoritatively
/// confirmed (Block-X can never fire) but a lying source keeps the agreement
/// view lagging forever. Pre-maturity every poll is the advisory
/// `AwaitingVerification` re-drive; the poll at our pre-armed refund's CSV
/// maturity terminates the swap to `Refunding` and advances the early record
/// to `AbortRefund` — the same height at which the dead-device tower fires
/// this refund anyway, so the app's terminal agrees with the backstop.
#[test]
fn awaiting_verification_escalates_to_refund_at_maturity() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 650_000u32;

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);

    // Deterministically be the First funder for crisp sequencing.
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

    // Truth (self-verifying) vs a liar that NEVER syncs the setups.
    let truth = SimChain::new(base);
    let liar = SimChain::new(base);
    let (sl_setup, our_op) = build_real_setup(&truth, &params, sl_pre, base, &e_ours, &sl.sk);
    let (sh_setup, their_op) =
        build_real_setup(&truth, &params, OutPoint::new(txid_from(0xB3), 0), base, &e_theirs, &sh.sk);
    let view = DualSourceChainView::new(
        Source::self_verifying(truth.clone()),
        Source::untrusted(liar.clone()),
    )
    .unwrap();

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let maturity = refund.csv_maturity_height();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let peer = PeerSession::new([0u8; 32], Box::new(DeadEnd));
    let mut app = SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

    // Fund both escrows ON TRUTH ONLY — the stall premise.
    assert_eq!(app.poll(&mut engine, &view).unwrap(), AppTick::BroadcastSetup);
    truth.broadcast(&sl_setup).unwrap();
    app.setup_broadcast(&engine, &sl_setup).unwrap();
    truth.broadcast(&sh_setup).unwrap();
    truth.mine();

    // Pre-maturity: every poll is the advisory re-drive, never a terminal.
    assert_eq!(app.poll(&mut engine, &view).unwrap(), AppTick::AwaitingVerification);
    while truth.tip_height() < maturity - 1 {
        truth.mine();
    }
    assert_eq!(
        app.poll(&mut engine, &view).unwrap(),
        AppTick::AwaitingVerification,
        "one block before maturity the stall is still a re-drive"
    );

    // At maturity the stall has outlived the whole CSV window: escalate.
    truth.mine();
    match app.poll(&mut engine, &view).unwrap() {
        AppTick::Refunding(reason) => {
            assert!(reason.contains("verification stall"), "got {reason:?}")
        }
        other => panic!("a matured stall must escalate to Refunding, got {other:?}"),
    }
    assert!(app.is_terminal());
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::AbortRefund,
        "the escalation advances the early record to AbortRefund"
    );
    // recover() from here drives the refund broadcast (matured, unspent).
    let ticks = SwapApp::recover(&engine, &view).unwrap().ticks;
    assert!(
        matches!(ticks[0].1, RecoveryTick::Refund(AbortAction::BroadcastRefund)),
        "got {:?}",
        ticks[0].1
    );
}

/// The record-less crash shape (review finding on 0e0ec64/128a22a, HIGH): the
/// caller broadcast its Setup but crashed BEFORE `setup_broadcast` — no flag,
/// no record — and the restarted app then hits a terminal abort. The funded
/// discriminator must fall through to the CHAIN (our escrow is authoritatively
/// confirmed), classify `Refunding` (never a false clean `Aborted`), and write
/// the early record it found missing so `recover()` is not blind.
///
/// Both live routes are driven: (A) Block-X passing with the counterparty
/// never funded; (B) the AwaitingVerification escalation at refund maturity
/// under a lying source (the Second-funder shape, where the coordinator never
/// re-issues `BroadcastSetup`, so the documented setup_broadcast heal can
/// never run).
#[test]
fn record_less_funded_abort_classifies_refunding_via_the_chain() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;

    // ---- Route A: Block-X abort, fresh app over a chain-confirmed escrow. ----
    let base = 700_000u32;
    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);
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
    let (_x, their_op) =
        build_real_setup(&chain, &params, OutPoint::new(txid_from(0xB4), 0), base, &e_theirs, &sh.sk);

    // Pre-crash session: the Setup goes on the wire and CONFIRMS; the process
    // dies before setup_broadcast — no record, and the fresh app has no flag.
    chain.broadcast(&sl_setup).unwrap();
    chain.mine();

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let block_x = base + 40;
    let mut app = SwapApp::begin(&engine, ctx, PeerSession::new([0u8; 32], Box::new(DeadEnd)), block_x, 0).unwrap();
    assert!(engine.store().get(&sid).unwrap().is_none(), "record-less by construction");

    // Block-X passes with the counterparty never funded → the first poll is a
    // terminal abort — which must read the CHAIN and classify Refunding.
    while chain.tip_height() < block_x {
        chain.mine();
    }
    match app.poll(&mut engine, &chain).unwrap() {
        AppTick::Refunding(reason) => assert!(reason.contains("Block X"), "got {reason:?}"),
        other => panic!("a chain-funded record-less abort must be Refunding, got {other:?}"),
    }
    // ...and recover() is no longer blind: the record was written and advanced.
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::AbortRefund,
        "the terminal wrote the missing early record and advanced it"
    );
    let ticks = SwapApp::recover(&engine, &chain).unwrap().ticks;
    assert_eq!(ticks.len(), 1);
    assert!(matches!(ticks[0].1, RecoveryTick::Refund(_)), "got {:?}", ticks[0].1);

    // ---- Route B: the AwaitingVerification escalation, record-less. ----
    // The app must be the SECOND funder here: its broadcast is gated on the
    // very verification that is stalled, so the coordinator never re-issues
    // `BroadcastSetup` and the documented setup_broadcast heal cannot run.
    let base = 710_000u32;
    let wallet_dir2 = tempfile::tempdir().unwrap();
    let sl_pre2 = onboard_one_coin(wallet_dir2.path(), params.pre_encumbrance_sats(), [0xABu8; 32]);
    let (sh, sl) = loop {
        let a = keypair();
        let b = keypair();
        if vp(&a.pk).to_bytes() < vp(&b.pk).to_bytes() {
            break (a, b); // sl = b (larger = Second funder)
        } else if vp(&b.pk).to_bytes() < vp(&a.pk).to_bytes() {
            break (b, a);
        }
    };
    let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
    let e_ours = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let e_theirs = Escrow::new(&internal, &sh.pk, params.delta_early).unwrap();
    let truth = SimChain::new(base);
    let liar = SimChain::new(base);
    let (sl_setup2, our_op2) = build_real_setup(&truth, &params, sl_pre2, base, &e_ours, &sl.sk);
    let (sh_setup2, their_op2) =
        build_real_setup(&truth, &params, OutPoint::new(txid_from(0xB5), 0), base, &e_theirs, &sh.sk);
    // Both setups confirm ON TRUTH ONLY (pre-crash); the liar never syncs.
    truth.broadcast(&sl_setup2).unwrap();
    truth.broadcast(&sh_setup2).unwrap();
    truth.mine();
    let view = DualSourceChainView::new(
        Source::self_verifying(truth.clone()),
        Source::untrusted(liar.clone()),
    )
    .unwrap();

    let dest2 = e_ours.funding_script_pubkey().clone();
    let comp2 = build_completion(&e_ours, our_op2, escrow_amt, dest2.clone(), d, params.anchor_sats).unwrap();
    let refund2 =
        PreArmedRefund::arm(&e_ours, our_op2, escrow_amt, &sl.sk, dest2, d, params.anchor_sats, base).unwrap();
    let maturity = refund2.csv_maturity_height();
    let receipt2 = confirm_watchtower_handoff(&refund2, refund2.fingerprint()).unwrap();
    let (mut engine2, _) = SwapEngine::open(
        wallet_dir2.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease2 = tempfile::tempdir().unwrap();
    let possession2 = tempfile::tempdir().unwrap();
    let ctx2 = make_ctx(
        sl.sk, sh.pk, our_op2, their_op2, escrow_amt, comp2.sighash, comp2.sighash, refund2, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease2.path().to_path_buf(), possession2.path().to_path_buf(),
        receipt2, sl_pre2,
    );
    let sid2 = SwapEngine::swap_session_id(&ctx2).unwrap();
    let mut app2 = SwapApp::begin(&engine2, ctx2, PeerSession::new([0u8; 32], Box::new(DeadEnd)), base + 500, 0).unwrap();

    // The stall is live (advisory) pre-maturity, regardless of funding order.
    assert_eq!(app2.poll(&mut engine2, &view).unwrap(), AppTick::AwaitingVerification);
    while truth.tip_height() < maturity {
        truth.mine();
    }
    match app2.poll(&mut engine2, &view).unwrap() {
        AppTick::Refunding(reason) => {
            assert!(reason.contains("verification stall"), "got {reason:?}")
        }
        other => panic!("a record-less matured stall must be Refunding, got {other:?}"),
    }
    assert_eq!(
        engine2.store().get(&sid2).unwrap().unwrap().phase,
        SwapPhase::AbortRefund,
        "escalation wrote the missing record and advanced it"
    );
}

// ============================================================================
// Early Funding record: crash between Setup broadcast and Proceed is durable.
// ============================================================================

/// THE pre-record crash gap, closed: a crash after our Setup went on the wire
/// but before the `Proceed` handoff used to leave a funded escrow with NO store
/// record (recover() blind, and `open`'s reconcile re-exposing the leased
/// funding coin as a phantom). With the early record persisted at
/// `setup_broadcast`, the crashed swap (a) keeps its funding-coin lease across
/// the reopen, and (b) is re-entered by recover() with the standing pre-armed
/// refund as the exit — Wait while immature, BroadcastRefund at CSV maturity.
#[test]
fn early_funding_record_survives_crash_and_recovers() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 300_000u32;

    let wallet_dir = tempfile::tempdir().unwrap();
    // Onboard the coin (the helper's dummy lease is released by open's
    // reconcile — no record exists for it), then re-lease under the REAL sid.
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);

    // Deterministically be the First funder so the first poll is BroadcastSetup.
    let (sh, sl) = loop {
        let a = keypair();
        let b = keypair();
        if vp(&a.pk).to_bytes() < vp(&b.pk).to_bytes() {
            break (b, a);
        } else if vp(&b.pk).to_bytes() < vp(&a.pk).to_bytes() {
            break (a, b);
        }
    };
    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
    let e_ours = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let e_theirs = Escrow::new(&internal, &sh.pk, params.delta_early).unwrap();

    let chain = SimChain::new(base);
    let (sl_setup, our_op) = build_real_setup(&chain, &params, sl_pre, base, &e_ours, &sl.sk);
    let (_sh_setup, their_op) =
        build_real_setup(&chain, &params, OutPoint::new(txid_from(0xB2), 0), base, &e_theirs, &sh.sk);

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    // The production-shaped lease: the funding coin is leased to THIS swap.
    let leased = engine
        .ledger_mut()
        .lease_pre_encumbrance(params.pre_encumbrance_sats(), &FixedClock(u64::MAX), u32::MAX, sid)
        .unwrap()
        .expect("the reconciled coin re-leases under the swap's sid");
    assert_eq!(leased.outpoint, sl_pre, "same coin, now leased to the swap");

    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let peer = PeerSession::new([0u8; 32], Box::new(DeadEnd));
    let mut app = SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

    // Broadcast our Setup; the early record lands the moment we confirm it.
    assert_eq!(app.poll(&mut engine, &chain).unwrap(), AppTick::BroadcastSetup);
    chain.broadcast(&sl_setup).unwrap();
    app.setup_broadcast(&engine, &sl_setup).unwrap();
    let rec = engine.store().get(&sid).unwrap().expect("early record persisted");
    assert_eq!(rec.phase, SwapPhase::Funding);
    assert_eq!(rec.our_escrow_outpoint, Some(our_op));
    assert!(rec.pre_armed_refund.is_some(), "G2: the refund rides in the early record");
    // Idempotent re-confirm (a restarted caller re-broadcasting).
    app.setup_broadcast(&engine, &sl_setup).unwrap();

    chain.mine(); // our escrow confirms; counterparty never funds

    // CRASH: the live app AND engine die; only the store + chain survive.
    drop(app);
    drop(engine);

    let (engine2, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    // (a) The lease reconcile sees the live Funding record and KEEPS the lease —
    // the coin the in-flight Setup spends is never re-exposed as a phantom.
    let coin = engine2.ledger().find(&sl_pre).expect("funding coin tracked");
    assert_eq!(
        coin.state,
        CoinState::Leased,
        "the early record keeps the funding-coin lease across a crash"
    );

    // (b) recover() re-enters the crashed swap from the record alone: escrow
    // funded, refund immature → Wait; at CSV maturity → BroadcastRefund.
    let scan = SwapApp::recover(&engine2, &chain).unwrap();
    assert!(scan.unreadable.is_empty() && scan.failed.is_empty());
    let ticks = scan.ticks;
    assert_eq!(ticks.len(), 1);
    assert_eq!(ticks[0].0, sid);
    assert!(
        matches!(ticks[0].1, RecoveryTick::Funding { refund: Some(AbortAction::Wait) }),
        "immature: recover surfaces the standing refund as Wait, got {:?}",
        ticks[0].1
    );
    while chain.tip_height() < base + 200 {
        chain.mine();
    }
    let ticks = SwapApp::recover(&engine2, &chain).unwrap().ticks;
    assert!(
        matches!(ticks[0].1, RecoveryTick::Funding { refund: Some(AbortAction::BroadcastRefund) }),
        "matured: recover routes to the refund broadcast, got {:?}",
        ticks[0].1
    );

    // Restart shape: a FRESH app over the surviving record (broadcast flag
    // lost) hits the Block-X abort before the caller re-confirms its
    // re-broadcast. The early record is the durable discriminator — this must
    // classify as a FUNDED abort (Refunding, record → AbortRefund), never a
    // clean "nothing locked" Aborted.
    while chain.tip_height() < base + 500 {
        chain.mine(); // Block-X passes; the counterparty never funded
    }
    let refund2 = PreArmedRefund::arm(
        &e_ours,
        our_op,
        escrow_amt,
        &sl.sk,
        e_ours.funding_script_pubkey().clone(),
        d,
        params.anchor_sats,
        base,
    )
    .unwrap();
    let receipt2 = confirm_watchtower_handoff(&refund2, refund2.fingerprint()).unwrap();
    let lease2 = tempfile::tempdir().unwrap();
    let possession2 = tempfile::tempdir().unwrap();
    let ctx2 = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund2, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease2.path().to_path_buf(),
        possession2.path().to_path_buf(), receipt2, sl_pre,
    );
    let peer2 = PeerSession::new([0u8; 32], Box::new(DeadEnd));
    let mut engine2 = engine2;
    let mut app2 = SwapApp::begin(&engine2, ctx2, peer2, base + 500, 0).unwrap();
    match app2.poll(&mut engine2, &chain).unwrap() {
        AppTick::Refunding(reason) => assert!(reason.contains("Block X"), "got {reason:?}"),
        other => panic!("a restarted funded abort must be Refunding, got {other:?}"),
    }
    assert_eq!(
        engine2.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::AbortRefund,
        "the restarted funded abort advances the early record to AbortRefund"
    );
}

// ============================================================================
// Backstop delegation.
// ============================================================================

#[test]
fn swap_app_backstop_tick_is_idle_pre_record_then_delegates() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 500_000u32;

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);

    let sh = keypair();
    let sl = keypair();
    let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
    let e_ours = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let e_sl = OutPoint::new(txid_from(0x71), 0); // reveal escrow (their side for SH)
    let our_op = OutPoint::new(txid_from(0x70), 0);

    let chain = SimChain::new(base);
    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let (engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, e_sl, escrow_amt, comp.sighash, comp.sighash, refund.clone(), None,
        e_ours.merkle_root(), e_ours.merkle_root(), e_ours.output_key_xonly(),
        e_ours.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let peer = PeerSession::new([0u8; 32], Box::new(DeadEnd));
    let app = SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

    // Pre-record: no durable SwapRecord yet → Idle regardless of congestion.
    assert_eq!(app.backstop_tick(&engine, &chain, true, true).unwrap(), BackstopTick::Idle);

    // Establish a Completing SH record with a revealed reveal-escrow through the
    // store's legal transitions (Funding → Signing → Completing), then the
    // backstop delegates to the classifier: revealed + congested + reserve, with
    // the dead-device policy (consent=None), → NeedsConsent for a completion.
    chain.fund(e_sl, base);
    chain.broadcast(&spend_of(e_sl, escrow_amt - 500, None)).unwrap(); // reveal public
    let rec = |phase: SwapPhase, completion_tx: Option<Vec<u8>>| SwapRecord {
        swap_session_id: sid,
        role: Role::SecretHolder,
        phase,
        params: params.clone(),
        s_height: base,
        sweep_escrow_height: base,
        our_escrow_outpoint: Some(our_op),
        their_escrow_outpoint: Some(e_sl),
        pre_armed_refund: Some(refund.clone()),
        completion_tx,
        setup_tx: None,
        possession_record: None,
    };
    engine.store().put(&rec(SwapPhase::Funding, None)).unwrap();
    engine.store().put(&rec(SwapPhase::Signing, None)).unwrap();
    engine.store().put(&rec(SwapPhase::Completing, Some(vec![7u8; 64]))).unwrap();

    assert_eq!(
        app.backstop_tick(&engine, &chain, true, true).unwrap(),
        BackstopTick::NeedsConsent { target: BumpTarget::Completion },
        "a revealed, congested completion with a reserve awaits consent"
    );
    // Not congested ⇒ nothing to do.
    assert_eq!(app.backstop_tick(&engine, &chain, false, true).unwrap(), BackstopTick::Idle);
}

// ============================================================================
// Whole-wallet crash re-entry delegates to RecoveryDriver.
// ============================================================================

#[test]
fn swap_app_recover_delegates_to_recovery_driver() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 400_000u32;

    let wallet_dir = tempfile::tempdir().unwrap();
    let _coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAAu8; 32]);

    let sh = keypair();
    let sl = keypair();
    let internal = canonical_internal_key(sh.pk, sl.pk).unwrap();
    let e_ours = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let our_op = OutPoint::new(txid_from(0x90), 0);
    let sid = swap_session_id(sl.pk, sh.pk).unwrap();

    let chain = SimChain::new(base);
    chain.fund(our_op, base);
    let dest = e_ours.funding_script_pubkey().clone();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();

    let (engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    // A crashed swap left at AbortRefund (our escrow funded, refund the exit),
    // established through the store's legal Funding → AbortRefund transition.
    let rec = |phase: SwapPhase| SwapRecord {
        swap_session_id: sid,
        role: Role::SecretHolder,
        phase,
        params: params.clone(),
        s_height: base,
        sweep_escrow_height: base,
        our_escrow_outpoint: Some(our_op),
        their_escrow_outpoint: Some(OutPoint::new(txid_from(0x91), 0)),
        pre_armed_refund: Some(refund.clone()),
        completion_tx: None,
        setup_tx: None,
        possession_record: None,
    };
    engine.store().put(&rec(SwapPhase::Funding)).unwrap();
    engine.store().put(&rec(SwapPhase::AbortRefund)).unwrap();

    // SwapApp::recover returns the same scan RecoveryDriver::reenter_all does.
    let via_app = SwapApp::recover(&engine, &chain).unwrap();
    let via_driver = RecoveryDriver::reenter_all(engine.store(), &chain).unwrap();
    assert_eq!(via_app.ticks, via_driver.ticks, "SwapApp::recover must delegate to RecoveryDriver");
    assert_eq!(via_app.unreadable, via_driver.unreadable);
    assert_eq!(via_app.ticks.len(), 1);
    assert_eq!(via_app.ticks[0].0, sid);
    assert!(matches!(via_app.ticks[0].1, RecoveryTick::Refund(_)));
}

/// A real signed spend of `outpoint` (for the reveal fixture), so the sim gives
/// it a txid. `csv = None` for a no-timelock completion.
fn spend_of(outpoint: OutPoint, out: u64, csv: Option<u16>) -> Vec<u8> {
    use bitcoin::{
        absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    let sequence = match csv {
        Some(b) => Sequence::from_height(b),
        None => Sequence::ENABLE_RBF_NO_LOCKTIME,
    };
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&[0x77u8; 32]);
    let tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: ScriptBuf::from_bytes(spk) }],
    };
    bitcoin::consensus::encode::serialize(&tx)
}

// ============================================================================
// Autonomous backstop execution: the dead-device refund bump, end-to-end.
// ============================================================================

/// `backstop_execute` — the refund side needs NOTHING from the caller but a
/// target feerate: at CSV maturity under a fee floor the tower's fire stalls,
/// the decision routes to `Bump { Refund }`, and the app executes the 1P1C
/// bump itself (the pre-armed refund IS the stalled parent; its bytes live in
/// ctx): lease → enclave-sign → package submit → reserve marked spent →
/// child change tracked as a fresh Reserve coin. Pre-maturity the decision
/// passes through untouched, and once the refund confirms the loop quiesces.
#[test]
fn backstop_execute_bumps_a_stalled_refund_autonomously() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 720_000u32;

    // Provision a REAL reserve coin (onboarding change → promoted reserve)
    // into the wallet dir the engine will open.
    let wallet_dir = tempfile::tempdir().unwrap();
    let reserve_op = {
        let mut ledger = Ledger::create(
            wallet_dir.path(),
            &ModeledEnclave,
            acknowledge_phase0(PHASE0_WARNING).unwrap(),
        )
        .unwrap();
        let keys = ModeledKeySource::new(&ModeledEnclave);
        let unit = params.pre_encumbrance_sats();
        let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
        let dep = OutPoint::new(txid_from(0xD1), 0);
        ledger
            .register_deposit(
                dep,
                unit + 80_000 + 1_000,
                100,
                idx,
                &spk,
                &keys,
                Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
            )
            .unwrap();
        let plan = ledger.split_deposit(dep, &params, 1_000, &keys).unwrap();
        ledger.confirm_split(plan.txid, 105, &FixedClock(1_000)).unwrap();
        let change_op = OutPoint::new(plan.txid, plan.change_vout.expect("change output"));
        ledger.promote_change_to_reserve(change_op).unwrap();
        change_op
    };

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

    // Our escrow is funded on chain (the pre-Proceed funded shape — the
    // record-less tower arm guards it); the counterparty never funds.
    let chain = SimChain::new(base);
    let our_op = OutPoint::new(txid_from(0xC1), 0);
    let their_op = OutPoint::new(txid_from(0xC2), 0);
    chain.fund_with_amount(our_op, base, escrow_amt);

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let maturity = refund.csv_maturity_height();
    // The refund's own fee: escrow in, D + anchor out.
    let refund_fee = escrow_amt - d - params.anchor_sats;
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    // The reserve's UTXO exists on chain too (the child spends it).
    let reserve_amt = engine.ledger().find(&reserve_op).unwrap().amount_sats;
    chain.fund_with_amount(reserve_op, base, reserve_amt);

    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, OutPoint::new(txid_from(0xC3), 0),
    );
    let app = SwapApp::begin(&engine, ctx, PeerSession::new([0u8; 32], Box::new(DeadEnd)), base + 500, 0)
        .unwrap();

    // Pre-maturity: nothing to do — the decision passes through untouched.
    match app.backstop_execute(&mut engine, &chain, 50, None, None).unwrap() {
        BackstopRun::Decided(BackstopTick::Idle) => {}
        other => panic!("immature refund must pass through as Decided(Idle), got {other:?}"),
    }

    // Congestion: the refund alone can no longer relay. At maturity the
    // tower's fire stalls below the floor and the app bumps AUTONOMOUSLY.
    chain.set_congestion(refund_fee + 5_000);
    while chain.tip_height() < maturity {
        chain.mine();
    }
    let (change_op, child_fee) =
        match app.backstop_execute(&mut engine, &chain, 50, None, None).unwrap() {
            BackstopRun::Executed {
                decision: BackstopTick::Bump { target: BumpTarget::Refund },
                outcome:
                    BumpOutcome::Submitted {
                        reserve_outpoint,
                        deposit_linked,
                        change_outpoint,
                        change_amount_sats,
                        ..
                    },
            } => {
                assert_eq!(reserve_outpoint, reserve_op);
                assert!(!deposit_linked, "a refund bump is silent — no deposit linkage");
                (change_outpoint, (params.anchor_sats + reserve_amt) - change_amount_sats)
            }
            other => panic!("expected an executed refund bump, got {other:?}"),
        };
    assert!(child_fee > 0, "the child pays a real fee");
    // The 1P1C package is on the wire: the refund now spends our escrow, the
    // reserve is spent in the ledger, and the child change is a fresh coin.
    assert!(matches!(chain.spend_status(our_op), SpendStatus::InMempool));
    assert_eq!(engine.ledger().find(&reserve_op).unwrap().state, CoinState::Spent);
    // F5: the child change is PENDING until it confirms (an unconfirmed change
    // that could evict must not re-enter the leasable pool).
    assert_eq!(engine.ledger().find(&change_op).unwrap().state, CoinState::PendingConfirm);

    // Confirm: the refund lands; the loop quiesces (StandDown → Idle).
    chain.mine();
    assert!(matches!(chain.spend_status(our_op), SpendStatus::Confirmed(_)));
    match app.backstop_execute(&mut engine, &chain, 50, None, None).unwrap() {
        BackstopRun::Decided(BackstopTick::Idle) => {}
        other => panic!("a confirmed refund must quiesce, got {other:?}"),
    }
    // The confirmed child's change activates into the leasable pool via the
    // reserve-reconcile heal (the change outpoint is now a funded UTXO).
    engine.reconcile_reserves(&chain).unwrap();
    assert_eq!(engine.ledger().find(&change_op).unwrap().state, CoinState::Unspent);
}

/// Shared fixture for the backstop_execute regression tests: a record-less
/// funded swap (our escrow confirmed on chain, matured refund) whose wallet
/// holds one real provisioned reserve coin. Returns the engine, chain, app,
/// the reserve outpoint+amount, and the refund's own fee.
struct BackstopFixture {
    engine: SwapEngine,
    chain: SimChain,
    app: SwapApp,
    reserve_op: OutPoint,
    refund_fee: u64,
    _dirs: Vec<tempfile::TempDir>,
}

fn record_less_funded_with_reserve(base: u32, seed: u8) -> BackstopFixture {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let wallet_dir = tempfile::tempdir().unwrap();
    let reserve_op = {
        let mut ledger = Ledger::create(
            wallet_dir.path(),
            &ModeledEnclave,
            acknowledge_phase0(PHASE0_WARNING).unwrap(),
        )
        .unwrap();
        let keys = ModeledKeySource::new(&ModeledEnclave);
        let unit = params.pre_encumbrance_sats();
        let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
        let dep = OutPoint::new(txid_from(seed), 0);
        ledger
            .register_deposit(
                dep, unit + 80_000 + 1_000, 100, idx, &spk, &keys,
                Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
            )
            .unwrap();
        let plan = ledger.split_deposit(dep, &params, 1_000, &keys).unwrap();
        ledger.confirm_split(plan.txid, base - 5, &FixedClock(1_000)).unwrap();
        let change_op = OutPoint::new(plan.txid, plan.change_vout.expect("change output"));
        ledger.promote_change_to_reserve(change_op).unwrap();
        change_op
    };

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
    let our_op = OutPoint::new(txid_from(seed.wrapping_add(1)), 0);
    let their_op = OutPoint::new(txid_from(seed.wrapping_add(2)), 0);
    chain.fund_with_amount(our_op, base, escrow_amt);

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let maturity = refund.csv_maturity_height();
    let refund_fee = escrow_amt - d - params.anchor_sats;
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let (engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let reserve_amt = engine.ledger().find(&reserve_op).unwrap().amount_sats;
    chain.fund_with_amount(reserve_op, base, reserve_amt);

    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, OutPoint::new(txid_from(seed.wrapping_add(3)), 0),
    );
    let app = SwapApp::begin(&engine, ctx, PeerSession::new([0u8; 32], Box::new(DeadEnd)), base + 500, 0)
        .unwrap();
    while chain.tip_height() < maturity {
        chain.mine();
    }
    BackstopFixture { engine, chain, app, reserve_op, refund_fee, _dirs: vec![lease, possession, wallet_dir] }
}

/// Review finding 4 (per-side reserve gate): a stalled refund whose OWN small
/// child fee the reserve covers must bump even when the caller also supplies a
/// huge stalled completion parent the reserve could NEVER cover. The old
/// single-gate code sized the gate on the completion (too big → reserve
/// "unavailable") and starved the affordable refund bump; the two-pass gate
/// sizes on the ACTIVE (refund) side and bumps.
#[test]
fn backstop_execute_refund_bump_not_starved_by_a_huge_completion_parent() {
    let mut f = record_less_funded_with_reserve(730_000, 0xE1);
    // Congest so the refund's own fee can't relay → the tower stalls.
    f.chain.set_congestion(f.refund_fee + 5_000);

    // A caller-supplied completion "parent" so large its required child fee
    // dwarfs any reserve (fee 1 sat, vsize 10_000_000 vB → child fee ≫ reserve).
    let huge = swapkey::wallet::app::StalledParent {
        tx_bytes: &[0u8; 0],
        fee_sats: 1,
        vsize_vb: 10_000_000,
    };
    match f.app.backstop_execute(&mut f.engine, &f.chain, 50, Some(&huge), None).unwrap() {
        BackstopRun::Executed {
            decision: BackstopTick::Bump { target: BumpTarget::Refund },
            outcome: BumpOutcome::Submitted { reserve_outpoint, .. },
        } => assert_eq!(reserve_outpoint, f.reserve_op, "the refund bump ran, sized on the refund"),
        other => panic!("the affordable refund bump must not be starved, got {other:?}"),
    }
}

/// Review finding 5 (futile-bump short-circuit): a target feerate at/below the
/// parent's own feerate yields required_child_fee == 0 — a guaranteed NoBump.
/// backstop_execute must return the plain decision WITHOUT issuing a Reserve
/// key or a lease cycle, so a stale-feerate loop can't burn the index space.
#[test]
fn backstop_execute_short_circuits_a_futile_zero_fee_bump() {
    let mut f = record_less_funded_with_reserve(740_000, 0xE4);
    f.chain.set_congestion(f.refund_fee + 5_000); // tower stalled

    // The next Reserve key index BEFORE the call (issue then observe; a fresh
    // issue must return the SAME index if the futile call burned none).
    let idx_before = f.engine.issue_reserve_key().unwrap().0;

    // target_feerate 0 → required_child_fee == 0 → short-circuit.
    match f.app.backstop_execute(&mut f.engine, &f.chain, 0, None, None).unwrap() {
        BackstopRun::Decided(BackstopTick::KeepWaiting) => {}
        other => panic!("a futile bump must be Decided(KeepWaiting), got {other:?}"),
    }

    let idx_after = f.engine.issue_reserve_key().unwrap().0;
    assert_eq!(
        idx_after,
        idx_before + 1,
        "the futile bump must not burn a Reserve key index (only our two probes advance it)"
    );
    // And the reserve was never leased/spent.
    assert_eq!(
        f.engine.ledger().find(&f.reserve_op).unwrap().state,
        CoinState::Unspent
    );
}

/// A SECOND record-less funded swap over an EXISTING engine + chain (same
/// shape as [`record_less_funded_with_reserve`], minus the wallet/reserve
/// provisioning): our escrow confirmed, refund matured. For regressions that
/// need two swaps sharing one wallet's reserve pool in one process lifetime.
fn second_record_less_funded_app(
    engine: &SwapEngine,
    chain: &SimChain,
    seed: u8,
) -> (SwapApp, u64, Vec<tempfile::TempDir>) {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = chain.tip_height();

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

    let our_op = OutPoint::new(txid_from(seed), 0);
    let their_op = OutPoint::new(txid_from(seed.wrapping_add(1)), 0);
    chain.fund_with_amount(our_op, base, escrow_amt);

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let maturity = refund.csv_maturity_height();
    let refund_fee = escrow_amt - d - params.anchor_sats;
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();

    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, OutPoint::new(txid_from(seed.wrapping_add(2)), 0),
    );
    let app = SwapApp::begin(engine, ctx, PeerSession::new([0u8; 32], Box::new(DeadEnd)), base + 500, 0)
        .unwrap();
    while chain.tip_height() < maturity {
        chain.mine();
    }
    (app, refund_fee, vec![lease, possession])
}

/// F5 REGRESSION (Task F review): the CPFP-change reserve pool must replenish
/// MID-SESSION, not only at startup. One provisioned reserve; bump #1 spends
/// it and parks the child's change `PendingConfirm`; the package confirms; a
/// SECOND swap's stalled refund must then find the change leasable and bump —
/// with NO manual `reconcile_reserves` call and NO restart in between. Before
/// the fix the live loop read the gate without ever running the heal, so
/// under sustained congestion the pool depleted one reserve per bump and the
/// backstop stayed silently disabled until the process restarted — the exact
/// failure the pending-park (F5) set out to prevent.
#[test]
fn backstop_execute_replenishes_the_reserve_pool_mid_session() {
    let mut f = record_less_funded_with_reserve(750_000, 0xF1);
    f.chain.set_congestion(f.refund_fee + 5_000);

    // Bump #1 consumes the ONLY provisioned reserve; its change parks pending.
    let change_op = match f.app.backstop_execute(&mut f.engine, &f.chain, 50, None, None).unwrap() {
        BackstopRun::Executed {
            decision: BackstopTick::Bump { target: BumpTarget::Refund },
            outcome: BumpOutcome::Submitted { reserve_outpoint, change_outpoint, .. },
        } => {
            assert_eq!(reserve_outpoint, f.reserve_op);
            change_outpoint
        }
        other => panic!("bump #1 should have executed, got {other:?}"),
    };
    assert_eq!(f.engine.ledger().find(&f.reserve_op).unwrap().state, CoinState::Spent);
    assert_eq!(f.engine.ledger().find(&change_op).unwrap().state, CoinState::PendingConfirm);

    // The package confirms: swap #1 is done and the change is a real UTXO —
    // but the ledger still says PendingConfirm (no restart, no startup heal).
    f.chain.mine();
    assert_eq!(f.engine.ledger().find(&change_op).unwrap().state, CoinState::PendingConfirm);

    // A second swap's refund stalls under the same congestion. Its
    // backstop_execute must activate the confirmed change into the pool
    // ITSELF and bump from it.
    let (app2, refund_fee2, _dirs2) = second_record_less_funded_app(&f.engine, &f.chain, 0xF8);
    f.chain.set_congestion(refund_fee2 + 5_000);
    match app2.backstop_execute(&mut f.engine, &f.chain, 50, None, None).unwrap() {
        BackstopRun::Executed {
            decision: BackstopTick::Bump { target: BumpTarget::Refund },
            outcome: BumpOutcome::Submitted { reserve_outpoint, .. },
        } => assert_eq!(
            reserve_outpoint, change_op,
            "bump #2 must lease the healed change from bump #1"
        ),
        other => panic!("the pool must replenish mid-session (F5 live heal), got {other:?}"),
    }
    assert_eq!(f.engine.ledger().find(&change_op).unwrap().state, CoinState::Spent);
}

// ============================================================================
// Feature-2 audit: the funded discriminator's two blind spots (findings G/L)
// and the pre-record backstop's lying-source suppression (finding H).
// ============================================================================

/// Finding G (record-less crash, Setup still IN THE MEMPOOL): the caller
/// broadcast its fully-signed Setup and crashed in the broadcast ->
/// `setup_broadcast` gap; the Setup stalls UNCONFIRMED under congestion while
/// Block-X passes. The fresh app's first poll is a terminal abort -- and every
/// prior funded discriminator read negative here (no flag, no record, and the
/// escrow outpoint does not exist yet, so the authoritative funding read is
/// blind). Miners do not honor Block-X: that Setup can still confirm, so a
/// clean `Aborted` ("nothing locked") would abandon the refund guard and stop
/// the backstop on a coin that is about to lock -- violating forward-or-refund.
/// The funding COIN's spend status observes the shape throughout: the abort
/// must classify `Refunding` and write the early record it found missing.
#[test]
fn record_less_abort_with_setup_still_in_mempool_classifies_refunding() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 720_000u32;
    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xACu8; 32]);
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
    let (_x, their_op) =
        build_real_setup(&chain, &params, OutPoint::new(txid_from(0xB6), 0), base, &e_theirs, &sh.sk);

    // Pre-crash session: the Setup goes on the wire but NEVER CONFIRMS
    // (congestion); the process dies before setup_broadcast.
    chain.broadcast(&sl_setup).unwrap();
    assert!(
        matches!(chain.spend_status(sl_pre), SpendStatus::InMempool),
        "the funding coin's spend (our Setup) sits in the mempool"
    );
    assert_eq!(
        chain.authoritative_funding_height(our_op),
        None,
        "the escrow outpoint does not exist yet -- the funding read is blind"
    );

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let block_x = base + 40;
    let mut app =
        SwapApp::begin(&engine, ctx, PeerSession::new([0u8; 32], Box::new(DeadEnd)), block_x, 0)
            .unwrap();
    assert!(engine.store().get(&sid).unwrap().is_none(), "record-less by construction");

    // Block-X passes with the Setup STILL unconfirmed (advance, never mine).
    chain.advance(41);
    assert!(chain.tip_height() >= block_x);
    assert!(matches!(chain.spend_status(sl_pre), SpendStatus::InMempool));

    match app.poll(&mut engine, &chain).unwrap() {
        AppTick::Refunding(reason) => assert!(reason.contains("Block X"), "got {reason:?}"),
        other => panic!(
            "an in-mempool Setup means the coin can still lock -- must be Refunding, got {other:?}"
        ),
    }
    // The missing early record was written and advanced, so recover() sees it.
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::AbortRefund,
        "the terminal wrote the missing early record and advanced it"
    );

    // Miners confirm the Setup after Block-X (they do not honor it): recovery
    // drives the standing refund over the now-funded escrow.
    chain.mine();
    assert!(chain.authoritative_funding_height(our_op).is_some());
    let ticks = SwapApp::recover(&engine, &chain).unwrap().ticks;
    assert_eq!(ticks.len(), 1);
    assert!(matches!(ticks[0].1, RecoveryTick::Refund(_)), "got {:?}", ticks[0].1);
}

/// Finding H (pre-record backstop vs a lying source): the no-record arm of
/// `backstop_tick` guards a funded-but-record-less escrow's dead-device
/// refund. That funded/not decision must be the AUTHORITATIVE read -- on the
/// agreement-required `funding_height` a single lying source (never syncing)
/// collapses the reading to None, the tower reads Idle forever, and the
/// pre-armed refund never fires at CSV maturity: the escrow strands. Same
/// rationale as `terminate_abort` / `reenter_funding` /
/// `rebroadcast_setup_if_unconfirmed`, which all use the authoritative read.
#[test]
fn backstop_pre_record_fires_the_refund_despite_a_lying_source() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 730_000u32;
    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xADu8; 32]);
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
    let truth = SimChain::new(base);
    let liar = SimChain::new(base);
    let (sl_setup, our_op) = build_real_setup(&truth, &params, sl_pre, base, &e_ours, &sl.sk);
    let (_x, their_op) =
        build_real_setup(&truth, &params, OutPoint::new(txid_from(0xB7), 0), base, &e_theirs, &sh.sk);

    // Our Setup confirms ON TRUTH ONLY; the liar never syncs, so the
    // agreement-required funding_height reads None throughout.
    truth.broadcast(&sl_setup).unwrap();
    truth.mine();
    let view = DualSourceChainView::new(
        Source::self_verifying(truth.clone()),
        Source::untrusted(liar.clone()),
    )
    .unwrap();
    assert_eq!(view.funding_height(our_op), None, "the liar suppresses the agreement read");
    assert!(view.authoritative_funding_height(our_op).is_some());

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    // Arm at the escrow's REAL funding height so the refund's own maturity
    // matches the chain's CSV enforcement (the tower must actually broadcast).
    let funded_at = truth.funding_height(our_op).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, funded_at)
            .unwrap();
    let maturity = refund.csv_maturity_height();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
    let (engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund, None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    // Record-less: setup_broadcast never ran (the exact shape this arm guards).
    let app =
        SwapApp::begin(&engine, ctx, PeerSession::new([0u8; 32], Box::new(DeadEnd)), base + 500, 0)
            .unwrap();
    assert!(engine.store().get(&sid).unwrap().is_none());

    // Past CSV maturity the dead-device tower must fire REGARDLESS of the
    // liar: the tower acts on authoritative reads a liar cannot suppress.
    while truth.tip_height() < maturity {
        truth.mine();
    }
    match app.backstop_tick(&engine, &view, false, false).unwrap() {
        BackstopTick::FiredRefund => {}
        other => panic!("the pre-record tower must fire at maturity, got {other:?}"),
    }
    // The refund actually landed on the authoritative chain.
    assert!(
        !matches!(truth.spend_status(our_op), SpendStatus::Unspent),
        "the pre-armed refund is on the wire"
    );
}

/// Finding L (the read-err discriminator): a store read FAILURE at the abort
/// classifier must fail SAFE to `Refunding` -- never collapse into the "no
/// record" clean-abort arm (a false `Aborted` on a funded swap abandons the
/// refund guard; a false `Refunding` on an unfunded one is harmless). A
/// regression collapsing `get()` Err into None (e.g. an `.ok().flatten()`
/// refactor) would flip this test's terminal to `Aborted`. Also pins the
/// `!read_err` guard: the corrupt record is NOT overwritten by the early-
/// record write (the terminal stays in-memory; the evidence is preserved).
#[test]
fn terminate_abort_store_read_failure_fails_safe_to_refunding() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 740_000u32;
    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAEu8; 32]);
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
    // Real outpoints/refund, but NOTHING ever goes on the wire: the chain
    // discriminators all read negative, isolating the read-err arm.
    let (_sl_setup, our_op) = build_real_setup(&chain, &params, sl_pre, base, &e_ours, &sl.sk);
    let (_x, their_op) =
        build_real_setup(&chain, &params, OutPoint::new(txid_from(0xB8), 0), base, &e_theirs, &sh.sk);

    let dest = e_ours.funding_script_pubkey().clone();
    let comp = build_completion(&e_ours, our_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let refund =
        PreArmedRefund::arm(&e_ours, our_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, base).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, our_op, their_op, escrow_amt, comp.sighash, comp.sighash, refund.clone(), None,
        e_ours.merkle_root(), e_theirs.merkle_root(), e_ours.output_key_xonly(),
        e_theirs.output_key_xonly(), lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, sl_pre,
    );
    let sid = SwapEngine::swap_session_id(&ctx).unwrap();
    let block_x = base + 40;
    let mut app =
        SwapApp::begin(&engine, ctx, PeerSession::new([0u8; 32], Box::new(DeadEnd)), block_x, 0)
            .unwrap();

    // A prior session's record exists on disk...
    engine
        .store()
        .put(&SwapRecord {
            swap_session_id: sid,
            role: Role::SecretHolder,
            phase: SwapPhase::Funding,
            params: params.clone(),
            s_height: 0,
            sweep_escrow_height: 0,
            our_escrow_outpoint: Some(our_op),
            their_escrow_outpoint: Some(their_op),
            pre_armed_refund: Some(refund),
            completion_tx: None,
            setup_tx: None,
            possession_record: None,
        })
        .unwrap();
    // ...but the sealed file is DAMAGED (the post-crash condition records are
    // likeliest to be in): flip bytes so the GCM open fails.
    let rec_path = {
        let hex: String = sid.iter().map(|b| format!("{b:02x}")).collect();
        wallet_dir.path().join(format!("{hex}.swap"))
    };
    let mut sealed = std::fs::read(&rec_path).expect("the sealed record exists");
    let mid = sealed.len() / 2;
    sealed[mid] ^= 0xFF;
    std::fs::write(&rec_path, &sealed).unwrap();
    assert!(engine.store().get(&sid).is_err(), "the damaged record must read as Err");

    // Drive a Block-X abort: flag unset, record unreadable, chain clean --
    // the read failure alone must classify FUNDED (fail safe).
    chain.advance(41);
    match app.poll(&mut engine, &chain).unwrap() {
        AppTick::Refunding(reason) => assert!(reason.contains("Block X"), "got {reason:?}"),
        other => panic!("an unreadable record must fail safe to Refunding, got {other:?}"),
    }
    // The `!read_err` guard: the damaged file was NOT overwritten by the
    // early-record write -- the evidence survives for a rescan.
    assert!(
        engine.store().get(&sid).is_err(),
        "terminate_abort must not overwrite an unreadable record"
    );
}

// ============================================================================
// TASK 3: the eternal-mangled-reveal BOUND (forward-or-refund closure for the
// mangled-reveal re-drive, 77018f5) -- end-to-end through SwapApp + backstop.
// ============================================================================

/// A permanently DEGRADED/LYING view: for the reveal escrow it serves a
/// witness that FAILS extraction (a valid BIP340 signature over an unrelated
/// message) on every read, forever -- even after the escrow's real spend
/// confirms. Everything else delegates to the truth. This is the strongest
/// version of the degraded-single-source model the mangled-reveal re-drive
/// (77018f5) was built for: the lie never heals.
struct DegradedRevealView {
    inner: SimChain,
    reveal_escrow: OutPoint,
    bad_sig: [u8; 64],
}
impl ChainView for DegradedRevealView {
    fn tip_height(&self) -> u32 {
        self.inner.tip_height()
    }
    fn funding_height(&self, op: OutPoint) -> Option<u32> {
        self.inner.funding_height(op)
    }
    fn funding_amount(&self, op: OutPoint) -> Option<u64> {
        self.inner.funding_amount(op)
    }
    fn funding_spk(&self, op: OutPoint) -> Option<bitcoin::ScriptBuf> {
        self.inner.funding_spk(op)
    }
    fn spend_status(&self, op: OutPoint) -> SpendStatus {
        self.inner.spend_status(op)
    }
    fn spend_txid(&self, op: OutPoint) -> Option<bitcoin::Txid> {
        self.inner.spend_txid(op)
    }
    fn verified_funding_reading(&self, op: OutPoint) -> FundingReading {
        self.inner.verified_funding_reading(op)
    }
    fn authoritative_funding_height(&self, op: OutPoint) -> Option<u32> {
        self.inner.authoritative_funding_height(op)
    }
    fn spending_witness_sig(&self, op: OutPoint) -> Option<[u8; 64]> {
        if op == self.reveal_escrow {
            Some(self.bad_sig) // the eternal lie
        } else {
            self.inner.spending_witness_sig(op)
        }
    }
    fn broadcast(&self, tx: &[u8]) -> Result<bitcoin::Txid> {
        self.inner.broadcast(tx)
    }
    fn submit_package(&self, p: &[u8], c: &[u8]) -> Result<(bitcoin::Txid, bitcoin::Txid)> {
        self.inner.submit_package(p, c)
    }
}
impl swapkey::chain::AuthoritativeChainView for DegradedRevealView {}

/// TASK 3 -- a reveal that stays mangled FOREVER never strands SL. 77018f5
/// made a bad-witness reveal a bounded re-drive (`AwaitingReveal`, asserted
/// pre-maturity); this proves the BOUND end-to-end at the app level:
///
///   1. every `poll` under the eternal lie is `AwaitingReveal` -- never a
///      poison, never a false refund, never a false completion, before OR
///      after CSV maturity (the app instance cannot be misled either way);
///   2. `backstop_tick` (the primary-independent cadence) fires the pre-armed
///      refund exactly at CSV maturity (`FiredRefund`) -- the bound;
///   3. recovery reconciles the terminal UNDER THE SAME LYING VIEW: the
///      mangled witness must fall back to the refund decision (the recovery
///      twin of 77018f5's settle fix -- before that fix, one lying source
///      poisoned the WHOLE `reenter_all` scan with a hard Err, forever), and
///      the record advances AbortRefund -> Refunded.
#[test]
fn eternal_mangled_reveal_never_strands_sl() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 910_000u32;
    let s_height = base + 1;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let wallet_dir = tempfile::tempdir().unwrap();
    let sl_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xAFu8; 32]);
    let sh_pre = OutPoint::new(txid_from(0xB9), 0);

    // Grind SL (same as the headline full-swap fixture).
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
    let comp_sh = build_completion(&escrow_e_sl, sl_escrow_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let comp_sl = build_completion(&escrow_e_sh, sh_escrow_op, escrow_amt, dest.clone(), d, params.anchor_sats).unwrap();
    let (msg_sh, msg_sl) = (comp_sh.sighash, comp_sl.sighash);
    let (root_sh, root_sl) = (escrow_e_sl.merkle_root(), escrow_e_sh.merkle_root());
    let (ok_sh, ok_sl) = (escrow_e_sl.output_key_xonly(), escrow_e_sh.output_key_xonly());

    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let lease_sh = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    let sl_refund =
        PreArmedRefund::arm(&escrow_e_sl, sl_escrow_op, escrow_amt, &sl.sk, dest, d, params.anchor_sats, s_height)
            .unwrap();
    let maturity = sl_refund.csv_maturity_height();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // The DEGRADED view SL operates through: the witness it serves for E_sl
    // (the reveal escrow) is a VALID BIP340 signature over an unrelated
    // message -- observe_reveal happily surfaces it, extraction rejects it
    // (t*G != T) -- and it never heals.
    let bad_sig = sign_schnorr_single(sl.sk.serialize(), msg_sl).unwrap();
    let degraded = DegradedRevealView {
        inner: chain.clone(),
        reveal_escrow: sl_escrow_op,
        bad_sig,
    };

    // SH counterparty: completes the Phase-A exchange, then goes PERMANENTLY
    // silent -- it never broadcasts Comp->SH, so no genuine reveal ever
    // appears; the only "reveal" SL ever sees is the degraded view's lie.
    let sh_params = params.clone();
    let sh_handle = std::thread::spawn(move || -> Result<()> {
        let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + delta_late)?;
        let _receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
        let (t, _) = AdaptorSecret::generate()?;
        let peer = PeerSession::new([0xEAu8; 32], Box::new(io_sh));
        let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
        let _possessing = funded.run_adaptor_exchange(ExchangeInputs {
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
        Ok(()) // dies without ever broadcasting its completion
    });

    let (mut engine, actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(actions.is_empty());

    let ctx = make_ctx(
        sl.sk, sh.pk, sl_escrow_op, sh_escrow_op, escrow_amt, msg_sh, msg_sl, sl_refund, None,
        root_sh, root_sl, ok_sh, ok_sl, lease_sl.path().to_path_buf(),
        possession_store.path().to_path_buf(), sl_receipt, sl_pre,
    );
    let peer = PeerSession::new([0xEAu8; 32], Box::new(io_sl));
    let mut app = SwapApp::begin(&engine, ctx, peer, base + 500, 0).unwrap();

    // Drive to settlement through the DEGRADED view. The crossing poll blocks
    // in the Phase-A rendezvous with the SH thread; the first settlement step
    // then observes the mangled witness and must re-drive -- 77018f5's bound.
    let mut reached_awaiting = false;
    for _ in 0..12 {
        match app.poll(&mut engine, &degraded).unwrap() {
            AppTick::BroadcastSetup => {
                chain.broadcast(&sl_setup).expect("idempotent re-broadcast");
                app.setup_broadcast(&engine, &sl_setup).unwrap();
            }
            AppTick::Wait => {}
            AppTick::AwaitingReveal => {
                reached_awaiting = true;
                break;
            }
            other => panic!("unexpected tick under the eternal lie: {other:?}"),
        }
    }
    assert!(reached_awaiting, "the mangled witness must surface as AwaitingReveal");
    sh_handle.join().unwrap().expect("SH exchange half");
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::Released,
        "SL is post-G1 (possession persisted), awaiting a reveal that never validates"
    );

    // (1) The re-drive is STABLE: more polls under the unchanged lie stay
    // AwaitingReveal -- never a poison, never a false terminal.
    for _ in 0..3 {
        assert_eq!(app.poll(&mut engine, &degraded).unwrap(), AppTick::AwaitingReveal);
    }
    // Pre-maturity the backstop has nothing to do (escrow unspent, immature).
    assert_eq!(
        app.backstop_tick(&engine, &degraded, false, false).unwrap(),
        BackstopTick::Idle
    );

    // (2) THE BOUND: at CSV maturity the dead-device tower fires the
    // pre-armed refund -- the lie cannot delay it (authoritative reads).
    while chain.tip_height() < maturity {
        chain.mine();
    }
    assert_eq!(
        app.poll(&mut engine, &degraded).unwrap(),
        AppTick::AwaitingReveal,
        "the app loop itself never falsely refunds -- the tower owns the exit"
    );
    match app.backstop_tick(&engine, &degraded, false, false).unwrap() {
        BackstopTick::FiredRefund => {}
        other => panic!("the tower must fire the refund at CSV maturity, got {other:?}"),
    }
    chain.mine(); // the refund confirms
    assert!(matches!(chain.spend_status(sl_escrow_op), SpendStatus::Confirmed(_)));

    // (3) Terminal reconciliation UNDER THE LYING VIEW — recovery first, on
    // the still-`Released` record: reenter_released observes the mangled
    // witness and must fall back to the (now confirmed) refund decision.
    // Before the restore_and_extract fallback fix, this Err-POISONED the
    // whole recovery scan — recover() itself failed, forever.
    let scan = SwapApp::recover(&engine, &degraded).unwrap();
    assert!(scan.unreadable.is_empty() && scan.failed.is_empty());
    let ticks = scan.ticks;
    assert_eq!(ticks.len(), 1);
    assert!(
        matches!(
            ticks[0].1,
            RecoveryTick::Extract { final_sig: None, fallback: AbortAction::Refunded }
        ),
        "a mangled witness must fall back to the (confirmed) refund decision, got {:?}",
        ticks[0].1
    );

    // (4) THE APP'S OWN TERMINAL (settle-phase refund reconciliation): the
    // next poll discriminates the confirmed spender — it IS our pre-armed
    // refund — terminates as Refunding, and advances the record
    // Released → AbortRefund → Refunded through the engine. No store
    // surgery, no rebuilt context: the composed loop closes its own swap.
    match app.poll(&mut engine, &degraded).unwrap() {
        AppTick::Refunding(reason) => {
            assert!(reason.contains("refund confirmed"), "got {reason:?}")
        }
        other => panic!("a confirmed own-refund must terminate the app, got {other:?}"),
    }
    assert!(app.is_terminal());
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::Refunded,
        "forward-or-refund closed: the eternally-mangled reveal ended in Refunded"
    );
    // The terminal is cached — re-polls under the unchanged lie stay put.
    assert!(matches!(app.poll(&mut engine, &degraded).unwrap(), AppTick::Refunding(_)));

    // (5) A post-terminal recovery scan re-validates the Refunded record
    // against the chain and reports it at rest — still under the lying view.
    let ticks = SwapApp::recover(&engine, &degraded).unwrap().ticks;
    assert!(matches!(ticks[0].1, RecoveryTick::Settled), "got {:?}", ticks[0].1);
}

// ============================================================================
// TASK B: SwapApp::startup — steps 2+3 of the canonical sequence in one call.
// ============================================================================

/// `SwapApp::startup` composes the chain-aware phantom heal and the recovery
/// scan in the documented order over a freshly opened engine: the funding-coin
/// phantom (leased to a record-less swap, its Setup confirmed on chain — the
/// chain-blind `open` re-exposes it as `Unspent`) is swept BEFORE the scan
/// runs, and the scan re-enters the surviving recoverable swap (a `Funding`
/// record whose escrow is confirmed → the standing refund is surfaced) — one
/// call, both reports.
#[test]
fn swap_app_startup_heals_phantoms_then_recovers() {
    let params = Params::testnet_provisional();
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let base = 750_000u32;
    let wallet_dir = tempfile::tempdir().unwrap();

    // The PHANTOM: a pre-encumbrance coin leased to a swap that never wrote a
    // record, whose real Setup then CONFIRMED on chain.
    let phantom_pre = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0xB1u8; 32]);
    let (p1, p2) = (keypair(), keypair());
    let internal_p = canonical_internal_key(p1.pk, p2.pk).unwrap();
    let e_phantom = Escrow::new(&internal_p, &p1.pk, params.delta_early).unwrap();
    let chain = SimChain::new(base);
    let (phantom_setup, _phantom_escrow) =
        build_real_setup(&chain, &params, phantom_pre, base, &e_phantom, &p1.sk);
    chain.broadcast(&phantom_setup).unwrap();
    chain.mine();
    assert!(matches!(chain.spend_status(phantom_pre), SpendStatus::Confirmed(_)));

    // The RECOVERABLE swap: a `Funding` record whose escrow is confirmed on
    // chain (its standing pre-armed refund must surface in the scan).
    let (q1, q2) = (keypair(), keypair());
    let internal_q = canonical_internal_key(q1.pk, q2.pk).unwrap();
    let e_ours = Escrow::new(&internal_q, &q1.pk, params.delta_early).unwrap();
    let (rec_setup, rec_escrow_op) = build_real_setup(
        &chain, &params, OutPoint::new(txid_from(0xC2), 0), base, &e_ours, &q1.sk,
    );
    chain.broadcast(&rec_setup).unwrap();
    chain.mine();
    let dest = e_ours.funding_script_pubkey().clone();
    let funded_at = chain.funding_height(rec_escrow_op).unwrap();
    let rec_refund =
        PreArmedRefund::arm(&e_ours, rec_escrow_op, escrow_amt, &q1.sk, dest, d, params.anchor_sats, funded_at)
            .unwrap();

    // STEP 1: chain-blind open — the orphaned lease releases (the phantom is
    // now `Unspent`, on-chain-spent); then persist the recoverable record.
    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert_eq!(engine.ledger().find(&phantom_pre).unwrap().state, CoinState::Unspent);
    let rec_sid = [0x5Bu8; 32];
    engine
        .store()
        .put(&SwapRecord {
            swap_session_id: rec_sid,
            role: Role::SecretHolder,
            phase: SwapPhase::Funding,
            params: params.clone(),
            s_height: 0,
            sweep_escrow_height: 0,
            our_escrow_outpoint: Some(rec_escrow_op),
            their_escrow_outpoint: Some(OutPoint::new(txid_from(0xC3), 0)),
            pre_armed_refund: Some(rec_refund),
            completion_tx: None,
            setup_tx: None,
            possession_record: None,
        })
        .unwrap();

    // STEPS 2+3 in ONE call.
    let (reconcile, scan) = SwapApp::startup(&mut engine, &chain).unwrap();
    let reconcile = reconcile.expect("reconcile succeeds on a writable ledger");

    // Step 2 healed the phantom (swept by the lease pass, permanently Spent).
    assert_eq!(reconcile.leases.swept, vec![phantom_pre]);
    assert!(reconcile.reserves_swept.is_empty());
    assert_eq!(engine.ledger().find(&phantom_pre).unwrap().state, CoinState::Spent);

    // Step 3 re-entered the recoverable swap: funded escrow → the standing
    // pre-armed refund is surfaced (immature → Wait decision).
    assert!(scan.unreadable.is_empty() && scan.failed.is_empty());
    let ticks = scan.ticks;
    assert_eq!(ticks.len(), 1);
    assert_eq!(ticks[0].0, rec_sid);
    assert!(
        matches!(ticks[0].1, RecoveryTick::Funding { refund: Some(_) }),
        "the funded Funding record must surface its refund, got {:?}",
        ticks[0].1
    );
}

// ============================================================================
// TASK E: scan robustness — live_lessees folds unreadable records; startup
// decouples the scan from the reconcile persist.
// ============================================================================

/// Task E (MEDIUM): an UNREADABLE record (a transient read fault — here a
/// `<sid>.swap` that became a directory, so `fs::read` fails and `open` routes
/// it to `Unreadable`, not quarantine) must be treated as LIVE by
/// `live_lessees`, so `SwapEngine::open`'s chain-blind lease reconcile does NOT
/// release a live in-flight swap's funding-coin lease. Dropping it would let a
/// later swap re-select the coin and double-spend the in-flight Setup. The sid
/// is recovered from the filename; the lease survives.
#[test]
fn unreadable_record_keeps_its_funding_lease_across_open() {
    let dir = tempfile::tempdir().unwrap();
    let params = Params::testnet_provisional();
    let sid_a = [0xA5u8; 32];

    // A pre-encumbrance coin leased to live swap A (its ledger is persisted).
    let coin = onboard_one_coin(dir.path(), params.pre_encumbrance_sats(), sid_a);

    // A's live Funding record, written BEFORE any engine open, so the lease is
    // held by a real live swap rather than an orphan.
    {
        let (store, _) =
            swapkey::wallet::store::SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
        store
            .put(&SwapRecord {
                swap_session_id: sid_a,
                role: Role::SecretHolder,
                phase: SwapPhase::Funding,
                params: params.clone(),
                s_height: 0,
                sweep_escrow_height: 0,
                our_escrow_outpoint: None,
                their_escrow_outpoint: None,
                pre_armed_refund: None,
                completion_tx: None,
                setup_tx: None,
                possession_record: None,
            })
            .unwrap();
    }

    // Transient read fault on A's record: replace the `.swap` file with a
    // directory so `fs::read` fails (Unreadable, not quarantine).
    let swap_file = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().map(|x| x == "swap").unwrap_or(false))
        .expect("A's .swap record file");
    std::fs::remove_file(&swap_file).unwrap();
    std::fs::create_dir(&swap_file).unwrap();

    // Reopen: the chain-blind reconcile must KEEP A's lease (unreadable = live).
    let (engine, _) = SwapEngine::open(
        dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let c = engine.ledger().find(&coin).expect("coin still tracked");
    assert_eq!(
        c.state,
        CoinState::Leased,
        "an unreadable record's funding lease must be preserved, not released"
    );
    assert_eq!(c.lessee, Some(sid_a));
}

/// Task E (MEDIUM): `SwapApp::startup` must SURFACE the recovery scan even when
/// the reconcile ledger-persist fails (disk full / locked ledger). Recovery
/// reads only the store + chain, so a swap at a hard CSV refund deadline still
/// gets its `BroadcastRefund` tick — the reconcile failure is returned
/// alongside the scan, never allowed to suppress it.
#[test]
fn startup_surfaces_the_scan_even_when_reconcile_persist_fails() {
    let dir = tempfile::tempdir().unwrap();
    let params = Params::testnet_provisional();
    // Create a ledger (its orphan lease releases harmlessly at open).
    onboard_one_coin(dir.path(), params.pre_encumbrance_sats(), [0x01u8; 32]);

    // A mature, funded AbortRefund swap whose standing refund must be driven.
    let (a, b) = (keypair(), keypair());
    let internal = canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let our_op = OutPoint::new(txid_from(0xE7), 0);
    let s_height = 700_000u32;
    let refund = PreArmedRefund::arm(
        &escrow,
        our_op,
        params.escrow_amount_sats(),
        &a.sk,
        dest,
        params.tier_d_sats,
        params.anchor_sats,
        s_height,
    )
    .unwrap();
    let chain = SimChain::new(refund.csv_maturity_height());
    chain.fund(our_op, s_height);

    let (mut engine, _) = SwapEngine::open(
        dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    let sid = [0xE9u8; 32];
    let mut rec = SwapRecord {
        swap_session_id: sid,
        role: Role::SecretHolder,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height: 0,
        sweep_escrow_height: 0,
        our_escrow_outpoint: Some(our_op),
        their_escrow_outpoint: Some(OutPoint::new(txid_from(0xEA), 0)),
        pre_armed_refund: Some(refund),
        completion_tx: None,
        setup_tx: None,
        possession_record: None,
    };
    for phase in [SwapPhase::Funding, SwapPhase::AbortRefund] {
        rec.phase = phase;
        engine.store().put(&rec).unwrap();
    }

    // Block the ledger persist: a DIRECTORY at the tmp path makes File::create
    // fail, so reconcile_with_chain's unconditional persist returns Err.
    std::fs::create_dir(dir.path().join("ledger.bin.tmp")).unwrap();

    let (reconcile, scan) = SwapApp::startup(&mut engine, &chain).unwrap();
    assert!(reconcile.is_err(), "the reconcile ledger persist must have failed");
    // The scan STILL ran despite the reconcile Err: the funded, matured refund
    // is surfaced (a hard CSV deadline must not be blocked by a ledger write).
    assert_eq!(scan.ticks.len(), 1);
    assert_eq!(scan.ticks[0].0, sid);
    assert!(
        matches!(scan.ticks[0].1, RecoveryTick::Refund(AbortAction::BroadcastRefund)),
        "a reconcile write failure must not suppress a hard-deadline refund tick, got {:?}",
        scan.ticks[0].1
    );
}
