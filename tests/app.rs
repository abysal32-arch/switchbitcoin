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
use swapkey::wallet::app::{AppTick, SwapApp};
use swapkey::wallet::backstop_driver::BackstopTick;
use swapkey::wallet::engine::{SwapContext, SwapEngine};
use swapkey::wallet::keys::ModeledKeySource;
use swapkey::wallet::ledger::{acknowledge_phase0, BumpTarget, Ledger, WalletClock, PHASE0_WARNING};
use swapkey::wallet::ledger::CoinState;
use swapkey::wallet::manifest::ModeledTrustRoot;
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
                    app.setup_broadcast();
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
                app.setup_broadcast();
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
    app.setup_broadcast();
    chain.fund_with_amount(their_op, base + 1, escrow_amt - 1); // hostile: 1 sat short
    chain.mine();

    match app.poll(&mut engine, &chain).unwrap() {
        AppTick::Refunding(_) => {}
        other => panic!("a funded abort must be Refunding, got {other:?}"),
    }
    assert!(app.is_terminal());

    // The funded abort wrote NO durable record (record_funding only runs at
    // Proceed) — yet forward-or-refund must still hold: backstop_tick guards the
    // funded escrow's dead-device refund via the tower and fires it at CSV
    // maturity, record or no record.
    assert!(engine.store().get(&sid).unwrap().is_none(), "no record before Proceed");
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
        "the record-less funded escrow's refund fires at maturity"
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
        possession_record: None,
    };
    engine.store().put(&rec(SwapPhase::Funding)).unwrap();
    engine.store().put(&rec(SwapPhase::AbortRefund)).unwrap();

    // SwapApp::recover returns the same scan RecoveryDriver::reenter_all does.
    let (via_app, failed_app) = SwapApp::recover(&engine, &chain).unwrap();
    let (via_driver, failed_driver) = RecoveryDriver::reenter_all(engine.store(), &chain).unwrap();
    assert_eq!(via_app, via_driver, "SwapApp::recover must delegate to RecoveryDriver");
    assert_eq!(failed_app, failed_driver);
    assert_eq!(via_app.len(), 1);
    assert_eq!(via_app[0].0, sid);
    assert!(matches!(via_app[0].1, RecoveryTick::Refund(_)));
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
