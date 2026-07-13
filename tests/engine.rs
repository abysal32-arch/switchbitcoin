//! Swap engine full-stack integration (wallet rank 7): a COMPLETE two-party
//! swap driven through the `SwapEngine`, which composes every rank —
//! SwapStore + Ledger + ManifestStore + the settlement exchange + the claim
//! scheduler — into one persisted lifecycle. The SL side runs entirely through
//! the engine; the SH side is a raw settlement thread (as the other
//! integration tests use). Proves the parts actually compose, not just pass in
//! isolation.

use bitcoin::OutPoint;
use swapkey::chain::{ChainView, SimChain, SpendStatus};
use swapkey::crypto::adaptor::AdaptorSecret;
use swapkey::crypto::ValidatedPoint;
use swapkey::settlement::params::Params;
use swapkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use swapkey::settlement::state_machine::{
    swap_session_id, ExchangeInputs, Funding, PeerSession, Role, Transport,
};
use swapkey::tx::escrow::Escrow;
use swapkey::tx::txbuild::{build_completion, finalize_key_spend, sign_schnorr_single};
use swapkey::wallet::driver::{DriveStatus, SwapDriver};
use swapkey::wallet::engine::{ChainReconcile, SwapContext, SwapEngine, SwapOutcome};
use swapkey::wallet::keys::ModeledKeySource;
use swapkey::wallet::ledger::{acknowledge_phase0, CoinState, Ledger, WalletClock, PHASE0_WARNING};
use swapkey::wallet::manifest::{ClaimDelayPosture, ModeledTrustRoot};
use swapkey::wallet::store::{ModeledEnclave, SwapPhase};
use swapkey::{Error, Result};
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
/// ledger, and return its outpoint (the swap's funding coin). `pre_enc` is the
/// FULL pre-encumbrance amount (D + Δ_fee) the ledger splits into and the Setup
/// tx consumes — NOT the escrow amount (which is pre_enc − setup_cost).
fn onboard_one_coin(dir: &std::path::Path, pre_enc: u64, lessee: [u8; 32]) -> OutPoint {
    // Create the ledger (onboarding) then release it so the engine can reopen.
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
    // Lease the (now-mature) coin far in the future so both delay anchors pass.
    let coin = ledger
        .lease_pre_encumbrance(pre_enc, &FixedClock(u64::MAX), u32::MAX, lessee)
        .unwrap()
        .expect("a mature pre-encumbrance coin");
    coin.outpoint
}

#[test]
fn full_swap_driven_through_the_engine() {
    let params = Params::testnet_provisional();
    let unit = params.escrow_amount_sats(); // the ESCROW amount (scheme (a))
    let d = params.tier_d_sats;
    let s_height = 700_000u32;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let sh = keypair();
    let sl = keypair();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap(); // E_sl
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).unwrap(); // E_sh
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // E_sl — SL funded, SH sweeps
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // E_sh — SH funded, SL sweeps

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, unit, dest.clone(), d, params.anchor_sats).unwrap();
    let comp_sl_spend = build_completion(&escrow_comp_sl, op_comp_sl, unit, dest, d, params.anchor_sats).unwrap();
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

    // Onboard SL's funding coin, then open the engine (reopens the ledger +
    // the swap store + the manifest store, and reconciles leases).
    let funding_coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid);
    let (mut engine, actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(actions.is_empty(), "fresh wallet has no recovery actions");

    // SL's REAL pre-armed refund of its own escrow (E_sl, early leaf).
    let dest2 = escrow_comp_sh.funding_script_pubkey().clone();
    let sl_refund =
        PreArmedRefund::arm(&escrow_comp_sh, op_comp_sh, unit, &sl.sk, dest2, d, params.anchor_sats, s_height).unwrap();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // SH runs the exchange raw + broadcasts Comp→SH to the mempool.
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

    // SL side, ENTIRELY through the engine.
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
    // The Funding record exists.
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::Funding
    );

    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .unwrap();
    let mut ctx = make_ctx(
        sl.sk, sh.pk, op_comp_sh, op_comp_sl, unit, msg_sh, msg_sl, sl_refund, None,
        root_sh, root_sl, ok_sh, ok_sl, lease_sl.path().to_path_buf(),
        possession_store.path().to_path_buf(), sl_receipt, funding_coin,
    );

    // Phase A: run the exchange through the engine (concurrent with SH).
    let possessing = engine.run_exchange(funded, &mut ctx, &chain).unwrap();
    // Persisted to Released (G1 post-release).
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Released);

    // SH has broadcast Comp->SH by the time it joins.
    sh_handle.join().unwrap().expect("SH side");
    assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::InMempool));

    // Phase B: settle through the engine — observe the reveal (mempool-first),
    // extract, schedule the posture-bounded claim, persist Completing→Completed,
    // mark the funding coin spent.
    match engine.settle(&possessing, &ctx, &chain).unwrap() {
        SwapOutcome::Completed { our_final_sig, .. } => {
            // The completed SL claim is a valid key-path spend of E_sh.
            let comp_sl_final = finalize_key_spend(comp_sl_spend, our_final_sig);
            chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
            chain.mine();
            assert!(matches!(chain.spend_status(op_comp_sl), SpendStatus::Confirmed(_)));
        }
        other => panic!("expected Completed, got {other:?}"),
    }

    // The full lifecycle persisted, and the ledger reconciled.
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Completed);
    let coin = engine
        .ledger()
        .find(&funding_coin)
        .expect("funding coin tracked");
    assert_eq!(
        coin.state,
        swapkey::wallet::ledger::CoinState::Spent,
        "the engine marked the funding coin spent"
    );
}

/// Drive an SL settle through the engine with the claim posture forced to
/// `Aggressive` (min band 12), but with the reveal arranged LATE — the SimChain
/// mined to `s_height + reveal_offset` before settle — so the runtime ceiling
/// clamp (anchored to the SWEPT escrow's height `s_height`) bites BELOW the
/// aggressive minimum. Returns `(delay_blocks, broadcast_at_height, ceiling,
/// sweep_escrow_height)`. Mirrors `full_swap_driven_through_the_engine`.
fn settle_sl_with_late_reveal(reveal_offset: u32) -> (u32, u32, u64, u32) {
    let params = Params::testnet_provisional();
    let unit = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let s_height = 700_000u32;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let sh = keypair();
    let sl = keypair();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap(); // E_sl
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).unwrap(); // E_sh
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // E_sl — SL funded, SH sweeps
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // E_sh — SH funded, SL sweeps

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, unit, dest.clone(), d, params.anchor_sats).unwrap();
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

    let funding_coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid);
    let (mut engine, _actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    // Force the Aggressive posture: a NON-clamped schedule samples >= 12, so a
    // sub-12 result PROVES the ceiling clamp bit.
    engine.set_claim_posture(Some(ClaimDelayPosture::Aggressive));

    let dest2 = escrow_comp_sh.funding_script_pubkey().clone();
    let sl_refund =
        PreArmedRefund::arm(&escrow_comp_sh, op_comp_sh, unit, &sl.sk, dest2, d, params.anchor_sats, s_height).unwrap();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

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

    // Record funding (throwaway ctx) then run the exchange over the real ctx.
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
    sh_handle.join().unwrap().expect("SH side");
    assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::InMempool));

    // Arrange the reveal LATE: the tip at settle IS the reveal height, and it
    // drives the ceiling.
    while chain.tip_height() < s_height + reveal_offset {
        chain.mine();
    }
    let reveal_height = chain.tip_height();
    // The ceiling the engine will apply: anchored to the SWEPT escrow's height
    // (= s_height under funded_manual), not S.
    let ceiling = params.max_claim_delay(s_height, reveal_height);

    let hold = match engine.settle(&possessing, &ctx, &chain).unwrap() {
        SwapOutcome::Completed { claim_hold, .. } => {
            claim_hold.expect("a fresh SL settle must surface a claim hold")
        }
        other => panic!("expected Completed, got {other:?}"),
    };
    (hold.delay_blocks, hold.broadcast_at_height, ceiling, s_height)
}

/// Task 13 — the runtime ceiling clamp BINDS: with the posture forced to
/// `Aggressive` (min band 12) but the reveal arranged LATE, the sampled delay
/// is clamped DOWN below 12 (and to 0 at the boundary), so the held claim still
/// confirms strictly before the swept escrow's late refund matures.
#[test]
fn sl_claim_hold_is_clamped_below_the_posture_by_a_late_reveal() {
    let params = Params::testnet_provisional();
    let delta_late = params.delta_late();
    let allowance = params.claim_confirm_allowance as u64;

    // reveal = s_height + 204 ⇒ ceiling = 216 − 6 − 1 − 204 = 5 (< aggressive min 12).
    let (delay, broadcast_at, ceiling, sweep_h) = settle_sl_with_late_reveal(204);
    assert!(
        ceiling < 12,
        "the fixture must drive the ceiling below the aggressive minimum, got {ceiling}"
    );
    assert!(
        delay as u64 <= ceiling,
        "Aggressive (min 12) must be CLAMPED DOWN to the ceiling {ceiling}, got delay {delay}"
    );
    // broadcast_at <= (sweep_h + delta_late - allowance - 1); the strict `<`
    // form is the clippy-clean equivalent of that adversary-proof budget end.
    assert!(
        (broadcast_at as u64) < sweep_h as u64 + delta_late - allowance,
        "broadcast_at {broadcast_at} exceeds the adversary-proof budget end {}",
        sweep_h as u64 + delta_late - allowance - 1
    );

    // The tight boundary: reveal = s_height + 209 ⇒ ceiling == 0 ⇒ delay 0 ⇒
    // claim IMMEDIATELY (the runner broadcasts the same tick).
    let (delay0, broadcast_at0, ceiling0, sweep_h0) = settle_sl_with_late_reveal(209);
    assert_eq!(ceiling0, 0, "reveal at the budget end must give a zero ceiling");
    assert_eq!(delay0, 0, "a zero ceiling must clamp the delay to 0 (claim immediately)");
    assert_eq!(
        broadcast_at0,
        sweep_h0 + 209,
        "with delay 0 the broadcast height must equal the (late) reveal height"
    );
}

/// The engine's crash recovery: a swap left mid-`Signing` by a crash is routed
/// to ABORT_REFUND on the next `open` (INV-2), and its orphaned coin lease is
/// reconciled back to spendable — all composed through the engine.
#[test]
fn engine_open_recovers_a_crashed_signing_swap() {
    let params = Params::testnet_provisional();
    let unit = params.escrow_amount_sats(); // the ESCROW amount (scheme (a))
    let d = params.tier_d_sats;
    let s_height = 500_000u32;
    let wallet_dir = tempfile::tempdir().unwrap();

    let sh = keypair();
    let sl = keypair();
    // The engine derives the id from the keys — the test must key on the same.
    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let op = OutPoint::new(txid_from(7), 0);
    let dest = escrow.funding_script_pubkey().clone();
    let refund = PreArmedRefund::arm(&escrow, op, unit, &sl.sk, dest, d, params.anchor_sats, s_height).unwrap();
    let poss = tempfile::tempdir().unwrap();
    let poss_path = poss.path().join(format!("{}.possession", hex(&sid)));

    // Onboard + lease a coin to this swap, then leave a Signing record (crash).
    let funding_coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid);

    {
        let (engine, _) = SwapEngine::open(
            wallet_dir.path(),
            &ModeledEnclave,
            Box::new(ModeledKeySource::new(&ModeledEnclave)),
            &ModeledTrustRoot,
        )
        .unwrap();
        // Funding → Signing (SL, possession pointer registered), then "crash".
        let ctx = make_ctx(
            sl.sk, sh.pk, op, OutPoint::new(txid_from(8), 0), unit, [1u8; 32], [2u8; 32],
            refund.clone(), None, escrow.merkle_root(), escrow.merkle_root(),
            escrow.output_key_xonly(), escrow.output_key_xonly(), poss.path().to_path_buf(),
            poss.path().to_path_buf(),
            confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap(), funding_coin,
        );
        engine.record_funding(&ctx, Role::SecretLearner, params.clone()).unwrap();
        // Manually advance to Signing with the possession pointer (mirrors what
        // run_exchange persists before the exchange), then drop = crash.
        let mut rec = engine.store().get(&sid).unwrap().unwrap();
        rec.phase = SwapPhase::Signing;
        rec.s_height = s_height;
        rec.sweep_escrow_height = s_height;
        rec.possession_record = Some(poss_path.clone());
        engine.store().put(&rec).unwrap();
    }

    // Reopen: INV-2 routes the crashed Signing swap to AbortRefund (no
    // possession record was written, so nothing was released), and the
    // orphaned lease is reconciled back.
    let (engine, actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(
        actions.iter().any(|a| matches!(
            a,
            swapkey::wallet::store::RecoveryAction::AbortedLiveSigning { .. }
        )),
        "a crashed Signing swap must be routed to AbortRefund on open: {actions:?}"
    );
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::AbortRefund);
    // The coin leased to the now-aborted swap is reconciled to spendable — but
    // this swap is still "live" (AbortRefund isn't terminal), so its lease is
    // kept for the refund path. The reconcile releases only truly-orphaned
    // leases (swaps with no record at all).
    let coin = engine.ledger().find(&funding_coin).unwrap();
    assert!(
        matches!(
            coin.state,
            swapkey::wallet::ledger::CoinState::Leased | swapkey::wallet::ledger::CoinState::Unspent
        ),
        "coin state after recovery: {:?}",
        coin.state
    );
}

/// The SAME complete two-party swap as `full_swap_driven_through_the_engine`,
/// but the SL side runs end-to-end through the `SwapDriver` composition layer
/// (start → poll* → Completed) instead of hand-sequencing record_funding →
/// run_exchange → settle. Proves the driver composes the engine spine into one
/// re-enterable API that honours the engine boundary (returns our_final_sig;
/// the caller does the chain-layer finalize+broadcast) and the forward-or-refund
/// invariant (AwaitingReveal is a re-drive, never a terminal).
#[test]
fn full_swap_driven_through_the_swap_driver() {
    let params = Params::testnet_provisional();
    let unit = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let s_height = 700_000u32;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let sh = keypair();
    let sl = keypair();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap(); // E_sl
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).unwrap(); // E_sh
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // E_sl — SL funded, SH sweeps
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // E_sh — SH funded, SL sweeps

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    // Fund the SWEPT escrow (E_sh) WITH its real spk so the engine's CSV-binding
    // guard can read it — and confirm the guard PASSES an honest delta_late
    // escrow (no false abort; the swap still completes below).
    chain.fund_with_spk(
        op_comp_sl,
        s_height,
        unit,
        escrow_comp_sl.funding_script_pubkey().clone(),
    );

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, unit, dest.clone(), d, params.anchor_sats).unwrap();
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

    let funding_coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid);
    let (mut engine, actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(actions.is_empty(), "fresh wallet has no recovery actions");

    let dest2 = escrow_comp_sh.funding_script_pubkey().clone();
    let sl_refund =
        PreArmedRefund::arm(&escrow_comp_sh, op_comp_sh, unit, &sl.sk, dest2, d, params.anchor_sats, s_height).unwrap();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // SH counterparty as a raw settlement thread (a separate node in production).
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

    // SL side, driven ENTIRELY through the SwapDriver.
    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, op_comp_sh, op_comp_sl, unit, msg_sh, msg_sl, sl_refund, None,
        root_sh, root_sl, ok_sh, ok_sl, lease_sl.path().to_path_buf(),
        possession_store.path().to_path_buf(), sl_receipt, funding_coin,
    );

    // Scope the driver so its &mut engine borrow is released before the
    // post-run assertions read the store/ledger.
    let our_final_sig = {
        let mut driver =
            SwapDriver::start(&mut engine, Role::SecretLearner, funded, ctx, &chain).unwrap();

        // SH finishes the interlocked exchange and broadcasts Comp->SH (the
        // reveal); capture its sig so we can re-broadcast below.
        let sh_sig = sh_handle.join().unwrap().expect("SH side");
        assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::InMempool));

        // Regression (review Bug A): the SL reveal peek and settle's own
        // re-observe are two NON-ATOMIC ChainView reads. Evict the reveal to
        // force the "seen, then gone" case at poll granularity — the driver must
        // stay re-drivable (AwaitingReveal), NOT poison. This holds only because
        // settle now BORROWS the Possessing instead of consuming it.
        chain.evict(op_comp_sh);
        assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::Unspent));
        assert_eq!(driver.poll(&chain).unwrap(), DriveStatus::AwaitingReveal);

        // Reveal reappears → the SAME retained driver drives to the terminal.
        chain
            .broadcast(&finalize_key_spend(comp_sh_spend, sh_sig))
            .expect("re-broadcast Comp->SH");
        assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::InMempool));
        let mut sig = None;
        for _ in 0..4 {
            match driver.poll(&chain).unwrap() {
                DriveStatus::Completed { our_final_sig, .. } => {
                    sig = Some(our_final_sig);
                    break;
                }
                DriveStatus::AwaitingReveal => continue,
                DriveStatus::Refunding(r) => panic!("unexpected refund: {r}"),
            }
        }
        sig.expect("driver settled SL's leg to Completed")
    };

    // Engine boundary: the caller finalizes + broadcasts OUR completion tx.
    let comp_sl_final = finalize_key_spend(comp_sl_spend, our_final_sig);
    chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
    chain.mine();
    assert!(matches!(chain.spend_status(op_comp_sl), SpendStatus::Confirmed(_)));

    // The full lifecycle persisted through the driver, and the ledger reconciled.
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Completed);
    let coin = engine
        .ledger()
        .find(&funding_coin)
        .expect("funding coin tracked");
    assert_eq!(
        coin.state,
        swapkey::wallet::ledger::CoinState::Spent,
        "the driver's run_exchange marked the funding coin spent"
    );
}

/// Task 2 (mangled-reveal Err routing): on the SL settle path, a degraded/lying
/// single source can surface a witness that FAILS extraction (here a valid
/// BIP340 signature unrelated to the adaptor). `schedule_claim`'s extraction Err
/// must NOT propagate out of `settle` as a hard poll error the caller has to
/// special-case, and must NOT be a refund — it re-drives as `AwaitingReveal`
/// (the `Possessing` is retained), exactly like an evicted reveal. When a VALID
/// reveal then appears, the SAME retained driver completes the swap.
#[test]
fn sl_settle_reroutes_a_mangled_reveal_to_awaiting_reveal() {
    let params = Params::testnet_provisional();
    let unit = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let s_height = 700_000u32;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let sh = keypair();
    let sl = keypair();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap(); // E_sl
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).unwrap(); // E_sh
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // E_sl — SL funded, SH sweeps
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // E_sh — SH funded, SL sweeps

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund_with_spk(
        op_comp_sl,
        s_height,
        unit,
        escrow_comp_sl.funding_script_pubkey().clone(),
    );

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, unit, dest.clone(), d, params.anchor_sats).unwrap();
    let comp_sl_spend =
        build_completion(&escrow_comp_sl, op_comp_sl, unit, dest, d, params.anchor_sats).unwrap();
    let msg_sh = comp_sh_spend.sighash;
    let msg_sl = comp_sl_spend.sighash;
    let root_sh = escrow_comp_sh.merkle_root();
    let root_sl = escrow_comp_sl.merkle_root();
    let ok_sh = escrow_comp_sh.output_key_xonly();
    let ok_sl = escrow_comp_sl.output_key_xonly();

    let swap_id = [0xEBu8; 32];
    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let lease_sh = tempfile::tempdir().unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    let funding_coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid);
    let (mut engine, actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(actions.is_empty(), "fresh wallet has no recovery actions");

    let dest2 = escrow_comp_sh.funding_script_pubkey().clone();
    let sl_refund =
        PreArmedRefund::arm(&escrow_comp_sh, op_comp_sh, unit, &sl.sk, dest2, d, params.anchor_sats, s_height).unwrap();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // SH counterparty thread: completes and broadcasts the REAL Comp->SH reveal.
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

    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, op_comp_sh, op_comp_sl, unit, msg_sh, msg_sl, sl_refund, None,
        root_sh, root_sl, ok_sh, ok_sl, lease_sl.path().to_path_buf(),
        possession_store.path().to_path_buf(), sl_receipt, funding_coin,
    );

    let our_final_sig = {
        let mut driver =
            SwapDriver::start(&mut engine, Role::SecretLearner, funded, ctx, &chain).unwrap();

        let sh_sig = sh_handle.join().unwrap().expect("SH side");
        assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::InMempool));

        // EVICT the honest reveal and replace it with a BAD-witness spend of the
        // same escrow: a valid BIP340 signature (over an unrelated message) that
        // observe_reveal happily surfaces but extract_and_complete_claim rejects
        // (t*G != T). This models a degraded/lying single source.
        chain.evict(op_comp_sh);
        let bad_sig = sign_schnorr_single(sl.sk.serialize(), msg_sl).unwrap();
        chain
            .broadcast(&finalize_key_spend(comp_sh_spend.clone(), bad_sig))
            .expect("bad reveal to mempool");
        assert!(matches!(chain.spend_status(op_comp_sh), SpendStatus::InMempool));

        // The mangled reveal must re-drive, NOT hard-error and NOT refund.
        assert_eq!(
            driver.poll(&chain).unwrap(),
            DriveStatus::AwaitingReveal,
            "a witness that fails extraction must re-drive as AwaitingReveal"
        );
        // Still re-drivable on a repeat poll (the bad witness persists) — never
        // a poison / terminal.
        assert_eq!(driver.poll(&chain).unwrap(), DriveStatus::AwaitingReveal);

        // The VALID reveal reappears (SH re-broadcast / a second source agrees):
        // the SAME retained driver drives to Completed.
        chain.evict(op_comp_sh);
        chain
            .broadcast(&finalize_key_spend(comp_sh_spend, sh_sig))
            .expect("re-broadcast the valid Comp->SH");
        let mut sig = None;
        for _ in 0..4 {
            match driver.poll(&chain).unwrap() {
                DriveStatus::Completed { our_final_sig, .. } => {
                    sig = Some(our_final_sig);
                    break;
                }
                DriveStatus::AwaitingReveal => continue,
                DriveStatus::Refunding(r) => panic!("unexpected refund: {r}"),
            }
        }
        sig.expect("driver settled SL's leg to Completed after a valid reveal")
    };

    // The swap completed through the driver despite the intervening bad reveal.
    let comp_sl_final = finalize_key_spend(comp_sl_spend, our_final_sig);
    chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
    chain.mine();
    assert!(matches!(chain.spend_status(op_comp_sl), SpendStatus::Confirmed(_)));
    assert_eq!(engine.store().get(&sid).unwrap().unwrap().phase, SwapPhase::Completed);
}

/// Regression (review Bug B): a Phase-A exchange failure must surface as
/// `Refunding` ONLY when the engine actually persisted `AbortRefund`. Here the
/// counterparty transport is dead, so `run_adaptor_exchange` fails and
/// `run_exchange` routes to `abort()` → `AbortRefund`; `start` must read that
/// persisted phase (not the bare `Err`) and report `Refunding`.
#[test]
fn swap_driver_reports_refunding_when_phase_a_fails() {
    let params = Params::testnet_provisional();
    let unit = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let s_height = 700_000u32;

    let sh = keypair();
    let sl = keypair();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let escrow_comp_sl =
        Escrow::new(&internal, &sh.pk, u32::try_from(params.delta_late()).unwrap()).unwrap();
    let op_comp_sh = OutPoint::new(txid_from(2), 0);
    let op_comp_sl = OutPoint::new(txid_from(1), 0);

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, unit, dest.clone(), d, params.anchor_sats).unwrap();
    let comp_sl_spend =
        build_completion(&escrow_comp_sl, op_comp_sl, unit, dest, d, params.anchor_sats).unwrap();
    let msg_sh = comp_sh_spend.sighash;
    let msg_sl = comp_sl_spend.sighash;

    let swap_id = [0xE9u8; 32];
    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();

    let funding_coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid);
    let (mut engine, _actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();

    let dest2 = escrow_comp_sh.funding_script_pubkey().clone();
    let sl_refund =
        PreArmedRefund::arm(&escrow_comp_sh, op_comp_sh, unit, &sl.sk, dest2, d, params.anchor_sats, s_height).unwrap();
    let sl_receipt = confirm_watchtower_handoff(&sl_refund, sl_refund.fingerprint()).unwrap();

    // Kill the counterparty transport: with the SH end dropped, SL's interlocked
    // adaptor exchange cannot complete and run_exchange aborts to the refund.
    let (io_sh, io_sl) = duplex();
    drop(io_sh);
    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk, op_comp_sh, op_comp_sl, unit, msg_sh, msg_sl, sl_refund, None,
        escrow_comp_sh.merkle_root(), escrow_comp_sl.merkle_root(),
        escrow_comp_sh.output_key_xonly(), escrow_comp_sl.output_key_xonly(),
        lease_sl.path().to_path_buf(), possession_store.path().to_path_buf(),
        sl_receipt, funding_coin,
    );

    let mut driver =
        SwapDriver::start(&mut engine, Role::SecretLearner, funded, ctx, &chain).unwrap();
    assert!(
        matches!(driver.poll(&chain).unwrap(), DriveStatus::Refunding(_)),
        "a Phase-A failure that persisted AbortRefund must surface as Refunding"
    );
    drop(driver);

    // The engine persisted the refund exit — the pre-armed refund is the sink.
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::AbortRefund
    );
}

/// The manifest-params bookend (row 98 residual): `record_funding` must reject
/// any params VALUE that diverges from the signed, version-gated manifest
/// BEFORE persisting. A fresh wallet's manifest store falls back to the
/// compiled-in provisional manifest, whose params == `testnet_provisional()`,
/// so a mutated clone is off-manifest and must be refused with nothing written.
#[test]
fn record_funding_rejects_params_off_manifest() {
    let params = Params::testnet_provisional();
    let wallet_dir = tempfile::tempdir().unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let funding_coin =
        onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), [0x5Au8; 32]);
    let (engine, actions) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(actions.is_empty(), "fresh wallet has no recovery actions");

    let sl = keypair();
    let sh = keypair();
    // The guard fires before the ctx is read, so a cheap-but-well-typed ctx is
    // enough: a raw-bytes pre-armed refund + its watchtower receipt (same
    // lightweight constructors the SH settlement thread uses above).
    let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], 700_010).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
    let ctx = make_ctx(
        sl.sk, sh.pk,
        OutPoint::new(txid_from(2), 0), OutPoint::new(txid_from(1), 0),
        params.escrow_amount_sats(), [0u8; 32], [0u8; 32],
        refund, None, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],
        lease.path().to_path_buf(), possession.path().to_path_buf(),
        receipt, funding_coin,
    );

    // A params value one satoshi off the signed manifest must be rejected...
    let off_manifest = {
        let mut p = params.clone();
        p.tier_d_sats += 1;
        p
    };
    let rejected = engine.record_funding(&ctx, Role::SecretLearner, off_manifest);
    assert!(
        matches!(rejected, Err(Error::Validation(_))),
        "off-manifest params must be rejected, got {rejected:?}"
    );

    // ...and rejected BEFORE the store put: nothing was persisted for this swap.
    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    assert!(
        engine.store().get(&sid).unwrap().is_none(),
        "a rejected record_funding must not persist a SwapRecord"
    );

    // Sanity: the exact manifest params ARE accepted (same ctx, correct value).
    engine
        .record_funding(&ctx, Role::SecretLearner, params)
        .expect("manifest-matching params must be accepted");
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::Funding
    );
}

/// A minimal v3 spend of `outpoint` to a standard P2TR, so a funding coin's
/// outpoint can be marked confirmed-spent on the sim.
fn spend_std(outpoint: OutPoint, out: u64) -> Vec<u8> {
    use bitcoin::{
        absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
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

/// Task 3 end-to-end: the funding-coin phantom, healed through the engine. A
/// pre-encumbrance coin leased to a swap whose Setup CONFIRMED on chain (the coin
/// is spent into its escrow) but which then aborted pre-funding leaves the coin
/// `Leased`; `open`'s chain-BLIND reconcile releases the orphan lease back to
/// `Unspent` — a phantom, because the coin is genuinely spent. The post-open
/// `engine.reconcile_leases_with_chain` marks it `Spent`, so it is never
/// re-selected for a lease and rejected at submit forever.
#[test]
fn engine_reconcile_leases_with_chain_heals_a_funding_coin_phantom() {
    use swapkey::wallet::ledger::CoinState;
    let params = Params::testnet_provisional();
    let base = 500_000u32;
    let wallet_dir = tempfile::tempdir().unwrap();
    let sid = [0x7Au8; 32];
    let funding_coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid);

    // The Setup confirmed on chain: the funding coin is spent into its escrow.
    let chain = SimChain::new(base);
    chain.fund_with_amount(funding_coin, base, params.pre_encumbrance_sats());
    chain
        .broadcast(&spend_std(funding_coin, params.pre_encumbrance_sats() - 500))
        .unwrap();
    chain.mine();
    assert!(matches!(chain.spend_status(funding_coin), SpendStatus::Confirmed(_)));

    // open's chain-blind reconcile releases the orphan lease (no record for sid)
    // back to Unspent — the phantom (the coin is actually spent on chain).
    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert_eq!(
        engine.ledger().find(&funding_coin).unwrap().state,
        CoinState::Unspent,
        "the chain-blind reconcile re-exposes the spent coin as a phantom"
    );

    // The chain-aware reconcile heals it to Spent.
    let out = engine.reconcile_leases_with_chain(&chain).unwrap();
    assert_eq!(out.swept, vec![funding_coin], "the phantom is swept");
    assert_eq!(engine.ledger().find(&funding_coin).unwrap().state, CoinState::Spent);

    // Never re-selected for a lease again (the pool is not silently poisoned).
    assert!(
        engine
            .ledger_mut()
            .lease_pre_encumbrance(params.pre_encumbrance_sats(), &FixedClock(u64::MAX), u32::MAX, sid)
            .unwrap()
            .is_none(),
        "a swept phantom must never be leasable again"
    );
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
    watchtower_receipt: swapkey::settlement::refund::WatchtowerReceipt,
    funding_coin: OutPoint,
) -> SwapContext {
    SwapContext {
        our_seckey,
        their_pubkey: ValidatedPoint::from_bytes(&their_pk.serialize()).unwrap(),
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

fn hex(id: &[u8; 32]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// THEFT-PREVENTION regression (deep-audit UNBLOCKED path — role<->CSV binding):
/// a malicious counterparty funds the escrow SL sweeps (E_sh) with the WRONG,
/// SHORTER refund CSV (delta_early instead of delta_late), which — absent this
/// guard — would let it refund E_sh out from under SL's miscalibrated claim
/// window while also taking E_sl (both sides). The engine's CSV-binding guard
/// reconstructs the role-correct escrow spk (delta_late for SL), sees the
/// on-chain spk does NOT match, and REFUSES to release — aborting to the
/// pre-armed refund (Funding -> AbortRefund) before any partial is exchanged.
#[test]
fn wrong_csv_swept_escrow_refuses_to_release_and_refunds() {
    let params = Params::testnet_provisional();
    let unit = params.escrow_amount_sats();
    let s_height = 700_000u32;
    let delta_early = params.delta_early;

    let sh = keypair();
    let sl = keypair();
    let sid = swap_session_id(sl.pk, sh.pk).unwrap();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();

    // E_sl (SL funds, SH sweeps) — honest early leaf; its spk is irrelevant to
    // the SL-side guard (SH sweeps it), so a bare fund is fine.
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // E_sl (our escrow)
    // E_sh (SH funds, SL sweeps) — MALICIOUS: built with delta_early, not
    // delta_late, and funded WITH that wrong-CSV spk so the guard can read it.
    let escrow_evil = Escrow::new(&internal, &sh.pk, delta_early).unwrap();
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // E_sh (swept escrow)

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund_with_spk(
        op_comp_sl,
        s_height,
        unit,
        escrow_evil.funding_script_pubkey().clone(),
    );

    let wallet_dir = tempfile::tempdir().unwrap();
    let lease = tempfile::tempdir().unwrap();
    let possession = tempfile::tempdir().unwrap();
    let funding_coin = onboard_one_coin(wallet_dir.path(), params.pre_encumbrance_sats(), sid);
    let (mut engine, _) = SwapEngine::open(
        wallet_dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();

    // A lightweight but well-typed ctx: the guard reads our_seckey, their_pubkey
    // and their_escrow_op only, and fires before the exchange touches the rest.
    let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + delta_early).unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
    let mut ctx = make_ctx(
        sl.sk, sh.pk, op_comp_sh, op_comp_sl, unit, [0u8; 32], [0u8; 32], refund, None,
        [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], lease.path().to_path_buf(),
        possession.path().to_path_buf(), receipt, funding_coin,
    );

    engine
        .record_funding(&ctx, Role::SecretLearner, params.clone())
        .unwrap();

    let (io_sl, _io_sh) = duplex();
    let peer = PeerSession::new([0xE9u8; 32], Box::new(io_sl));
    let funded = Funding::new(params, peer)
        .funded_manual(Role::SecretLearner, s_height)
        .unwrap();

    // The guard fires: run_exchange refuses and routes to the refund.
    match engine.run_exchange(funded, &mut ctx, &chain) {
        Err(swapkey::Error::Abort(reason)) => {
            assert!(reason.contains("wrong refund CSV"), "got {reason:?}")
        }
        Err(other) => panic!("expected the CSV-mismatch Abort, got {other:?}"),
        Ok(_) => panic!("a wrong-CSV swept escrow must abort before release, got Ok(Possessing)"),
    }
    // The refund exit is armed; nothing was released.
    assert_eq!(
        engine.store().get(&sid).unwrap().unwrap().phase,
        SwapPhase::AbortRefund
    );
}

/// TASK 2 (the composed startup seam): a fresh chain-blind `open` followed by
/// ONE `reconcile_with_chain` call heals BOTH phantom kinds --
///
///   1. the FUNDING-COIN phantom: a pre-encumbrance coin leased to a swap
///      that never wrote a record, whose Setup confirmed on chain; the
///      chain-blind open releases the orphaned lease back to `Unspent`,
///      re-exposing a coin the chain already spent (a later lease would
///      re-select it and fail every submit forever);
///   2. the RESERVE phantom: a CPFP bump child consumed the reserve on chain
///      but the crash lost the ledger persist, so the coin still counts
///      spendable.
///
/// The canonical sequence is open -> reconcile_with_chain -> recover; this
/// pins step 2's composed heal (per-class reports, both coins permanently
/// `Spent`) and its idempotence.
#[test]
fn fresh_open_plus_reconcile_with_chain_heals_both_phantom_kinds() {
    let params = Params::testnet_provisional();
    let pre_enc = params.pre_encumbrance_sats();
    let dir = tempfile::tempdir().unwrap();

    // Onboard: one deposit split into a pre-encumbrance coin + change, the
    // change promoted into the Reserve pool (the 2a provisioning path).
    let (pre_phantom, reserve_phantom, reserve_amt) = {
        let ack = acknowledge_phase0(PHASE0_WARNING).unwrap();
        let mut ledger = Ledger::create(dir.path(), &ModeledEnclave, ack).unwrap();
        let keys = ModeledKeySource::new(&ModeledEnclave);
        let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
        let dep = OutPoint::new(txid_from(0xD1), 0);
        ledger
            .register_deposit(
                dep,
                pre_enc + 80_000 + 2_000,
                100,
                idx,
                &spk,
                &keys,
                Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
            )
            .unwrap();
        let plan = ledger.split_deposit(dep, &params, 2_000, &keys).unwrap();
        ledger.confirm_split(plan.txid, 150, &FixedClock(1_000)).unwrap();
        let change_op = OutPoint::new(plan.txid, plan.change_vout.expect("change output"));
        ledger.promote_change_to_reserve(change_op).unwrap();
        let reserve_amt = ledger.find(&change_op).unwrap().amount_sats;

        // Phantom 1: leased to a swap that never wrote a SwapRecord.
        let coin = ledger
            .lease_pre_encumbrance(pre_enc, &FixedClock(u64::MAX), u32::MAX, [0xCCu8; 32])
            .unwrap()
            .expect("a mature pre-encumbrance coin");
        (coin.outpoint, change_op, reserve_amt)
    }; // ledger dropped -- the single-instance lock releases for the reopen

    // Both phantoms are CONFIRMED SPENT on chain (the Setup / the bump child
    // landed) while the ledger still counts them spendable.
    let chain = SimChain::new(200);
    chain.fund_with_amount(pre_phantom, 200, pre_enc);
    chain.broadcast(&spend_std(pre_phantom, pre_enc - 500)).unwrap();
    chain.fund_with_amount(reserve_phantom, 200, reserve_amt);
    chain.broadcast(&spend_std(reserve_phantom, reserve_amt - 500)).unwrap();
    chain.mine();
    assert!(matches!(chain.spend_status(pre_phantom), SpendStatus::Confirmed(_)));
    assert!(matches!(chain.spend_status(reserve_phantom), SpendStatus::Confirmed(_)));

    // STEP 1 -- fresh chain-blind open: the orphaned lease is released, which
    // RE-EXPOSES the spent pre-encumbrance coin as `Unspent` (the phantom this
    // seam exists to heal); the spent reserve also still reads `Unspent`.
    let (mut engine, actions) = SwapEngine::open(
        dir.path(),
        &ModeledEnclave,
        Box::new(ModeledKeySource::new(&ModeledEnclave)),
        &ModeledTrustRoot,
    )
    .unwrap();
    assert!(actions.is_empty(), "no store records -> no recovery actions");
    assert_eq!(
        engine.ledger().find(&pre_phantom).unwrap().state,
        CoinState::Unspent,
        "the chain-blind open re-exposed the on-chain-spent coin -- the phantom"
    );
    assert_eq!(engine.ledger().find(&reserve_phantom).unwrap().state, CoinState::Unspent);

    // STEP 2 -- the composed chain-aware reconcile heals BOTH in one call,
    // with per-class reports (reserves swept by the Reserve pass, the
    // pre-encumbrance coin by the lease pass).
    let report = engine.reconcile_with_chain(&chain).unwrap();
    assert_eq!(report.reserves_swept, vec![reserve_phantom]);
    assert_eq!(report.leases.swept, vec![pre_phantom]);
    assert!(report.leases.released.is_empty());
    assert_eq!(engine.ledger().find(&pre_phantom).unwrap().state, CoinState::Spent);
    assert_eq!(engine.ledger().find(&reserve_phantom).unwrap().state, CoinState::Spent);

    // Idempotent: a second run over the healed ledger reports nothing.
    let again = engine.reconcile_with_chain(&chain).unwrap();
    assert_eq!(again, ChainReconcile::default());
}
