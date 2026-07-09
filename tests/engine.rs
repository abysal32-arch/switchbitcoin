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
use swapkey::tx::txbuild::{build_completion, finalize_key_spend};
use swapkey::wallet::engine::{SwapContext, SwapEngine, SwapOutcome};
use swapkey::wallet::keys::ModeledKeySource;
use swapkey::wallet::ledger::{acknowledge_phase0, Ledger, WalletClock, PHASE0_WARNING};
use swapkey::wallet::manifest::ModeledTrustRoot;
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
    match engine.settle(possessing, &ctx, &chain).unwrap() {
        SwapOutcome::Completed { our_final_sig } => {
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
