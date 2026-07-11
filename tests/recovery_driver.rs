//! Crash-recovery re-entry integration (orchestration increment 4): the
//! `RecoveryDriver` re-enters every non-terminal record from the persisted
//! store ALONE (no in-memory context survives the "crash") and drives it to
//! the same continuation a live wallet would — restore-and-extract for a
//! released SL, the completion-supersedes refund decision for an aborting
//! swap, rebroadcast for an in-flight completion, and a safe surface for a
//! funding-phase swap whose transport is gone.

use bitcoin::{OutPoint, Txid};
use swapkey::chain::{ChainView, DualSourceChainView, SimChain, Source, SpendStatus};
use swapkey::crypto::adaptor::AdaptorSecret;
use swapkey::crypto::ValidatedPoint;
use swapkey::settlement::params::Params;
use swapkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund};
use swapkey::settlement::state_machine::{
    swap_session_id, ExchangeInputs, Funding, PeerSession, Role, Transport,
};
use swapkey::tx::escrow::Escrow;
use swapkey::tx::setup::build_setup;
use swapkey::tx::txbuild::{build_completion, finalize_key_spend, SpendTx};
use swapkey::wallet::orchestrator::AbortAction;
use swapkey::wallet::{
    ModeledEnclave, RecoveryAction, RecoveryDriver, RecoveryTick, SwapPhase, SwapRecord, SwapStore,
};
use swapkey::{Error, Result};
use secp::{Point, Scalar};
use std::sync::mpsc;

// ----- fixtures (mirror tests/wallet_store.rs) -------------------------------

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

fn txid_from(seed: u8) -> Txid {
    let mut b = [0u8; 32];
    b[0] = seed;
    Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b))
}

fn hex32(id: &[u8; 32]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Everything a released-SL recovery test needs, driven through the fresh
/// process `open` so the record is `Released` and the store is all that
/// survives. `comp_sh_final` is SH's completion, ready to broadcast (the
/// reveal); `comp_sl_spend` is SL's own claim template the caller finalizes
/// with the recovered signature.
struct ReleasedSwap {
    store: SwapStore,
    sid: [u8; 32],
    chain: SimChain,
    op_comp_sh: OutPoint,
    op_comp_sl: OutPoint,
    comp_sh_final: Vec<u8>,
    comp_sl_spend: SpendTx,
    _dirs: Vec<tempfile::TempDir>,
}

/// Drive crash story 1 (SL dies in the G1 window) up to the fresh-process
/// reopen: the record is `Released` by G1 evidence, both escrows confirmed,
/// SH's completion available but NOT yet on chain.
fn released_swap() -> ReleasedSwap {
    let sh = keypair();
    let sl = keypair();
    let params = Params::testnet_provisional();
    let s_height = 700_000u32;
    let escrow_amount = params.escrow_amount_sats();
    let d = params.tier_d_sats;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(sh.pk, sl.pk).unwrap();
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).expect("E_sl");
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).expect("E_sh");
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // SL-funded (E_sl)
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // SH-funded (E_sh)

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, escrow_amount, dest.clone(), d, params.anchor_sats)
            .unwrap();
    let comp_sl_spend =
        build_completion(&escrow_comp_sl, op_comp_sl, escrow_amount, dest.clone(), d, params.anchor_sats)
            .unwrap();
    let msg_comp_sh = comp_sh_spend.sighash;
    let msg_comp_sl = comp_sl_spend.sighash;
    let root_sh = escrow_comp_sh.merkle_root();
    let root_sl = escrow_comp_sl.merkle_root();
    let outkey_sh = escrow_comp_sh.output_key_xonly();
    let outkey_sl = escrow_comp_sl.output_key_xonly();

    let sl_refund = PreArmedRefund::arm(
        &escrow_comp_sh, op_comp_sh, escrow_amount, &sl.sk, dest.clone(), d, params.anchor_sats,
        s_height,
    )
    .expect("arm SL refund");

    let swap_id = [0x77u8; 32];
    let lease_sh = tempfile::tempdir().unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let possession_store = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    let sid = swap_session_id(sl.pk, sh.pk).expect("sid");
    let (store, actions) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
    assert!(actions.is_empty());
    let mut rec = SwapRecord {
        swap_session_id: sid,
        role: Role::SecretLearner,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height: 0,
        sweep_escrow_height: 0,
        our_escrow_outpoint: Some(op_comp_sh),
        their_escrow_outpoint: Some(op_comp_sl),
        pre_armed_refund: Some(sl_refund.clone()),
        completion_tx: None,
        setup_tx: None,
        possession_record: None,
    };
    store.put(&rec).unwrap();

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    let possession_path = possession_store.path().join(format!("{}.possession", hex32(&sid)));
    rec.phase = SwapPhase::Signing;
    rec.s_height = s_height;
    rec.sweep_escrow_height = s_height;
    rec.possession_record = Some(possession_path.clone());
    store.put(&rec).unwrap();

    let sh_params = params.clone();
    let sh_handle = std::thread::spawn(move || -> Result<Vec<u8>> {
        let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + delta_late)?;
        let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
        let (t_secret, _) = AdaptorSecret::generate()?;
        let peer = PeerSession::new(swap_id, Box::new(io_sh));
        let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
        let possessing = funded.run_adaptor_exchange(ExchangeInputs {
            our_seckey: sh.sk,
            their_pubkey: ValidatedPoint::from_bytes(&sl.pk.serialize())?,
            msg_comp_sh,
            msg_comp_sl,
            pre_armed_refund: refund,
            adaptor_secret: Some(t_secret),
            lease_dir: Some(lease_sh.path().to_path_buf()),
            possession_store: None,
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
            taproot_output_comp_sh: Some(outkey_sh),
            taproot_output_comp_sl: Some(outkey_sl),
        })?;
        let sig = possessing.broadcast_completion(s_height + 10, &receipt)?;
        Ok(finalize_key_spend(comp_sh_spend, sig.0))
    });

    let peer = PeerSession::new(swap_id, Box::new(io_sl));
    let funded = Funding::new(params.clone(), peer)
        .funded_manual(Role::SecretLearner, s_height)
        .expect("funded");
    let sl_possessing = funded
        .run_adaptor_exchange(ExchangeInputs {
            our_seckey: sl.sk,
            their_pubkey: ValidatedPoint::from_bytes(&sh.pk.serialize()).unwrap(),
            msg_comp_sh,
            msg_comp_sl,
            pre_armed_refund: sl_refund,
            adaptor_secret: None,
            lease_dir: Some(lease_sl.path().to_path_buf()),
            possession_store: Some(possession_store.path().to_path_buf()),
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
            taproot_output_comp_sh: Some(outkey_sh),
            taproot_output_comp_sl: Some(outkey_sl),
        })
        .expect("SL exchange");
    assert!(possession_path.exists());
    let comp_sh_final = sh_handle.join().unwrap().expect("SH side");

    // ===== CRASH: SL in-memory state and the store handle die. =====
    drop(sl_possessing);
    drop(store);

    // ===== FRESH PROCESS: the store is all that survives. =====
    let (store, actions) = SwapStore::open(wallet_dir.path(), &ModeledEnclave).unwrap();
    assert_eq!(actions, vec![RecoveryAction::RestoredPostRelease { swap_session_id: sid }]);
    assert_eq!(store.get(&sid).unwrap().unwrap().phase, SwapPhase::Released);

    ReleasedSwap {
        store,
        sid,
        chain,
        op_comp_sh,
        op_comp_sl,
        comp_sh_final,
        comp_sl_spend,
        _dirs: vec![lease_sl, possession_store, wallet_dir],
    }
}

/// Released + the reveal is on chain: recovery restores the possession record,
/// extracts t, persists the finalized claim (`Completing`, rule 3), and hands
/// it back to broadcast. Re-running is idempotent (Rebroadcast), and once the
/// claim confirms the record advances to Completed.
#[test]
fn released_with_reveal_extracts_claims_and_is_idempotent() {
    let s = released_swap();

    // SH's completion (the reveal) lands on SL's escrow.
    s.chain.broadcast(&s.comp_sh_final).expect("Comp->SH accepted");
    s.chain.mine();
    assert!(matches!(s.chain.spend_status(s.op_comp_sh), SpendStatus::Confirmed(_)));

    let rec = s.store.get(&s.sid).unwrap().unwrap();
    let tick = RecoveryDriver::reenter_one(&s.store, &rec, &s.chain).expect("reenter released");
    let final_sig = match tick {
        RecoveryTick::Extract { final_sig: Some(sig), fallback } => {
            assert_eq!(fallback, AbortAction::Wait);
            sig
        }
        other => panic!("expected Extract with a finalized claim, got {other:?}"),
    };
    // Rule 3: the finalized claim is persisted as Completing before broadcast.
    assert_eq!(s.store.get(&s.sid).unwrap().unwrap().phase, SwapPhase::Completing);

    // Idempotent: a second scan (now Completing) surfaces the SAME sig to
    // rebroadcast, not a re-extraction.
    let rec2 = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &rec2, &s.chain).unwrap() {
        RecoveryTick::Rebroadcast { final_sig: sig2, confirmed: false } => assert_eq!(sig2, final_sig),
        other => panic!("expected idempotent Rebroadcast(unconfirmed), got {other:?}"),
    }

    // Broadcast the claim; once our escrow (E_sh) is swept, recovery finalizes.
    let finalized = finalize_key_spend(s.comp_sl_spend, final_sig);
    s.chain.broadcast(&finalized).expect("Comp->SL accepted");
    s.chain.mine();
    assert!(matches!(s.chain.spend_status(s.op_comp_sl), SpendStatus::Confirmed(_)));

    let rec3 = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &rec3, &s.chain).unwrap() {
        RecoveryTick::Rebroadcast { confirmed: true, .. } => {}
        other => panic!("expected Rebroadcast(confirmed) once swept, got {other:?}"),
    }
    assert_eq!(s.store.get(&s.sid).unwrap().unwrap().phase, SwapPhase::Completed);
}

/// Released but SH never completes (no reveal): recovery must NOT strand — it
/// surfaces the `Released -> AbortRefund` fallback on our own escrow. Immature
/// => Wait; matured => BroadcastRefund.
#[test]
fn released_without_reveal_falls_back_to_refund_decision() {
    let s = released_swap();
    let refund_maturity =
        s.store.get(&s.sid).unwrap().unwrap().pre_armed_refund.unwrap().csv_maturity_height();

    let rec = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &rec, &s.chain).unwrap() {
        RecoveryTick::Extract { final_sig: None, fallback: AbortAction::Wait } => {}
        other => panic!("no reveal + immature must Wait, got {other:?}"),
    }

    // Advance past our refund's CSV maturity: the fallback becomes BroadcastRefund.
    while s.chain.tip_height() < refund_maturity {
        s.chain.mine();
    }
    let rec = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &rec, &s.chain).unwrap() {
        RecoveryTick::Extract { final_sig: None, fallback: AbortAction::BroadcastRefund } => {}
        other => panic!("no reveal + matured must offer BroadcastRefund, got {other:?}"),
    }
}

/// The post-release AbortRefund corner (C5 audit finding): an SL that released
/// its enabling partial (possession persisted, G1) and THEN aborted — record
/// at `AbortRefund` — is handed the swap by SH's completion, which spends OUR
/// escrow and reveals t. Recovery must EXECUTE the take-the-swap arm (restore
/// → extract → persist `Completing`, rule 3, via the new `AbortRefund →
/// Completing` edge), not merely signal `Refund(TakeTheSwap)` with no
/// extractor; without a reveal it stays the plain refund decision.
#[test]
fn abort_refund_with_reveal_executes_take_the_swap() {
    let s = released_swap();
    // Post-release abort: the wallet routed the swap to AbortRefund (e.g. the
    // transport died after SL's release). Released -> AbortRefund is legal.
    let mut rec = s.store.get(&s.sid).unwrap().unwrap();
    rec.phase = SwapPhase::AbortRefund;
    s.store.put(&rec).unwrap();

    // No reveal yet: the abort stays a refund decision (immature → Wait) —
    // never a stuck signal, never a premature extraction.
    match RecoveryDriver::reenter_one(&s.store, &s.store.get(&s.sid).unwrap().unwrap(), &s.chain)
        .unwrap()
    {
        RecoveryTick::Refund(AbortAction::Wait) => {}
        other => panic!("no reveal: the abort stays a refund decision, got {other:?}"),
    }

    // SH's completion lands — the reveal spends OUR escrow while we sit in
    // AbortRefund. Completion-supersedes must now EXECUTE.
    s.chain.broadcast(&s.comp_sh_final).expect("Comp->SH accepted");
    s.chain.mine();

    let rec = s.store.get(&s.sid).unwrap().unwrap();
    let final_sig = match RecoveryDriver::reenter_one(&s.store, &rec, &s.chain).unwrap() {
        RecoveryTick::Extract { final_sig: Some(sig), .. } => sig,
        other => panic!("a reveal on an SL AbortRefund must extract, got {other:?}"),
    };
    // Rule 3: the finalized claim is persisted BEFORE broadcast.
    assert_eq!(s.store.get(&s.sid).unwrap().unwrap().phase, SwapPhase::Completing);

    // The recovered signature is a real, broadcastable claim; the record
    // finalizes once our sweep confirms.
    let finalized = finalize_key_spend(s.comp_sl_spend, final_sig);
    s.chain.broadcast(&finalized).expect("Comp->SL accepted");
    s.chain.mine();
    assert!(matches!(s.chain.spend_status(s.op_comp_sl), SpendStatus::Confirmed(_)));
    let rec = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &rec, &s.chain).unwrap() {
        RecoveryTick::Rebroadcast { confirmed: true, .. } => {}
        other => panic!("expected Rebroadcast(confirmed) once swept, got {other:?}"),
    }
    assert_eq!(s.store.get(&s.sid).unwrap().unwrap().phase, SwapPhase::Completed);
}

/// AbortRefund and Funding records need no possession material — recovery
/// routes AbortRefund to the completion-supersedes decision (Wait until CSV
/// maturity, then BroadcastRefund) and surfaces a funded Funding record's
/// standing refund while leaving an unfunded one for a fresh driver. Also
/// exercises `reenter_all` over a mixed store, skipping the terminal record.
#[test]
fn abort_and_funding_records_route_correctly() {
    let params = Params::testnet_provisional();
    let s_height = 800_000u32;
    let chain = SimChain::new(s_height);
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();

    // Build one real escrow + pre-armed refund so refund_txid decodes and the
    // AbortDriver's ours-vs-theirs check has a real txid.
    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let our_escrow = OutPoint::new(txid_from(0x30), 0);
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, params.escrow_amount_sats(), &a.sk, dest, params.tier_d_sats,
        params.anchor_sats, s_height,
    )
    .unwrap();
    chain.fund(our_escrow, s_height); // our escrow is confirmed on chain

    let base = |sid: [u8; 32], phase: SwapPhase, escrow: Option<OutPoint>| SwapRecord {
        swap_session_id: sid,
        role: Role::SecretHolder,
        phase,
        params: params.clone(),
        s_height,
        sweep_escrow_height: s_height,
        our_escrow_outpoint: escrow,
        their_escrow_outpoint: Some(OutPoint::new(txid_from(0x99), 0)),
        pre_armed_refund: escrow.map(|_| refund.clone()),
        completion_tx: None,
        setup_tx: None,
        possession_record: None,
    };

    // (1) AbortRefund, escrow unspent + immature => Wait.
    let sid_abort = [0x11u8; 32];
    let mut r = base(sid_abort, SwapPhase::Funding, Some(our_escrow));
    store.put(&r).unwrap();
    r.phase = SwapPhase::AbortRefund;
    store.put(&r).unwrap();
    match RecoveryDriver::reenter_one(&store, &store.get(&sid_abort).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::Wait) => {}
        other => panic!("immature AbortRefund must Wait, got {other:?}"),
    }

    // (2) Funding, escrow funded => the standing refund surfaces (Wait now).
    let sid_fund = [0x22u8; 32];
    let r = base(sid_fund, SwapPhase::Funding, Some(our_escrow));
    store.put(&r).unwrap();
    match RecoveryDriver::reenter_one(&store, &store.get(&sid_fund).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::Funding { refund: Some(AbortAction::Wait) } => {}
        other => panic!("funded Funding must surface a refund decision, got {other:?}"),
    }

    // (3) Funding, escrow NOT on chain => nothing locked, needs fresh driver.
    let sid_unfunded = [0x33u8; 32];
    let unfunded_escrow = OutPoint::new(txid_from(0x44), 0);
    let r = base(sid_unfunded, SwapPhase::Funding, Some(unfunded_escrow));
    store.put(&r).unwrap();
    match RecoveryDriver::reenter_one(&store, &store.get(&sid_unfunded).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::Funding { refund: None } => {}
        other => panic!("unfunded Funding must surface no refund, got {other:?}"),
    }

    // Advance past maturity: the AbortRefund record now offers BroadcastRefund.
    while chain.tip_height() < refund.csv_maturity_height() {
        chain.mine();
    }
    match RecoveryDriver::reenter_one(&store, &store.get(&sid_abort).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::BroadcastRefund) => {}
        other => panic!("matured AbortRefund must BroadcastRefund, got {other:?}"),
    }

    // reenter_all covers every record and returns one tick each.
    let (ticks, failed) = RecoveryDriver::reenter_all(&store, &chain).unwrap();
    assert!(failed.is_empty());
    assert_eq!(ticks.len(), 3, "three records scanned");
    assert!(ticks.iter().any(|(sid, t)| *sid == sid_abort && matches!(t, RecoveryTick::Refund(_))));
    assert!(ticks.iter().any(|(sid, t)| *sid == sid_unfunded && matches!(t, RecoveryTick::Funding { refund: None })));
}

/// Task 1 (never-confirming-Setup residual): a pre-funding abort whose Setup was
/// broadcast + persisted (store v4 `setup_tx`) but fell out of every mempool and
/// NEVER confirmed leaves an `AbortRefund` whose pre-armed refund spends an
/// escrow outpoint that never came to exist — permanently non-terminal. Recovery
/// must RE-SUBMIT the persisted Setup (idempotent) so the escrow confirms and the
/// ordinary refund path becomes reachable, instead of stranding.
#[test]
fn never_confirming_setup_is_rebroadcast_until_the_escrow_confirms() {
    let params = Params::testnet_provisional();
    let s_height = 640_000u32;
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();

    // A funded pre-encumbrance coin + the REAL signed Setup that spends it into
    // our escrow. The Setup is NOT broadcast here — it "fell out of the mempool".
    let chain = SimChain::new(s_height);
    let pre_op = OutPoint::new(txid_from(0x50), 0);
    chain.fund_with_amount(pre_op, s_height, params.pre_encumbrance_sats());
    let (setup_bytes, our_escrow) = build_setup(
        pre_op,
        params.pre_encumbrance_sats(),
        escrow_amt,
        params.anchor_sats,
        &escrow,
        &a.sk,
    )
    .unwrap();

    // The escrow does not yet exist on chain (the Setup never confirmed).
    assert!(chain.funding_height(our_escrow).is_none());

    let dest = escrow.funding_script_pubkey().clone();
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, escrow_amt, &a.sk, dest, d, params.anchor_sats, s_height,
    )
    .unwrap();

    // Persist the pre-funding abort record carrying the Setup bytes (Funding ->
    // AbortRefund, exactly as SwapApp::terminate_abort advances the early record).
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
    let sid = [0x5au8; 32];
    let mut rec = SwapRecord {
        swap_session_id: sid,
        role: Role::SecretHolder,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height: 0,
        sweep_escrow_height: 0,
        our_escrow_outpoint: Some(our_escrow),
        their_escrow_outpoint: Some(OutPoint::new(txid_from(0x51), 0)),
        pre_armed_refund: Some(refund.clone()),
        completion_tx: None,
        setup_tx: Some(setup_bytes.clone()),
        possession_record: None,
    };
    store.put(&rec).unwrap();
    rec.phase = SwapPhase::AbortRefund;
    store.put(&rec).unwrap();

    // Recovery on the stranded record: the escrow is unconfirmed and the Setup
    // is retained, so re-submit it rather than stranding on an unbroadcastable
    // refund.
    match RecoveryDriver::reenter_one(&store, &store.get(&sid).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::RebroadcastSetup { setup_tx } => {
            assert_eq!(setup_tx, setup_bytes, "recovery hands back the persisted Setup");
            // The caller performs the broadcast (engine boundary).
            chain.broadcast(&setup_tx).expect("the evicted Setup re-enters the mempool");
        }
        other => panic!("a never-confirming Setup must be rebroadcast, got {other:?}"),
    }

    // Mine: the escrow now confirms, so the record is no longer stranded — the
    // ordinary refund decision is reachable (immature => Wait).
    chain.mine();
    assert!(chain.funding_height(our_escrow).is_some(), "the escrow confirmed");
    match RecoveryDriver::reenter_one(&store, &store.get(&sid).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::Wait) => {}
        other => panic!("a confirmed escrow's abort must reach the refund path, got {other:?}"),
    }

    // And once the CSV matures, that refund is broadcastable (the exit exists).
    while chain.tip_height() < refund.csv_maturity_height() {
        chain.mine();
    }
    match RecoveryDriver::reenter_one(&store, &store.get(&sid).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::BroadcastRefund) => {}
        other => panic!("matured refund must be broadcastable now the escrow exists, got {other:?}"),
    }
}

/// Task 1 (review finding 2): the never-confirming-Setup arm also fires from the
/// FUNDING phase — a crash during the ordinary funding wait (before any abort is
/// classified) leaves a Funding record carrying setup_tx over an unconfirmed
/// escrow, which must re-submit the Setup rather than report "nothing locked".
#[test]
fn funding_phase_never_confirming_setup_is_rebroadcast() {
    let params = Params::testnet_provisional();
    let s_height = 645_000u32;
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let chain = SimChain::new(s_height);
    let pre_op = OutPoint::new(txid_from(0x52), 0);
    chain.fund_with_amount(pre_op, s_height, params.pre_encumbrance_sats());
    let (setup_bytes, our_escrow) = build_setup(
        pre_op, params.pre_encumbrance_sats(), escrow_amt, params.anchor_sats, &escrow, &a.sk,
    )
    .unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, escrow_amt, &a.sk, dest, d, params.anchor_sats, s_height,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
    let sid = [0x52u8; 32];
    // Funding phase (NOT advanced to AbortRefund): the ordinary post-Setup crash.
    let rec = SwapRecord {
        swap_session_id: sid,
        role: Role::SecretHolder,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height: 0,
        sweep_escrow_height: 0,
        our_escrow_outpoint: Some(our_escrow),
        their_escrow_outpoint: Some(OutPoint::new(txid_from(0x53), 0)),
        pre_armed_refund: Some(refund.clone()),
        completion_tx: None,
        setup_tx: Some(setup_bytes.clone()),
        possession_record: None,
    };
    store.put(&rec).unwrap();

    // Escrow unconfirmed + Setup retained ⇒ re-submit rather than "nothing locked".
    match RecoveryDriver::reenter_one(&store, &store.get(&sid).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::RebroadcastSetup { setup_tx } => {
            assert_eq!(setup_tx, setup_bytes);
            chain.broadcast(&setup_tx).expect("the evicted Setup re-enters the mempool");
        }
        other => panic!("a funding-phase never-confirming Setup must rebroadcast, got {other:?}"),
    }
    chain.mine();
    // Confirmed now ⇒ the ordinary funded-Funding surface (standing refund).
    match RecoveryDriver::reenter_one(&store, &store.get(&sid).unwrap().unwrap(), &chain).unwrap() {
        RecoveryTick::Funding { refund: Some(AbortAction::Wait) } => {}
        other => panic!("a confirmed funding escrow must surface its refund, got {other:?}"),
    }
}

/// Task 1 (review findings 1 + 3): recovery reads the AUTHORITATIVE confirmation,
/// not the agreement view, for BOTH the rebroadcast arm and the Funding refund
/// gate. A lying untrusted source that HIDES a real confirmation must neither
/// force a needless re-submission nor suppress the standing pre-armed refund; a
/// source that FABRICATES a confirmation it cannot verify must not skip the
/// re-submission.
#[test]
fn recovery_setup_arm_uses_the_authoritative_confirmation_read() {
    let params = Params::testnet_provisional();
    let s_height = 646_000u32;
    let escrow_amt = params.escrow_amount_sats();
    let d = params.tier_d_sats;

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();

    // ---- (i) truth confirms the escrow; the untrusted source HIDES it. ----
    let truth = SimChain::new(s_height);
    let liar = SimChain::new(s_height);
    let pre_op = OutPoint::new(txid_from(0x54), 0);
    truth.fund_with_amount(pre_op, s_height, params.pre_encumbrance_sats());
    let (setup_bytes, our_escrow) = build_setup(
        pre_op, params.pre_encumbrance_sats(), escrow_amt, params.anchor_sats, &escrow, &a.sk,
    )
    .unwrap();
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, escrow_amt, &a.sk, dest.clone(), d, params.anchor_sats, s_height,
    )
    .unwrap();
    let sid = [0x54u8; 32];
    let rec = SwapRecord {
        swap_session_id: sid,
        role: Role::SecretHolder,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height: 0,
        sweep_escrow_height: 0,
        our_escrow_outpoint: Some(our_escrow),
        their_escrow_outpoint: Some(OutPoint::new(txid_from(0x55), 0)),
        pre_armed_refund: Some(refund.clone()),
        completion_tx: None,
        setup_tx: Some(setup_bytes.clone()),
        possession_record: None,
    };
    store.put(&rec).unwrap();

    // The Setup genuinely confirmed on the self-verifying source; the liar never
    // saw it, so the AGREEMENT view disagrees and reads unconfirmed.
    truth.broadcast(&setup_bytes).unwrap();
    truth.mine();
    let hide = DualSourceChainView::new(
        Source::self_verifying(truth.clone()),
        Source::untrusted(liar.clone()),
    )
    .unwrap();
    assert!(hide.funding_height(our_escrow).is_none(), "the agreement view sees the disagreement");
    // Authoritative = confirmed ⇒ surface the refund, do NOT re-submit.
    match RecoveryDriver::reenter_one(&store, &store.get(&sid).unwrap().unwrap(), &hide).unwrap() {
        RecoveryTick::Funding { refund: Some(AbortAction::Wait) } => {}
        other => panic!("a truth-confirmed escrow hidden by a liar must surface the refund, got {other:?}"),
    }

    // ---- (ii) an untrusted source FABRICATES a confirmation truth lacks. ----
    let truth2 = SimChain::new(s_height);
    let liar2 = SimChain::new(s_height);
    let fresh_pre = OutPoint::new(txid_from(0x56), 0);
    let (setup2, our_escrow2) = build_setup(
        fresh_pre, params.pre_encumbrance_sats(), escrow_amt, params.anchor_sats, &escrow, &a.sk,
    )
    .unwrap();
    // Only the liar "confirms" the escrow; the self-verifying source never saw it.
    liar2.fund_with_amount(our_escrow2, s_height, escrow_amt);
    let refund2 = PreArmedRefund::arm(
        &escrow, our_escrow2, escrow_amt, &a.sk, dest, d, params.anchor_sats, s_height,
    )
    .unwrap();
    let sid2 = [0x56u8; 32];
    let rec2 = SwapRecord {
        swap_session_id: sid2,
        role: Role::SecretHolder,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height: 0,
        sweep_escrow_height: 0,
        our_escrow_outpoint: Some(our_escrow2),
        their_escrow_outpoint: Some(OutPoint::new(txid_from(0x57), 0)),
        pre_armed_refund: Some(refund2),
        completion_tx: None,
        setup_tx: Some(setup2.clone()),
        possession_record: None,
    };
    store.put(&rec2).unwrap();
    let fabricate = DualSourceChainView::new(
        Source::self_verifying(truth2),
        Source::untrusted(liar2),
    )
    .unwrap();
    // Authoritative = unconfirmed ⇒ still re-submit (a fabricator cannot skip it).
    match RecoveryDriver::reenter_one(&store, &store.get(&sid2).unwrap().unwrap(), &fabricate).unwrap() {
        RecoveryTick::RebroadcastSetup { setup_tx } => assert_eq!(setup_tx, setup2),
        other => panic!("a fabricated confirmation must not skip re-submission, got {other:?}"),
    }
}

/// A standard P2TR-shaped spk and a minimal v3 spend of `outpoint`, so a swept
/// escrow can be marked confirmed-spent on the sim.
fn std_p2tr_spk() -> bitcoin::ScriptBuf {
    let mut v = vec![0x51u8, 0x20];
    v.extend_from_slice(&[0x66u8; 32]);
    bitcoin::ScriptBuf::from_bytes(v)
}
fn spend_of(outpoint: OutPoint, out_sats: u64) -> Vec<u8> {
    use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    let tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(out_sats), script_pubkey: std_p2tr_spk() }],
    };
    bitcoin::consensus::encode::serialize(&tx)
}

/// Deep-audit gap #2: a terminal `Completed`/`Refunded` record is RE-VALIDATED
/// against the chain, not trusted blindly. When the defining spend is still
/// confirmed the record reads `Settled`; when a reorg reverted it (the spend is
/// no longer confirmed) recovery re-drives — rebroadcast the completion, or
/// re-enter the refund decision — instead of a false `Settled`.
#[test]
fn terminal_records_are_revalidated_against_reorg() {
    let params = Params::testnet_provisional();
    let s_height = 800_000u32;
    let unit = params.escrow_amount_sats();

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let our_escrow = OutPoint::new(txid_from(0x50), 0);
    let their_escrow = OutPoint::new(txid_from(0x51), 0);
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, unit, &a.sk, dest, params.tier_d_sats, params.anchor_sats, s_height,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
    let rec = |phase| SwapRecord {
        swap_session_id: [0x60u8; 32],
        role: Role::SecretHolder,
        phase,
        params: params.clone(),
        s_height,
        sweep_escrow_height: s_height,
        our_escrow_outpoint: Some(our_escrow),
        their_escrow_outpoint: Some(their_escrow),
        pre_armed_refund: Some(refund.clone()),
        completion_tx: Some(vec![0xcdu8; 64]),
        setup_tx: None,
        possession_record: None,
    };

    // --- Completed, swept escrow still CONFIRMED-spent → Settled. ---
    let good = SimChain::new(s_height);
    good.fund(their_escrow, s_height);
    good.broadcast(&spend_of(their_escrow, unit - 500)).unwrap();
    good.mine();
    assert_eq!(
        RecoveryDriver::reenter_one(&store, &rec(SwapPhase::Completed), &good).unwrap(),
        RecoveryTick::Settled
    );

    // --- Completed, but a reorg reverted the completion (swept escrow unspent
    // again) → rebroadcast the persisted completion signature, not Settled. ---
    let reorged = SimChain::new(s_height);
    reorged.fund(their_escrow, s_height); // funded, NOT spent (completion reverted)
    match RecoveryDriver::reenter_one(&store, &rec(SwapPhase::Completed), &reorged).unwrap() {
        RecoveryTick::Rebroadcast { final_sig, confirmed: false } => {
            assert_eq!(final_sig, [0xcdu8; 64])
        }
        other => panic!("a reverted Completed must rebroadcast, got {other:?}"),
    }

    // --- Refunded, our refund still CONFIRMED-spent → Settled. ---
    let good_r = SimChain::new(s_height);
    good_r.fund(our_escrow, s_height);
    good_r.broadcast(&spend_of(our_escrow, unit - 500)).unwrap();
    good_r.mine();
    assert_eq!(
        RecoveryDriver::reenter_one(&store, &rec(SwapPhase::Refunded), &good_r).unwrap(),
        RecoveryTick::Settled
    );

    // --- Refunded, but a reorg reverted the refund (our escrow live again) →
    // re-enter the refund decision (matured + unspent → BroadcastRefund). ---
    let reorged_r = SimChain::new(refund.csv_maturity_height());
    reorged_r.fund(our_escrow, s_height); // funded, unspent
    match RecoveryDriver::reenter_one(&store, &rec(SwapPhase::Refunded), &reorged_r).unwrap() {
        RecoveryTick::Refund(AbortAction::BroadcastRefund) => {}
        other => panic!("a reverted Refunded must re-drive the refund, got {other:?}"),
    }
}
