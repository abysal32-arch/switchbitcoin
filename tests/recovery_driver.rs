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
    let scan = RecoveryDriver::reenter_all(&store, &chain).unwrap();
    assert!(scan.unreadable.is_empty());
    assert!(scan.failed.is_empty());
    let ticks = scan.ticks;
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
    spend_with_witness(outpoint, out_sats, None)
}
/// A minimal v3 spend of `outpoint`; `witness_sig` = `Some(sig)` makes it a
/// key-path-shaped spend (single 64-byte witness element) so the recovery
/// driver's spender attribution can read it, `None` leaves the witness empty
/// (an UNATTRIBUTABLE spend — `spending_witness_sig` reports nothing).
fn spend_with_witness(outpoint: OutPoint, out_sats: u64, witness_sig: Option<[u8; 64]>) -> Vec<u8> {
    use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    let mut witness = Witness::new();
    if let Some(sig) = witness_sig {
        witness.push(sig);
    }
    let tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
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

    // --- Completed, swept escrow still CONFIRMED-spent BY OUR COMPLETION
    // (key-path witness == the persisted signature) → Settled. ---
    let good = SimChain::new(s_height);
    good.fund(their_escrow, s_height);
    good.broadcast(&spend_with_witness(their_escrow, unit - 500, Some([0xcdu8; 64]))).unwrap();
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

    // --- Refunded, our escrow still CONFIRMED-spent BY OUR OWN REFUND (the
    // record's pre-armed refund tx itself — txid attribution) → Settled. ---
    let good_r = SimChain::new(refund.csv_maturity_height());
    good_r.fund(our_escrow, s_height);
    good_r.broadcast(refund.tx_bytes()).expect("mature refund accepted");
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

/// Spend-attribution cluster (Feature-3 audit, HIGH): a confirmed FOREIGN
/// spend of the swept escrow — the counterparty's own refund of the escrow we
/// were sweeping — must never be read as OUR completion. `reenter_completing`
/// must not persist `Completed` (a false "paid" terminal that unguards our own
/// funded escrow forever); it routes `Completing -> AbortRefund` so the
/// standing pre-armed refund on OUR escrow is surfaced, and at CSV maturity
/// the refund is driven.
#[test]
fn completing_foreign_spend_routes_to_abort_not_completed() {
    let params = Params::testnet_provisional();
    let s_height = 800_000u32;
    let unit = params.escrow_amount_sats();

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let our_escrow = OutPoint::new(txid_from(0x70), 0);
    let their_escrow = OutPoint::new(txid_from(0x71), 0);
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, unit, &a.sk, dest, params.tier_d_sats, params.anchor_sats, s_height,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
    let mut rec = SwapRecord {
        swap_session_id: [0x61u8; 32],
        role: Role::SecretHolder,
        phase: SwapPhase::Funding,
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
    // Legal ladder to the phase under test (new records start in Funding).
    for phase in [SwapPhase::Funding, SwapPhase::Signing, SwapPhase::Completing] {
        rec.phase = phase;
        store.put(&rec).unwrap();
    }

    // The counterparty's own (dead-device) refund of the escrow WE sweep
    // confirms: a key-path-shaped witness that is NOT our completion sig.
    let chain = SimChain::new(s_height);
    chain.fund(our_escrow, s_height);
    chain.fund(their_escrow, s_height);
    chain.broadcast(&spend_with_witness(their_escrow, unit - 500, Some([0xabu8; 64]))).unwrap();
    chain.mine();

    let got = store.get(&rec.swap_session_id).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&store, &got, &chain).unwrap() {
        // Our escrow is untouched and the refund immature → Wait, but NEVER a
        // confirmed Rebroadcast and NEVER a Completed terminal.
        RecoveryTick::Refund(AbortAction::Wait) => {}
        other => panic!("foreign swept spend must surface the refund decision, got {other:?}"),
    }
    assert_eq!(
        store.get(&rec.swap_session_id).unwrap().unwrap().phase,
        SwapPhase::AbortRefund,
        "a lost sweep must route Completing -> AbortRefund, not freeze a false Completed"
    );

    // At CSV maturity the AbortRefund re-entry drives the refund broadcast.
    while chain.tip_height() < refund.csv_maturity_height() {
        chain.mine();
    }
    let got = store.get(&rec.swap_session_id).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&store, &got, &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::BroadcastRefund) => {}
        other => panic!("matured refund on our escrow must be driven, got {other:?}"),
    }
}

/// Same cluster, unattributable spend: the view reports the swept escrow's
/// spend as confirmed but cannot report the spending witness. Recovery must
/// stay honestly non-terminal — no `Completed` persist, no guessed `Settled`,
/// and (for a `Completed` record) no refund drive either, since the spend
/// might be OUR OWN completion and refunding on top would take both sides.
#[test]
fn unattributable_swept_spend_stays_nonterminal() {
    let params = Params::testnet_provisional();
    let s_height = 800_000u32;
    let unit = params.escrow_amount_sats();

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let our_escrow = OutPoint::new(txid_from(0x72), 0);
    let their_escrow = OutPoint::new(txid_from(0x73), 0);
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, unit, &a.sk, dest, params.tier_d_sats, params.anchor_sats, s_height,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
    let put_at = |sid: u8, phases: &[SwapPhase]| -> SwapRecord {
        let mut rec = SwapRecord {
            swap_session_id: [sid; 32],
            role: Role::SecretHolder,
            phase: SwapPhase::Funding,
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
        store.put(&rec).unwrap();
        for phase in phases {
            rec.phase = *phase;
            store.put(&rec).unwrap();
        }
        rec
    };

    // Confirmed spend with an EMPTY witness: `spending_witness_sig` = None.
    let chain = SimChain::new(s_height);
    chain.fund(our_escrow, s_height);
    chain.fund(their_escrow, s_height);
    chain.broadcast(&spend_of(their_escrow, unit - 500)).unwrap();
    chain.mine();

    // Completing: keep babysitting, unconfirmed — never advance the record.
    let completing = put_at(0x62, &[SwapPhase::Signing, SwapPhase::Completing]);
    match RecoveryDriver::reenter_one(&store, &completing, &chain).unwrap() {
        RecoveryTick::Rebroadcast { confirmed: false, .. } => {}
        other => panic!("unattributable spend must stay an unconfirmed babysit, got {other:?}"),
    }
    assert_eq!(store.get(&[0x62; 32]).unwrap().unwrap().phase, SwapPhase::Completing);

    // Completed: honestly non-terminal Wait — no Settled, no refund drive.
    let completed =
        put_at(0x63, &[SwapPhase::Signing, SwapPhase::Completing, SwapPhase::Completed]);
    match RecoveryDriver::reenter_one(&store, &completed, &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::Wait) => {}
        other => panic!("unattributable spend must never settle a Completed, got {other:?}"),
    }
    assert_eq!(store.get(&[0x63; 32]).unwrap().unwrap().phase, SwapPhase::Completed);
}

/// Spend-attribution cluster (HIGH, `reenter_completed`): a Completed record
/// whose swept-escrow spend confirms as a provably FOREIGN tx (we lost the
/// race with zero reorg — the completion never made it) must re-enter the
/// abort path so OUR OWN funded escrow is driven to its refund, not read
/// `Settled` forever.
#[test]
fn completed_foreign_spend_reenters_abort() {
    let params = Params::testnet_provisional();
    let s_height = 800_000u32;
    let unit = params.escrow_amount_sats();

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let our_escrow = OutPoint::new(txid_from(0x74), 0);
    let their_escrow = OutPoint::new(txid_from(0x75), 0);
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, unit, &a.sk, dest, params.tier_d_sats, params.anchor_sats, s_height,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
    let mut rec = SwapRecord {
        swap_session_id: [0x64u8; 32],
        role: Role::SecretHolder,
        phase: SwapPhase::Funding,
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
    // Legal ladder to the Completed terminal (new records start in Funding).
    for phase in [
        SwapPhase::Funding,
        SwapPhase::Signing,
        SwapPhase::Completing,
        SwapPhase::Completed,
    ] {
        rec.phase = phase;
        store.put(&rec).unwrap();
    }

    let chain = SimChain::new(s_height);
    chain.fund(our_escrow, s_height);
    chain.fund(their_escrow, s_height);
    chain.broadcast(&spend_with_witness(their_escrow, unit - 500, Some([0xabu8; 64]))).unwrap();
    chain.mine();

    let got = store.get(&rec.swap_session_id).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&store, &got, &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::Wait) => {}
        other => panic!("foreign spend of the swept escrow must not settle, got {other:?}"),
    }
    assert_eq!(
        store.get(&rec.swap_session_id).unwrap().unwrap().phase,
        SwapPhase::AbortRefund,
        "the false 'paid' terminal must be undone (Completed -> AbortRefund)"
    );

    // From AbortRefund the matured refund is driven like any abort.
    while chain.tip_height() < refund.csv_maturity_height() {
        chain.mine();
    }
    let got = store.get(&rec.swap_session_id).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&store, &got, &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::BroadcastRefund) => {}
        other => panic!("matured refund must be driven after the false terminal, got {other:?}"),
    }
}

/// Spend-attribution cluster (HIGH, `reenter_refunded`): a Refunded SL record
/// whose escrow spend is now the COUNTERPARTY'S COMPLETION (a shallow reorg
/// replaced our 1-conf refund with SH's timelock-free completion) must not
/// read `Settled` — t is revealed on chain and the SL holds G1 possession, so
/// recovery EXECUTES take-the-swap (`Refunded -> Completing`, rule 3) and the
/// claim is driven to `Completed`.
#[test]
fn refunded_foreign_completion_executes_take_the_swap() {
    let s = released_swap();

    // The wallet had recorded the refund terminal before the reorg:
    // Released -> AbortRefund -> Refunded (both edges legal).
    let mut rec = s.store.get(&s.sid).unwrap().unwrap();
    rec.phase = SwapPhase::AbortRefund;
    s.store.put(&rec).unwrap();
    rec.phase = SwapPhase::Refunded;
    s.store.put(&rec).unwrap();

    // Post-reorg chain reality: E_sl is spent-confirmed by SH's COMPLETION
    // (key-path reveal), not by our refund.
    s.chain.broadcast(&s.comp_sh_final).expect("Comp->SH accepted");
    s.chain.mine();
    assert!(matches!(s.chain.spend_status(s.op_comp_sh), SpendStatus::Confirmed(_)));

    let got = s.store.get(&s.sid).unwrap().unwrap();
    let final_sig = match RecoveryDriver::reenter_one(&s.store, &got, &s.chain).unwrap() {
        RecoveryTick::Extract { final_sig: Some(sig), .. } => sig,
        other => panic!("a reorged-out refund with t revealed must take the swap, got {other:?}"),
    };
    assert_eq!(
        s.store.get(&s.sid).unwrap().unwrap().phase,
        SwapPhase::Completing,
        "rule 3: the extracted claim is persisted before it is handed back"
    );

    // Drive the claim home: broadcast, confirm, finalize.
    let finalized = finalize_key_spend(s.comp_sl_spend, final_sig);
    s.chain.broadcast(&finalized).expect("Comp->SL accepted");
    s.chain.mine();
    let got = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &got, &s.chain).unwrap() {
        RecoveryTick::Rebroadcast { confirmed: true, .. } => {}
        other => panic!("confirmed claim must finalize, got {other:?}"),
    }
    assert_eq!(s.store.get(&s.sid).unwrap().unwrap().phase, SwapPhase::Completed);
}

/// The lost-race SL shape + flip-flop stability: an SL whose extracted claim
/// (persisted `Completing`) loses E_sh to SH's late refund must (1) never
/// freeze a false `Completed`, (2) route to `AbortRefund` with the loss
/// visible (`Refund(Completed)` — E_sl was swept by SH's completion), and
/// (3) STAY there: the take-the-swap executor must not re-extract a claim
/// whose swept escrow is confirmed-foreign (else the record would flip-flop
/// `AbortRefund <-> Completing` forever).
#[test]
fn completing_sl_lost_race_is_stable_loss_not_false_completed() {
    let s = released_swap();

    // SH's completion lands (the reveal); recovery extracts and persists the
    // claim (Released -> Completing) but the claim is NOT broadcast (crash).
    s.chain.broadcast(&s.comp_sh_final).expect("Comp->SH accepted");
    s.chain.mine();
    let rec = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &rec, &s.chain).unwrap() {
        RecoveryTick::Extract { final_sig: Some(_), .. } => {}
        other => panic!("expected the claim extraction, got {other:?}"),
    }
    assert_eq!(s.store.get(&s.sid).unwrap().unwrap().phase, SwapPhase::Completing);

    // SH's late refund of E_sh confirms first — SL lost the claim race.
    let unit = s.store.get(&s.sid).unwrap().unwrap().params.escrow_amount_sats();
    s.chain
        .broadcast(&spend_with_witness(s.op_comp_sl, unit - 500, Some([0xabu8; 64])))
        .expect("SH's late refund accepted");
    s.chain.mine();

    // (1)+(2): the loss is surfaced, never recorded as success.
    let rec = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &rec, &s.chain).unwrap() {
        RecoveryTick::Refund(AbortAction::Completed) => {}
        other => panic!("lost race must surface as a superseded abort, got {other:?}"),
    }
    assert_eq!(s.store.get(&s.sid).unwrap().unwrap().phase, SwapPhase::AbortRefund);

    // (3): re-scanning is STABLE — the futile claim is not re-extracted.
    let rec = s.store.get(&s.sid).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&s.store, &rec, &s.chain).unwrap() {
        RecoveryTick::Refund(AbortAction::Completed) => {}
        other => panic!("the lost-race decision must be stable, got {other:?}"),
    }
    assert_eq!(
        s.store.get(&s.sid).unwrap().unwrap().phase,
        SwapPhase::AbortRefund,
        "no AbortRefund <-> Completing flip-flop on a confirmed-foreign swept escrow"
    );
}

/// FORWARD-OR-REFUND both-sides guard (adversarial review of Task D): a record
/// at `AbortRefund`/`Refunded` whose SWEPT escrow is confirmed-spent BY OUR OWN
/// completion (witness == the persisted completion sig — reachable when a
/// shallow reorg flips the swept escrow back to our completion after the record
/// was routed to the abort path) must NEVER drive our own escrow's refund: we
/// are already paid on that leg, and refunding E_ours on top takes BOTH sides.
/// The decision is `Completed`, never `BroadcastRefund`.
#[test]
fn abort_never_refunds_when_our_completion_already_swept() {
    let params = Params::testnet_provisional();
    let s_height = 800_000u32;
    let unit = params.escrow_amount_sats();

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let our_escrow = OutPoint::new(txid_from(0xA0), 0);
    let their_escrow = OutPoint::new(txid_from(0xA1), 0);
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, unit, &a.sk, dest, params.tier_d_sats, params.anchor_sats, s_height,
    )
    .unwrap();
    let ours: [u8; 64] = [0xcdu8; 64]; // our persisted completion signature

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
    let mut rec = SwapRecord {
        swap_session_id: [0x91u8; 32],
        role: Role::SecretHolder,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height,
        sweep_escrow_height: s_height,
        our_escrow_outpoint: Some(our_escrow),
        their_escrow_outpoint: Some(their_escrow),
        pre_armed_refund: Some(refund.clone()),
        completion_tx: Some(ours.to_vec()),
        setup_tx: None,
        possession_record: None,
    };
    for phase in [
        SwapPhase::Funding,
        SwapPhase::Signing,
        SwapPhase::Completing,
        SwapPhase::AbortRefund,
    ] {
        rec.phase = phase;
        store.put(&rec).unwrap();
    }

    // Swept escrow confirmed-spent by OUR completion (witness == ours); our own
    // escrow unspent and the refund matured (the state that WOULD BroadcastRefund).
    let chain = SimChain::new(s_height);
    chain.fund(our_escrow, s_height);
    chain.fund(their_escrow, s_height);
    chain.broadcast(&spend_with_witness(their_escrow, unit - 500, Some(ours))).unwrap();
    chain.mine();
    while chain.tip_height() < refund.csv_maturity_height() {
        chain.mine();
    }

    // AbortRefund: Completed, never the both-sides BroadcastRefund.
    let got = store.get(&rec.swap_session_id).unwrap().unwrap();
    assert_eq!(
        RecoveryDriver::reenter_one(&store, &got, &chain).unwrap(),
        RecoveryTick::Refund(AbortAction::Completed),
        "our completion swept the counterparty escrow — refunding our own would take both sides"
    );

    // Same guard at Refunded (record later recorded Refunded; a reorg then left
    // our escrow unspent while our completion still holds the swept escrow).
    rec.phase = SwapPhase::Refunded;
    store.put(&rec).unwrap();
    let got = store.get(&rec.swap_session_id).unwrap().unwrap();
    assert_eq!(
        RecoveryDriver::reenter_one(&store, &got, &chain).unwrap(),
        RecoveryTick::Refund(AbortAction::Completed),
        "Refunded re-validation must not drive a both-sides refund either"
    );
}

/// Task D regression: a Refunded SL record whose OWN pre-armed refund sits in
/// the mempool on E_sl (a script-path witness whose leading element is a
/// 64-byte sig) must NOT be mistaken for the counterparty's reveal. Before the
/// `spend_is_our_refund` guard, `reenter_refunded` ran `restore_and_extract` on
/// it, which Errs on a migrated/pruned possession file and (via the `?` in
/// `reenter_all`) poisoned the whole scan. It must fall through to the honest
/// refund decision (Wait — our own refund is in flight), and the scan stays Ok.
#[test]
fn refunded_sl_own_mempool_refund_is_not_a_reveal() {
    let params = Params::testnet_provisional();
    let s_height = 800_000u32;
    let unit = params.escrow_amount_sats();

    let a = keypair();
    let b = keypair();
    let internal = swapkey::settlement::state_machine::canonical_internal_key(a.pk, b.pk).unwrap();
    let escrow = Escrow::new(&internal, &a.pk, params.delta_early).unwrap();
    let dest = escrow.funding_script_pubkey().clone();
    let our_escrow = OutPoint::new(txid_from(0xB0), 0);
    let their_escrow = OutPoint::new(txid_from(0xB1), 0);
    let refund = PreArmedRefund::arm(
        &escrow, our_escrow, unit, &a.sk, dest, params.tier_d_sats, params.anchor_sats, s_height,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (store, _) = SwapStore::open(dir.path(), &ModeledEnclave).unwrap();
    // A possession pointer whose file is gone (device migration / pruned).
    let bogus = dir.path().join("gone.possession");
    let mut rec = SwapRecord {
        swap_session_id: [0xB2u8; 32],
        role: Role::SecretLearner,
        phase: SwapPhase::Funding,
        params: params.clone(),
        s_height,
        sweep_escrow_height: s_height,
        our_escrow_outpoint: Some(our_escrow),
        their_escrow_outpoint: Some(their_escrow),
        pre_armed_refund: Some(refund.clone()),
        completion_tx: None,
        setup_tx: None,
        possession_record: Some(bogus),
    };
    for phase in [
        SwapPhase::Funding,
        SwapPhase::Signing,
        SwapPhase::AbortRefund,
        SwapPhase::Refunded,
    ] {
        rec.phase = phase;
        store.put(&rec).unwrap();
    }

    // Our own matured refund is broadcast but back in the mempool (its 1-conf
    // reorged out / not yet re-mined). The swept escrow is untouched.
    let chain = SimChain::new(refund.csv_maturity_height());
    chain.fund(our_escrow, s_height);
    chain.fund(their_escrow, s_height);
    chain.broadcast(refund.tx_bytes()).unwrap();
    assert!(matches!(chain.spend_status(our_escrow), SpendStatus::InMempool));

    // reenter_one: the honest in-flight-refund decision, NOT an Err from a
    // spurious restore attempt.
    let got = store.get(&rec.swap_session_id).unwrap().unwrap();
    match RecoveryDriver::reenter_one(&store, &got, &chain).unwrap() {
        RecoveryTick::Refund(AbortAction::Wait) => {}
        other => panic!("our own mempool refund must not trigger extraction, got {other:?}"),
    }

    // And a whole-store scan stays Ok (the record does not poison the scan).
    let scan = RecoveryDriver::reenter_all(&store, &chain).unwrap();
    assert!(scan.unreadable.is_empty());
    assert!(scan.failed.is_empty());
    assert_eq!(scan.ticks.len(), 1);
}

/// Task E (scan robustness, HIGH): one damaged record must NOT poison the whole
/// scan. `reenter_all` isolates each per-record failure into
/// `RecoveryScan::failed` and keeps going, so a lost/corrupt possession file on
/// ONE swap surfaces loudly WITHOUT hiding another swap's deadline (before the
/// fix, the `?` in the scan loop aborted every record at the first Err).
#[test]
fn one_damaged_record_does_not_poison_the_scan() {
    let s = released_swap();
    // Lose the possession file: reenter_released's up-front restore now Errs.
    let poss = s.store.get(&s.sid).unwrap().unwrap().possession_record.unwrap();
    std::fs::remove_file(&poss).unwrap();

    // A second, healthy swap behind it: a pre-funding Funding record (nothing
    // locked — a clean Funding { refund: None } tick).
    let healthy = [0xE1u8; 32];
    s.store
        .put(&SwapRecord {
            swap_session_id: healthy,
            role: Role::SecretHolder,
            phase: SwapPhase::Funding,
            params: Params::testnet_provisional(),
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

    let scan = RecoveryDriver::reenter_all(&s.store, &s.chain).unwrap();
    // The .swap files are readable; only the possession file is gone.
    assert!(scan.unreadable.is_empty());
    // The damaged swap surfaces per-record, loudly — never silently dropped.
    assert!(
        scan.failed.iter().any(|(sid, _)| *sid == s.sid),
        "the damaged record must surface in `failed`, got {:?}",
        scan.failed
    );
    // The healthy swap STILL gets its tick despite the sibling's corruption.
    assert!(
        scan.ticks
            .iter()
            .any(|(sid, t)| *sid == healthy && matches!(t, RecoveryTick::Funding { refund: None })),
        "a sibling's corruption must not hide the healthy swap's tick"
    );
}
