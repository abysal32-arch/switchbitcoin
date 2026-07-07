//! Test-first failure checklist (v3.16 Requirement 7).
//!
//! Each test below is written BEFORE the implementation and maps 1:1 to a
//! failure-path row. They are `#[ignore]` until the scaffold is filled; remove
//! `#[ignore]` as each is implemented. The prototype is not "testnet-validated"
//! until every one of these passes against a real testnet swap.
//!
//! Run:  cargo test            (runs implemented rows; skips ignored)
//!       cargo test -- --ignored   (runs the rest; they fail until implemented)
//!
//! STATUS: all 8 rows are implemented. Rows 2/5/6 exercise the crypto core;
//! rows 1/3/4/7/8 drive a full taproot swap against the in-process `SimChain`
//! (real CSV maturity, no-double-spend, and fee/congestion physics). Note the
//! sim does not run script or verify signatures — real signature validity is
//! proven in `tests/taproot_swap.rs` (bitcoin-side schnorr verify).

use bitcoin::{OutPoint, Txid};
use musig2::KeyAggContext;
use newkey::chain::{ChainView, DualSourceChainView, SimChain, Source, SpendStatus};
use newkey::crypto::adaptor::AdaptorSecret;
use newkey::crypto::{ValidatedFinalSig, ValidatedPoint};
use newkey::settlement::params::Params;
use newkey::settlement::refund::{confirm_watchtower_handoff, PreArmedRefund, Watchtower};
use newkey::settlement::state_machine::{
    ExchangeInputs, Funding, PeerSession, Possessing, Role, Transport,
};
use newkey::signing::{commit_and_reveal, SigningSession, SingleSignerLease};
use newkey::tx::escrow::Escrow;
use newkey::tx::txbuild::{build_completion, finalize_key_spend, SpendTx};
use newkey::wire::parse_message;
use newkey::{Error, Result};
use secp::{Point, Scalar};
use std::sync::mpsc;

fn test_key_ctx() -> (musig2::KeyAggContext, Scalar) {
    let mut rng = rand::rng();
    let sk = Scalar::random(&mut rng);
    let other = Scalar::random(&mut rng);
    let mut keys = [sk * secp::G, other * secp::G];
    keys.sort_by_key(|p| p.serialize());
    (musig2::KeyAggContext::new(keys).expect("valid keys"), sk)
}

// ===== On-chain swap harness (rows 1/3/4/7) ================================

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

fn aggregate_internal(a: Point, b: Point) -> Point {
    let mut keys = [a, b];
    keys.sort_by_key(|p| p.serialize());
    KeyAggContext::new(keys).expect("keys").aggregated_pubkey_untweaked()
}

fn txid_from(seed: u8) -> Txid {
    let mut b = [0u8; 32];
    b[0] = seed;
    Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b))
}

/// Everything a checklist row needs after a full on-chain exchange has run.
struct Swap {
    chain: SimChain,
    params: Params,
    s_height: u32,
    escrow_amount: u64,
    d: u64,
    sh: Party,
    sl: Party,
    /// E_sl — funded by SL, swept by SH via Comp->SH (early refund).
    escrow_comp_sh: Escrow,
    op_comp_sh: OutPoint,
    /// E_sh — funded by SH, swept by SL via Comp->SL (late refund).
    escrow_comp_sl: Escrow,
    op_comp_sl: OutPoint,
    /// SH's finalized Comp->SH, ready to broadcast, and its raw sig.
    comp_sh_final: Vec<u8>,
    comp_sh_sig: [u8; 64],
    /// Comp->SL template (spends E_sh); finalize with SL's claim sig.
    comp_sl_spend: SpendTx,
    sl_possessing: Possessing,
}

/// Fund both escrows and run the full taproot adaptor exchange. Uses
/// `funded_manual` with the known roles; `await_funded`'s role derivation is
/// covered separately.
fn run_onchain_exchange() -> Swap {
    let sh = keypair();
    let sl = keypair();
    let params = Params::testnet_provisional();
    let s_height = 700_000u32;
    let escrow_amount = params.tier_d_sats + params.delta_fee_sats;
    let d = params.tier_d_sats;
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let internal = aggregate_internal(sh.pk, sl.pk);
    let escrow_comp_sh = Escrow::new(&internal, &sl.pk, params.delta_early).expect("E_sl");
    let escrow_comp_sl = Escrow::new(&internal, &sh.pk, delta_late).expect("E_sh");
    let op_comp_sh = OutPoint::new(txid_from(2), 0); // SL-funded
    let op_comp_sl = OutPoint::new(txid_from(1), 0); // SH-funded

    let chain = SimChain::new(s_height);
    chain.fund(op_comp_sh, s_height);
    chain.fund(op_comp_sl, s_height);

    let dest = escrow_comp_sh.funding_script_pubkey().clone();
    let comp_sh_spend =
        build_completion(&escrow_comp_sh, op_comp_sh, escrow_amount, dest.clone(), d).unwrap();
    let comp_sl_spend =
        build_completion(&escrow_comp_sl, op_comp_sl, escrow_amount, dest, d).unwrap();
    let msg_comp_sh = comp_sh_spend.sighash;
    let msg_comp_sl = comp_sl_spend.sighash;
    let root_sh = escrow_comp_sh.merkle_root();
    let root_sl = escrow_comp_sl.merkle_root();
    let outkey_sh = escrow_comp_sh.output_key_xonly();
    let outkey_sl = escrow_comp_sl.output_key_xonly();

    let swap_id = [0x99u8; 32];
    let lease_sh = tempfile::tempdir().unwrap();
    let lease_sl = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (io_sh, io_sl) = duplex();

    let sh_params = params.clone();
    let comp_sh_for_sh = comp_sh_spend.clone();
    let sh_handle = std::thread::spawn(move || -> Result<(Vec<u8>, [u8; 64])> {
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
        let final_tx = finalize_key_spend(comp_sh_for_sh, sig.0);
        Ok((final_tx, sig.0))
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
            pre_armed_refund: PreArmedRefund::from_signed_tx(vec![0xbb; 64], s_height + params.delta_early)
                .unwrap(),
            adaptor_secret: None,
            lease_dir: Some(lease_sl.path().to_path_buf()),
            possession_store: Some(store.path().to_path_buf()),
            taproot_root_comp_sh: Some(root_sh),
            taproot_root_comp_sl: Some(root_sl),
            taproot_output_comp_sh: Some(outkey_sh),
            taproot_output_comp_sl: Some(outkey_sl),
        })
        .expect("SL exchange");

    let (comp_sh_final, comp_sh_sig) = sh_handle.join().unwrap().expect("SH side");

    Swap {
        chain,
        params,
        s_height,
        escrow_amount,
        d,
        sh,
        sl,
        escrow_comp_sh,
        op_comp_sh,
        escrow_comp_sl,
        op_comp_sl,
        comp_sh_final,
        comp_sh_sig,
        comp_sl_spend,
        sl_possessing,
    }
}

fn tx_input_count_and_output_value(tx_bytes: &[u8]) -> (usize, u64) {
    let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(tx_bytes).unwrap();
    (tx.input.len(), tx.output[0].value.to_sat())
}

// ---- 1. Happy path --------------------------------------------------------
#[test]
fn happy_path_full_swap() {
    let swap = run_onchain_exchange();

    // SH broadcasts Comp->SH; it confirms.
    swap.chain.broadcast(&swap.comp_sh_final).expect("Comp->SH accepted");
    swap.chain.mine();
    assert!(matches!(swap.chain.spend_status(swap.op_comp_sh), SpendStatus::Confirmed(_)));

    // SL observes the reveal, extracts t, and completes its own leg.
    let observed = ValidatedFinalSig::from_bytes(&swap.comp_sh_sig).unwrap();
    let plan = swap
        .sl_possessing
        .claim_after_reveal(&observed, swap.chain.tip_height())
        .expect("extract + claim");
    let comp_sl_final = finalize_key_spend(swap.comp_sl_spend.clone(), plan.comp_sl_final.0);
    swap.chain.broadcast(&comp_sl_final).expect("Comp->SL accepted");
    swap.chain.mine();
    assert!(matches!(swap.chain.spend_status(swap.op_comp_sl), SpendStatus::Confirmed(_)));

    // Both completion outputs equal D exactly, and neither has an external
    // (non-escrow) input — each spends exactly the one escrow output.
    let (in_sh, out_sh) = tx_input_count_and_output_value(&swap.comp_sh_final);
    let (in_sl, out_sl) = tx_input_count_and_output_value(&comp_sl_final);
    assert_eq!(in_sh, 1, "Comp->SH has an external input");
    assert_eq!(in_sl, 1, "Comp->SL has an external input");
    assert_eq!(out_sh, swap.d);
    assert_eq!(out_sl, swap.d);

    // The claim delay stays within the safe window (review item #5).
    let reveal = swap.s_height + 1; // Comp->SH confirmed at s+1
    assert!(
        reveal as u64 + plan.delay_blocks as u64 + swap.params.claim_confirm_allowance as u64
            <= swap.s_height as u64 + swap.params.delta_late()
    );
}

// ---- 2. Crash during signing (INV-4: no nonce reuse) ----------------------
// This row proves the RETRY property: after a session ends and a fresh one is
// begun for the same (key, message), the nonce differs — no reuse (INV-4).
// The distinct REAL-CRASH property (Drop skipped => lease stays held => signing
// is refused, INV-3) is proven separately in
// signing::tests::real_crash_leaves_lease_held_and_refuses_signing; here we
// model a GRACEFUL restart (Drop runs, lease released) and check nonce freshness.
#[test]
fn crash_during_signing_never_reuses_nonce() {
    let dir = tempfile::tempdir().expect("tempdir");
    let swap_id = [0x42u8; 32];
    let (ctx, sk) = test_key_ctx();
    let (msg_a, msg_b) = ([1u8; 32], [2u8; 32]);

    // First attempt: sessions live, nonces revealed... then a graceful shutdown
    // (scope exit runs Drop, releasing the lease). INV-2: no session state
    // persists — the signing state lived only in volatile memory.
    let first = {
        let lease = SingleSignerLease::acquire_in(dir.path(), swap_id).expect("lease");
        let mut s1 = SigningSession::begin(lease.clone(), ctx.clone(), sk, msg_a).expect("s1");
        let mut s2 = SigningSession::begin(lease.clone(), ctx.clone(), sk, msg_b).expect("s2");
        let revealed = commit_and_reveal(&mut s1, &mut s2).expect("reveal");
        (revealed.comp_sh.to_bytes(), revealed.comp_sl.to_bytes())
    };

    // No session/nonce state persisted anywhere (lease dir is the only surface).
    let leftovers: Vec<_> = std::fs::read_dir(dir.path()).expect("dir").collect();
    assert!(leftovers.is_empty(), "no session/nonce state may survive a restart");

    // Retry: fresh lease, fresh sessions. INV-4: every nonce differs.
    let lease = SingleSignerLease::acquire_in(dir.path(), swap_id).expect("re-acquire");
    let mut s1 = SigningSession::begin(lease.clone(), ctx.clone(), sk, msg_a).expect("s1 retry");
    let mut s2 = SigningSession::begin(lease.clone(), ctx, sk, msg_b).expect("s2 retry");
    let second = commit_and_reveal(&mut s1, &mut s2).expect("reveal retry");

    assert_ne!(first.0, second.comp_sh.to_bytes(), "comp_sh nonce reused after restart+retry");
    assert_ne!(first.1, second.comp_sl.to_bytes(), "comp_sl nonce reused after restart+retry");
}

// ---- 3. SH offline after broadcast (G2 crash-safety) ----------------------
#[test]
fn sh_offline_after_broadcast_watchtower_covers() {
    // After the exchange, SH's exposure is E_sh (SL sweeps it via Comp->SL).
    // SH arms a watchtower over E_sh and goes offline. If SL never completes,
    // the watchtower fires SH's pre-armed refund once the late CSV matures.
    let swap = run_onchain_exchange();
    let refund = PreArmedRefund::arm(
        &swap.escrow_comp_sl,
        swap.op_comp_sl,
        swap.escrow_amount,
        &swap.sh.sk,
        swap.escrow_comp_sl.funding_script_pubkey().clone(),
        swap.d,
        swap.s_height,
    )
    .expect("arm SH refund of E_sh");
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
    let wt = Watchtower::arm(refund, swap.op_comp_sl, &receipt).expect("watchtower");

    // Before the late refund matures: nothing to do.
    assert!(!wt.poll(&swap.chain).expect("poll"), "fired before maturity");

    // Advance past the late CSV (delta_late); the watchtower fires the refund.
    swap.chain.advance(u32::try_from(swap.params.delta_late()).unwrap());
    assert!(wt.poll(&swap.chain).expect("poll fires"), "did not fire at maturity");
    swap.chain.mine();
    assert!(matches!(swap.chain.spend_status(swap.op_comp_sl), SpendStatus::Confirmed(_)));

    // Completion-supersedes: if SL HAD a completion in flight, the watchtower
    // would stand down instead of racing it (covered in row 4).
}

// ---- 3b. Watchtower must not stand down forever on an EVICTABLE mempool
// completion (dead-owner robustness; regression for a review find) ----------
#[test]
fn watchtower_waits_through_mempool_completion_then_fires_on_eviction() {
    let swap = run_onchain_exchange();
    let refund = PreArmedRefund::arm(
        &swap.escrow_comp_sl,
        swap.op_comp_sl,
        swap.escrow_amount,
        &swap.sh.sk,
        swap.escrow_comp_sl.funding_script_pubkey().clone(),
        swap.d,
        swap.s_height,
    )
    .unwrap();
    let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint()).unwrap();
    let wt = Watchtower::arm(refund, swap.op_comp_sl, &receipt).unwrap();

    // A completion of E_sh sits in the mempool (the sim does not verify sigs, so
    // a placeholder-witnessed key-path spend is enough to occupy the outpoint).
    let pending = finalize_key_spend(swap.comp_sl_spend.clone(), [0u8; 64]);
    swap.chain.broadcast(&pending).expect("completion to mempool");
    swap.chain.advance(u32::try_from(swap.params.delta_late()).unwrap()); // CSV matured

    // Even though the refund's CSV has matured, the watchtower must WAIT (not
    // fire and not stand down) while a completion is pending in the mempool.
    assert!(!wt.poll(&swap.chain).expect("poll waits"), "fired against a pending completion");

    // The completion is evicted (never confirms). Now the watchtower fires.
    swap.chain.evict(swap.op_comp_sl);
    assert!(wt.poll(&swap.chain).expect("poll fires"), "did not fire after eviction");
    swap.chain.mine();
    assert!(matches!(swap.chain.spend_status(swap.op_comp_sl), SpendStatus::Confirmed(_)));
}

// ---- 4. Refund/completion race (completion-supersedes) ---------------------
#[test]
fn refund_completion_race_resolves_deterministically() {
    let swap = run_onchain_exchange();

    // SL holds a pre-armed refund of E_sl (the escrow SH sweeps via Comp->SH).
    let sl_refund = PreArmedRefund::arm(
        &swap.escrow_comp_sh,
        swap.op_comp_sh,
        swap.escrow_amount,
        &swap.sl.sk,
        swap.escrow_comp_sh.funding_script_pubkey().clone(),
        swap.d,
        swap.s_height,
    )
    .expect("arm SL refund of E_sl");

    // SH broadcasts Comp->SH into the mempool (revealing t) but it is not yet
    // mined — this is the race window.
    swap.chain.broadcast(&swap.comp_sh_final).expect("Comp->SH to mempool");
    assert!(matches!(swap.chain.spend_status(swap.op_comp_sh), SpendStatus::InMempool));

    // Even though the early CSV may have matured, SL must NOT refund: the
    // completion is winning. refund::run returns Abort ("take the swap").
    swap.chain.advance(swap.params.delta_early); // early refund now mature by time
    let decision = newkey::settlement::refund::run(&sl_refund, &swap.chain, swap.op_comp_sh);
    assert!(matches!(decision, Err(Error::Abort(_))), "SL refunded against a winning completion");

    // Confirm the completion; the decision is unchanged and no refund exists.
    swap.chain.mine();
    assert!(matches!(swap.chain.spend_status(swap.op_comp_sh), SpendStatus::Confirmed(_)));
    let decision = newkey::settlement::refund::run(&sl_refund, &swap.chain, swap.op_comp_sh);
    assert!(matches!(decision, Err(Error::Abort(_))));

    // Deterministic reconciliation: the escrow is spent by exactly the
    // completion; a late refund broadcast of the same output is rejected (no
    // self-double-spend).
    assert!(swap.chain.broadcast(sl_refund.tx_bytes()).is_err());

    // And SL still gets its coins the correct way — by extracting t.
    let observed = ValidatedFinalSig::from_bytes(&swap.comp_sh_sig).unwrap();
    assert!(swap
        .sl_possessing
        .claim_after_reveal(&observed, swap.chain.tip_height())
        .is_ok());
}

// ---- 5. Claim-delay bound (review item #5) --------------------------------
#[test]
fn claim_delay_never_breaches_safe_window() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    // Valid-by-construction parameter space: delta_buffer in (0, delta_early),
    // allowance in (0, margin + delta_buffer) — matching Params::validate.
    let strategy = (2u32..1000, 1u32..500, 0u32..5_000_000, 0u32..600)
        .prop_flat_map(|(delta_early, margin, s_height, reveal_off)| {
            (
                Just(delta_early),
                Just(margin),
                1u32..delta_early,
                Just(s_height),
                Just(reveal_off),
            )
        })
        .prop_flat_map(|(delta_early, margin, delta_buffer, s_height, reveal_off)| {
            let window = (margin as u64 + delta_buffer as u64).min(u32::MAX as u64) as u32;
            (
                Just(delta_early),
                Just(margin),
                Just(delta_buffer),
                1u32..window.max(2),
                Just(s_height),
                Just(reveal_off),
            )
        });

    let mut runner = TestRunner::new(Config::with_cases(4096));
    runner
        .run(
            &strategy,
            |(delta_early, margin, delta_buffer, allowance, s_height, reveal_off)| {
                let mut p = Params::testnet_provisional();
                p.delta_early = delta_early;
                p.margin = margin;
                p.delta_buffer = delta_buffer;
                p.claim_confirm_allowance = allowance;
                // This property isolates the claim-delay bound; neutralize the
                // unrelated cofunding-skew guard (delta_buffer > cofunding_window)
                // so the generated space is exactly the claim-delay validated space.
                p.cofunding_window = 0;
                // The generated space must be exactly the validated space.
                prop_assert!(p.validate().is_ok(), "generator produced invalid params");

                let reveal = s_height.saturating_add(reveal_off);
                let max_delay = p.max_claim_delay(s_height, reveal);

                // THE BOUND (review item #5): if any delay is granted, even the
                // maximum one still confirms before S + delta_late.
                if max_delay > 0 {
                    prop_assert!(
                        reveal as u64 + max_delay + p.claim_confirm_allowance as u64
                            <= s_height as u64 + p.delta_late(),
                        "max delay {} breaches S + delta_late", max_delay
                    );
                }
                // And the bound is total: no panic for any inputs (incl. reveal
                // beyond the window, where the only correct delay is zero).
                let _ = p.max_claim_delay(u32::MAX, 0);
                let _ = p.max_claim_delay(0, u32::MAX);
                Ok(())
            },
        )
        .expect("claim-delay bound property");
}

// ---- 6. Invalid wire input (validation gate; never panic) -----------------
#[test]
fn invalid_wire_input_is_rejected_not_panicked() {
    // Structured malformed corpus: every tag with truncated, oversized, and
    // corrupt bodies; off-curve points; >= n scalars; unknown tags; empty.
    let mut corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x06],
        vec![0xff; 4],
        vec![0x01],                 // nonces, no body
        vec![0x01; 132],            // nonces, one byte short
        vec![0x02; 40],             // adaptor point, oversized
        vec![0x03; 33],             // partials, short
        vec![0x04; 40],             // enabling, oversized
        vec![0x05; 2],              // destination, short
    ];
    // Off-curve point in a correctly-framed Destination message.
    let mut off_curve = vec![0x05];
    off_curve.extend_from_slice(&{
        let mut b = [0xffu8; 33];
        b[0] = 0x02;
        b
    });
    corpus.push(off_curve);
    // Scalar >= n in a correctly-framed SlEnablingPartial.
    let mut big_scalar = vec![0x04];
    big_scalar.extend_from_slice(&[0xffu8; 32]);
    corpus.push(big_scalar);
    // All-zero "identity" point encoding in AdaptorPoint frame.
    let mut zero_point = vec![0x02];
    zero_point.extend_from_slice(&[0u8; 33]);
    corpus.push(zero_point);

    for sample in &corpus {
        // Must reject — and reaching the assert at all means no panic.
        assert!(parse_message(sample).is_err(), "accepted malformed input: {sample:02x?}");
    }

    // Pseudorandom blast (deterministic seed): total behavior on arbitrary bytes.
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x6e65_776b_6579);
    for _ in 0..50_000 {
        let len = rng.random_range(0..512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        let _ = parse_message(&bytes); // Ok or Err both fine; panic is the bug.
    }
}

// ---- 7. Partial funding / fund-and-run ------------------------------------
#[test]
fn partial_funding_funded_side_reclaims() {
    // Only ONE side funds: SL funds its escrow E_sl; SH never funds E_sh. No
    // adaptor exchange happens (await_funded fails), so no completion can ever
    // exist against E_sl. The funded side reclaims via the CSV refund leaf.
    let sl = keypair();
    let sh = keypair();
    let params = Params::testnet_provisional();
    let s_height = 500_000u32;
    let escrow_amount = params.tier_d_sats + params.delta_fee_sats;

    let internal = aggregate_internal(sh.pk, sl.pk);
    let escrow = Escrow::new(&internal, &sl.pk, params.delta_early).expect("E_sl");
    let op = OutPoint::new(txid_from(2), 0);
    let their_op = OutPoint::new(txid_from(1), 0); // SH's escrow, never funded

    let chain = SimChain::new(s_height);
    chain.fund(op, s_height); // only SL funds

    // await_funded fails: the counterparty escrow is not confirmed.
    let our_pk = ValidatedPoint::from_bytes(&sl.pk.serialize()).unwrap();
    let their_pk = ValidatedPoint::from_bytes(&sh.pk.serialize()).unwrap();
    let peer = PeerSession::new([0x55u8; 32], Box::new(duplex().0));
    let funded =
        Funding::new(params.clone(), peer).await_funded(&chain, op, their_op, &our_pk, &their_pk);
    assert!(matches!(funded, Err(Error::Deadline(_))), "await_funded must fail on partial funding");

    // SL reclaims E_sl via the pre-armed refund once the early CSV matures.
    let refund = PreArmedRefund::arm(
        &escrow,
        op,
        escrow_amount,
        &sl.sk,
        escrow.funding_script_pubkey().clone(),
        params.tier_d_sats,
        s_height,
    )
    .expect("arm SL refund");

    // Before maturity: refund is not yet broadcastable.
    assert!(newkey::settlement::refund::run(&refund, &chain, op).is_err());
    // After the early CSV: no completion exists (Absent), so the refund fires.
    chain.advance(params.delta_early);
    newkey::settlement::refund::run(&refund, &chain, op).expect("refund broadcasts");
    chain.mine();
    assert!(matches!(chain.spend_status(op), SpendStatus::Confirmed(_)));
    // Nothing broadcastable against it: a DIFFERENT tx (e.g. a would-be
    // completion) spending the now-confirmed refund output is rejected.
    let competing = finalize_key_spend(
        build_completion(&escrow, op, escrow_amount, escrow.funding_script_pubkey().clone(), params.tier_d_sats)
            .unwrap(),
        [0u8; 64],
    );
    assert!(chain.broadcast(&competing).is_err(), "a competing spend of the reclaimed escrow was accepted");
}

// ---- 8. Congestion beyond delta_fee ---------------------------------------
#[test]
fn congestion_backstop_behaves() {
    let params = Params::testnet_provisional();
    let sh = keypair();
    let sl = keypair();
    let internal = aggregate_internal(sh.pk, sl.pk);
    let s = 700_000u32;
    let escrow_amount = params.tier_d_sats + params.delta_fee_sats; // funds D + fee margin
    let delta_late = u32::try_from(params.delta_late()).unwrap();

    let chain = SimChain::new(s);
    // A fee spike BEYOND the baked delta_fee margin.
    chain.set_congestion(params.delta_fee_sats + 1);

    // (A) COMPLETION under congestion: the standard completion pays exactly the
    //     baked margin (fee == delta_fee), so it STALLS; an OPT-IN bump (the
    //     user accepts a smaller output to add fee) clears it.
    let escrow_a = Escrow::new(&internal, &sh.pk, delta_late).unwrap();
    let op_a = OutPoint::new(txid_from(1), 0);
    chain.fund_with_amount(op_a, s, escrow_amount);
    let dest_a = escrow_a.funding_script_pubkey().clone();

    let standard = finalize_key_spend(
        build_completion(&escrow_a, op_a, escrow_amount, dest_a.clone(), params.tier_d_sats).unwrap(),
        [0u8; 64],
    );
    assert!(
        matches!(chain.broadcast(&standard), Err(Error::Deadline(_))),
        "a completion paying only the baked margin should stall under congestion"
    );
    let bumped = finalize_key_spend(
        build_completion(&escrow_a, op_a, escrow_amount, dest_a, params.tier_d_sats - 5).unwrap(),
        [0u8; 64],
    );
    chain.broadcast(&bumped).expect("opt-in fee bump clears congestion");
    chain.mine();
    assert!(matches!(chain.spend_status(op_a), SpendStatus::Confirmed(_)));

    // (B) REFUND under the SAME congestion uses a SILENT backstop: it is
    //     pre-armed with a reserve fee that already clears the threshold, so it
    //     needs no interactive bump — the watchtower can fire it unattended.
    let escrow_b = Escrow::new(&internal, &sh.pk, delta_late).unwrap();
    let op_b = OutPoint::new(txid_from(2), 0);
    chain.fund_with_amount(op_b, s, escrow_amount);
    let reserve_output = params.tier_d_sats - 10; // fee = delta_fee + 10 (reserve)
    let refund = PreArmedRefund::arm(
        &escrow_b,
        op_b,
        escrow_amount,
        &sh.sk,
        escrow_b.funding_script_pubkey().clone(),
        reserve_output,
        s,
    )
    .unwrap();
    chain.advance(delta_late); // CSV matured
    newkey::settlement::refund::run(&refund, &chain, op_b)
        .expect("pre-armed refund clears congestion silently via its reserve fee");
    chain.mine();
    assert!(matches!(chain.spend_status(op_b), SpendStatus::Confirmed(_)));
}

// ---- Co-funding-skew race window (regression for the critical review find) -
// SL's claim deadline MUST anchor to the SH-funded escrow's OWN confirmation
// height, not the later co-funding baseline S. Under skew (E_sh confirms before
// E_sl), anchoring to S would authorize a Comp->SL confirmation PAST the height
// at which SH's refund of E_sh matures — a reachable extract-and-race window
// where SH takes both legs. This test funds E_sh strictly earlier than E_sl.
#[test]
fn cofunding_skew_anchors_claim_to_swept_escrow_not_s() {
    let params = Params::testnet_provisional();
    let f_sh = 600_000u32; // SH-funded escrow (SL sweeps it) confirms FIRST
    let f_sl = f_sh + params.cofunding_window; // SL-funded escrow later; max skew
    let chain = SimChain::new(f_sl);
    let op_sh_funded = OutPoint::new(txid_from(1), 0); // E_sh — SL sweeps via Comp->SL
    let op_sl_funded = OutPoint::new(txid_from(2), 0); // E_sl — SH sweeps via Comp->SH
    chain.fund(op_sh_funded, f_sh);
    chain.fund(op_sl_funded, f_sl);

    // The party that funded E_sl (and sweeps E_sh) runs await_funded. The
    // anchoring property is role-independent: sweep_escrow_height is always the
    // COUNTERPARTY escrow's height, so we assert on that, not on the (now
    // hash-derived) role.
    let sl = keypair();
    let sh = keypair();
    let our_pk = ValidatedPoint::from_bytes(&sl.pk.serialize()).unwrap();
    let their_pk = ValidatedPoint::from_bytes(&sh.pk.serialize()).unwrap();
    let funded = Funding::new(params.clone(), PeerSession::new([1u8; 32], Box::new(duplex().0)))
        .await_funded(&chain, op_sl_funded, op_sh_funded, &our_pk, &their_pk)
        .expect("funded");
    assert_eq!(funded.s_height(), f_sl, "S is the later confirmation");
    assert_eq!(funded.sweep_escrow_height(), f_sh, "anchor is the swept escrow's own height");

    // The true on-chain maturity of SH's refund of E_sh (relative to E_sh):
    let true_deadline = f_sh as u64 + params.delta_late();
    let reveal = funded.s_height(); // Comp->SH confirms around when E_sl is funded

    // CORRECT anchor (the swept escrow) keeps SL's worst-case claim within the
    // true deadline.
    let ok_max = params.max_claim_delay(funded.sweep_escrow_height(), reveal);
    assert!(
        reveal as u64 + ok_max + params.claim_confirm_allowance as u64 <= true_deadline,
        "correctly-anchored claim must confirm before SH's E_sh refund matures"
    );
    // The OLD buggy anchor (S) would have over-granted PAST the true deadline —
    // this proves the skew scenario genuinely exposes the bug (regression guard).
    let buggy_max = params.max_claim_delay(funded.s_height(), reveal);
    assert!(
        reveal as u64 + buggy_max + params.claim_confirm_allowance as u64 > true_deadline,
        "skew scenario does not actually exercise the race window"
    );
}

// ---- Taproot funded-key == signed-key guard (unspendable-funds footgun) ----
// A mis-specified merkle root would make both parties sign under a key that is
// not the funded output key — completions that verify against each other but
// are unspendable on-chain. The exchange proves signing-key == funded-output-key
// before producing any partial, so a wrong output key aborts immediately.
#[test]
fn exchange_rejects_wrong_taproot_output_key() {
    let sh = keypair();
    let sl = keypair();
    let params = Params::testnet_provisional();
    let internal = aggregate_internal(sh.pk, sl.pk);
    let escrow_sh = Escrow::new(&internal, &sl.pk, params.delta_early).unwrap();
    let escrow_sl =
        Escrow::new(&internal, &sh.pk, u32::try_from(params.delta_late()).unwrap()).unwrap();
    let mut wrong = escrow_sh.output_key_xonly();
    wrong[0] ^= 0x01; // corrupt the expected Comp->SH output key

    let lease = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    // tweak_ctx runs before any lease/message, so SL aborts without a peer.
    let funded = Funding::new(params, PeerSession::new([1u8; 32], Box::new(duplex().0)))
        .funded_manual(Role::SecretLearner, 100)
        .unwrap();
    let out = funded.run_adaptor_exchange(ExchangeInputs {
        our_seckey: sl.sk,
        their_pubkey: ValidatedPoint::from_bytes(&sh.pk.serialize()).unwrap(),
        msg_comp_sh: [1u8; 32],
        msg_comp_sl: [2u8; 32],
        pre_armed_refund: PreArmedRefund::from_signed_tx(vec![1; 32], 200).unwrap(),
        adaptor_secret: None,
        lease_dir: Some(lease.path().to_path_buf()),
        possession_store: Some(store.path().to_path_buf()),
        taproot_root_comp_sh: Some(escrow_sh.merkle_root()),
        taproot_root_comp_sl: Some(escrow_sl.merkle_root()),
        taproot_output_comp_sh: Some(wrong), // WRONG — must be caught
        taproot_output_comp_sl: Some(escrow_sl.output_key_xonly()),
    });
    assert!(
        matches!(out, Err(Error::Verification(_))),
        "a signing key that does not match the funded output key was not caught"
    );
}

// ---- Concurrent-session interlock: equivocated nonces are caught ----------
// v3.13 requires commit-then-reveal on the wire. If a counterparty reveals
// nonces that do NOT match its earlier commitment (an adaptive-nonce /
// Wagner-Drijvers attempt), the victim MUST abort before signing.
#[test]
fn equivocated_nonce_reveal_is_rejected() {
    use newkey::crypto::ValidatedPubNonce;
    use std::sync::mpsc;

    // A transport that passes the commitment through but SUBSTITUTES a different
    // (still valid) Nonces reveal, so it no longer matches the commitment.
    struct Equivocator {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }
    impl Transport for Equivocator {
        fn send(&mut self, bytes: &[u8]) -> Result<()> {
            self.tx.send(bytes.to_vec()).map_err(|_| Error::Abort("hung up"))
        }
        fn recv(&mut self) -> Result<Vec<u8>> {
            let b = self.rx.recv().map_err(|_| Error::Abort("hung up"))?;
            if b.first() == Some(&0x01) {
                // Replace the counterparty's real Nonces reveal with different
                // valid nonces — the commitment check must then fail.
                let vn = |k: u32| -> ValidatedPubNonce {
                    let s = |x: u32| {
                        let mut z = [0u8; 32];
                        z[28..].copy_from_slice(&x.to_be_bytes());
                        Scalar::from_slice(&z).unwrap()
                    };
                    let mut nb = [0u8; 66];
                    nb[..33].copy_from_slice(&(s(k) * secp::G).serialize());
                    nb[33..].copy_from_slice(&(s(k + 1) * secp::G).serialize());
                    ValidatedPubNonce::from_bytes(&nb).unwrap()
                };
                return Ok(newkey::wire::serialize_message(&newkey::wire::Message::Nonces {
                    comp_sh: vn(101),
                    comp_sl: vn(103),
                }));
            }
            Ok(b)
        }
    }

    let sh = keypair();
    let sl = keypair();
    let params = Params::testnet_provisional();
    let s = 400_000u32;
    let (tx_a, rx_b) = mpsc::channel();
    let (tx_b, rx_a) = mpsc::channel();
    let victim_io = Equivocator { tx: tx_a, rx: rx_a };
    let honest_io = ChannelTransport { tx: tx_b, rx: rx_b };
    let swap_id = [0x3fu8; 32];
    let lease_v = tempfile::tempdir().unwrap();
    let lease_h = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();

    // Honest counterparty (SH) runs in a thread; it will error when the victim aborts.
    let sh_sk = sh.sk;
    let sl_pub = sl.pk;
    let sh_params = params.clone();
    let h = std::thread::spawn(move || {
        let refund = PreArmedRefund::from_signed_tx(vec![1; 32], s + 300).unwrap();
        let (t, _) = AdaptorSecret::generate().unwrap();
        let peer = PeerSession::new(swap_id, Box::new(honest_io));
        let funded =
            Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s).unwrap();
        let _ = funded.run_adaptor_exchange(ExchangeInputs {
            our_seckey: sh_sk,
            their_pubkey: ValidatedPoint::from_bytes(&sl_pub.serialize()).unwrap(),
            msg_comp_sh: [1u8; 32],
            msg_comp_sl: [2u8; 32],
            pre_armed_refund: refund,
            adaptor_secret: Some(t),
            lease_dir: Some(lease_h.path().to_path_buf()),
            possession_store: None,
            taproot_root_comp_sh: None,
            taproot_root_comp_sl: None,
            taproot_output_comp_sh: None,
            taproot_output_comp_sl: None,
        });
    });

    // Victim (SL) receives equivocated nonces and MUST abort with Verification.
    let peer = PeerSession::new(swap_id, Box::new(victim_io));
    let funded = Funding::new(params, peer).funded_manual(Role::SecretLearner, s).unwrap();
    let out = funded.run_adaptor_exchange(ExchangeInputs {
        our_seckey: sl.sk,
        their_pubkey: ValidatedPoint::from_bytes(&sh.pk.serialize()).unwrap(),
        msg_comp_sh: [1u8; 32],
        msg_comp_sl: [2u8; 32],
        pre_armed_refund: PreArmedRefund::from_signed_tx(vec![2; 32], s + 200).unwrap(),
        adaptor_secret: None,
        lease_dir: Some(lease_v.path().to_path_buf()),
        possession_store: Some(store.path().to_path_buf()),
        taproot_root_comp_sh: None,
        taproot_root_comp_sl: None,
        taproot_output_comp_sh: None,
        taproot_output_comp_sl: None,
    });
    assert!(
        matches!(out, Err(Error::Verification(_))),
        "equivocated nonce reveal was not caught by the commit-reveal interlock"
    );
    let _ = h.join();
}

// ---- Self-verifying dual-source chain view defeats an eclipse (v3.13) ------
// Signing never proceeds on unverified state: if a lying explorer fabricates a
// confirmation but the self-verifying source disagrees, await_funded refuses.
#[test]
fn await_funded_refuses_under_eclipse_but_proceeds_on_agreement() {
    let params = Params::testnet_provisional();
    let s = 600_000u32;
    let op_a = OutPoint::new(txid_from(1), 0);
    let op_b = OutPoint::new(txid_from(2), 0);
    let a_party = keypair();
    let b_party = keypair();
    let pk_a = ValidatedPoint::from_bytes(&a_party.pk.serialize()).unwrap();
    let pk_b = ValidatedPoint::from_bytes(&b_party.pk.serialize()).unwrap();

    // Eclipse: the self-verifying source sees the truth (unfunded); a lying
    // explorer claims both escrows confirmed. The gate must refuse.
    let honest = SimChain::new(s);
    let liar = SimChain::new(s);
    liar.fund(op_a, s);
    liar.fund(op_b, s);
    let eclipsed = DualSourceChainView::new(
        Source::new(honest, true),
        Source::new(liar, false),
    )
    .unwrap();
    let out = Funding::new(params.clone(), PeerSession::new([1u8; 32], Box::new(duplex().0)))
        .await_funded(&eclipsed, op_a, op_b, &pk_a, &pk_b);
    assert!(
        matches!(out, Err(Error::Deadline(_))),
        "await_funded must not proceed when a source disagrees (eclipse)"
    );

    // Agreement: both sources back the same (truthful) chain; funding confirms.
    let truth = SimChain::new(s);
    truth.fund(op_a, s);
    truth.fund(op_b, s);
    let agreed = DualSourceChainView::new(
        Source::new(truth.clone(), true),
        Source::new(truth.clone(), false),
    )
    .unwrap();
    let funded = Funding::new(params, PeerSession::new([1u8; 32], Box::new(duplex().0)))
        .await_funded(&agreed, op_a, op_b, &pk_a, &pk_b)
        .expect("agreeing dual-source view must confirm funding");
    assert_eq!(funded.s_height(), s);
}

// ---- await_funded role derivation (v3.14 role_seed = SHA256(...)) ---------
#[test]
fn await_funded_derives_opposite_roles_and_enforces_cofunding_window() {
    let params = Params::testnet_provisional();
    let s = 600_000u32;
    let chain = SimChain::new(s);
    let op_a = OutPoint::new(txid_from(1), 0);
    let op_b = OutPoint::new(txid_from(2), 0);
    chain.fund(op_a, s);
    chain.fund(op_b, s + params.cofunding_window); // within the window

    // Two parties, distinct session pubkeys; each computes the same role_seed
    // and derives OPPOSITE roles (antisymmetric in the canonical pubkey order).
    let a_party = keypair();
    let b_party = keypair();
    let pk_a = ValidatedPoint::from_bytes(&a_party.pk.serialize()).unwrap();
    let pk_b = ValidatedPoint::from_bytes(&b_party.pk.serialize()).unwrap();
    let mk = || Funding::new(params.clone(), PeerSession::new([1u8; 32], Box::new(duplex().0)));

    let a = mk().await_funded(&chain, op_a, op_b, &pk_a, &pk_b).expect("A funded");
    let b = mk().await_funded(&chain, op_b, op_a, &pk_b, &pk_a).expect("B funded");
    assert_ne!(a.role(), b.role(), "the two parties must derive opposite roles");
    // S is the later confirmation.
    assert_eq!(a.s_height(), s + params.cofunding_window);

    // Outside the co-funding window: abandon.
    let chain2 = SimChain::new(s);
    chain2.fund(op_a, s);
    chain2.fund(op_b, s + params.cofunding_window + 1);
    let out = mk().await_funded(&chain2, op_a, op_b, &pk_a, &pk_b);
    assert!(matches!(out, Err(Error::Deadline(_))));
}
