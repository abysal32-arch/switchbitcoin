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
//! STATUS: rows 1-7 are implemented. Rows 2/5/6 exercise the crypto core; rows
//! 1/3/4/7 drive a full taproot swap against the in-process `SimChain` (real
//! CSV maturity + no-double-spend physics). Row 8 (fee-congestion backstop)
//! stays ignored: it needs a fee model the sim deliberately omits.

use bitcoin::{OutPoint, Txid};
use musig2::KeyAggContext;
use newkey::chain::{ChainView, SimChain, SpendStatus};
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
    let peer = PeerSession::new([0x55u8; 32], Box::new(duplex().0));
    let funded = Funding::new(params.clone(), peer).await_funded(&chain, op, their_op);
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
    // Nothing broadcastable against it: the output is now spent by SL's refund.
    assert!(chain.broadcast(refund.tx_bytes()).is_ok()); // idempotent re-broadcast of same txid
}

// ---- 8. Congestion beyond delta_fee ---------------------------------------
#[test]
#[ignore = "needs a fee model: the SimChain deliberately omits fees, so a spike > delta_fee, opt-in completion bump, and silent refund backstop cannot be exercised here"]
fn congestion_backstop_behaves() {
    unimplemented!("congestion backstop needs a fee-aware chain model");
}

// ---- await_funded role derivation (chain-view coverage) -------------------
#[test]
fn await_funded_derives_opposite_roles_and_enforces_cofunding_window() {
    let params = Params::testnet_provisional();
    let s = 600_000u32;
    let chain = SimChain::new(s);
    let op_a = OutPoint::new(txid_from(1), 0);
    let op_b = OutPoint::new(txid_from(2), 0);
    chain.fund(op_a, s);
    chain.fund(op_b, s + params.cofunding_window); // within the window

    // Both parties derive from the same public data; roles are opposite.
    let mk = || {
        Funding::new(params.clone(), PeerSession::new([1u8; 32], Box::new(duplex().0)))
    };
    let a = mk().await_funded(&chain, op_a, op_b).expect("A funded");
    let b = mk().await_funded(&chain, op_b, op_a).expect("B funded");
    assert_ne!(a.role(), b.role(), "the two parties must derive opposite roles");
    // S is the later confirmation.
    assert_eq!(a.s_height(), s + params.cofunding_window);

    // Outside the co-funding window: abandon.
    let chain2 = SimChain::new(s);
    chain2.fund(op_a, s);
    chain2.fund(op_b, s + params.cofunding_window + 1);
    let out = mk().await_funded(&chain2, op_a, op_b);
    assert!(matches!(out, Err(Error::Deadline(_))));
}
