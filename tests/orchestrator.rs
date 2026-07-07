//! Swap orchestrator integration (wallet rank 4): drive the funding
//! coordinator and abort driver against a real SimChain, composed with the
//! built settlement core.
//!
//!   1. `coordinator_drives_sl_first_funding_to_proceed` — the poll loop
//!      sequences canonical-order funding: first funder broadcasts a REAL
//!      Setup, the second funder waits until it verifies the first escrow is
//!      confirmed at exactly D+Δ_fee (via the dual-source verified reads),
//!      then funds; both within the window → Proceed with the right S.
//!   2. `fund_and_run_reclaims_via_abort_driver` — the counterparty never
//!      funds; past Block X the coordinator aborts, and the abort driver
//!      broadcasts the pre-armed refund at CSV maturity (v3.13 partial-
//!      funding / fund-and-run row, driven by the wallet loop).

use bitcoin::OutPoint;
use newkey::chain::{ChainView, DualSourceChainView, SimChain, Source};
use newkey::settlement::refund::PreArmedRefund;
use newkey::tx::escrow::Escrow;
use newkey::tx::setup::build_setup;
use newkey::wallet::manifest::SignedManifest;
use newkey::wallet::orchestrator::{
    AbortAction, AbortDriver, FundingAction, FundingCoordinator, FundingOrder,
};

fn dual(chain: &SimChain) -> DualSourceChainView<Source<SimChain>, Source<SimChain>> {
    // Both sources back the same sim; one is labeled self-verifying (the
    // real deployment pairs a BIP157/158 client with an explorer).
    DualSourceChainView::new(
        Source::new(chain.clone(), true),
        Source::new(chain.clone(), false),
    )
    .unwrap()
}

fn keypair() -> (secp::Scalar, secp::Point) {
    let mut rng = rand::rng();
    let sk = secp::Scalar::random(&mut rng);
    (sk, sk * secp::G)
}

#[test]
fn coordinator_drives_canonical_first_funding_to_proceed() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let coord = FundingCoordinator::from_manifest(&manifest);
    let unit = params.tier_d_sats + params.delta_fee_sats;
    let block_x = 900_500u32;

    // Two parties with real pre-encumbrance keys.
    let (sk_a, pk_a) = keypair();
    let (sk_b, pk_b) = keypair();
    let va = newkey::crypto::ValidatedPoint::from_bytes(&pk_a.serialize()).unwrap();
    let vb = newkey::crypto::ValidatedPoint::from_bytes(&pk_b.serialize()).unwrap();

    // We play canonical User A; determine our order.
    let our_order = FundingCoordinator::funding_order(&va, &vb).unwrap();
    let (we_first, our_sk, our_pk, their_pk, their_sk) = match our_order {
        FundingOrder::First => (true, sk_a, pk_a, pk_b, sk_b),
        FundingOrder::Second => (false, sk_a, pk_a, pk_b, sk_b),
    };
    let _ = their_pk;

    // Build both escrows (both orderings' leaves; here one each for the test).
    let internal =
        newkey::settlement::state_machine::canonical_internal_key(our_pk, their_pk).unwrap();
    let our_escrow = Escrow::new(&internal, &our_pk, params.delta_early).unwrap();
    let their_escrow = Escrow::new(&internal, &their_pk, params.delta_early).unwrap();

    // Fund each escrow from a pre-encumbrance UTXO via a REAL Setup.
    let chain = SimChain::new(900_000);
    let our_pre = OutPoint::new(txid(0xA0), 0);
    let their_pre = OutPoint::new(txid(0xB0), 0);
    chain.fund_with_amount(our_pre, 900_000, unit);
    chain.fund_with_amount(their_pre, 900_000, unit);
    let (our_setup, our_escrow_op) = build_setup(our_pre, unit, &our_escrow, &our_sk).unwrap();
    let (their_setup, their_escrow_op) =
        build_setup(their_pre, unit, &their_escrow, &their_sk).unwrap();

    let view = dual(&chain);

    // --- Poll 1: nobody funded, jitter not ready → Wait.
    assert_eq!(
        coord
            .next_funding_action(&view, our_order, our_escrow_op, their_escrow_op, false, false, block_x)
            .unwrap(),
        FundingAction::Wait
    );

    // --- Drive per canonical order.
    if we_first {
        // We are first: jitter ready → broadcast ours.
        assert_eq!(
            coord
                .next_funding_action(&view, our_order, our_escrow_op, their_escrow_op, false, true, block_x)
                .unwrap(),
            FundingAction::BroadcastOurSetup
        );
        chain.broadcast(&our_setup).unwrap();
        chain.mine(); // our escrow confirms
                      // Their side now funds (they verified ours); it confirms next block.
        chain.broadcast(&their_setup).unwrap();
        chain.mine();
    } else {
        // We are second: must wait until THEIR escrow is verified at D+fee.
        assert_eq!(
            coord
                .next_funding_action(&view, our_order, our_escrow_op, their_escrow_op, false, true, block_x)
                .unwrap(),
            FundingAction::Wait,
            "second funder must not fund before verifying the first escrow"
        );
        chain.broadcast(&their_setup).unwrap();
        chain.mine(); // their escrow confirms at exactly D+fee
        assert_eq!(
            coord
                .next_funding_action(&view, our_order, our_escrow_op, their_escrow_op, false, true, block_x)
                .unwrap(),
            FundingAction::BroadcastOurSetup
        );
        chain.broadcast(&our_setup).unwrap();
        chain.mine();
    }

    // --- Both confirmed within the window → Proceed with correct S.
    let action = coord
        .next_funding_action(&view, our_order, our_escrow_op, their_escrow_op, true, true, block_x)
        .unwrap();
    match action {
        FundingAction::Proceed { our_height, their_height, s_height } => {
            assert_eq!(s_height, our_height.max(their_height));
            assert!(our_height.abs_diff(their_height) <= params.cofunding_window);
        }
        other => panic!("expected Proceed, got {other:?}"),
    }
}

#[test]
fn fund_and_run_reclaims_via_abort_driver() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let coord = FundingCoordinator::from_manifest(&manifest);
    let unit = params.tier_d_sats + params.delta_fee_sats;
    let d = params.tier_d_sats;
    let s_height = 900_000u32;
    let block_x = s_height + 50;

    let (our_sk, our_pk) = keypair();
    let (_their_sk, their_pk) = keypair();
    let internal =
        newkey::settlement::state_machine::canonical_internal_key(our_pk, their_pk).unwrap();
    // Our escrow with an early refund leaf keyed to us.
    let our_escrow = Escrow::new(&internal, &our_pk, params.delta_early).unwrap();
    let our_escrow_op = OutPoint::new(txid(1), 0);
    let their_escrow_op = OutPoint::new(txid(2), 0);

    let chain = SimChain::new(s_height);
    chain.fund_with_amount(our_escrow_op, s_height, unit); // we funded
                                                           // ...the counterparty NEVER funds their escrow.
    let view = dual(&chain);

    // Before Block X: we wait for the counterparty.
    assert_eq!(
        coord
            .next_funding_action(&view, FundingOrder::First, our_escrow_op, their_escrow_op, true, true, block_x)
            .unwrap(),
        FundingAction::Wait
    );

    // Past Block X with only our escrow confirmed → Abort (fund-and-run).
    while chain.tip_height() < block_x {
        chain.mine();
    }
    assert_eq!(
        coord
            .next_funding_action(&view, FundingOrder::First, our_escrow_op, their_escrow_op, true, true, block_x)
            .unwrap(),
        FundingAction::Abort("Block X funding deadline passed; abandon to refunds")
    );

    // The abort driver reclaims our escrow via its pre-armed refund. Build a
    // REAL script-path refund of our escrow.
    let dest = our_escrow.funding_script_pubkey().clone();
    let refund = PreArmedRefund::arm(
        &our_escrow,
        our_escrow_op,
        unit,
        &our_sk,
        dest,
        d,
        s_height,
    )
    .unwrap();

    // Not matured yet → Wait; no counterparty completion exists.
    assert_eq!(
        AbortDriver::next_abort_action(&view, our_escrow_op, &refund, None),
        AbortAction::Wait
    );
    // Mine to CSV maturity → BroadcastRefund; then broadcast + confirm →
    // Refunded.
    while chain.tip_height() < refund.csv_maturity_height() {
        chain.mine();
    }
    assert_eq!(
        AbortDriver::next_abort_action(&view, our_escrow_op, &refund, None),
        AbortAction::BroadcastRefund
    );
    let refund_txid = chain.broadcast(refund.tx_bytes()).unwrap();
    chain.mine();
    assert_eq!(
        AbortDriver::next_abort_action(&view, our_escrow_op, &refund, Some(refund_txid)),
        AbortAction::Refunded
    );
}

/// The adversarial-review regression: a lying NON-authoritative source
/// (the explorer) that disagrees on the counterparty escrow's amount must
/// only DELAY (Wait), never force a terminal Abort of an honestly-funded
/// swap — and once it stops lying, the swap Proceeds.
#[test]
fn lying_explorer_delays_but_cannot_force_abort() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let coord = FundingCoordinator::from_manifest(&manifest);
    let unit = params.tier_d_sats + params.delta_fee_sats;
    let s = 900_000u32;
    let block_x = s + 100;

    let our_escrow = OutPoint::new(txid(1), 0);
    let their_escrow = OutPoint::new(txid(2), 0);

    // Honest self-verifying source: both escrows confirmed at exactly D+fee.
    let honest = SimChain::new(s);
    honest.fund_with_amount(our_escrow, s, unit);
    honest.fund_with_amount(their_escrow, s, unit);
    // Lying explorer: reports the counterparty escrow at the WRONG amount.
    let liar = SimChain::new(s);
    liar.fund_with_amount(our_escrow, s, unit);
    liar.fund_with_amount(their_escrow, s, unit + 1);

    let view = DualSourceChainView::new(
        Source::new(honest.clone(), true),  // self-verifying = truth
        Source::new(liar.clone(), false),   // explorer = lying
    )
    .unwrap();

    // The sources disagree on the counterparty amount → the swap WAITS
    // (does NOT abort), because the self-verifying source holds the truth.
    assert_eq!(
        coord
            .next_funding_action(&view, FundingOrder::First, our_escrow, their_escrow, true, true, block_x)
            .unwrap(),
        FundingAction::Wait,
        "a lying explorer must not force a terminal abort"
    );

    // Even past Block X, the no-show judgment uses the AUTHORITATIVE source,
    // which shows the counterparty genuinely funded → still not a no-show.
    while honest.tip_height() < block_x {
        honest.mine();
        liar.mine();
    }
    assert_eq!(
        coord
            .next_funding_action(&view, FundingOrder::First, our_escrow, their_escrow, true, true, block_x)
            .unwrap(),
        FundingAction::Wait,
        "Block-X must not abort a counterparty confirmed on the authoritative source"
    );

    // The explorer stops lying (re-syncs to the truth): now the sources agree
    // and the swap Proceeds — the liar only delayed it.
    liar.fund_with_amount(their_escrow, s, unit);
    assert!(matches!(
        coord
            .next_funding_action(&view, FundingOrder::First, our_escrow, their_escrow, true, true, block_x)
            .unwrap(),
        FundingAction::Proceed { .. }
    ));

    // But a GENUINE wrong amount (BOTH sources agree it is not D+fee) still
    // aborts — the fix distinguishes disagreement from a hostile escrow.
    let honest2 = SimChain::new(s);
    honest2.fund_with_amount(their_escrow, s, unit - 500);
    let liar2 = SimChain::new(s);
    liar2.fund_with_amount(their_escrow, s, unit - 500);
    let view2 = DualSourceChainView::new(
        Source::new(honest2, true),
        Source::new(liar2, false),
    )
    .unwrap();
    assert_eq!(
        coord
            .next_funding_action(&view2, FundingOrder::First, our_escrow, their_escrow, true, true, block_x)
            .unwrap(),
        FundingAction::Abort("counterparty escrow is not exactly D+delta_fee; abort")
    );
}

fn txid(seed: u8) -> bitcoin::Txid {
    let mut b = [0u8; 32];
    b[0] = seed;
    bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b))
}
