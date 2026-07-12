//! FundingDriver integration (orchestration increment 3): the pre-funding
//! poll loop composed end-to-end — canonical-order funding with REAL Setup
//! txs on a SimChain, both parties driven through their own `FundingDriver`,
//! ending in `into_funded` role derivation (the `Funded` handoff that
//! `SwapDriver::start` consumes).

use std::cell::{Cell, RefCell};
use std::collections::HashSet;

use bitcoin::OutPoint;
use swapkey::chain::{
    AuthoritativeChainView, ChainView, DualSourceChainView, FundingReading, SimChain, Source,
    SpendStatus,
};
use swapkey::crypto::ValidatedPoint;
use swapkey::settlement::state_machine::{PeerSession, Role, Transport};
use swapkey::tx::escrow::Escrow;
use swapkey::tx::setup::build_setup;
use swapkey::wallet::funding_driver::{FundingDriver, FundingTick, HandoffError};
use swapkey::wallet::manifest::SignedManifest;
use swapkey::wallet::orchestrator::FundingOrder;
use swapkey::{Error, Result};

fn dual(chain: &SimChain) -> DualSourceChainView<Source<SimChain>, Source<SimChain>> {
    DualSourceChainView::new(
        Source::self_verifying(chain.clone()),
        Source::untrusted(chain.clone()),
    )
    .unwrap()
}

fn keypair() -> (secp::Scalar, secp::Point) {
    let mut rng = rand::rng();
    let sk = secp::Scalar::random(&mut rng);
    (sk, sk * secp::G)
}

fn txid(seed: u8) -> bitcoin::Txid {
    let mut b = [0u8; 32];
    b[0] = seed;
    bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b))
}

/// The pre-funding half never touches the peer transport (proven by the
/// cofunding tests driving `await_funded` with a dangling duplex half), so a
/// transport that errors on ANY use both satisfies `into_funded` and asserts
/// that property.
struct DeadEnd;
impl Transport for DeadEnd {
    fn send(&mut self, _bytes: &[u8]) -> Result<()> {
        Err(Error::Abort("pre-funding must not touch the transport"))
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        Err(Error::Abort("pre-funding must not touch the transport"))
    }
}
fn dead_peer() -> PeerSession {
    PeerSession::new([0xE3u8; 32], Box::new(DeadEnd))
}

/// One party's funding-side fixture: keys, escrow, signed Setup, outpoint.
struct Party {
    pk: ValidatedPoint,
    setup: Vec<u8>,
    escrow_op: OutPoint,
}

/// Build both parties' REAL Setups against the same chain (pre-encumbrance
/// coins funded at `base_height`).
fn two_parties(chain: &SimChain, manifest: &SignedManifest, base_height: u32) -> (Party, Party) {
    let params = manifest.params().clone();
    let unit = params.pre_encumbrance_sats();
    let (sk_a, pk_a) = keypair();
    let (sk_b, pk_b) = keypair();
    let va = ValidatedPoint::from_bytes(&pk_a.serialize()).unwrap();
    let vb = ValidatedPoint::from_bytes(&pk_b.serialize()).unwrap();

    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(pk_a, pk_b).unwrap();
    let escrow_a = Escrow::new(&internal, &pk_a, params.delta_early).unwrap();
    let escrow_b = Escrow::new(&internal, &pk_b, params.delta_early).unwrap();

    let pre_a = OutPoint::new(txid(0xA0), 0);
    let pre_b = OutPoint::new(txid(0xB0), 0);
    chain.fund_with_amount(pre_a, base_height, unit);
    chain.fund_with_amount(pre_b, base_height, unit);

    let (setup_a, escrow_op_a) = build_setup(
        pre_a, unit, params.escrow_amount_sats(), params.anchor_sats, &escrow_a, &sk_a,
    )
    .unwrap();
    let (setup_b, escrow_op_b) = build_setup(
        pre_b, unit, params.escrow_amount_sats(), params.anchor_sats, &escrow_b, &sk_b,
    )
    .unwrap();

    (
        Party { pk: va, setup: setup_a, escrow_op: escrow_op_a },
        Party { pk: vb, setup: setup_b, escrow_op: escrow_op_b },
    )
}

/// The whole pre-funding half through two independent FundingDrivers on the
/// same chain: canonical-order sequencing, real Setups, Proceed on both sides,
/// then `into_funded` minting OPPOSITE roles with the SAME S — the exact
/// handoff `SwapDriver::start` consumes.
#[test]
fn both_sides_drive_to_funded_with_opposite_roles() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);
    let block_x = 900_500u32;

    // Each side runs its OWN driver (jitter 0 keeps the sequencing crisp).
    let mut da =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, block_x, 0)
            .unwrap();
    let mut db =
        FundingDriver::begin(&manifest, &b.pk, &a.pk, b.escrow_op, a.escrow_op, block_x, 0)
            .unwrap();

    // Both wallets independently derive the SAME sequencing (opposite orders).
    assert_ne!(da.order(), db.order(), "the two wallets must disagree on who is First");

    // Split by who funds first.
    let (first, second, first_setup, second_setup) = match da.order() {
        FundingOrder::First => (&mut da, &mut db, &a.setup, &b.setup),
        FundingOrder::Second => (&mut db, &mut da, &b.setup, &a.setup),
    };

    // First funder is told to broadcast; second must wait (deferred
    // encumbrance verification — it funds only after verifying escrow #1).
    assert_eq!(first.tick(&view).unwrap(), FundingTick::BroadcastOurSetup);
    assert_eq!(second.tick(&view).unwrap(), FundingTick::Wait);

    chain.broadcast(first_setup).unwrap();
    first.setup_broadcast();
    chain.mine(); // escrow #1 confirms

    assert_eq!(first.tick(&view).unwrap(), FundingTick::Wait, "first waits for the peer");
    assert_eq!(second.tick(&view).unwrap(), FundingTick::BroadcastOurSetup);

    chain.broadcast(second_setup).unwrap();
    second.setup_broadcast();
    chain.mine(); // escrow #2 confirms

    // Both sides Proceed with the same S = max(h1, h2).
    let (p1, p2) = (first.tick(&view).unwrap(), second.tick(&view).unwrap());
    let s = match (p1, p2) {
        (
            FundingTick::Proceed { s_height: s1, our_height: o1, their_height: t1 },
            FundingTick::Proceed { s_height: s2, .. },
        ) => {
            assert_eq!(s1, s2, "both sides must agree on S");
            assert_eq!(s1, o1.max(t1));
            assert!(o1.abs_diff(t1) <= params.cofunding_window);
            s1
        }
        other => panic!("expected Proceed on both sides, got {other:?}"),
    };

    // Cross into the funded half on BOTH sides: opposite roles, same S, and
    // each side's claim anchor is the COUNTERPARTY escrow's own height.
    let fa = da
        .into_funded(params.clone(), dead_peer(), &view)
        .expect("A's await_funded");
    let fb = db.into_funded(params, dead_peer(), &view).expect("B's await_funded");
    assert_ne!(fa.role(), fb.role(), "role derivation must split the two parties");
    assert_eq!(fa.s_height(), s);
    assert_eq!(fb.s_height(), s);
    let (ha, hb) = (
        view.funding_height(a.escrow_op).unwrap(),
        view.funding_height(b.escrow_op).unwrap(),
    );
    assert_eq!(fa.sweep_escrow_height(), hb, "A sweeps B's escrow");
    assert_eq!(fb.sweep_escrow_height(), ha, "B sweeps A's escrow");
}

/// Jitter gates the FIRST broadcast: sampled delay (clamped to the manifest
/// bound) counts in blocks from the first tick's tip.
#[test]
fn jitter_clamps_to_manifest_bound_and_gates_broadcast() {
    let manifest = SignedManifest::provisional();
    let jitter_max = {
        // provisional bound is 6; clamp must bring an oversized sample down.
        let c = swapkey::wallet::orchestrator::FundingCoordinator::from_manifest(&manifest);
        c.jitter_max()
    };
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);

    // Whichever party is First gets the driver (jitter request 999 → clamp).
    let mut d =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, 999)
            .unwrap();
    if d.order() == FundingOrder::Second {
        d = FundingDriver::begin(&manifest, &b.pk, &a.pk, b.escrow_op, a.escrow_op, 900_500, 999)
            .unwrap();
    }
    assert_eq!(d.order(), FundingOrder::First);

    // Anchor = tip at first tick; not ready until jitter_max more blocks.
    assert_eq!(d.tick(&view).unwrap(), FundingTick::Wait);
    for _ in 0..jitter_max - 1 {
        chain.mine();
        assert_eq!(d.tick(&view).unwrap(), FundingTick::Wait, "still inside the jitter delay");
    }
    chain.mine(); // anchor + jitter_max reached
    assert_eq!(d.tick(&view).unwrap(), FundingTick::BroadcastOurSetup);
}

/// Block-X no-show: nobody funds, the deadline passes → Abort, and the
/// terminal is STICKY (a later tick cannot resurrect the swap).
#[test]
fn block_x_abort_is_terminal_and_sticky() {
    let manifest = SignedManifest::provisional();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);

    let block_x = 900_003u32;
    let mut d =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, block_x, 0)
            .unwrap();
    // Suppress our own broadcast (simulate the operator holding off) and let
    // the deadline pass with neither escrow funded.
    while chain.tip_height() < block_x {
        chain.mine();
    }
    match d.tick(&view).unwrap() {
        FundingTick::Abort(reason) => assert!(reason.contains("Block X")),
        other => panic!("expected Abort at Block X, got {other:?}"),
    }
    // Sticky: even if funding now appeared, the driver stays aborted.
    chain.broadcast(&a.setup).unwrap();
    chain.broadcast(&b.setup).unwrap();
    chain.mine();
    assert!(matches!(d.tick(&view).unwrap(), FundingTick::Abort(_)), "abort must be sticky");
}

/// A lying explorer (sources disagree) after both escrows are authoritatively
/// confirmed surfaces as AwaitingVerification — the caller-visible escalation
/// signal — and resolves to Proceed once the liar re-syncs. Never an Abort.
#[test]
fn verification_stall_is_surfaced_not_aborted() {
    let manifest = SignedManifest::provisional();
    let truth = SimChain::new(900_000);
    let liar = SimChain::new(900_000);
    let (a, b) = two_parties(&truth, &manifest, 900_000);
    // The liar chain needs the same pre-encumbrance coins to accept the Setups
    // later (re-sync); fund them identically.
    let params = manifest.params().clone();
    liar.fund_with_amount(OutPoint::new(txid(0xA0), 0), 900_000, params.pre_encumbrance_sats());
    liar.fund_with_amount(OutPoint::new(txid(0xB0), 0), 900_000, params.pre_encumbrance_sats());

    // Self-verifying source = truth; the other source lies by omission.
    let view = DualSourceChainView::new(
        Source::self_verifying(truth.clone()),
        Source::untrusted(liar.clone()),
    )
    .unwrap();

    let mut d =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, 0)
            .unwrap();

    // Drive our broadcast, then both escrows confirm ON TRUTH ONLY.
    let first_is_us = d.order() == FundingOrder::First;
    if first_is_us {
        assert_eq!(d.tick(&view).unwrap(), FundingTick::BroadcastOurSetup);
    }
    truth.broadcast(&a.setup).unwrap();
    truth.broadcast(&b.setup).unwrap();
    d.setup_broadcast();
    truth.mine();

    // Authoritatively funded on both, but the agreement view lags → the
    // distinct AwaitingVerification signal (Block-X can no longer fire).
    assert_eq!(d.tick(&view).unwrap(), FundingTick::AwaitingVerification);

    // Liar re-syncs → Proceed.
    liar.broadcast(&a.setup).unwrap();
    liar.broadcast(&b.setup).unwrap();
    liar.mine();
    assert!(
        matches!(d.tick(&view).unwrap(), FundingTick::Proceed { .. }),
        "re-synced sources must yield Proceed"
    );
}

/// The pre-funding half is transport-free end-to-end: `into_funded` succeeds
/// with a transport that errors on ANY I/O (also asserted by DeadEnd's use in
/// the both-sides test), and the derived role is only knowable afterwards.
#[test]
fn into_funded_never_touches_the_transport() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);

    let mut d = FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, 0)
        .unwrap();
    chain.broadcast(&a.setup).unwrap();
    chain.broadcast(&b.setup).unwrap();
    d.setup_broadcast();
    chain.mine();
    assert!(matches!(d.tick(&view).unwrap(), FundingTick::Proceed { .. }));

    let funded = d.into_funded(params, dead_peer(), &view).expect("transport-free await_funded");
    assert!(matches!(funded.role(), Role::SecretHolder | Role::SecretLearner));
}

/// Crash-restart, end-to-end: a SECOND driver built over a chain where both
/// Setups already confirmed (broadcast flag lost, jitter resampled — the
/// module doc's accepted restart shape) must (a) surface its own jitter wait
/// as plain `Wait`, NOT `AwaitingVerification` — no source is disagreeing,
/// and a doc-compliant caller with a matured refund would otherwise abandon
/// a healthy swap; (b) re-broadcast the SAME confirmed bytes idempotently
/// (same txid via the AlreadyKnown dedup, not an "already spent" error); and
/// (c) reach `Proceed` and a successful handoff.
#[test]
fn restarted_driver_rebroadcasts_idempotently_and_reaches_funded() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);

    // Pre-crash: both Setups confirm.
    chain.broadcast(&a.setup).unwrap();
    chain.broadcast(&b.setup).unwrap();
    chain.mine();

    // Restart: fresh driver for party A, resampled jitter > 0, flag lost.
    // (The observable sequence is order-independent: First anchors at the
    // first tick; Second's readiness — B's escrow verified — already holds.)
    let jitter = 3u32;
    let mut d =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, jitter)
            .unwrap();
    for _ in 0..jitter {
        assert_eq!(
            d.tick(&view).unwrap(),
            FundingTick::Wait,
            "a restart's own jitter wait must not read as a verification stall"
        );
        chain.mine();
    }
    assert_eq!(d.tick(&view).unwrap(), FundingTick::BroadcastOurSetup);

    let txid = chain.broadcast(&a.setup).expect("re-broadcast of a confirmed Setup is idempotent");
    assert_eq!(txid, a.escrow_op.txid, "idempotent re-broadcast returns the same txid");
    d.setup_broadcast();

    assert!(matches!(d.tick(&view).unwrap(), FundingTick::Proceed { .. }));
    let funded = d.into_funded(params, dead_peer(), &view).expect("post-restart handoff");
    assert!(matches!(funded.role(), Role::SecretHolder | Role::SecretLearner));
}

/// The handoff is gated BY CONSTRUCTION, not by caller discipline: a driver
/// that aborted (Block X) refuses `into_funded` even though both escrows
/// confirmed afterwards, and a wrong-amount counterparty escrow — the state
/// tick() answers with Abort — refuses it too. Without these gates a caller
/// sequencing bug would mint a `Funded` against an escrow the encumbrance
/// gate rejected and sign the exchange against a 1-sat counterparty escrow.
#[test]
fn handoff_refuses_abort_and_wrong_amount_states() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();

    // 1. Sticky Block-X abort, then both escrows confirm: still refused.
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);
    let block_x = 900_003u32;
    let mut d =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, block_x, 0)
            .unwrap();
    while chain.tip_height() < block_x {
        chain.mine();
    }
    assert!(matches!(d.tick(&view).unwrap(), FundingTick::Abort(_)));
    chain.broadcast(&a.setup).unwrap();
    chain.broadcast(&b.setup).unwrap();
    chain.mine();
    d.setup_broadcast();
    match d.into_funded(params.clone(), dead_peer(), &view) {
        Err(HandoffError::Refused { error: Error::Abort(_), .. }) => {}
        Err(other) => panic!("aborted driver must refuse with Abort, got {other:?}"),
        Ok(_) => panic!("aborted driver must refuse the handoff, got Ok(Funded)"),
    }

    // 2. Counterparty escrow at the wrong amount (both sources agree): the
    // encumbrance gate refuses the handoff even if no tick ever ran.
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);
    let mut d =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, 0)
            .unwrap();
    chain.broadcast(&a.setup).unwrap();
    chain.fund_with_amount(b.escrow_op, 900_001, 1); // hostile: 1 sat
    chain.mine();
    d.setup_broadcast();
    assert!(
        matches!(d.tick(&view).unwrap(), FundingTick::Abort(_)),
        "tick must abort on a wrong-amount counterparty escrow"
    );
    match d.into_funded(params, dead_peer(), &view) {
        Err(HandoffError::Refused { error: Error::Abort(_), .. }) => {}
        Err(other) => panic!("wrong-amount escrow must refuse with Abort, got {other:?}"),
        Ok(_) => panic!("wrong-amount escrow must refuse the handoff, got Ok(Funded)"),
    }
}

/// A premature handoff is NON-DESTRUCTIVE: `into_funded` before the
/// go-signal hands the driver and the peer session back (`Refused`), and
/// that SAME returned state then drives to `Proceed` and a successful
/// handoff — the "plain re-drive" the docs promise, with no torn-down
/// transport.
#[test]
fn premature_handoff_returns_state_and_re_drives() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);

    // Whichever party is First gets the driver (crisp sequencing, jitter 0).
    let (mut d, our_setup, their_setup) = {
        let d = FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, 0)
            .unwrap();
        if d.order() == FundingOrder::First {
            (d, &a.setup, &b.setup)
        } else {
            let d =
                FundingDriver::begin(&manifest, &b.pk, &a.pk, b.escrow_op, a.escrow_op, 900_500, 0)
                    .unwrap();
            (d, &b.setup, &a.setup)
        }
    };

    assert_eq!(d.tick(&view).unwrap(), FundingTick::BroadcastOurSetup);
    chain.broadcast(our_setup).unwrap();
    d.setup_broadcast();
    chain.mine();

    // Counterparty escrow not yet on chain: the handoff must refuse WITHOUT
    // consuming — driver and peer come back for a plain re-drive.
    let (mut d, peer) = match d.into_funded(params.clone(), dead_peer(), &view) {
        Err(HandoffError::Refused { driver, peer, error: Error::Ordering(_) }) => (*driver, peer),
        Err(other) => panic!("premature handoff must be Refused(Ordering), got {other:?}"),
        Ok(_) => panic!("premature handoff must be Refused(Ordering), got Ok(Funded)"),
    };

    chain.broadcast(their_setup).unwrap();
    chain.mine();
    assert!(matches!(d.tick(&view).unwrap(), FundingTick::Proceed { .. }));
    let funded = d.into_funded(params, peer, &view).expect("re-driven handoff with the RETURNED peer");
    assert!(matches!(funded.role(), Role::SecretHolder | Role::SecretLearner));
}

/// Anti-substitution: a counterparty that funds its escrow outpoint at EXACTLY
/// the tier amount but with a scriptPubKey it solely controls (not the agreed
/// 2-of-2+CSV) must be refused — the amount gate alone would Proceed and let
/// the counterparty sweep our escrow while our completion against the fake
/// output is unspendable (deterministic take-both-sides). The driver aborts on
/// the spk mismatch and the handoff refuses, for whichever funding order we are.
#[test]
fn substituted_counterparty_escrow_spk_is_refused() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let unit = params.pre_encumbrance_sats();
    let chain = SimChain::new(900_000);

    // Victim A (honest, real 2-of-2 escrow) and attacker B (a fake escrow that
    // B solely controls — internal key = B's own key, not the canonical
    // aggregate — funded at the correct amount).
    let (sk_a, pk_a) = keypair();
    let (sk_b, pk_b) = keypair();
    let va = ValidatedPoint::from_bytes(&pk_a.serialize()).unwrap();
    let vb = ValidatedPoint::from_bytes(&pk_b.serialize()).unwrap();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(pk_a, pk_b).unwrap();
    let escrow_a = Escrow::new(&internal, &pk_a, params.delta_early).unwrap(); // genuine
    let escrow_b_fake = Escrow::new(&pk_b, &pk_b, params.delta_early).unwrap(); // solo-control

    let pre_a = OutPoint::new(txid(0xA1), 0);
    let pre_b = OutPoint::new(txid(0xB1), 0);
    chain.fund_with_amount(pre_a, 900_000, unit);
    chain.fund_with_amount(pre_b, 900_000, unit);
    let (setup_a, op_a) =
        build_setup(pre_a, unit, params.escrow_amount_sats(), params.anchor_sats, &escrow_a, &sk_a)
            .unwrap();
    let (setup_b, op_b_fake) =
        build_setup(pre_b, unit, params.escrow_amount_sats(), params.anchor_sats, &escrow_b_fake, &sk_b)
            .unwrap();

    let view = dual(&chain);
    let mut d =
        FundingDriver::begin(&manifest, &va, &vb, op_a, op_b_fake, 900_500, 0).unwrap();

    // Both escrows confirm — B's at the RIGHT amount but the wrong (fake) spk.
    chain.broadcast(&setup_a).unwrap();
    chain.broadcast(&setup_b).unwrap();
    chain.mine();

    // Drive: whichever order we are, we must reach a scriptPubKey Abort and
    // never Proceed. (First: BroadcastOurSetup once, then Proceed→spk Abort.
    // Second: the pre-broadcast gate aborts before we ever fund.)
    let mut spk_aborted = false;
    for _ in 0..6 {
        match d.tick(&view).unwrap() {
            FundingTick::BroadcastOurSetup => d.setup_broadcast(),
            FundingTick::Wait => {}
            FundingTick::Abort(reason) => {
                assert!(reason.contains("scriptPubKey"), "expected spk abort, got {reason:?}");
                spk_aborted = true;
                break;
            }
            FundingTick::Proceed { .. } => panic!("must not Proceed against a substituted escrow"),
            FundingTick::AwaitingVerification => panic!("unexpected AwaitingVerification"),
        }
    }
    assert!(spk_aborted, "the substituted escrow must drive a scriptPubKey abort");

    // The handoff refuses too (sticky abort survives into into_funded).
    match d.into_funded(params, dead_peer(), &view) {
        Err(HandoffError::Refused { error: Error::Abort(reason), .. }) => {
            assert!(reason.contains("scriptPubKey"));
        }
        Err(other) => panic!("substituted escrow handoff must refuse with the spk abort, got {other:?}"),
        Ok(_) => panic!("substituted escrow must never mint a Funded"),
    }
}

/// An honest Second funder whose wallet was offline past the co-funding window
/// must NOT broadcast Setup #2 into an already-dead window: the first escrow is
/// confirmed at the exact tier amount, but the tip has advanced ≥ cofunding_window
/// blocks beyond it, so our Setup could never confirm inside the window. The
/// driver must clean-abort BEFORE anything is locked (nothing on the wire), not
/// BroadcastOurSetup (which would lock the coin ~delta_early into a swap the
/// post-broadcast window check aborts deterministically). Still before Block X,
/// so Block-X cannot rescue it either.
#[test]
fn second_funder_aborts_before_locking_into_a_dead_cofunding_window() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);
    let block_x = 900_500u32;

    // Take whichever driver is the Second funder; the OTHER party's Setup is #1.
    let (mut d, first_setup) = {
        let d = FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, block_x, 0)
            .unwrap();
        if d.order() == FundingOrder::Second {
            (d, &b.setup)
        } else {
            let d =
                FundingDriver::begin(&manifest, &b.pk, &a.pk, b.escrow_op, a.escrow_op, block_x, 0)
                    .unwrap();
            (d, &a.setup)
        }
    };
    assert_eq!(d.order(), FundingOrder::Second);

    // ONLY the first party's Setup goes on the wire and confirms (escrow #1).
    chain.broadcast(first_setup).unwrap();
    chain.mine();
    let h1 = chain.tip_height();

    // The Second funder's wallet was offline: the tip advances past the window
    // (still well before Block X). Broadcasting Setup #2 now could never meet
    // the co-funding window (our Setup confirms at ≥ tip+1 → oh − h1 ≥ cw+1).
    let cw = params.cofunding_window;
    while chain.tip_height() < h1 + cw + 1 {
        chain.mine();
    }
    assert!(chain.tip_height() < block_x, "still inside the Block-X deadline");

    // The tick is a clean, sticky Abort — NOT BroadcastOurSetup. Our Setup was
    // never broadcast (our_setup_broadcast unset), so the abort locks nothing.
    match d.tick(&view).unwrap() {
        FundingTick::Abort(reason) => {
            assert!(reason.contains("co-funding window can no longer be met"), "got {reason:?}");
        }
        other => panic!("expected a clean pre-broadcast Abort, got {other:?}"),
    }
    assert!(matches!(d.tick(&view).unwrap(), FundingTick::Abort(_)), "abort must be sticky");

    // The handoff refuses too — a dead window never mints a Funded.
    match d.into_funded(params, dead_peer(), &view) {
        Err(HandoffError::Refused { error: Error::Abort(reason), .. }) => {
            assert!(reason.contains("co-funding window can no longer be met"));
        }
        Err(other) => panic!("dead-window handoff must refuse with the window Abort, got {other:?}"),
        Ok(_) => panic!("a dead co-funding window must never mint a Funded"),
    }
}

/// The Second funder's jitter decorrelates Setup #2 from escrow #1's
/// CONFIRMATION: the delay counts from the verification event, not from the
/// driver's first tick — a first-tick anchor would elapse concurrently with
/// waiting for escrow #1 and put Setup #2 on the wire a deterministic beat
/// after verification, the exact linkage the manifest-signed jitter exists
/// to break.
#[test]
fn second_funder_jitter_counts_from_verification_event() {
    let manifest = SignedManifest::provisional();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);
    let view = dual(&chain);

    // Whichever party is Second gets the driver; the other's Setup is #1.
    let jitter = 2u32;
    let (mut d, first_setup) = {
        let d = FundingDriver::begin(
            &manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, jitter,
        )
        .unwrap();
        if d.order() == FundingOrder::Second {
            (d, &b.setup)
        } else {
            let d = FundingDriver::begin(
                &manifest, &b.pk, &a.pk, b.escrow_op, a.escrow_op, 900_500, jitter,
            )
            .unwrap();
            (d, &a.setup)
        }
    };
    assert_eq!(d.order(), FundingOrder::Second);

    // Burn well past the sampled jitter BEFORE escrow #1 exists: under
    // first-tick anchoring the whole budget would be spent by now.
    for _ in 0..jitter + 2 {
        assert_eq!(d.tick(&view).unwrap(), FundingTick::Wait);
        chain.mine();
    }

    // Escrow #1 confirms and verifies — the jitter must START here.
    chain.broadcast(first_setup).unwrap();
    chain.mine();
    for _ in 0..jitter {
        assert_eq!(
            d.tick(&view).unwrap(),
            FundingTick::Wait,
            "the Second funder's jitter counts from verification, not the first tick"
        );
        chain.mine();
    }
    assert_eq!(d.tick(&view).unwrap(), FundingTick::BroadcastOurSetup);
}

// ============================================================================
// Feature-2 audit: spk-Unverifiable stall classification + handoff gates,
// jitter re-clamp, and the pinned-handoff reading (findings A/E/C/M).
// ============================================================================

/// A persistent liar that agrees on HEIGHTS and AMOUNTS but serves a WRONG
/// scriptPubKey for the counterparty escrow: the coordinator is satisfied
/// (Proceed-eligible) while the anti-substitution spk read stays Unverifiable
/// forever. Both escrows are authoritatively confirmed, so Block-X is
/// permanently disarmed -- a bare `Wait` here would stall the swap FOREVER
/// (`SwapApp::poll` escalates only on `AwaitingVerification`). The same liar
/// lying about the AMOUNT already classifies as the stall; the spk must not
/// be the softer lie. The handoff refuses non-destructively, and the SAME
/// returned driver resolves once the sources agree.
#[test]
fn spk_only_disagreement_classifies_awaiting_verification_not_forever_wait() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let truth = SimChain::new(900_000);
    let liar = SimChain::new(900_000);
    let (a, b) = two_parties(&truth, &manifest, 900_000);

    // Both setups confirm ON TRUTH (real 2-of-2 spks reportable).
    truth.broadcast(&a.setup).unwrap();
    truth.broadcast(&b.setup).unwrap();
    truth.mine();
    let h = truth.tip_height();

    // The liar AGREES on both heights and amounts -- but reports a solo-style
    // spk for the counterparty escrow (and no spk for ours, which is never
    // read). verified_funding_reading stays Confirmed at the exact amount;
    // only verified_funding_spk collapses (disagreement -> None).
    let unit = params.escrow_amount_sats();
    liar.fund_with_amount(a.escrow_op, h, unit);
    let mut wrong = vec![0x51u8, 0x20];
    wrong.extend_from_slice(&[0x33u8; 32]);
    liar.fund_with_spk(b.escrow_op, h, unit, bitcoin::ScriptBuf::from_bytes(wrong));
    let view = DualSourceChainView::new(
        Source::self_verifying(truth.clone()),
        Source::untrusted(liar.clone()),
    )
    .unwrap();

    // Party A's driver in the restart shape (both escrows long confirmed,
    // broadcast flag re-confirmed): the coordinator reaches Proceed
    // internally; only the spk gate is unverifiable.
    let mut d =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, 0)
            .unwrap();
    d.setup_broadcast();
    assert_eq!(
        d.tick(&view).unwrap(),
        FundingTick::AwaitingVerification,
        "an spk-only disagreement with both escrows authoritatively confirmed is the \
         persistent-liar stall -- the escalation signal, never a bare Wait"
    );

    // The handoff refuses WITHOUT consuming (identity unverifiable = re-drive).
    let (mut d, peer) = match d.into_funded(params.clone(), dead_peer(), &view) {
        Err(HandoffError::Refused { driver, peer, error: Error::Deadline(msg) }) => {
            assert!(msg.contains("unverifiable"), "got {msg:?}");
            (*driver, peer)
        }
        Err(other) => panic!("unverifiable identity must refuse with Deadline, got {other:?}"),
        Ok(_) => panic!("must never mint a Funded on an unverifiable escrow identity"),
    };

    // The liar re-syncs (sources agree on the spk): the SAME returned driver
    // proceeds and hands off -- the stall was a re-drive, not a terminal.
    let healed = dual(&truth);
    assert!(matches!(d.tick(&healed).unwrap(), FundingTick::Proceed { .. }));
    let funded = d.into_funded(params, peer, &healed).expect("healed handoff");
    assert!(matches!(funded.role(), Role::SecretHolder | Role::SecretLearner));
}

/// The handoff's OWN identity gate, exercised FRESH (finding E): a caller that
/// never ticks cannot bypass the anti-substitution check -- `into_funded`
/// called directly against a substituted-but-right-amount counterparty escrow
/// must discover the mismatch itself (the existing substituted-escrow test
/// reaches the handoff only via the sticky abort a prior tick set, so the
/// in-handoff `Proceed -> Mismatch` arm had no coverage), refuse with the spk
/// abort, and leave the RETURNED driver sticky-aborted.
#[test]
fn handoff_discovers_a_substituted_spk_without_a_prior_tick() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let unit = params.pre_encumbrance_sats();
    let chain = SimChain::new(900_000);

    // Honest A (real 2-of-2 escrow), attacker B (solo-control escrow at the
    // exact tier amount) -- the `substituted_counterparty_escrow_spk_is_refused`
    // fixture, but the driver never ticks.
    let (sk_a, pk_a) = keypair();
    let (sk_b, pk_b) = keypair();
    let va = ValidatedPoint::from_bytes(&pk_a.serialize()).unwrap();
    let vb = ValidatedPoint::from_bytes(&pk_b.serialize()).unwrap();
    let internal =
        swapkey::settlement::state_machine::canonical_internal_key(pk_a, pk_b).unwrap();
    let escrow_a = Escrow::new(&internal, &pk_a, params.delta_early).unwrap();
    let escrow_b_fake = Escrow::new(&pk_b, &pk_b, params.delta_early).unwrap();

    let pre_a = OutPoint::new(txid(0xA2), 0);
    let pre_b = OutPoint::new(txid(0xB2), 0);
    chain.fund_with_amount(pre_a, 900_000, unit);
    chain.fund_with_amount(pre_b, 900_000, unit);
    let (setup_a, op_a) =
        build_setup(pre_a, unit, params.escrow_amount_sats(), params.anchor_sats, &escrow_a, &sk_a)
            .unwrap();
    let (setup_b, op_b_fake) =
        build_setup(pre_b, unit, params.escrow_amount_sats(), params.anchor_sats, &escrow_b_fake, &sk_b)
            .unwrap();
    chain.broadcast(&setup_a).unwrap();
    chain.broadcast(&setup_b).unwrap();
    chain.mine();

    let view = dual(&chain);
    let mut d = FundingDriver::begin(&manifest, &va, &vb, op_a, op_b_fake, 900_500, 0).unwrap();
    d.setup_broadcast();

    // Straight to the handoff -- no tick ever ran, so no sticky abort exists;
    // the refusal below is the in-handoff gate's own discovery.
    let mut d = match d.into_funded(params.clone(), dead_peer(), &view) {
        Err(HandoffError::Refused { driver, error: Error::Abort(reason), .. }) => {
            assert!(reason.contains("scriptPubKey"), "got {reason:?}");
            *driver
        }
        Err(other) => panic!("fresh handoff must refuse with the spk abort, got {other:?}"),
        Ok(_) => panic!("a substituted escrow must never mint a Funded"),
    };

    // The discovery is STICKY on the returned driver: a later tick stays
    // aborted and a second handoff refuses at the terminal.
    assert!(matches!(d.tick(&view).unwrap(), FundingTick::Abort(_)), "abort must be sticky");
    match d.into_funded(params, dead_peer(), &view) {
        Err(HandoffError::Refused { error: Error::Abort(reason), .. }) => {
            assert!(reason.contains("scriptPubKey"));
        }
        Err(other) => panic!("the sticky abort must keep refusing with the spk abort, got {other:?}"),
        Ok(_) => panic!("the sticky abort must keep refusing the handoff, got Ok(Funded)"),
    }
}

/// A test-only view whose reported tip can REGRESS (a reorg, or a briefly-
/// ahead authoritative source healing) -- SimChain's own height only climbs,
/// so this is the only way to exercise the documented anchor re-clamp.
struct RegressedTip {
    inner: SimChain,
    offset: Cell<u32>,
}
impl ChainView for RegressedTip {
    fn tip_height(&self) -> u32 {
        self.inner.tip_height().saturating_sub(self.offset.get())
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
        self.inner.spending_witness_sig(op)
    }
    fn broadcast(&self, tx: &[u8]) -> Result<bitcoin::Txid> {
        self.inner.broadcast(tx)
    }
    fn submit_package(&self, p: &[u8], c: &[u8]) -> Result<(bitcoin::Txid, bitcoin::Txid)> {
        self.inner.submit_package(p, c)
    }
}
impl AuthoritativeChainView for RegressedTip {}

/// The jitter anchor's tip-regression re-clamp (finding C): a Second funder
/// anchored at tip T whose authoritative tip then RECEDES to T-k must re-clamp
/// the anchor down (delay <= jitter from the CURRENT tip -- the documented
/// property), so the broadcast readiness fires at (T-k)+j, never at T+j
/// ("tip recovery plus jitter") -- and the anchor never re-anchors upward when
/// the tip re-climbs.
#[test]
fn jitter_anchor_reclamps_to_a_regressing_tip() {
    let manifest = SignedManifest::provisional();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);

    // Whichever party is Second gets the driver; the other's Setup is #1.
    let jitter = 3u32;
    let (mut d, first_setup) = {
        let d = FundingDriver::begin(
            &manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, jitter,
        )
        .unwrap();
        if d.order() == FundingOrder::Second {
            (d, &b.setup)
        } else {
            let d = FundingDriver::begin(
                &manifest, &b.pk, &a.pk, b.escrow_op, a.escrow_op, 900_500, jitter,
            )
            .unwrap();
            (d, &a.setup)
        }
    };
    assert_eq!(d.order(), FundingOrder::Second);

    // Escrow #1 confirms and verifies at tip T: the anchor is set here.
    chain.broadcast(first_setup).unwrap();
    chain.mine();
    let view = RegressedTip { inner: chain.clone(), offset: Cell::new(0) };
    let t = view.tip_height();
    assert_eq!(d.tick(&view).unwrap(), FundingTick::Wait, "anchor set at T, jitter pending");

    // The authoritative tip REGRESSES by 2: the anchor must re-clamp to T-2.
    view.offset.set(2);
    assert_eq!(view.tip_height(), t - 2);
    assert_eq!(d.tick(&view).unwrap(), FundingTick::Wait, "re-clamped, still inside the delay");

    // Tip recovers to T. Readiness is measured from the re-clamped anchor
    // (T-2)+3 = T+1 -- NOT from the original T (which would demand T+3), and
    // the anchor must not have re-anchored upward on the recovery tick.
    view.offset.set(0);
    assert_eq!(
        d.tick(&view).unwrap(),
        FundingTick::Wait,
        "at T the re-clamped delay has one block to go"
    );
    chain.mine(); // T+1
    assert_eq!(
        d.tick(&view).unwrap(),
        FundingTick::BroadcastOurSetup,
        "readiness fires at (T-k)+jitter from the re-clamped anchor -- a regression must \
         never cost tip-recovery PLUS jitter"
    );
}

/// A view whose agreement funding reads FLICKER: each (method, outpoint) pair
/// answers genuinely ONCE, then degrades to unconfirmed -- the one-read
/// transient a live dual-source view can produce when a source lags between
/// two queries. Everything else answers genuinely.
struct FlickerOnce {
    inner: SimChain,
    heights_seen: RefCell<HashSet<OutPoint>>,
    readings_seen: RefCell<HashSet<OutPoint>>,
}
impl ChainView for FlickerOnce {
    fn tip_height(&self) -> u32 {
        self.inner.tip_height()
    }
    fn funding_height(&self, op: OutPoint) -> Option<u32> {
        if self.heights_seen.borrow_mut().insert(op) {
            self.inner.funding_height(op)
        } else {
            None
        }
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
        if self.readings_seen.borrow_mut().insert(op) {
            self.inner.verified_funding_reading(op)
        } else {
            FundingReading::Unconfirmed
        }
    }
    fn authoritative_funding_height(&self, op: OutPoint) -> Option<u32> {
        self.inner.authoritative_funding_height(op)
    }
    fn spending_witness_sig(&self, op: OutPoint) -> Option<[u8; 64]> {
        self.inner.spending_witness_sig(op)
    }
    fn broadcast(&self, tx: &[u8]) -> Result<bitcoin::Txid> {
        self.inner.broadcast(tx)
    }
    fn submit_package(&self, p: &[u8], c: &[u8]) -> Result<(bitcoin::Txid, bitcoin::Txid)> {
        self.inner.submit_package(p, c)
    }
}
impl AuthoritativeChainView for FlickerOnce {}

/// The handoff PINS its agreement funding reads (finding M): `into_funded`'s
/// coordinator go-signal and settlement's `await_funded` are separate reads of
/// a live view, and a one-read flicker landing between them used to turn a
/// fully-funded honest swap into a session-consuming `Fatal`. With the pin,
/// the whole handoff judges the first (genuine) reading and mints the
/// `Funded` -- a flicker can never destroy the peer session.
#[test]
fn handoff_pins_its_funding_reads_against_a_one_read_flicker() {
    let manifest = SignedManifest::provisional();
    let params = manifest.params().clone();
    let chain = SimChain::new(900_000);
    let (a, b) = two_parties(&chain, &manifest, 900_000);

    // Both escrows confirm for real.
    chain.broadcast(&a.setup).unwrap();
    chain.broadcast(&b.setup).unwrap();
    chain.mine();

    let mut d =
        FundingDriver::begin(&manifest, &a.pk, &b.pk, a.escrow_op, b.escrow_op, 900_500, 0)
            .unwrap();
    d.setup_broadcast();

    // Every agreement read after the FIRST returns unconfirmed: without the
    // pin, the coordinator's go-signal reads pass and `await_funded`'s own
    // re-read then sees None -> Err -> HandoffError::Fatal (session gone).
    let flicker = FlickerOnce {
        inner: chain.clone(),
        heights_seen: RefCell::new(HashSet::new()),
        readings_seen: RefCell::new(HashSet::new()),
    };
    let funded = d
        .into_funded(params, dead_peer(), &flicker)
        .expect("the pinned handoff must absorb a one-read flicker, never a Fatal");
    assert!(matches!(funded.role(), Role::SecretHolder | Role::SecretLearner));
}
