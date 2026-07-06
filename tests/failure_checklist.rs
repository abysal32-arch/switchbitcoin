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
//! STATUS: rows 2, 5, 6 are implemented against the crypto core (no chain
//! needed). Rows 1, 3, 4, 7, 8 require the tx/chain layer (escrows, dual-source
//! chain view, watchtower runtime) and stay ignored until it exists.

use newkey::settlement::params::Params;
use newkey::signing::{commit_and_reveal, SigningSession, SingleSignerLease};
use newkey::wire::parse_message;
use secp::Scalar;

fn test_key_ctx() -> (musig2::KeyAggContext, Scalar) {
    let mut rng = rand::rng();
    let sk = Scalar::random(&mut rng);
    let other = Scalar::random(&mut rng);
    let mut keys = [sk * secp::G, other * secp::G];
    keys.sort_by_key(|p| p.serialize());
    (musig2::KeyAggContext::new(keys).expect("valid keys"), sk)
}

// ---- 1. Happy path --------------------------------------------------------
#[test]
#[ignore = "tx/chain layer: full swap, both outputs == D, no external input, completions decorrelated"]
fn happy_path_full_swap() {
    // Assert: both completion outputs equal params.tier_d_sats exactly.
    // Assert: neither completion has an external (non-escrow) input.
    // Assert: on-chain gap between the two completions reflects the claim delay.
    // (The crypto-core half — exchange, extraction, claim — is proven in
    // settlement::state_machine::tests::two_party_exchange_extract_and_claim.)
    unimplemented!("happy path needs the tx/chain layer");
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
#[ignore = "watchtower runtime: SH broadcasts then dies; watchtower bumps or fires pre-armed refund at deadline"]
fn sh_offline_after_broadcast_watchtower_covers() {
    unimplemented!("SH-offline pre-armed refund needs the watchtower runtime");
}

// ---- 4. Refund/completion race (completion-supersedes) ---------------------
#[test]
#[ignore = "chain layer: induce both; verify completion-supersedes + deterministic CSV reconciliation; no self-double-spend"]
fn refund_completion_race_resolves_deterministically() {
    // The DECISION half (should_refund: never fight a winning completion;
    // InMempool routes to extraction) is unit-tested in settlement::refund.
    unimplemented!("full race needs the chain layer");
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
#[ignore = "tx/chain layer: one side never funds; funded side reclaims via refund leaf; nothing broadcastable against it"]
fn partial_funding_funded_side_reclaims() {
    unimplemented!("partial funding needs the tx/chain layer");
}

// ---- 8. Congestion beyond delta_fee ---------------------------------------
#[test]
#[ignore = "tx/chain layer: fee spike > delta_fee; completion prompts opt-in bump; refund uses silent backstop"]
fn congestion_backstop_behaves() {
    unimplemented!("congestion backstop needs the tx/chain layer");
}
