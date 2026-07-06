//! Test-first failure checklist (v3.16 Requirement 7).
//!
//! Each test below is written BEFORE the implementation and maps 1:1 to a
//! failure-path row. They are `#[ignore]` until the scaffold is filled; remove
//! `#[ignore]` as each is implemented. The prototype is not "testnet-validated"
//! until every one of these passes against a real testnet swap.
//!
//! Run:  cargo test            (skips ignored)
//!       cargo test -- --ignored   (runs these; they will fail until implemented)

// ---- 1. Happy path --------------------------------------------------------
#[test]
#[ignore = "implement: full swap, both outputs == D, no external input, completions decorrelated"]
fn happy_path_full_swap() {
    // Assert: both completion outputs equal params.tier_d_sats exactly.
    // Assert: neither completion has an external (non-escrow) input.
    // Assert: on-chain gap between the two completions reflects the claim delay.
    unimplemented!("happy path");
}

// ---- 2. Crash during signing (INV-4: no nonce reuse) ----------------------
#[test]
#[ignore = "implement: kill mid-signing -> ABORT_REFUND; prove no nonce reused on retry"]
fn crash_during_signing_never_reuses_nonce() {
    // Drop a SigningSession mid-flight; begin a fresh swap/retry.
    // Assert: the new session's nonce differs; no persisted nonce exists on disk.
    unimplemented!("crash-during-signing / INV-4");
}

// ---- 3. SH offline after broadcast (G2 crash-safety) ----------------------
#[test]
#[ignore = "implement: SH broadcasts then dies; watchtower bumps or fires pre-armed refund at deadline"]
fn sh_offline_after_broadcast_watchtower_covers() {
    unimplemented!("SH-offline pre-armed refund");
}

// ---- 4. Refund/completion race (completion-supersedes) ---------------------
#[test]
#[ignore = "implement: induce both; verify completion-supersedes + deterministic CSV reconciliation; no self-double-spend"]
fn refund_completion_race_resolves_deterministically() {
    unimplemented!("refund/completion race");
}

// ---- 5. Claim-delay bound (review item #5) --------------------------------
#[test]
#[ignore = "implement: max claim delay still confirms before S + delta_late"]
fn claim_delay_never_breaches_safe_window() {
    // Property test candidate: for all sampled delays d in [0, max],
    // reveal_height + d + expected_confirm < s + delta_late.
    unimplemented!("claim-delay bound");
}

// ---- 6. Invalid wire input (validation gate; never panic) -----------------
#[test]
#[ignore = "implement: feed fuzz corpus of malformed points/scalars/PSBTs; gate rejects, never panics/proceeds"]
fn invalid_wire_input_is_rejected_not_panicked() {
    // for each malformed sample: assert parse_message(sample).is_err();
    unimplemented!("validation gate");
}

// ---- 7. Partial funding / fund-and-run ------------------------------------
#[test]
#[ignore = "implement: one side never funds; funded side reclaims via refund leaf; nothing broadcastable against it"]
fn partial_funding_funded_side_reclaims() {
    unimplemented!("partial funding");
}

// ---- 8. Congestion beyond delta_fee ---------------------------------------
#[test]
#[ignore = "implement: fee spike > delta_fee; completion prompts opt-in bump; refund uses silent backstop"]
fn congestion_backstop_behaves() {
    unimplemented!("congestion backstop");
}
