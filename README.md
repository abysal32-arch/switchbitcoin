# Swap Key Protocol — Settlement-Core Scaffold (v3.16)

This is the **step-1/step-2 reference scaffold** from the v3.16 build sequence:
pinned crypto + validation gate + nonce invariants + settlement core, with
**discovery stubbed**. It is *not* an implementation — every `todo!`/
`unimplemented!` is a fill point. The value is that the **dangerous decisions are
already encoded in the types and invariants**, so filling it in cannot quietly
break them.

> Built by hand without a local Rust toolchain. **First thing to do: `cargo check`**
> and fix any mechanical errors (imports, versions, trait bounds). Treat the crate
> versions in `Cargo.toml` as starting points — pin to current releases.

## Hard rules that must survive implementation (do not weaken)

1. **Pinned crypto (Req 1).** MuSig2, adaptor sigs, and nonce gen come from
   `libsecp256k1-zkp` via the `musig2` crate. **No hand-rolling.** No pure-Rust
   curve backend for anything touching funds.
2. **Validation gate (Req 2).** The only way to obtain a `ValidatedPoint` /
   `ValidatedScalar` / `ValidatedPubNonce` / `ValidatedPartial` is the validating
   constructor. Keep inner fields private. Parsed `Message`s are validated by
   construction.
3. **Nonce invariants INV-1..4 (Req 3).** `SecretNonce` stays `!Clone`,
   `!Serialize`, zeroized on drop, private. `SigningSession` has **no** resume /
   deserialize / with-nonce path. Crash ⇒ drop ⇒ `ABORT_REFUND`.
4. **Fuzz the parser (Req 4).** `wire::parse_message` must be **total** — never
   panic. `fuzz/` is set up; run it from commit one.
5. **Frozen scope (Req 5).** Fill settlement only. Do **not** add overlay /
   store-and-forward / bootstrap. `PeerSession` is handed in manually.
6. **Parameter ordering (Req 6).** `Params::validate` enforces the safety-critical
   timelock ordering. Values may be tuned; the ordering check may not fail.
7. **Test-first (Req 7).** `tests/failure_checklist.rs` holds one `#[ignore]` test
   per failure path. Un-ignore each as you implement it. Not testnet-valid until
   all pass.

## The two gates the external cryptographer must confirm are enforced

- **G1 Possession** — `PossessionWitness` is constructible only after verifying we
  hold a valid `CompletePreSig` for the tx we must extract from. SL's enabling
  partial is released only against that witness. (`settlement::state_machine`,
  `signing`, `crypto::adaptor`.)
- **G2 Deadline** — `broadcast_completion` refuses without runway + armed
  watchtower + an already-armed `PreArmedRefund`. The race region is unreachable
  incl. under crash/restart. (`settlement::state_machine`, `settlement::refund`.)

## Suggested fill order

1. `cargo check`; pin dependency versions; get it compiling with `unimplemented!`.
2. `crypto::validate` — wire up real `secp256k1`/`musig2` parsing + on-curve /
   range checks. Then `wire::parse_message` (length-checked, gate-routed).
3. Start fuzzing `wire_parse` immediately; keep it green as you go.
4. `signing` — real `NonceGen`, partial sign/verify, complete-pre-sig assembly.
   Prove INV-1..4 with tests (esp. crash + retry ⇒ fresh nonce).
5. `crypto::adaptor` — extraction `t = s_final − s_hat`, with the `t*G == T`
   check. This is cryptographer review item #2 — get it reviewed.
6. `settlement::state_machine` + `refund` — the typestate transitions and the
   completion-supersedes subroutine. Enforce G1/G2.
7. Drive one real **testnet** swap end-to-end with `PeerSession` supplied by hand.
8. Un-ignore the failure checklist tests as each path works.

## Do NOT proceed to build anything on top of this until

the **scoped external cryptographer review** (build sequence step 4) clears the
adaptor + timelock composition, the exchange ordering, extraction correctness,
and the nonce lifecycle. The scaffold is structured to make that review easy:
the load-bearing operations are isolated in `crypto::adaptor` and `signing`.

## Layout

```
src/
  lib.rs                     crate root; Error/Result; the invariant summary
  crypto/
    validate.rs              the validation gate (newtypes = proof-of-validation)
    adaptor.rs               adaptor point, complete pre-sig, EXTRACTION (review #2)
  signing/mod.rs             SecretNonce + SigningSession — INV-1..4 (review #4)
  wire/mod.rs                Phase-5 messages + parser (THE fuzz target)
  settlement/
    params.rs                provisional signed params + ordering invariant (review #5)
    state_machine.rs         typestate phases; gates G1 (possession) & G2 (deadline)
    refund.rs                pre-armed refund + completion-supersedes subroutine
tests/failure_checklist.rs   Req-7 tests, one per failure path (start #[ignore])
fuzz/…                       cargo-fuzz target for the wire parser (Req 4)
```
