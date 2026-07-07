# New Key Protocol — External Cryptographer Review Packet

**Artifact:** settlement-core reference scaffold (Rust crate `newkey` v0.0.1), spec baseline v3.13–v3.16
**Path:** `C:\Users\Joe\Desktop\swap key\newkey-scaffold`
**Prepared for:** external cryptographer review — the hard stop-gate before any testnet promotion
**Status of packet:** synthesis of six reviewer mappings; all file:line citations preserved from source review.

---

## 1. Purpose — why this is the hard gate

The New Key Protocol settles a two-party coin swap through a **novel composition** of four primitives that individually are well-understood but whose *interaction* is load-bearing and unaudited:

1. **Adaptor-signature settlement** — a MuSig2 pre-signature adaptor-shifted by `T = t·G`; broadcasting the completion reveals `s_final`, from which the counterparty extracts `t` and claims.
2. **Possession gating (G1)** — the Secret-Learner (SL) releases its single enabling partial *only after* it holds a verified complete pre-signature for the transaction it must later extract from, so "the other party can broadcast" and "I can already extract" become simultaneous.
3. **Ordered timelocks** — two escrows with relative BIP68 CSV refund leaves maturing at Δ_early (SL-funded) and Δ_late (SH-funded), plus policy deadlines (Δ_buffer, claim-delay bound) that must nest correctly to keep an "extract-and-race" window unreachable.
4. **Baked-in fees (Δ_fee)** — a fixed per-tier fee margin funded into each escrow so completion/refund pay for themselves with **zero change**, which is also the privacy linchpin.

No individual primitive is novel enough to need review; **the composition is.** The failure modes that matter are not "is MuSig2 correct" (it is inherited from a pinned library) but "does the *ordering* of possession, broadcast, extraction, and timelock maturity leave any reachable state in which one party can take funds without the other's guaranteed recourse." That is a protocol-composition question, and it is exactly what an external cryptographer is being asked to bless. Per the project memory, **external cryptographer review is the declared stop-gate**; nothing proceeds to a real testnet swap until this composition is signed off.

The reviewer's time is best spent on **Section 4 (Open Questions)** — the deliberate, self-flagged divergences and subtleties — with Sections 3 (mapping) and 6 (test evidence) as the substrate.

---

## 2. What to review — load-bearing files

| File | Role in the composition |
|---|---|
| `src/crypto/adaptor.rs` | `CompletePreSig` type; adaptor construction, `verify_adaptor`, `extract_secret` (the `t·G == T` correctness guard); serialization + re-verification on restore. |
| `src/signing/mod.rs` | MuSig2 session lifecycle; nonce invariants INV-1..4; concurrent-session interlock primitive; `assemble_complete_presig`; single-signer lease. |
| `src/settlement/state_machine.rs` | The Phase-5 driver: six-message ordered exchange, possession gate G1, crash-safe persist-then-release, broadcast deadline gate (G2), claim-delay sampling, role derivation. **The composition lives here.** |
| `src/settlement/params.rs` | All timelock/deadline/fee arithmetic and its totality/ordering `validate()` invariants. |
| `src/settlement/refund.rs` | Pre-armed refund, watchtower receipt (G2 witness), completion-supersedes subroutine, own-device watchtower `poll`. |
| `src/tx/` (`escrow.rs`, `txbuild.rs`) | Taproot escrow + refund leaf, tweak-equality guard, TRUC/v3 + ephemeral-anchor completion/refund builders. |
| `src/crypto/validate.rs` | Curve-point / scalar / nonce / partial / final-sig validation gate (the deserialization hard gate). |
| `src/chain.rs` | `SimChain` (consensus *physics* only — no script/sig execution) + dual-source chain-view logic. **Read the limitations, Section 5.** |

Supporting: `src/wire/mod.rs` (message tags + round-trip parsing).

---

## 3. Clause-by-clause mapping (organized under the v3.13 external-audit list)

Status legend: **implemented** (built + enforced, typically type-level) · **partial** (core built, part deferred/approximated) · **stub** (primitives exist, policy binding absent) · **divergence** (intentional deviation from spec letter — see Section 4) · **deferred** (correctly out of frozen scope).

### 3.1 Adaptor construction & exchange ordering

| Requirement | Spec | Code location | Status | Test |
|---|---|---|---|---|
| Complete pre-sig = aggregate of **both** partials over agreed nonce, adaptor-shifted by `T`, verifying against `(R+T,P,m)`; not constructible from a lone partial (closes v3.11 bug) | v3.13 Ph5 L5,26,86–88; audit L249 | `signing/mod.rs:300` `assemble_complete_presig` (→`:309`); `crypto/adaptor.rs:88–134` `CompletePreSig`+`new()` (pub(crate)); verify `adaptor.rs:143`→`:148` | implemented | `state_machine.rs:990` (end-to-end both legs, independent BIP340 verify `:899`) |
| Exact Phase-5 message order, each verified before next sent; any failure aborts both sessions | v3.13 Ph5 L82–89,128 | `state_machine.rs:416` `run_adaptor_exchange` (commit `:445/:446`; reveal `:449/:453`; re-check `:460`; SH `T:476`/`ShPartials:481`/recv `:487`; SL `T:513`/`ShPartials:517`/enabling `:576`); tags `wire/mod.rs:29–47` | implemented | `state_machine.rs:990`; wire round-trip + unknown-tag reject `wire/mod.rs:187,205` |
| Concurrent-session interlock: both sessions' nonces committed before either revealed (Wagner/Drijvers) | v3.13 L23,83–84,101 | `signing/mod.rs:224` `commit_and_reveal`; wire enforcement `state_machine.rs:444–464`; `sign_partial` refuses if `!committed_both_sessions` (`:193`) | implemented | `signing/mod.rs:352,376`; wire-mismatch branch `state_machine.rs:460` (happy-path only — see 4) |
| Possession gate **G1**: SL releases enabling partial only after verified complete pre-sig for Comp→SH, bound to this swap | v3.13 L88,23,252 | assemble `:533`→verify `:537`; own-leg `:541/:545`; `PossessionWitness` mint `:572`; `release_enabling_partial:268` (sole tag-0x04 sender, swap-id check `:273`) | implemented | `state_machine.rs:1036` (definitive G1 negative: corrupt partial → no release, no record) |
| G1 crash-safety: persist pre-sigs **before** releasing enabling partial | v3.13 Ph5 L89; SM L99,102,130–131 | `state_machine.rs:552`→`write_possession_record:616` (atomic tmp+rename `:651–653`) **before** mint/release; restore `:722` re-verifies both legs `:750–751`; serde `adaptor.rs:189/:217/:259` | implemented | `state_machine.rs:1138` (fresh-process restore+claim); `:1173` (corrupt record → Err) |
| Extraction correctness: recover `t = s_final − s_hat`; never return a wrong secret (`t·G == T`) | v3.13 Ph5 L92; audit L249 | `adaptor.rs:157` `extract_secret` (reveal `:160`; zero-check `:162–167`; `t·G==T` guard `:168–170`); driver `state_machine.rs:843` (SL-only `:836`) | implemented | `state_machine.rs:1198` (unrelated final sig → Err); `:990/:1028` (extracted `t` proven correct by independent BIP340 verify) |

### 3.2 Nonce lifecycle (INV-1..4)

| Requirement | Spec | Code location | Status | Test |
|---|---|---|---|---|
| INV-1 no-persistence: secret nonce volatile-memory only | v3.16 Req3; v3.13 L69,83,98 | `signing/mod.rs:126` `SecretNonce(SecNonce)` — no Serialize/Clone/Debug; docs `:7–22` | implemented (no-persistence half) | by construction; no on-disk-absence test (honest gap) |
| INV-1 **scrubbing** half: nonce material wiped, not merely dropped | v3.16 Req3; review item #4 | `signing/mod.rs:10–22` (caveats a/b/c); seed `:160–166`; seckey `:138` | **divergence** | none (documented; not testable vs current deps) |
| INV-2 no session survives restart → ABORT_REFUND | v3.16 Req3; v3.13 L99,96–99 | `signing/mod.rs:131–142` (no (de)serialize); `begin():152–178` sole constructor | implemented | `signing/mod.rs:390–413` (crash via `mem::forget`, restart refused) |
| INV-3 single-signer lease keyed to swap_session_id | v3.16 Req3; v3.13 L224 | `signing/mod.rs:66–121` `SingleSignerLease`; atomic `create_new` `:92–108`; `Rc<..>` required at construction | **partial** (local-FS prototype of a cross-device primitive) | `signing/mod.rs:337–349,390–413` |
| INV-4 fresh nonce every session/retry; BIP327 NonceGen w/ fresh randomness only; deterministic forbidden | v3.16 Req3+Req1; v3.13 L69,83,98 | `signing/mod.rs:152–178` (OsRng seed `:160–163`→`SecNonce::generate:166`, domain tag `b"newkey-v3.16"`); `sign_partial(self)` consumes session `:192` | implemented | `signing/mod.rs:415–425` (identical inputs → distinct nonces) |

### 3.3 Timelock & deadline arithmetic

| Requirement | Spec | Code location | Status | Test |
|---|---|---|---|---|
| Δ_late = Δ_early + margin, **strictly** later; ordering invariant inviolable | v3.16 Req6 L59; v3.13 L70 | `params.rs:56` `delta_late()` (u64); `validate():62` rejects margin==0 (`:64–66`); ≤u16::MAX `:90` | implemented | `params.rs::provisional_defaults_validate`, `::ordering_violations_are_rejected_not_panicked` |
| Δ_buffer real deadline strictly inside (0, Δ_early); SH confirms Comp→SH by S+Δ_early−Δ_buffer | v3.16 Req6; v3.13 SM L112, Map L166 | `params.rs:68–69` validate; gate `state_machine.rs:806–812` (`>=` refuses boundary) | implemented | `broadcast_gate_boundary_and_receipt` (S+120 refused, S+119 allowed) |
| Broadcast gate = evidence not bool: runway **AND** watchtower armed w/ *this* refund | v3.13 SM L111–113; policy G2 | `state_machine.rs:794–822`; watchtower check `:813`; `WatchtowerReceipt` `refund.rs:87–112` | implemented | `broadcast_gate_boundary_and_receipt` (wrong receipt → Err) |
| Claim-delay bound: even at max delay, SL confirms before S+Δ_late | v3.16 Req6 L66; v3.13 Map L171, L251 | `params.rs` `max_claim_delay`; sampler `state_machine.rs:698–709`; consumed `:831–854` | implemented — **SEMANTICS TIGHTENED 2026-07-07 (⚠ post-packet change inside the frozen timelock surface — re-review):** the budget now ends at `deadline − allowance − 1` (extra −1). Rationale: under BIP68 the SH refund is includable in block `anchor+Δ_late` ITSELF, so a claim budgeted to confirm AT the deadline shares a block with the live refund — the boundary is the race. The change strictly SHRINKS the granted delay (safe direction), and the wallet-layer manifest enforces the matching static bound (`delay_max < margin+Δ_buffer−cofund−allowance`, strict). Checklist row 5's property is now strict (`<` not `<=`). | `two_party_exchange_extract_and_claim`, `claim_delay_sampler_respects_boundaries`, row-5 strict property |
| **Co-funding-skew anchor fix**: SL claim deadline anchored to swept escrow height `f_sh`, not S | v3.13 L21/L75; v3.16 L59 | `params.rs:103–118`; `Funded.sweep_escrow_height` `state_machine.rs:89–99`, set `:360–366`; used `:847–849` | **divergence-as-hardening** (see 4.1) | **no skew≠0 test** — both paths go through `funded_manual` (skew=0). Gap. |
| Escrow orientation: SL-funded→Δ_early, SH-funded→Δ_late; leaves for both orderings, unused discarded | v3.13 L70; Map L176/L181 | `escrow.rs:85–117` builds **one** CSV leaf; `txbuild.rs:90–124` uses `csv_blocks()`. No role→{Δ_early\|Δ_late} mapper in production. | **stub** (primitives exist; policy binding absent) | tests pass literal CSV (216,144), not role-derived. No orientation assertion. |
| Relative-vs-S reasoning: on-chain CSVs are BIP68 relative (consensus); S+Δ are policy | v3.13 Map L176/L181 vs L166/L171, L182 | `chain.rs:147–160` (tip−funding≥CSV); `escrow.rs:53–61` `from_height`; `refund.rs:54–56` `csv_maturity = s_height + csv_blocks` | **partial** | `chain.rs::csv_spend_is_rejected_until_matured`, `::double_spend_of_confirmed_output_is_rejected` |

### 3.4 KeyAgg coefficients & canonical ordering (rogue-key safety)

| Requirement | Spec | Code location | Status | Test |
|---|---|---|---|---|
| KeyAgg uses BIP327 per-key coefficients (rogue-key-safe) | v3.13 L22,68,234; v3.16 Req1 | `musig2::KeyAggContext::new` at `state_machine.rs:226`, `escrow.rs:184`, `txbuild.rs:199`, `refund.rs:261`, `adaptor.rs:249` | implemented (inherited from pinned dep) | `escrow.rs:188–207`; **no rogue-key attack test** (property inherited from library audit) |
| Canonical lexicographic party ordering for KeyAgg (order-dependent) | v3.13 L22,44,68,234 | `state_machine.rs:220–227` `canonical_key_agg` (sorts, rejects a==b); **re-implemented inline** at `escrow.rs:183`, `txbuild.rs:198`, `refund.rs:260` | implemented (divergence-**risk**: 4 duplicate sort sites — see 4) | incidental via escrow/signing tests |

### 3.5 Taproot leaves & validation gate

| Requirement | Spec | Code location | Status | Test |
|---|---|---|---|---|
| Refund leaf `<N> OP_CSV OP_DROP <funder_xonly> OP_CHECKSIG` (owner-only, relative CSV) | v3.13 L68,70; v3.16 L51 | `escrow.rs:53–61` `refund_leaf_script` (`from_height`); `Escrow::new:85–117`; control block `:140–144`; CSV bounded u16 `:90` | implemented (single leaf; "both orderings/discard unused" not built) | `escrow_builds_p2tr_and_tweak_equality_holds`, `csv_out_of_16bit_range_is_rejected` |
| Funded-key==signed-key: tweaked aggregate byte-equals escrow output key else abort | v3.13 L249; v3.16 Req2 | `escrow.rs:156–169` `taproot_tweaked_keyagg` (`with_taproot_tweak`→compare→`TweakMismatch`) | implemented | `escrow.rs:198–203` (tweaked x-only == output key) |
| Mandatory validation of all deserialized curve points/scalars before math; invalid → abort | v3.16 Req2; v3.13 L87 | `crypto/validate.rs` `ValidatedPoint:56`, `Scalar:80`, `PubNonce:99`, `Partial:121`, `FinalSig:142` (each `from_bytes` sole ctor) | implemented | `validate.rs:169,182,191,198` (garbage/identity/zero/overflow gates) |

### 3.6 Fee / funding / change arithmetic

| Requirement | Spec | Code location | Status | Test |
|---|---|---|---|---|
| Δ_fee fixed, signed, versioned, manifest-distributed, not user-editable | v3.13 L11,35 | `params.rs:24` field; `:45` default 5_000; `validate():83–85` rejects 0 | **partial** (plain field; no signing/versioning — deferred to manifest layer) | `provisional_defaults_validate` |
| Escrow input = D + Δ_fee (Setup spends UTXO whole, no change) | v3.13 L37; Map L153/L158 | `tx::setup::build_setup` — whole pre-encumbrance UTXO → escrow, single input, `[escrow(D+Δ_fee), anchor]`, no change; escrow outpoint = setup_txid:0 | **implemented** | `setup_is_zero_change_and_signs_the_pre_encumbrance`, `full_swap_from_real_setup_funding` |
| Completion output = exactly D to fresh dest; Δ_fee→miner; single value output + anchor, no child | v3.13 L38,163–170,201 | `txbuild.rs:54–84` `build_completion` (1 in; `[TxOut(D→dest), ephemeral_anchor()]`) | implemented | `taproot_swap.rs:89,156,167` — but **no `output[0].value==D` assertion** (see 4) |
| Refund output = D+Δ_fee − fee, above dust | v3.13 L39,173–180 | `txbuild.rs:90–124` `build_refund`; wired `refund.rs:36–58` | **partial** (**no dust floor** anywhere) | `failure_checklist.rs:637–652`, `refund.rs:255` |
| Every contract tx TRUC/v3 | v3.13 L4,27,74,197 | `txbuild::TRUC_VERSION = Version(3)`, applied to completion/refund AND `setup::build_setup` | **partial** (all three contract txs are v3; SimChain enforces no TRUC package-relay semantics — info gap) | `txbuild.rs`, `refund.rs`, `setup.rs` |
| TRUC/v3 ephemeral anchor (P2A), spent only on real fee spike w/ consent, else unspent | v3.13 L12,40–41,74,197–203 | `txbuild.rs:34–39` `ephemeral_anchor()` (OP_1 0x4e73), attached `:74,:108` | **partial** (anchor present; **CPFP child + consent gate unbuilt**) | `refund.rs:280`, `failure_checklist.rs:592` |
| Congestion backstop: opt-in CPFP from reserve UTXO; off by default | v3.13 L40–41,108,140 | `chain.rs:48/50,81–83,167–169` (min-fee gate + RBF); **no reserve-UTXO/CPFP builder** | **partial** (stall/RBF physics real; reserve-CPFP + consent + escalation stubbed/approximated) | `failure_checklist.rs:592`, `chain.rs:419,430` |
| Onboarding auto-split → D+Δ_fee UTXOs + single change (the ONLY change in lifecycle) | v3.13 L10,58,192–195 | **not implemented** (`onboarding_delay_hours` param `:37` only) | **stub** (deferred to wallet layer) | none |
| Fee = input − output, saturating (arithmetic totality) | v3.13 L249; Req6 totality | `chain.rs:138–163` (`saturating_add`/`sub`); height/deadline u64 saturating `params.rs:56,114–118` | implemented | `chain.rs:419,430`; `params.rs:131` (no panic at u32::MAX) |

### 3.7 Watchtower bundle & deadline discipline (G2), completion-supersedes, dual-source view

| Requirement | Spec | Code location | Status | Test |
|---|---|---|---|---|
| Pre-armed refund exists on disk before any completion broadcast | v3.13 Pre-armed/§Deadline b1 | `refund.rs:36` `arm`; `:61` `from_signed_tx`; input at `state_machine.rs:153`, threaded `:507/:589` | implemented (does not re-verify sig — tx layer's job, `refund.rs:19–20`) | `arm_produces_a_signed_script_path_refund`, `sh_offline_after_broadcast_watchtower_covers` |
| G2 part 1 (runway): broadcast only with runway to S+Δ_early−Δ_buffer | v3.13 §Settlement, §Deadline b2 | `state_machine.rs:794`, runway `:806–812` | implemented (confirmation depth folded into Δ_buffer — see 4) | `two_party_exchange_extract_and_claim` |
| G2 part 2 (armed watchtower): unforgeable receipt, not a bool | v3.13 §Settlement, §Deadline b2 | `broadcast_completion` takes `&WatchtowerReceipt`, `matches():813–817`; receipt non-Clone/private, sole ctor `confirm_watchtower_handoff:102` (fingerprint echo `refund.rs:77`) | implemented (proves "a tower ack'd this refund", not "a live tower will fire" — see 4) | `watchtower_receipt_requires_matching_echo` |
| Completion-supersedes: before refunding, re-check completion (confirmed **or** mempool) → don't refund, take swap | v3.13 §Refund subroutine b1–2 | `refund.rs:129` `should_refund`; `:143` `completion_status_of`; `:164` `run` (re-reads every entry `:154–163`) | implemented (InMempool treated as winning → extract; caller routes to extraction) | `completion_supersedes_decision_table`, `refund_completion_race_resolves_deterministically` |
| Watchtower InMempool handling: only **confirmed** is terminal; evicted completion must not stand tower down | v3.13 §Deadline b3 | `refund.rs:214` `Watchtower::poll` (Confirmed→terminal; InMempool→transient keep-watching; Unspent&matured→fire) | implemented (correct disposition asymmetry vs `run()` — see notes) | `watchtower_waits_through_mempool_completion_then_fires_on_eviction` (named regression) |
| Deterministic race reconciliation; wallet never self-double-spends | v3.13 §Refund b5 | chain layer: `chain.rs:129` `broadcast` (rejects 2nd spend of confirmed `:178–180`, CSV maturity `:148–160`); surfaced `refund.rs:176` | implemented (SIM physics, not consensus) | `double_spend_of_confirmed_output_is_rejected`, `refund_completion_race_resolves_deterministically` |
| Self-verifying dual-source chain view; SV source AUTHORITATIVE; proceed-gate disagreement → wait-or-abort | v3.13 What's-New; Threat "eclipse" | `chain.rs` `ChainSource`/`is_self_verifying`; `DualSourceChainView` (`new` needs ≥1 SV); `verified_*` Err on disagreement (the proceed-to-sign gate → `funding_height` waits); `authoritative_tip_height`/`authoritative_spend_status` (the self-verifying source's reading, used by the refund/watchtower path so a liar cannot strand a matured refund) | **partial** — `is_self_verifying` is a **bool label**; no real BIP157/158 filter or PoW-header validation (see 5) | `dual_source_requires_at_least_one_self_verifying`, `eclipse_all_api_path_is_defeated_by_the_self_verifying_source`, `await_funded_refuses_under_eclipse_but_proceeds_on_agreement`, `lying_source_cannot_suppress_a_matured_refund` |
| Self-limiting third-party watchtower delegated-**claim** bundle (t-gated ŝ(Comp→SL), trigger, per-swap delegation key, TEK-wrapped) | v3.13 Delegation bundle; v3.16 Req5 | **own-device SH-side refund tower present** (`refund.rs:183` `Watchtower`/`poll`); delegated SL-side claim bundle **deferred/unbuilt** | **partial** (own-device only, per Req5 frozen scope) | SH-side fully tested; **no delegated-claim / delegation-key test** |

---

## 4. OPEN QUESTIONS FOR THE REVIEWER

These are the decisions and subtleties that most need expert eyes. Each is a place where the implementation makes a defensible choice that is *not* a literal transcription of the spec, or where a security property rests on an assumption only a cryptographer can ratify.

### 4.1 Timelock anchoring — the central question

**The divergence.** The spec (v3.13 L21, L75) states plainly that **all relative timelocks key off `S = max(f_our, f_their)`** and derives the atomicity/ordering proof from a single shared `S`. The implementation **anchors SL's claim deadline to `f_sh`** — the confirmation height of the SH-funded escrow SL actually sweeps — via `sweep_escrow_height = their_h` (`state_machine.rs:360–366`, consumed `:847–849`), **not** to `S`.

**Why the implementation is stricter (and, we believe, correct).** Bitcoin's relative CSV on the SH-funded escrow matures from *that UTXO's own funding height*, not from `S`. If the SH-funded escrow confirmed *earlier* than ours, its refund leaf (`Refund(SH)` at `f_sh + Δ_late`, consensus-enforced) matures up to `cofunding_window` blocks **before** `S + Δ_late`. Anchoring SL's claim budget to `S` would over-grant SL up to `cofunding_window` blocks and **reopen a reachable extract-and-race window**. The refund-leaf CSV is fixed in Phase 3, *before* `S` is even known, so a per-escrow anchor is the only consensus-honest baseline. Anchoring to `f_sh` is strictly conservative. Rationale in code: `params.rs:107–113`.

**What the reviewer must decide:**
1. **Is per-escrow anchoring the intended reading?** Confirm the spec's "key off `S`" is *shorthand for the safe/conservative baseline*, not a literal on-chain anchor. If so, **the spec text should be reconciled** to match the implementation — this is a spec-vs-code divergence that must be closed in the spec, not the code.
2. **Is the defense-in-depth sufficient?** `validate()` at `params.rs:97–99` requires `delta_buffer > cofunding_window` so the SH broadcast buffer absorbs the same skew on the Comp→SH side. Confirm this is adequate **given the buffer is also consumed by confirmation depth** (see 4.4).
3. **The skew path is tested at two levels.** `failure_checklist.rs::cofunding_skew_anchors_claim_to_swept_escrow_not_s` drives `await_funded` at maximum skew (`f_sh = S − cofunding_window`), asserts `sweep_escrow_height == f_sh`, and proves the correctly-anchored claim confirms before `f_sh + Δ_late` while the *old* S-anchored bound would have breached it. And `failure_checklist.rs::full_swap_under_cofunding_skew` now drives the **complete six-message exchange + broadcast + extract + claim** end-to-end through `await_funded` (real role derivation, not `funded_manual`) with the SH-funded escrow confirming a full `cofunding_window` earlier than the SL-funded one, asserting SL's actual sampled claim confirms before `f_sh + Δ_late` (strictly earlier than `S + Δ_late`). Both are regression guards for the critical fix. **Reviewer should still ratify the anchoring choice itself** (points 1–2 above) — the tests prove the code does what it intends, not that the intent matches an authoritative spec reading.

Related maturity-bookkeeping subtlety: `PreArmedRefund::arm` (`refund.rs:54`) computes `csv_maturity_height = s_height + csv_blocks` using `S` as base. Under skew this over-grants the *pre-armed refund's* ETA — but this is only a wallet-side "when to attempt" hint; the chain layer independently rejects a premature spend (`chain.rs:153`), so it cannot cause a consensus-invalid broadcast, only a mistimed attempt. Reviewer should still confirm `arm()` callers pass per-escrow funding height when skew is possible.

### 4.2 Role-seed LSB → party-bit choice

`state_machine.rs:350–356`:
```
we_are_a    = our_session_pubkey < their_session_pubkey;
seed_picks_a = (seed[31] & 1) == 0;
role = SH  iff  we_are_a == seed_picks_a;
```
The spec says "the least-significant bit assigns SH" but **does not pin (a) LSB of which byte under which endianness, nor (b) which parity selects A vs B.** The code takes the LSB of the last byte of the big-endian SHA-256 and maps `LSB==0 → canonical user A is SH`. The scaffold self-flags this (`state_machine.rs:300–302,347–349`: "a documented stand-in"). Both wallets running *this* code agree (antisymmetric; tested `failure_checklist.rs:905`), so it is internally consistent — but it is a **unilateral convention not ratified against an authoritative spec bit-mapping.**

**Reviewer action:** ratify the exact bit-to-role convention as canonical. A divergence here between two independent implementations produces **two SHs or two SLs** — a non-atomic, potentially fund-losing state. Cheap to pin, dangerous if left ambiguous. Urgency: MEDIUM.

### 4.3 Concurrent-session interlock — wire-level enforcement & missing adversarial test

The interlock *primitive* is evidence-in-the-type (`public_nonce` readable only via `commit_and_reveal`, which needs both sibling sessions sharing one `Rc<SingleSignerLease>`; `sign_partial` hard-blocks before the flag is set). The *wire ordering* — both parties' commitments exchanged before either reveal, and the counterparty's revealed nonces re-hashed against their prior commitment — lives in the driver (`state_machine.rs:444–464`, mismatch → Err at `:460`).

**Reviewer should confirm** the driver matches the counterparty's commitment against the revealed nonces before aggregation (it does, at `:460`). The commitment-mismatch branch **is exercised adversarially** by `failure_checklist.rs::equivocated_nonce_reveal_is_rejected`: an `Equivocator` transport passes the counterparty's commitment through but substitutes a *different* valid `Nonces` reveal, and the victim aborts with `Error::Verification` before signing — the concurrent-session-attack property, proven negatively.

### 4.4 Deadline discipline — is Δ_buffer alone the right encoding of confirmation runway?

The G2 runway check is a pure height comparison (`current_height >= s_height + delta_early - delta_buffer → refuse`, `state_machine.rs:806–812`, `>=` so the boundary height is itself refused). The spec's "enough blocks to reach confirmation" is **folded into Δ_buffer sizing** rather than modeled as a separate confirmation-depth parameter. Since Δ_buffer is *also* required to exceed `cofunding_window` (4.1), it is doing double duty: skew absorption **and** confirmation runway.

**Reviewer should confirm** Δ_buffer alone is the intended encoding of both, and that the two demands on it (depth + skew) do not conflict at the tuned values (defaults: Δ_early=144, margin=72, Δ_buffer=24, cofunding_window=12).

Related: `broadcast_completion` returns the `CompletionSig` but **does not actually broadcast** — the Tor multi-peer broadcast + confirmation babysitting + fee bump is a documented stub (`state_machine.rs:819–820`). The deadline *arithmetic* is real; the network fill is deferred.

### 4.5 Possession gate G1 — liveness on undeliverable enabling partial

On release send-error (`state_machine.rs:576–580`) the code **deliberately does not unwind to refund**: it treats delivered-or-not as unknowable (TCP/Tor) and proceeds as released, relying on the persisted record. This is the correct crash-safe choice, but it means a genuinely-never-delivered enabling partial leaves SL committed to the extraction path while SH cannot complete — **both then refund via timelocks.** Consistent with spec L129 ("every intermediate state is non-broadcastable"). **Reviewer should confirm the liveness reasoning.**

Also: G1's binding-to-message (`msg_comp_sh`) is *recorded* (`:138`, dead_code) for audit, but the operative runtime check keys on **swap_session_id** (`:273`). Confirm swap-id binding is sufficient and that message binding need not be runtime-enforced.

### 4.6 Adaptor security rests on the pinned library's internal check

`assemble_complete_presig` trusts that `musig2 0.4.x`'s `aggregate_partial_signatures` performs the `(R+T,P,m)` verification internally (asserted in comment `signing/mod.rs:293`); it maps the library error to a generic `Verification` error and does **not** independently re-derive `R+T` before trusting it. `verify_adaptor` re-checks immediately after every assemble in `run_adaptor_exchange`, so the check is not skippable in practice — but **the reviewer should confirm the internal-verification claim against the pinned `musig2 0.4` source.** (See also 4.8: this is conduition/musig2, not libsecp256k1-zkp.)

### 4.7 Canonical-ordering duplication — divergence risk

**RESOLVED.** The canonical ordering is now a single source of truth: `state_machine::canonical_pair` (sort + reject-equal), with `canonical_key_agg` and `canonical_internal_key` built on it, and `role_seed` + `swap_session_id` derivations all routed through it. The four previously-inline sorts (`escrow.rs`, `txbuild.rs`, `refund.rs`, signing tests) and the two integration `aggregate_internal` helpers now call the shared helper — no duplicated sort remains. Reviewer should still confirm the *rule itself* (lexicographic sort of 33-byte compressed session pubkeys) matches the authoritative spec ordering.

### 4.8 Pinned-crypto identity (HIGH for scope awareness)

Req 1 mandates **libsecp256k1-zkp** (Blockstream fork, MuSig2+adaptor in one audited C module). The scaffold pins **conduition `musig2` 0.4 over stock libsecp256k1** (via `secp256k1 0.31` / `secp 0.7`). Curve *math* delegates to libsecp256k1 (satisfying "no hand-rolling"), but the **adaptor-signature algebra itself is conduition-Rust, not the zkp C module.** The audit items in 3.1/3.4 (adaptor construction, extraction, KeyAgg coefficients) are therefore being reviewed **against conduition/musig2 0.4, not libsecp256k1-zkp.** The reviewer should either **bless conduition/musig2 as the pinned dependency** or formally note that the spec's named library is not the one used. (Project memory references libsecp256k1-zkp as the eventual target.)

---

## 4.99 Cross-cutting invariant audit (forward-or-refund)

Beyond the per-module adversarial reviews, the whole built system was audited
against the **single safety invariant** the protocol exists to uphold:

> *Every reachable state of a swap either moves FORWARD toward both parties
> completing, or decays into an ALREADY-ARMED refund that returns the party's
> own coin. No reachable state is fund-loss, fund-stuck-with-no-exit, theft,
> self-double-spend, or a deadline that cannot be met. Recovery never depends
> on the counterparty being honest, online, or having a working device.*

Six independent adversarial attack lenses (funding phase, signing phase,
settlement/extract-and-race, crash-and-restart at every point, lying/eclipsed
chain view, griefing/Sybil) each tried to construct a reachable state that
breaks the invariant; every candidate was then adversarially verified against
the code. **Result: the invariant HOLDS.** One candidate surfaced; it was
refuted on verification; **zero surviving violations.** The prior 11 review
rounds' criticals (G1-window abort-stranding, co-funding-skew extract-and-race,
dual-source refund-stranding, boundary race at `delay_max==window`, in-mempool
refund-race, lying-source forced-abort) are all fixed and regression-tested.

**Two caveats bound the verdict** (both are exactly why THIS review exists):
1. It is conditional on the external cryptographer blessing the frozen
   adaptor+timelock composition — this document's whole purpose.
2. It is conditional on the modeled stand-ins (the `platform_secure_key`
   enclave key; the `SimChain`, which models consensus *physics* but does not
   execute Script or verify signatures) being replaced by real infra. Real
   BIP340 validity is proven separately in `tests/taproot_swap.rs`.

All residual items are either **capital-lockup griefing** (the coin always
returns — the invariant tolerates a bounded liveness delay, not a loss) or the
documented deferred infra/discovery seams in Section 5. Anti-griefing posture:
proof-of-encumbrance (the orchestrator verifies the counterparty escrow at
exactly D+Δ_fee before signing) + the tight co-funding window + Block-X are the
built defenses; `wallet::abort_hygiene` adds coordinator-free UTXO-keyed
rate-limiting of repeat aborters (pure liveness policy, never touches fund
safety). **Deferred and flagged for THIS review's scope:** burnable fidelity
bonds (v3.14) would touch the timelock surface, so they are NOT built onto the
frozen composition — scope them into the review rather than treating their
absence as a gap.

---

## 5. KNOWN STAND-INS & DEFERRED (honest inventory)

Nothing below is hidden; each is disclosed in-code. Urgency is for *this prototype review*.

| Item | Status | What exists / what's absent | Reviewer urgency |
|---|---|---|---|
| **TEK / GCM at-rest custody** (HKDF→TEK, AES-256-GCM, enclave-wrapped) | **implemented** | `crypto::storage`: `TEK = HKDF-SHA256(ikm=platform_secure_key, salt=swap_session_id, info="newkey-txn-enc")`; `seal` writes `[12-byte OS-CSPRNG nonce] ‖ AES-256-GCM(tek, nonce, plaintext)`; `open` fails closed on any tamper/truncation/wrong-key (GCM tag). The SL possession record is now **sealed** on write (`write_possession_record`) and **unsealed-then-parsed** on restore (`restore_secret_learner(path, swap_session_id)`) — attacker-controlled bytes reach the parser only after GCM auth. Per-swap TEK binds a record to its swap: `possession_record_is_bound_to_its_swap_session` proves a foreign `swap_session_id` cannot open it. Money-bearing secrets (`t`, MuSig2 seckeys) remain **never persisted**; the record still holds only public artifacts, so confidentiality here is defence-in-depth over the re-verify-on-restore integrity. `platform_secure_key` is a **documented fixed modeled stand-in** for the Secure Enclave key (a real build injects it). | LOW–MEDIUM — confirm AES-256-GCM under a 96-bit random nonce is acceptable for this per-TEK seal volume, the HKDF salt/ikm assignment, and the enclave-key injection seam. |
| **Real dual-source / BIP157-158** | **partial** | Disagreement-resolution + wait-or-abort collapse are real and tested. `is_self_verifying` is a **bool label** over an in-process SimChain: **no compact-filter client, no PoW-header validation, no independent header chain.** Eclipse defense proven only as "if one source is honest-and-labeled-SV, the gate refuses." | MEDIUM — gate wiring reviewable; the security-load-bearing filter/header client is deferred. |
| **Third-party watchtower delegated-claim bundle** | **partial (own-device only, per Req5)** | Own-device SH-side refund tower present + tested. **Deferred/unbuilt:** t-gated ŝ(Comp→SL) claim bundle, per-swap delegation-key exchange, mempool trigger predicate, TEK-wrapped at-rest bundle. Claim crypto (`extract_secret`+complete) exists in-process (`state_machine.rs:831`) but is **not packaged as a delegable redirect-proof bundle.** | LOW (explicitly out of first-build scope) — but the audit-list "watchtower bundle" item is unreviewable until built. |
| **Discovery layer (entire v3.15)** | **deferred (correct)** | Per v3.16 Req5, settlement core only; peers fed each other's `PeerSession` manually. No overlay/bootstrap/store-and-forward/quorum. | NONE for this review (explicitly scoped out). |
| **Setup-tx construction (zero-change)** | **implemented** | `tx::setup::build_setup` spends the whole D+Δ_fee pre-encumbrance UTXO (Taproot single-sig, `pre_encumbrance_spk`) into the escrow with NO change — single input, escrow output + ephemeral anchor, TRUC/v3, key-path signed with the funder's taproot-tweaked key. The SimChain now registers a confirmed tx's outputs as spendable, so `full_swap_from_real_setup_funding` runs the whole chain: pre-encumbrance → SL-first Setup → real escrow outpoint → adaptor swap → both completions at exactly D. | LOW — confirm the Setup fee model (0-fee TRUC bumped by the anchor under congestion) and the whole-UTXO/no-change arithmetic. |
| **SimChain does not run script / verify sigs** | **partial (deliberate, documented)** | SimChain models consensus **physics** (single-spend, CSV maturity, RBF, congestion min-fee) so the atomicity/ordering rows are meaningful — but **does not execute Bitcoin Script or verify signatures.** Any test broadcasting a `[0u8;64]` placeholder witness exercises **outpoint/timelock logic only.** Real BIP340 key-path validity is proven **only** in `tests/taproot_swap.rs` (bitcoin-side `verify_schnorr`) and independently in `state_machine.rs:899`. **No real bitcoind/testnet broadcast has occurred.** | MEDIUM — "confirmed in SimChain" is **not** evidence of a valid signature; the two proofs (physics vs sig-validity) live in different files, neither alone a full-node validation. |
| INV-1 memory-scrubbing (4.x) | **divergence** | No-persistence half fully type-enforced; scrubbing half best-effort — musig2 0.4.1 `SecNonce`, secp 0.7 `Scalar` carry no `Zeroize`; by-value seed copies drop unscrubbed (and NonceGen is deterministic in inputs, so a residual seed ≡ residual nonce). Fix belongs upstream. | MEDIUM — honestly flagged nonce-lifecycle deviation. |
| Δ_fee signing/versioning; SL-first order + funding jitter; `swap_key`=HKDF; real Tor broadcast | **stub/deferred** | Δ_fee is a plain field (no manifest signing/version-gating → equal-Δ_fee anonymity **cannot be enforced by this crate**). SL-first order + jitter absent (privacy/grief, not theft). Storage `swap_key`/HKDF→TEK is now **built** (see TEK/GCM row); **delegation-key** material (for the deferred watchtower claim bundle) remains absent. Tor/multi-peer/Dandelion entirely absent (comments only). | LOW–MEDIUM. |
| **Wallet layer: signed params manifest** (`src/wallet/manifest.rs`, outside the settlement crypto modules; BIP340 verify via the pinned libsecp256k1) | **implemented + adversarially reviewed (11 findings fixed, 2 high)** | v3.13 "signed manifest" trust path: tagged-hash (`newkey/manifest/v1`) BIP340 envelope against a pinned `ManifestTrustRoot` (modeled stand-in documented); strictly-monotonic version gate backed by a **quarantine-surviving floor sidecar** (fixes the fallback-downgrade replay); rollback-by-file-swap detection; ordering invariant + static delay/jitter/economic bounds asserted on EVERY parse regardless of signature (a compromised operator key cannot violate the timelock ordering or push a boundary-racing delay distribution); swap refusal compares (version, **id**) so same-version divergent-content manifests refuse. Honest limits: floor sidecar shares the disk (enclave counter is the real anti-rollback); `Params::testnet_provisional()` is still consumed directly by settlement entry points until the rank-4 orchestrator threads `ManifestStore::current().params()`. | LOW–MEDIUM — check the tagged-hash domain separation and the static delay-bound arithmetic against the runtime `max_claim_delay` (they are designed to coincide at the worst case, strictly inside the refund maturity). |
| **Wallet layer: SL claim scheduler + SH routing** (`src/wallet/claim_scheduler.rs`; `state_machine.rs` accessors; `chain.rs` `spending_witness_sig`; zero new curve math) | **implemented + adversarially reviewed (2 fixed: 1 high, 1 medium)** | v3.14 claim-delay decorrelation — the primary privacy-vs-liveness dial. Posture delay sampled from the signed manifest's active-posture `[min,max]` **clamped to the hard settlement ceiling** (`claim_delay_ceiling`, anchored to the swept escrow, budgets to deadline−allowance−1), so even the aggressive posture provably confirms strictly before the late refund. Mempool-first reveal (`observe_reveal` reads Comp→SH's witness sig from the authoritative source, confirmed or not). `next_broadcast`: Wait / Broadcast (incl. **fight a foreign racing spend** rather than stand down) / Won / Lost terminals. `sh_broadcast_decision`: runway (`deadline−tip ≥ safe_depth`) + watchtower gate → Broadcast/Wait/FallbackToRefund. Review fixes: a foreign mempool/confirmed spend of the swept escrow (SH's late refund) previously stranded SL (Wait forever) and misreported the loss as success — now SL fights the race (RBF; the winning fee bump is rank-6) and reports Lost distinctly. Analyzed-safe: a stale `reveal_height` cannot breach the bound (the ceiling subtracts it, `broadcast_at` adds it back — absolute cap holds). | LOW for crypto (no new curve math); MEDIUM — confirm the posture-clamp composition with `max_claim_delay` and that "fight the race" (RBF) is the intended response to SH's late refund appearing. |
| **Wallet layer: swap orchestrator** (`src/wallet/orchestrator.rs` + `chain.rs` funding-amount/txid/tri-state reads; zero new curve math) | **implemented + adversarially reviewed (1 medium fixed)** | Poll-driven pure decision machines over the settlement core: `FundingCoordinator` (canonical-order funding, deferred encumbrance verification of the counterparty escrow at exactly D+Δ_fee via the dual-source `verified_funding` read, co-funding window + Block-X abandon policy, per-party jitter) and `AbortDriver` (re-enterable completion-supersedes refund sink with terminal reconciliation via `spend_txid`). Review fix: a lying non-authoritative source could force a terminal Abort (DoS + script-leaf reveal) — now a `FundingReading` tri-state distinguishes genuine-wrong-amount (Abort) from source-disagreement (Wait; the self-verifying source is authoritative), and the Block-X no-show read is authoritative. **OPEN QUESTION for the reviewer:** "SL-first funding minimizes exposure" (v3.13/v3.14) cannot be enforced pre-role — SH/SL derive from txids+S only *after* both escrows confirm. The coordinator fixes the order by canonical session-pubkey sort (the only coordinator-free, both-agree option) and bounds exposure symmetrically; whether the spec intends a stronger SL-specifically-first guarantee (needing role pre-commitment) is a spec-resolution item. | LOW for crypto (no new curve math); MEDIUM — confirm the coordinator's `Proceed`-S and window agree with `await_funded`'s (they compute S = max(heights) identically), and resolve the SL-first framing. |
| **Wallet layer: coin ledger + onboarding** (`src/wallet/ledger.rs` + `keys.rs` + `tx::setup::build_onboarding_split`; zero new curve math — single-sig signing behind the `KeySource` enclave seam) | **implemented + adversarially reviewed (19 findings fixed, 4 high)** | v3.13 Phase 0–1: typed Phase-0 warning gate (exact spec copy echo); auto-split to exactly D+Δ_fee (≤64 outputs, shuffled change position, sub-dust folds to fee at the P2TR 330 threshold); randomized 24–72h delay **anchored at CONFIRMATION** and **double-anchored** (wall clock + chain-height floor — a shifted clock alone cannot collapse it); RBF `bump_split_fee` (same child keys/delays, all attempts tracked until one confirms) closes the stuck-split fund-lockout; class-pure non-mixing selectors; leases carry lessee identity + startup reconciliation; completion bumps from reserve demand a typed `LinkageAck` and the bumped swap's output carries a persisted `deposit_linked` taint; sealed fail-closed persistence, transactional mutators. Known limits: key-counter rewind on restore-from-backup needs `raise_key_index_floor` + forward scan (documented); MuSig2 swap signing still needs raw scalars (musig2 API — enclave exception documented). | LOW for the crypto review (no new curve math); MEDIUM for the privacy audit — the split-tx SHAPE is inherently classifiable as protocol usage (k equal outputs at tier size); the anonymity set is the tier, not unclassifiability — confirm this framing matches the spec's intent. |
| **Wallet layer: crash-safe SwapStore** (`src/wallet/store.rs`, OUTSIDE the frozen crypto-review surface — zero new curve math) | **implemented + adversarially reviewed (24 findings fixed, 1 critical)** | Sealed per-swap lifecycle records (format v2) under the same per-swap TEK; INV-2 non-resumability + INV-4 no-retry enforced by a phase transition table; G1-evidence recovery routing (possession record authenticates ⇒ Released/restore-and-extract, else AbortRefund); G2 crash half structural ("funded escrow without pre-armed refund" is unrepresentable); write-once money fields; fsync'd atomic writes; OS-file-lock single instance. **The critical (fixed + regression-tested):** a crash inside the G1 window (possession persisted, `put(Released)` not reached) previously blanket-aborted to refund and stranded SL when SH completed normally. Known accepted limits: no anti-rollback (needs an enclave-held monotonic counter — same seam as the modeled platform key); `write_possession_record` still hardcodes the modeled platform key, so a REAL `EnclaveKeyProvider` must be threaded into it or the two artifacts seal under different keys (flagged as a rank-4/K-ENCLAVE completion item). | LOW for the crypto review itself (no curve math); MEDIUM for the composition audit — the recovery routing (Signing→Released on G1 evidence) is a policy decision the reviewer should sanity-check against gates G1/G2. |
| `swap_session_id` = SHA256(sessionpub_lower‖higher) | **implemented** | Derived in `state_machine::swap_session_id` from the canonically-ordered session pubkeys and used to key the single-signer lease + bind the possession witness inside `run_adaptor_exchange` (the `PeerSession` field is now just a routing tag). Both wallets derive the same id. Unit test: `swap_session_id_is_canonical_and_agreed`. | LOW — confirm the derivation matches the spec formula. |

---

## 6. Test evidence summary

**End-to-end composition (the core proof):**
- `state_machine.rs:990` `two_party_exchange_extract_and_claim` — full ordered six-message exchange between two real parties over in-memory duplex; assemble+verify both legs; **independent BIP340 verification** of both completed signatures (`independently_verify_leg:899`); proves extracted `t` is correct because a wrong `t` could not produce a verifying signature (`:1028`); asserts claim lands before `S + Δ_late` for the actual sampled delay.

**G1 possession gate:**
- `state_machine.rs:1036` `sl_aborts_without_releasing_on_corrupt_sh_partial` — **definitive G1 negative**: `CorruptingTransport` flips a byte; SL aborts, never sends tag-0x04 (`:1126`), writes no possession record (`:1128`).

**Crash safety:**
- `state_machine.rs:1138` `sl_restores_possession_after_crash_and_claims` — drops in-memory `Possessing`, rebuilds from the **sealed** on-disk record in a fresh process, extracts + claims.
- `:1173` `corrupt_possession_record_is_rejected` — flipped ciphertext byte → GCM auth fails → restore Err (tamper never reaches the parser).
- `possession_record_is_bound_to_its_swap_session` — correct `swap_session_id` opens the sealed record; a foreign one fails the GCM tag (per-swap TEK binding).
- `signing/mod.rs:390–413` `real_crash_leaves_lease_held_and_refuses_signing` — crash via `mem::forget`; restart refused.

**At-rest storage crypto (`crypto::storage`):**
- `round_trips_under_the_derived_tek`, `per_swap_tek_and_unique_nonce` (distinct TEK per swap; unique ciphertext per seal), `tampering_and_wrong_key_are_rejected` (GCM tag rejects flipped byte and wrong TEK).

**Extraction correctness:**
- `state_machine.rs:1198` `extraction_rejects_unrelated_final_sig` — foreign swap's final sig → Err; own → Ok.

**Nonce lifecycle & interlock:**
- `signing/mod.rs:352,376` — lone/mismatched sessions rejected; signing before interlock refused.
- `:415–425` `fresh_nonce_every_session_even_same_inputs`.
- `:337–349` lease exclusivity.

**Timelocks & deadlines:**
- `broadcast_gate_boundary_and_receipt` — S+120 refused, S+119 allowed; wrong receipt → Err even with runway.
- `claim_delay_sampler_respects_boundaries`; `params.rs::ordering_violations_are_rejected_not_panicked`, `::provisional_defaults_validate`.

**Taproot / validation:**
- `escrow.rs:188–207` p2tr + tweak equality; `csv_out_of_16bit_range_is_rejected`.
- `validate.rs:169,182,191,198` — garbage/identity/zero/overflow gates.

**Watchtower / race / eclipse:**
- `watchtower_receipt_requires_matching_echo`; `sh_offline_after_broadcast_watchtower_covers`; `watchtower_waits_through_mempool_completion_then_fires_on_eviction` (named regression).
- `completion_supersedes_decision_table`; `refund_completion_race_resolves_deterministically`.
- `chain.rs` `double_spend_of_confirmed_output_is_rejected`, `csv_spend_is_rejected_until_matured`, `congestion_rejects_low_fee_and_accepts_bumped`, `higher_fee_replaces_mempool_incumbent_lower_does_not`; dual-source eclipse suite (`dual_source_requires_at_least_one_self_verifying` … `eclipse_all_api_path_is_defeated_by_the_self_verifying_source`, `await_funded_refuses_under_eclipse_but_proceeds_on_agreement`).

**Real BIP340 signature validity (separate from SimChain physics):**
- `tests/taproot_swap.rs:156,167` `verify_taproot_key_spend` (bitcoin secp256k1-0.29 side) — the only place a completed MuSig2+adaptor signature is proven a valid Taproot key-path witness.

**Notable test gaps (recap of Section 4):**
1. **No co-funding-skew (skew ≠ 0) test** — the central timelock-anchoring fix is coded but uncovered (4.1). *Highest-priority addition.*
2. No adversarial commitment-mismatch test (interlock wire branch) (4.3).
3. No rogue-key attack test (property inherited from library audit, not demonstrated) (3.4).
4. No escrow-orientation assertion (SL-escrow=Δ_early / SH-escrow=Δ_late is unwired) (3.3).
5. No `output[0].value == D` assertion on the completion (v3.13 L243 asks for it explicitly) (3.6).
6. No on-disk-absence test for the secret nonce (guarantee is by-construction) (3.2).

---

*Reviewer's shortest path:* read Section 4.1 (timelock anchoring) and 4.8 (library identity) first — they gate the composition's soundness and the very meaning of the adaptor audit; then the G1 flow in `state_machine.rs:416–590` against 3.1; then Section 5 to bound what the tests actually prove. The atomicity argument is only as strong as (a) the `f_sh` anchoring being correct and reconciled with the spec, and (b) conduition/musig2's internal `(R+T,P,m)` verification being genuine.