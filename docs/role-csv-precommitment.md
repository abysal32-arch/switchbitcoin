# Role↔CSV pre-commitment — external review packet

Status: **OPEN — the mainnet stop-gate.** Pre-alpha ships regtest/testnet only;
no real funds until an external cryptographer answers the questions in §9.
Companion document: `docs/CRYPTOGRAPHER_REVIEW_PACKET.md` (the whole-protocol
packet; its §4.1 timelock-anchoring and §4.2 role-seed-bit questions are
subsumed and sharpened here). Code citations are against commit `fa3c17e`
(pre-alpha validated live on regtest, Bitcoin Core v29.4.0, 2026-07-13).

---

## 1. The problem in one paragraph

The protocol derives the two parties' roles (SecretHolder / SecretLearner)
from a hash of the two **funding txids** plus the **confirmation height S** —
values that do not exist until both escrows confirm. But each escrow's refund
leaf must carry the ROLE-correct relative timelock (`delta_early` = 144 blocks
on the SL-funded escrow, `delta_late` = 216 on the SH-funded one), and the
leaf is committed inside the escrow's P2TR output key — i.e. inside the very
scriptPubKey the funding transaction pays, which fixes the funding txid. Role
needs txids; txids need the CSV; the CSV needs role. Two independent parties
therefore **cannot pre-commit the role-correct CSVs**. The shipped interim
convention guesses, a guard refuses-and-refunds wrong guesses, and ~half of
all honest attempts abort to refund by design.

## 2. Protocol context (only what this question needs)

Two parties each fund one Taproot escrow from a pre-encumbrance coin via a
"Setup" transaction. Both escrows pay the same MuSig2 aggregate internal key
(role-independent), and each carries exactly one tapscript leaf:

```
<CSV> OP_CHECKSEQUENCEVERIFY OP_DROP <funder_xonly> OP_CHECKSIG
```

— the funder's unilateral refund after the relative timelock
(`src/tx/escrow.rs::Escrow::new`, escrow.rs:85–117; the leaf is in the
taptree, so the output key — hence the SPK, hence the funding txid —
**cryptographically commits to the CSV value**).

Roles: **SH** (SecretHolder) picks the adaptor secret t, publishes T, and
must broadcast+confirm the completion `Comp→SH` (sweeping the SL-funded
escrow `E_sl`) by the policy deadline `S + delta_early − delta_buffer`
(= S+120). Its broadcast is the **reveal**: the final signature leaks t.
**SL** (SecretLearner) observes the reveal, extracts t, and claims the
SH-funded escrow `E_sh` via `Comp→SL` within a posture-randomized delay
budgeted by `Params::max_claim_delay` (params.rs:257: deadline =
`anchor_height + delta_late()`). Forward-or-refund is the load-bearing
invariant: every funded escrow has a driven exit — completion, or the
**pre-armed refund**, a fully-signed script-path spend of the escrow's own
CSV leaf, armed *before* the Setup may broadcast (refund.rs:22–31,
runner.rs:354–369, 413–417).

Testnet-provisional params (params.rs:71–85): `delta_early`=144, `margin`=72
(so `delta_late`=216), `delta_buffer`=24, `claim_confirm_allowance`=6,
`cofunding_window`=12.

Funding is **structurally sequential**: the coordinator's `Second` arm
broadcasts only once the counterparty escrow is verified-confirmed at the
exact tier amount (orchestrator.rs:184–208, read via
funding_driver.rs:242–251), so the second Setup confirms at least one block
later — skew ≥ 1 and ≤ `cofunding_window`, enforced at handoff
(state_machine.rs:367–371). S is the later of the two confirmation heights.

## 3. The role derivation (v3.14, verbatim from code)

`Funding::await_funded` (state_machine.rs:350–418):

```
role_seed   = SHA256("newkey-role" || txid_lower || txid_higher || S_be)
canonical A = lexicographically smaller session pubkey (the KeyAgg sort)
seed_picks_a = (role_seed[31] & 1) == 0        // LSB → SH selection
role(us)    = SH  iff  we_are_a == seed_picks_a
```

The design intent recorded in the code (state_machine.rs:337–345): putting
S in the hash makes the role unpredictable before confirmation, so
"re-rolling a role costs a real on-chain funding, so grinding is
uneconomical." §7 (OBS-1) shows this intent is **not achieved** for the
second funder.

## 4. Why the CSV asymmetry is load-bearing (no symmetric escape)

The adversarial claim-window arithmetic (mirrored in params.rs:139–159):

* A **malicious SH** is not bound by the honest S+120 broadcast gate — it can
  complete the pre-signature itself and broadcast raw. Its reveal is bounded
  only by `E_sl`'s refund leaf: it must confirm `Comp→SH` before
  `f_sl + 144`, else SL refunds `E_sl` and SH gets nothing.
* SL's claim on `E_sh` must confirm before `E_sh`'s leaf matures at
  `f_sh + 216`.
* Worst case (SL funded second, `f_sl = f_sh + cofunding_window`), SL's
  guaranteed window is `(f_sh+216) − (f_sl+144) = margin − cofunding_window
  = 60 blocks`. `claim_confirm_allowance` must fit inside it — it does (6).

Scope caveat: only the runtime `max_claim_delay` clamp and
`Params::validate` are on this adversary-proof window. The manifest-layer
delay-bound validator still checks postures against the *looser* honest-SH
window `margin + delta_buffer − cofunding_window − allowance`
(manifest.rs:228–238), which the code itself flags as CRYPTOGRAPHER REVIEW
ITEM #5 (OPEN) — the runtime clamp is what makes this safe today. See R-6.

Both "make the escrows identical" variants collapse this window:

* **Both leaves at 216**: the malicious-SH reveal bound becomes `f_sl + 216`,
  the window becomes `≤ 0`, and SH takes both escrows. Unsound.
* **Both leaves at 144**: SL's claim deadline becomes `f_sh + 144 ≤` the
  reveal bound `f_sl + 144`. Window `≤ 0`. Unsound.

So the two escrows **must** carry different CSVs, and which escrow carries
which is exactly the role assignment. There is no symmetric-script exit —
the asymmetry is what creates SL's guaranteed post-reveal window. (Further
"single refund valid under either role" variants are refuted in §8c.)

## 5. The theft this enables (the deep audit's `SH-takes-both`)

At funding time roles are unknown, so the funding-time identity gate
`verify_their_escrow_spk` **must admit both candidate CSVs**
(funding_driver.rs:177–213: it reconstructs the counterparty escrow under
144 *and* 216 and accepts either — both bind the aggregate internal key, so
no solo-controlled output passes, but the CSV is unpinned). Meanwhile SL's
claim budget `max_claim_delay` hard-codes `delta_late` (params.rs:257–258).

The path, worst-case concrete: a malicious SH funds `E_sh` with CSV **144**
instead of 216. The funding gate admits it. SL budgets its post-reveal claim
against `f_sh + 216`. SH reveals adversarially late (near `f_sl + 144`) —
which is *at or past* `E_sh`'s true maturity `f_sh + 144`. SL's sampled
claim sits inside a budget that extends up to 72 blocks past the true
maturity, so SH refunds `E_sh` out from under the claim while its `Comp→SH`
sweeps `E_sl`: **SH exits with both escrows; SL loses its claim.**

## 6. What is shipped today (the mitigation under review)

### 6.1 The CSV-binding guard (commit `dd248b9`)

`SwapEngine::verify_swept_escrow_csv` (engine.rs:613–664), executed at the
top of `run_exchange` (engine.rs:532–541) — **before any ledger/store
mutation and before any partial signature is released**:

* Reconstructs the swept (counterparty-funded) escrow under the ROLE-correct
  CSV — `delta_late` when we are SL, `delta_early` when we are SH — and
  requires byte-equality with the on-chain SPK reported by the authoritative
  chain view. Because the P2TR output key commits to the single leaf,
  equality **proves** the leaf; any other SPK is hostile.
* On mismatch: abort → the pre-armed refund is the exit, exactly like an
  adaptor-exchange failure. Nothing is released.
* Exactness cuts both directions. The shorter-CSV direction is the theft in
  §5; the longer-CSV direction is not an obvious theft against the sweeper
  but breaks deadline nesting elsewhere (watchtower maturity prediction, the
  funder's own refund posture), and SPK-equality is in any case the only
  property a hash commitment can prove. Non-conforming ⇒ refuse.
* If the view cannot report the SPK (`None`), the guard defers to the
  funding gate: in production `into_funded` refuses the handoff outright on
  an unreported or mismatched counterparty SPK (funding_driver.rs:442–462;
  restated in the guard's docs, engine.rs:630–635). Reviewer: see R-6.

### 6.2 The interim convention (runner.rs:13–27, 303–313)

The canonically-smaller session pubkey (party A, also the first funder)
funds at `delta_early` (presumed SL); the larger (party B, second funder) at
`delta_late` (presumed SH). Presumed SH generates the adaptor secret
(runner.rs:371–374). When the derived flip agrees with the presumption the
swap settles; when it disagrees the guard refuses and both sides exit
through their pre-armed refunds. Both outcomes were observed live in the
Task-11 validation (2 of 4 attempts completed; every non-completing attempt
closed forward-or-refund on both sides, refund reclaims ledger-registered —
`docs/artifacts/regtest-run-2026-07-13.txt`, `manual-run-2026-07-13.txt`).

### 6.3 What the convention costs (why this gate matters commercially)

Honest-vs-honest, attempts are Bernoulli(½) ⇒ expected 2 attempts per
completed swap; each failed attempt, **per party**:

* burns the coin's fee budget on a refund instead of a completion
  (≈ `Δ_fee` = 5,000 sats at provisional params: 1,200 Setup fee + 3,320
  settlement fee + anchors);
* locks `D + Δ_fee` (≈ 0.01005 tBTC) until the refund leaf matures —
  ~24 h (144) or ~36 h (216);
* and — the dominating cost — the refund output re-enters the wallet as a
  `Swapped` coin, which `lease_pre_encumbrance` will not lease
  (ledger.rs:1125–1140): that capital must pass a fresh onboarding split
  with its randomized 24–72 h delay before it can fund another attempt.
* Privacy: each failed attempt leaves an extra Setup + leaf-path refund pair
  on-chain, a recognizable pattern that erodes the equal-escrow uniformity
  the tier design pays for.

So the practical retry latency is days, not blocks. This is THE usability
blocker for anything beyond pre-alpha, which is why candidate schemes are
worth a reviewed frozen-core seam.

## 7. OBS-1 (new, for reviewer confirmation): the current formula is already
## grindable by the second funder

The anti-grind intent of S-in-the-hash assumes role re-rolls cost an
on-chain funding. But once both Setups are *constructed*, both txids are
fixed (segwit; txids don't depend on witnesses), so
`role_seed(S) = SHA256("newkey-role" ‖ lo ‖ hi ‖ S)` is a pure, computable
function of the candidate confirmation height S. Funding is sequential
(§2): by the time the second funder may broadcast, the first escrow is
confirmed at height `f_1`, and S will be the second Setup's own confirmation
height, which the **second funder controls by broadcast timing** within the
`cofunding_window` (12 blocks):

* It evaluates `role_seed(h)` for each candidate `h ∈ (f_1, f_1+12]` —
  roughly half are favorable.
* It broadcasts targeting next-block inclusion at a favorable height; a
  one-block slip re-rolls a fair coin, so naive targeting already yields its
  preferred role with probability ≈ next-block-inclusion reliability.
* Targeting a *run* of two consecutive favorable heights (expected within
  ~4 candidate positions) makes even a one-block slip harmless; within the
  12-block window the achievable bias approaches 1.

Consequences, if confirmed:

1. The fairness the txid+S flip is meant to provide **does not hold against
   a strategic second funder** — who, under the convention, is party B, the
   presumed SH. B can force `derived == presumed` (always complete) or force
   mismatch (grief A into a refund cycle while looking honest-unlucky).
2. The ~50% refund tax is therefore paid only in honest-vs-honest runs; it
   buys no adversarial fairness. This materially weakens the case for
   keeping post-funding role derivation at all, and strengthens candidates
   (a)/(a′) below: moving to an explicit pre-funding assignment loses
   little fairness that actually exists today.
3. Related, pre-existing and orthogonal: session pubkeys are ephemeral and
   free to grind, so a party can already choose to be A or B — i.e. choose
   its **funding order** (second funder holds a free option to walk away
   after the first funder's capital confirms, costing A a refund cycle).
   Pre-funding role assignment does not add a new choice surface beyond
   these two.

A one-block miner-collusion variant of the same observation exists (a miner
shifting the second confirmation by one block re-rolls the bit), but the
broadcast-timing form needs no miner at all.

## 8. Candidate designs

Legend for each: mechanics → security argument → forward-or-refund →
curve math → integration cost → on-chain cost / rounds.

### (a) Commit-then-reveal role seed before funding  — RECOMMENDED-pending-R-1/R-4

Blum coin flip in the pre-swap handshake (runner.rs handshake, before any
capital moves): each party sends `C_i = SHA256("newkey-role-commit" ‖ sid ‖
r_i ‖ salt_i)`, then reveals; `role_seed' = SHA256("newkey-role-v2" ‖ sid ‖
r_A ‖ r_B)`, LSB assigns SH among the canonical (KeyAgg-sorted) users. Both
escrows are then built with **known-correct CSVs**; the funding gate pins
ONE expected counterparty SPK instead of two (strictly stronger than today);
the CSV-binding guard stays as an unchanged backstop.

* Security: binding/hiding from SHA256 commitments; neither party can bias
  the *completed* flip. The residual is Cleve's structural abort bias: the
  second revealer learns the outcome first and can abort — and pre-funding
  aborts are free, so a strategic party re-rolls until it gets its preferred
  role (Bentov–Kumaresan: refund-without-penalty does NOT neutralize abort
  incentives). Under OBS-1 this is not a regression — B already has
  near-total role choice today — and commit-reveal makes strategic aborts
  *observable and attributable* at the wallet layer (rate-limit / reputation
  / refuse-to-retry policy), which silent broadcast-timing grinding is not.
  Whether free role choice is acceptable at all is R-1. Side benefit: the
  role becomes reorg-immune (see R-5).
* Forward-or-refund: preserved identically — pre-armed refunds and the guard
  are untouched; a hostile peer funding a wrong-CSV escrow is refused at the
  (now stricter) funding gate or the guard, and refunds fire as today.
* Curve math: none (hash commitments only).
* Integration: +2 handshake frames (~80 lines in runner.rs incl. validation
  and domain separation); **one frozen-core seam** (§8.1); funding gate pins
  a single SPK (~10 lines in funding_driver.rs). No wire-envelope changes
  (the handshake precedes the Task-05 envelope by design).
* On-chain cost: none. Rounds: +2 messages pre-funding.

### (a′) Convention-authoritative assignment (degenerate (a))

Make the existing presumption binding: A (smaller session pubkey) IS SL.
No new frames; same frozen seam; ~15 wallet lines. Security-equivalent to
(a) under a *free-abort* adversary (both reduce to "adversary picks role":
here by grinding the ephemeral session key to sort as desired — zero
messages, zero evidence). (a) dominates (a′) only in abort-visibility;
(a′) dominates in simplicity. Same R-1 dependency.

### (b) Fund both CSV variants; abandon the wrong pair

Each party funds TWO escrows (one at 144, one at 216) from two
pre-encumbrance coins; role derives post-funding over the four txids + S
(fair flip preserved, and re-rolls again cost real fundings — now four); the
role-correct pair (SL's 144 + SH's 216) proceeds; the wrong pair exits
through its pre-armed refunds.

* Security: the only candidate that keeps an *actually fair* post-funding
  flip (modulo OBS-1-style timing grinding over the LAST confirmation — the
  4-txid variant needs its own grind analysis, R-7) while achieving 100%
  completion of the swap itself.
* Forward-or-refund: preserved per escrow (each of the four is born with a
  pre-armed refund).
* Curve math: none.
* Integration: frozen seam for the 4-txid role formula + live-pair
  selection; wallet-side dual funding coordination (lease two coins,
  4 Setups within the co-funding window) — the largest diff of any
  candidate.
* On-chain cost: **certain** waste of one Setup+refund pair per party per
  swap (vs. expected one-half pair today), 2× capital lockup during every
  swap, abandoned-pair capital held to leaf maturity (24–36 h) plus
  re-onboarding. Doubles the on-chain footprint the tier-privacy design
  wants uniform. Rounds: unchanged.

### (c) A single refund path valid under either role — REFUTED (three variants)

* **(c1) Dual funder-keyed leaves (144+216, both funder-keyed)**: the funder
  unilaterally uses the shorter leaf regardless of derived role — this IS
  the §5 theft, in-protocol. Unsound.
* **(c2) Dual leaves, early leaf keyed to the counterparty (or 2-of-2)**:
  early-leaf-to-sweeper lets the sweeper take the escrow after 144 *without
  completing* — sweeper-takes-both. Early-leaf-2-of-2 is cooperative-only:
  a withholding peer reverts the effective bound to the 216 leaf, which
  collapses SL's window per §4. Unsound.
* **(c3) Role-adaptor-gated early refund** (early spend completable only by
  the party the derived role entitles): the role derivation outputs a hash
  bit, not a scalar release; an adaptor gate needs a trustlessly-released
  secret correlated with the flip. No such release exists — a withholding
  counterparty again reverts to the 216 bound (window collapse). Making a
  script read post-funding chain data (txids, S) requires covenant
  introspection: **BIP-119 CTV / BIP-118 APO territory — not deployable
  today.** Flag for future consensus, out of scope.

Also considered: pushing the asymmetry into a **pre-signed descendant**
refund (Lightning-style plain 2-of-2 funding output, CSV via nSequence in a
cosigned refund tx — the DLC/LN pattern from the prior-art survey). Both
Setups' txids ARE known pre-broadcast, so cosigning before funding is
possible — but the role-correct nSequence is not (same circle), cosigning
both variants hands the funder the 144 variant (c1 again), and cosigning
*after* funding violates forward-or-refund on a vanished peer (the exact
reason the pre-armed refund must exist before Setup broadcast,
runner.rs:413–417). Same trilemma, no exit.

### (d) Deterministic role from pre-funding commitments (drop S from the hash)

Role over the two txids only (computable by the second funder before
broadcast — and by the first funder never): the second funder grinds its
own Setup (any non-witness degree of freedom) to choose the role
*invisibly*. Strictly dominated by (a′): identical adversarial power, no
transparency, plus it forfeits S's (partial) honest-case unpredictability.
Rejected.

### 8.1 The minimal frozen-core seam every viable candidate needs

`Funded` is only mintable via `await_funded` (derives the role itself) or
`funded_manual` (test seam: assumes zero skew, and skew ≥ 1 structurally;
feeding it `s_height=S` would set SL's sweep anchor to S, which the code
itself documents as over-granting under skew — state_machine.rs:106–109,
424–436). Its fields are private. **A pure wallet-layer candidate is
therefore impossible without smuggling role derivation around the frozen
surface — which is precisely the stop-gated decision.** The honest change is
a reviewed seam in `src/settlement/state_machine.rs`:

```rust
/// Like `await_funded`, but the role is an INPUT (pre-committed by the
/// negotiation layer) instead of derived from txids+S. Every other check
/// is identical: per-escrow confirmation heights, co-funding window,
/// distinct-txid and distinct-session-pubkey guards, S = max(heights),
/// sweep anchor = the counterparty escrow's own height.
pub fn await_funded_with_role(self, chain, our_funding, their_funding,
                              our_pk, their_pk, role: Role) -> Result<Funded>
```

≈ 20 lines, no curve math, diff = `await_funded` minus the seed block. Per
the frozen-surface rule and the stop-gate, **this packet proposes it and
pre-alpha does NOT implement it**; steps 1–2 of Task 12 ship without it.

### 8.2 Comparison

| | fair vs. strategic peer | completion (honest) | forward-or-refund | curve math | frozen diff | on-chain overhead |
|---|---|---|---|---|---|---|
| status quo | NO (OBS-1: B chooses) | ~50% | ✔ (guard) | — | none | E[1 refund pair]/2 per swap |
| (a) commit-reveal | NO vs. free-aborter, but visible | ~100% | ✔ unchanged | none | ~20-line seam | none |
| (a′) convention | NO (key grind), invisible | ~100% | ✔ unchanged | none | ~20-line seam | none |
| (b) fund both | YES (pending R-7 grind check) | 100% | ✔ per escrow | none | seam + formula | certain 1 refund pair/party/swap, 2× capital |
| (c) single refund | — | — | ✘ or window collapse | — | — | REFUTED / needs CTV-APO |
| (d) drop S | NO, invisible | ~100% | ✔ unchanged | none | seam | none — dominated by (a′) |

## 9. Questions for the external cryptographer

Answer format suggestion: confirm / refute / conditional, with the condition.

* **R-1 (the crux): role-utility asymmetry.** Under adversarial role
  *choice* (free and repeatable), can the chooser extract value beyond
  nuisance? Axes to bound: capital-lockup asymmetry (own-refund at 144 vs
  216); deadline pressure (SH must confirm by S+120 under fee volatility vs
  SL's reactive claim); fee-spike exposure during the claim window;
  privacy-posture asymmetry (SL's randomized claim delay); informational
  (SH chooses t/T); funding-order interaction (§7 note 3 — the second
  funder's free walk-away option exists under EVERY design including the
  status quo). If the asymmetry is boundable ⇒ (a)/(a′) are sound and the
  fix is the §8.1 seam. If not ⇒ (b) is the fallback; please also then rate
  whether a forfeit-on-abort deposit (Bentov–Kumaresan F*CR-style; new
  protocol surface, currently forbidden by the frozen-core rule) is
  preferable to (b)'s certain 2× cost.
* **R-2: confirm OBS-1** (second-funder broadcast-timing grind on S, §7),
  its achievable bias within `cofunding_window`=12, and whether it
  invalidates the v3.14 rationale for txid+S derivation independently of
  any candidate. Include the compounding: session-key grinding (§7 note 3)
  lets an adversary *choose* to sort as party B — i.e. guarantee it is the
  second funder holding the S-timing grind. Do the two free grinds compose
  into deterministic role choice?
* **R-3: the seam.** Are `await_funded_with_role` semantics (§8.1) —
  role as input, all other checks identical, sweep anchor = counterparty
  escrow's own height — sufficient and necessary? Anything else in the
  settlement machine assumes the role was txid-derived?
* **R-4: the (a) construction.** Commitment scheme (SHA256, sid-bound,
  salted), domain tags, LSB extraction, both-reveal-or-abort policy,
  cross-session commitment replay, and the abort/retry policy surface
  (rate-limiting recommendation). Subsumes the old §4.2 bit-ratification
  ask: pin the exact bit→role convention for (a) and for the status quo.
* **R-5: reorg behavior.** Current formula: a reorg displacing S or a
  funding txid after one party derived and before the other re-rolls the
  seed → role divergence → Phase-A verification failure → abort-refund.
  Confirm no worse outcome exists (esp. divergence discovered only at
  guard/claim time), and confirm (a)'s reorg-immunity is a genuine benefit.
* **R-6: the guard as universal backstop.** Is exact-SPK reconstruction
  (engine.rs:636–664) sufficient under every candidate: internal-key
  role-independence, the `None`-SPK deferral to the funding gate
  (engine.rs:630–635), and the exactness-in-both-directions policy (§6.1)?
* **R-7: if (b).** Review the 4-txid formula + live-pair selection for
  reintroduced grinding (last confirmer times the final height) and for
  pair-selection ambiguity under skewed confirmations.
* **R-8: interim posture.** Any objection to continued regtest/testnet
  pre-alpha operation on convention+guard at ~50% refunds while R-1..R-7
  are open?
* **R-9: `funded_manual`.** The zero-skew test seam is `pub` today. Should
  production builds gate it out (cfg(test)/feature) before any mainnet
  consideration?

## 10. Prior art (survey, 2026-07-13)

* **No deployed protocol assigns roles by post-funding randomness.**
  Lightning (BOLT2 single- and dual-funded), DLCs, COMIT/Farcaster XMR-BTC,
  Boltz submarine swaps, Belcher CoinSwap, Tier Nolan's original design all
  fix roles by out-of-band convention or economic position; the txid+S
  pattern appears novel/unpublished (treat as unproven — no literature to
  lean on, and OBS-1 suggests why the pattern is unattractive).
* **Fair two-party coin flipping**: Blum (commit-reveal, structural ¼ abort
  bias); Cleve 1986 (no r-round two-party flip beats Ω(1/r) bias — bias-zero
  is impossible, so "who aborts, and what it costs" is the whole game);
  Moran–Naor–Segev 2009 (optimal Θ(1/r)); Bentov–Kumaresan CRYPTO 2014
  (claim-or-refund with *forfeitable deposits* — the standard answer to
  free-abort bias; a free refund fallback does not remove the incentive).
* **Beacon grinding**: Bonneau–Clark–Goldfeder 2015 — manipulation
  resistance of blockchain randomness; the lens behind OBS-1.
* **The txid↔script circularity**: BIP-119 CTV excludes the input txid from
  its template hash for exactly this chicken-and-egg reason; BIP-118 APO
  unbinds signatures from outpoints. Both are the consensus-level dissolvers
  of this problem class and both are **not deployable** (no active soft
  fork). Lightning's structural workaround — keep the funding output
  role-agnostic, push asymmetry into pre-signed descendants — fails here
  against forward-or-refund (§8c, pre-signed-descendant note). DLC's
  symmetric refund (single cosigned CLTV tx) avoids the problem by having no
  unilateral per-party leaf at all — unavailable here because the dead-peer
  refund story (pre-armed refund + watchtower) requires exactly that leaf.

## 11. Empirical measurement (Task-12 step 2)

Two measurements ship with this packet; both assert, per attempt, the
STRONG property that the outcome equals the seed-bit prediction (refunds are
*exactly* the convention mismatches — the convention is a fair coin, not
worse), plus forward-or-refund closure on both sides.

* **SimChain, large-N** (fast, no node): `tests/runner.rs::
  measure_role_csv_refund_rate` — `SWAPKEY_RATE_ATTEMPTS` (default 32):
  `cargo test --test runner measure_role_csv_refund_rate -- --ignored --nocapture`
* **Live regtest** (real bitcoind + two swapkey-cli processes):
  `tests/regtest_e2e.rs::e2e_measure_refund_rate` — default 4 attempts:
  `cargo test --features bitcoind --test regtest_e2e e2e_measure_refund_rate -- --ignored --nocapture`

Results (this revision, 2026-07-13):

* SimChain, N=32: **completed 18/32 (56.2%), refunded 14/32,
  prediction-mismatches 0** — every refund was exactly a seed-bit mismatch,
  and the rate sits well inside the 3σ band around p=½ (deviation 2.00,
  bound 8.49). Runtime 38 s.
* Live regtest, dedicated `e2e_measure_refund_rate` runs (N=4 + N=8, 12
  attempts total): **7/12 completed (58.3%), 5/12 refunded; all 5 refunds
  closed forward-or-refund on both sides.** Per-attempt log:
  `docs/artifacts/role-csv-rate-2026-07-13.txt`. With Task-11's prior live
  evidence (2/4, `docs/artifacts/`), 9/16 live attempts completed (56.3%).

## 12. Code map (for the reviewer)

| What | Where |
|---|---|
| Role derivation (txids+S, LSB) | `src/settlement/state_machine.rs:337–418` |
| `funded_manual` zero-skew test seam | `src/settlement/state_machine.rs:424–436` |
| Sweep-anchor over-grant warning | `src/settlement/state_machine.rs:106–109` |
| Escrow leaf ⊂ P2TR output key | `src/tx/escrow.rs:85–117` |
| Funding gate admits both CSVs | `src/wallet/funding_driver.rs:177–213` |
| Sequential funding (skew ≥ 1) | `src/wallet/orchestrator.rs:184–208` (read: `funding_driver.rs:242–251`) |
| Manifest delay-bound — looser window, ITEM #5 OPEN | `src/wallet/manifest.rs:228–238` |
| Pinned handoff → `await_funded` | `src/wallet/funding_driver.rs:405–488` |
| CSV-binding guard + threat doc | `src/wallet/engine.rs:532–541, 613–664` |
| `max_claim_delay` hard-codes late | `src/settlement/params.rs:244–260` |
| Window invariant (margin − window) | `src/settlement/params.rs:127–160` |
| Interim convention | `src/wallet/runner.rs:13–27, 303–313, 340, 371–374` |
| Pre-armed refund (leaf spend, pre-broadcast) | `src/settlement/refund.rs:22–31`, `src/wallet/runner.rs:354–369, 413–417` |
| Refund capital not re-leasable | `src/wallet/ledger.rs:1125–1140` |
| Guard commit / live validation | `dd248b9` / `fa3c17e` + `docs/artifacts/` |

**Frozen surface note:** this packet analyzes `src/settlement/*`,
`src/crypto/*`, `src/tx/escrow.rs` but Task 12 modified none of them; §8.1
is a proposal, not a diff. Pre-alpha remains regtest/testnet-only.
