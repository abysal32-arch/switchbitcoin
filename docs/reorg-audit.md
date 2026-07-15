# Reorg + stale-tip robustness audit (Task 22)

**Scope of risk.** Regtest never reorged under us; testnet4 *will* — multi-block
reorgs are routine there, and spy/spam waves make stale tips and flapping fee
estimates normal. Every deadline in SwapKey is **height-anchored**. A reorg can
(a) make a "confirmed" funding vanish, (b) shift an anchor height, or (c) pull
the tip **backwards** between polls. This document walks every height-anchored
value, answers *"what happens if the block that produced this un-confirms?"*,
and records a verdict: **safe as-is**, **hardened here**, or **deferred to
cryptographer review** (a hole that can only be closed inside the frozen
settlement core — the scope guard forbids patching `settlement/*`, `crypto/*`,
`tx/*`).

**Guiding principle (the invariant this audit defends).** Forward-or-refund must
hold through any reorg, and a reorg may only ever **DELAY** an exit, never
**accelerate** one past its safety window. "Frozen time is safe" — the existing
node-outage rule (serve the last known tip) is the precedent.

**Method.** Two independent lines of defense already exist and are the reason
almost every row below is *safe as-is*:

1. **Live re-reads.** The drivers are pure decision functions re-run every poll,
   reading the chain fresh. A cached height is safe only if it is either
   *re-derived* from the current chain each poll or *provably conservative* when
   stale. This audit checks each one.
2. **Chain physics as a backstop.** `SimChain` and the real
   `BitcoinCoreChainView` both enforce relative-timelock (CSV) maturity, funding
   existence, and double-spend rules at broadcast. A deadline computed from a
   stale anchor that says "fire now" is still *rejected by the node* if the real
   CSV has not matured — so a stale anchor can delay, not accelerate.

The real backend adds a third: `BitcoinCoreChainView` binds every confirmed read
to its block hash and revalidates it per query against
`getblockheader.confirmations`, so a reorged-away confirmation *drops out of the
cache* instead of being reported forever (`chain/bitcoind.rs` module docs,
`funding_binding_race_reads_unknown_not_wrong_block`).

---

## 1. The reorg model (what a reorg does to the facts a deadline reads)

`SimChain` gained reorg primitives (`chain/mod.rs`) that mirror testnet:

| Primitive | Models |
|---|---|
| `unconfirm_funding(op)` | a funding output whose block was orphaned — `funding_height`/`amount`/`spk` all read *not confirmed*, amount retained for re-confirmation |
| `reconfirm_funding_at(op, h)` | the SAME outpoint re-confirming at a **new** height (the anchor-shift hazard) |
| `unconfirm_spend(op)` | a confirmed spend returning to the mempool; a later `mine()` re-confirms it at the new height |
| `rewind_to(new_tip)` / `rewind(n)` | the tip moving **backwards** N blocks, orphaning every confirmation above the fork; re-mining re-confirms the returned-to-mempool txs, possibly at different heights |

These make the failure-checklist rows testable; the real backend surfaces the
same truths from the node.

---

## 2. Height-anchor enumeration, per phase

Each row: the anchor, whether it is re-derived or cached, what a reorg does, and
the verdict.

### Phase: deposit registered → split confirmed (onboarding)

| Anchor | Kind | Reorg behavior | Verdict |
|---|---|---|---|
| `Ledger` deposit `confirmed_height` (register_deposit) | recorded | The deposit UTXO vanishes; any split/spend of it is rejected by the node (`missing inputs`) — nothing confirms through a vanished deposit. | **safe as-is** (physics gate) |
| `confirm_split` `created_height` + `eligible_height` (onboarding delay) | recorded, **double-anchored** with a wall clock | On un-confirm/re-confirm the FIRST confirmation's anchors are kept (`ledger.rs` "Known nuance" doc) — the coin can become eligible from the earlier height. This is a **bounded privacy nuance**, not fund loss: eligibility is an anti-correlation delay, and leasing a coin whose split has un-confirmed still fails at the node (missing inputs). | **safe as-is** (documented privacy nuance; physics gate) |
| Split flipped-winner reorg (RBF rival confirms) | — | The activated children become never-existed phantoms; a phantom Reserve is healed by `sweep_spent_reserves` (shape 2) + `run_cpfp_bump`'s submit-failure self-heal. | **safe as-is** (existing heal; `flipped_winner_reorg_phantom_reserve_is_swept`) |

### Phase: funding confirmed / `record_funding` (co-funding baseline)

The proceed-to-sign gate is **agreement-required** on the *current* chain
(`FundingCoordinator::next_funding_action`): both escrows must read confirmed on
`funding_height` this poll. Block-X uses the **authoritative** funding heights.

| Anchor | Kind | Reorg behavior | Verdict |
|---|---|---|---|
| `funding_height(escrow)` (proceed gate) | live re-read | Un-confirm → the `(Some, Some)` gate fails → `Wait` (never signs against a vanished confirmation). Re-confirm at a different height → gate re-opens with S re-derived. | **safe as-is** — test `reorg_unconfirming_an_escrow_withdraws_the_proceed_gate` (hardened test) |
| Block-X (`authoritative_funding_height`) | live re-read | A lying source cannot fabricate a no-show; a genuine un-confirm past Block-X pre-broadcast aborts cleanly (nothing locked). | **safe as-is** |
| co-funding window `\|oh − th\|` | live re-read | Recomputed from current heights each poll. | **safe as-is** |
| `Proceed { s_height = oh.max(th) }` | live re-read at handoff, then **pinned** for the handoff (`PinnedFundingView`), then **frozen** into the record | A reorg between a `Proceed` tick and `into_funded` is a non-consuming `Refused` (re-drive) — `funding_driver.rs` docs. | **safe as-is** |

### The two WRITE-ONCE record anchors (set at Funding→Signing, never re-derived)

`SwapRecord.s_height` and `SwapRecord.sweep_escrow_height` are written **once** at
the Funding→Signing transition from `funded.s_height()` /
`funded.sweep_escrow_height()` (engine `run_exchange`) and are then immutable
(`store.rs check_against`). They are consumed by **settlement-core** deadline
math (`Possessing`/`Funded`, frozen surface). This is the audit's one genuine
gap.

| Anchor | Consumed by | Dangerous direction | Mitigation | Verdict |
|---|---|---|---|---|
| `sweep_escrow_height` | `Possessing::claim_delay_ceiling` → `Params::max_claim_delay(anchor, reveal)`; the SL claim delay is clamped to `anchor + Δ_late − allowance − 1`. | Cached **higher** than the real re-confirmed height (a reorg re-confirmed the swept escrow **lower**) makes the ceiling too generous — SL could clamp to broadcast *after* SH's real late-refund maturity, widening the race. | (1) `ClaimScheduler::next_broadcast` **fights the moment SH's refund appears** (foreign spend → `Broadcast`); SL's claim is timelock-free + RBF-able, so it can still win by fee. (2) The node enforces SH's real CSV maturity, so SH cannot refund early either. (3) The posture-sampled delay is usually « ceiling. (4) The swept escrow is typically buried many blocks deep by claim time, so a reorg deep enough to re-confirm it *lower* is a rare deep reorg on testnet4. | **deferred to cryptographer review** (frozen core; grouped with review item #5). Conservative direction (cached lower) is safe. |
| `s_height` | `Possessing::sh_broadcast_deadline` = `S + Δ_early − Δ_buffer`; `broadcast_completion` hard gate at the same height. | Cached **higher** than real (reorg lowered a confirmation) lets SH broadcast Comp→SH slightly later than a re-derived S would. | `Δ_buffer > cofunding_window` is a **designed** margin that already absorbs co-funding skew of up to a window (`params.rs` validate); a reorg-induced S shift is the same class of skew, within that buffer for shallow reorgs. Conservative direction (cached lower → earlier fallback-to-refund) is safe. | **deferred to cryptographer review** (frozen core) — the buffer covers shallow reorgs; a formal bound vs. reorg depth is a review item. |

**Why not hardened here.** Re-deriving these two anchors requires threading a
fresh height into `claim_delay_ceiling` / `sh_broadcast_deadline`, whose
signatures live in the frozen `settlement/state_machine.rs`. The scope guard
forbids it. The wallet layer *cannot* override the cached value without a core
signature change. Per Task 22 step 3, this is documented as a review item rather
than patched. The wallet **surfaces** the shift loudly (see §5) so it is visible
to a tester and to a bug report.

### Phase: Signing

Off-chain and volatile — no height anchors. A crash here is non-resumable
(INV-2) and routes by G1 evidence; unaffected by reorgs.

### Phase: Completing (claim scheduled / completion broadcast)

| Anchor | Kind | Reorg behavior | Verdict |
|---|---|---|---|
| `reveal_height` (SL claim anchor) | live read at observe time | The reveal is a *live* `spend_status`/witness read; a re-driven settle re-observes it. An evicted/reorged reveal → `AwaitingReveal` re-drive (`engine.rs step_settlement` docs). | **safe as-is** |
| `broadcast_at_height = reveal + delay` | derived from live reveal | Only bounds *when SL broadcasts on an UNSPENT escrow*. On any foreign spend (SH's refund racing), `next_broadcast` returns `Broadcast` regardless — it never stands down. | **safe as-is** — tests `reorg_reverting_our_confirmed_claim_is_not_a_stale_won`, `reorg_letting_a_foreign_refund_win_reports_lost_not_stale_won` |
| claim ceiling (uses `sweep_escrow_height`) | cached (see above) | — | **deferred** (see the write-once table) |
| congestion classifier (`classify_stalled_tx`) reveal/confirm reads | live | A confirmed completion at `Completing` classifies `None` (nothing to bump) even before the record advances; a reveal read is live. | **safe as-is** |

### Phase: Refunding

| Anchor | Kind | Reorg behavior | Verdict |
|---|---|---|---|
| Refund CSV maturity (dead-device tower fire) | **RE-DERIVED**: `WatchtowerDriver::effective_maturity` = `authoritative_funding_height(escrow) + csv_blocks` | Un-confirm → `authoritative_funding_height` = `None` → `effective_maturity` = `None` → **Idle** (never fires against a vanished funding). Re-confirm at a different height → maturity shifts to match. | **safe as-is** — tests `reorg_unconfirm_holds_the_fire_then_reconfirm_reshifts_maturity`, `fire_gate_uses_chain_derived_maturity_not_the_arm_prediction` |
| `PreArmedRefund.csv_maturity_height` (arm-time prediction) | cached **fallback only** | Used only when `csv_blocks` cannot be decoded from the signed refund; and a premature broadcast is rejected by the node's relative-timelock gate (`Deadline`), so the driver just re-polls. | **safe as-is** (fallback + physics gate) |
| `AbortDriver` refund maturity (`refund.csv_maturity_height()` vs live tip) | cached vs live | `BroadcastRefund` at `tip ≥ cached_maturity` — but a premature broadcast against a reorged-lower funding is rejected by the node (`relative timelock not matured`), so a reorg **delays** the refund, never fires it early. | **safe as-is** — test `csv_spend_against_unconfirmed_funding_is_refused` (physics gate) |

### Phase: terminal (Completed / Refunded)

| Anchor | Kind | Reorg behavior | Verdict |
|---|---|---|---|
| Terminal `Completed`/`Refunded` records | **RE-VALIDATED** against the chain by `RecoveryDriver` | A reorg-reverted completion → `Rebroadcast` (re-drive); a reorg that let a foreign spend win → `Completed→AbortRefund` / `Refunded→Completing` supersede (chain-proven, spender-attributed). Never a stale `Settled`. | **safe as-is** — tests `terminal_records_are_revalidated_against_reorg`, `completed_record_survives_an_actual_reorg_round_trip` |

---

## 3. The three cross-cutting hazards (Task 22 step 1 call-outs)

**(a) Tip going BACKWARDS between `poll`/`backstop_tick` calls.** Every deadline
comparison uses a fresh `tip_height()` each poll. A *lower* tip fires *fewer*
deadlines — the conservative direction. `SimChain::rewind_to` proves no panic
and no early fire on a tip regression; `BitcoinCoreChainView` additionally serves
the last-known tip on an outage (frozen time), never a fabricated regression.
The funding-jitter anchor even re-clamps to a regressing tip
(`funding_driver.rs`). **Verdict: safe as-is.**

**(b) `funding_height` returning `None` AFTER it returned `Some`.** Handled at
every seam: the watchtower goes Idle, the proceed gate goes Wait, the recovery
funding/rebroadcast arms use the authoritative read, and the live observation
(§5) surfaces it. **Verdict: safe as-is** (surfaced by §5).

**(c) The same outpoint RE-CONFIRMING at a DIFFERENT height — the dangerous
one.** Re-derived anchors (refund maturity, proceed-gate S, reveal height, tip)
follow the chain and are safe. The two **write-once** record anchors
(`s_height`, `sweep_escrow_height`) do NOT re-derive — that is the deferred
review item above. The wallet **surfaces** the shift as a loud line (§5) rather
than silently continuing on a stale anchor, and the fight-on-foreign-spend +
CSV-physics mitigations bound the exposure to a rare deep-reorg corner.

---

## 4. Policy decisions

1. **Conservative-direction-only** is verified across every driver: a reorg
   holds/waits/re-derives; nothing accelerates an exit. The premature-broadcast
   physics gate is the universal backstop.
2. **Re-derive where cheap.** All cheaply-re-derivable anchors already re-derive
   each poll (refund maturity, funding gate, reveal, tip, terminal
   re-validation). The audit adds no new caching. The only non-re-derived
   anchors are the two frozen-core write-once values, which are surfaced and
   deferred.
3. **A funding that un-confirms while a swap is live releases nothing new.** The
   proceed gate withdraws (`Wait`), SH's `broadcast_completion` is gated on
   `S + Δ_early − Δ_buffer` and a live watchtower receipt, SL only acts on a
   *live* reveal, and `settle` short-circuits on the persisted phase — so no new
   release happens while a funding is un-confirmed. On re-confirmation at a
   different height, the refund anchor is re-derived; the two core anchors are
   the documented residual, mitigated by fight-on-foreign-spend + physics.

### Confirmation-depth decision (Task 22 step 3)

**Is 1-conf funding acceptable on testnet4 for 0.01 tBTC? YES — for pre-alpha
testnet, and no min-conf gate is added this task.** Reasoning:

- **The value is expendable test money** (0.01 tBTC/unit; the tester banner is
  explicit) — the downside of a reverted 1-conf funding is a bounded *delay*,
  not a loss.
- **Forward-or-refund holds at any reorg depth.** A reverted funding is handled
  conservatively (hold-and-wait; the proceed gate withdraws; the watchtower
  re-derives). The safety argument does not depend on confirmation depth — it
  depends on the conservative hold, which is depth-independent.
- **testnet4 reorg depth.** testnet4 was designed to tame testnet3's
  difficulty-reset storms, but reorgs still occur — typically 1–3 blocks, rarely
  deeper during mining races. A min-conf gate of, say, 2–3 would reduce
  re-derivation churn but cannot improve the *safety* bound (already
  depth-independent); it is a UX/privacy tuning knob, not a fund-safety
  requirement.
- **Where a min-conf gate WOULD live.** If a future round wants one, it belongs
  in the **wallet drivers** (`FundingCoordinator`/`FundingDriver` — gate
  `Proceed` on `tip − funding_height ≥ min_conf`), NOT in `Params` (no manifest
  format change this task). It is a cheap wallet-layer add; this audit
  deliberately does not add it, to keep the pre-alpha surface minimal and avoid a
  behavior change that would slow every swap.

---

## 5. Tester-visible surfacing

Because the drivers HOLD silently through a reorg, a hold is indistinguishable
from a hang to a tester. `wallet/reorg.rs` (`observe`) is a **pure observation**
(it changes no decision) that the CLI swap loop prints on its slow cadence:

- `reorg detected: <our|swept> escrow funding for <sid> un-confirmed; HOLDING …`
  — a live funding un-confirmed; every exit holds until it re-confirms.
- `reorg detected: swept-escrow funding for <sid> re-confirmed at height N
  (was M); …` — the anchor-shift, made visible for the tester and any bug report.

`docs/TESTER-GUIDE.md` gains a limitations-banner note ("testnet4 reorgs are
routine") and two troubleshooting rows keyed to these exact strings.

---

## 6. Deferred cryptographer-review items (frozen core)

1. **`sweep_escrow_height` is write-once and feeds the claim ceiling.** A reorg
   that re-confirms the swept escrow at a *lower* height leaves the cached anchor
   optimistic, widening the SL claim race. Mitigated by fight-on-foreign-spend +
   CSV physics; a formal bound belongs with review item #5 (the claim-delay
   ceiling proof). Closing it in code needs a `claim_delay_ceiling` signature
   change (frozen surface).
2. **`s_height` is write-once and feeds the SH broadcast deadline.** Shallow
   reorgs are absorbed by the designed `Δ_buffer > cofunding_window` margin; a
   formal bound of the tolerable reorg depth vs. `Δ_buffer` is a review item.

Both are the *dangerous* (window-widening) direction only; the conservative
direction is safe today. Neither is patched here (scope guard).

---

## 7. Test coverage map

| Concern | Test | File |
|---|---|---|
| SimChain reorg primitives (un-confirm/re-confirm/rewind) | `unconfirm_funding_reads_not_confirmed_then_reconfirm_restores`, `unconfirm_spend_returns_to_mempool_then_reconfirms`, `rewind_orphans_spend_and_its_outputs_then_remine_reconfirms`, `rewind_keeps_the_fork_block_and_ignores_forward_requests` | `src/chain/mod.rs` |
| No exit through a vanished funding (physics gate) | `csv_spend_against_unconfirmed_funding_is_refused` | `src/chain/mod.rs` |
| Refund maturity re-derived; no early fire | `reorg_unconfirm_holds_the_fire_then_reconfirm_reshifts_maturity` | `src/wallet/watchtower_driver.rs` |
| Proceed gate withdraws on un-confirm; re-derives S | `reorg_unconfirming_an_escrow_withdraws_the_proceed_gate` | `src/wallet/orchestrator.rs` |
| Claim: no stale Won; foreign re-mine winner is Lost | `reorg_reverting_our_confirmed_claim_is_not_a_stale_won`, `reorg_letting_a_foreign_refund_win_reports_lost_not_stale_won` | `src/wallet/claim_scheduler.rs` |
| Terminal re-validation across an actual reorg | `completed_record_survives_an_actual_reorg_round_trip`, `terminal_records_are_revalidated_against_reorg` | `tests/recovery_driver.rs` |
| Tester-visible surfacing | `*_unconfirmed_is_surfaced`, `swept_anchor_shift_is_surfaced`, `healthy_live_swap_is_silent`, `pre_funding_and_terminal_records_are_silent` | `src/wallet/reorg.rs` |

Every scenario asserts forward-or-refund holds: no panic, no early refund fire,
no stale terminal, no release on a vanished funding.
