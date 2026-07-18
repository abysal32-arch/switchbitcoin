# Manifest round 1→2 — the first REAL governance round (2026-07-18)

Task 27. The full author → sign → distribute → ingest → converge → drill
cycle, executed against the LIVE testnet4 fleet (walletA/walletB) with the
post-rotation operator key. Binary: `swapkey-cli 0.1.0 (git cb9e20f7a)`
(merged main; pin `fedd62229b6c8a194d6d174d68ad0ce303623cbd49df4b968b9b06ea9e6ec7fe`).
Raw stdouts: `tasks/task-27-manifest-v2-round/round-logs/` (outside the
repo). All times UTC, 2026-07-18 ~18:00Z.

## Context: this round rode a real key rotation

The v2 signing (2026-07-16) happened under the documented KEY-LOSS
recovery: the first operator key's reseal passphrase was lost, the rotation
procedure ran for real (new keypair `operator-key-v2\`, pin `fedd6222…`
compiled in at `95e1fb1`), and the first key (`fbb01df4…`) was retired.
TASK.md's reseal checkpoint was thereby OBE — this round doubled as the
live proof of the rotation's wallet-side consequences.

## 1. What v2 carries

ONE change (task-26 routing: params recommendation from the testing-period
owner decision): `onboarding_delay_hours` 24–72 → **1–2**. Digest-relevant
→ the staggered drill takes the REFUSAL arm. Everything else re-issued
verbatim. The COMPILED baseline stays 24–72 on purpose (v0-fallback wallets
keep the conservative draw). id
`cdda51a90e6d719b05e747666102483d1f7c799ae762b9d962bdddc4b011300e`.

## 2. Pre-state — the rotation fallback, observed in the wild

First `manifest show` under the new pin, BOTH wallets:

```
ALARM (manifest open): ProvisionalFallback { offending: "...manifest.current.bad0" }
— the stored manifest failed verification and was quarantined; running the
compiled baseline. Re-ingest the current signed manifest
manifest version: 0   (id 3025ccdb…)   version floor: 1 (persisted)
```

Exactly the documented behavior: stored v1 (retired-key signature) fails
pin verification → quarantined (`manifest.current.bad0`) → identical
compiled baseline params → floor KEPT (no downgrade window opened). The
v0-partition warning printed on both.

## 3. Ingest + staggered-rollout drill (DECISION 5, live)

* `manifest ingest docs/manifests/v2.manifest` into **A only** →
  `manifest v2 ACCEPTED (was v0) — persisted; every future open runs it`;
  floor 1→2; `onboarding_delay_hours: 1..2`.
* **A(v2) ↔ B(baseline) swap attempt** — A minted its ticket and listened;
  B refused BEFORE DIALING:

```
error: validation failed: ticket's signed params differ from this wallet's
manifest — update one side so both run the same signed parameters
```

  The ticket embeds the maker's params digest, so the split-fleet refusal
  happens at ticket validation — earlier than the expected wire-level
  `handshake: peer runs different signed params (manifest mismatch)`, which
  remains the second line for connect-style flows. Zero state, free
  refusal: B exited cleanly pre-dial; A never saw a connection and was
  still waiting on its 600 s listen leash when the drill harness tore it
  down — no negotiation, no lease, no broadcast on either side.

## 4. Converge

`manifest ingest` into B → `ACCEPTED (was v0)`. Post-state `manifest show`,
both wallets identical: **version 2, id `cdda51a9…`, floor 2, delay 1..2.**
The fleet is on one signed manifest version (a round-2 DONE-gate line item).

## 5. Operator-error drills — every arm refused, wallet unmoved

| Drill | Input | Refusal (verbatim core) | Gate |
|---|---|---|---|
| a. downgrade | re-ingest committed `v1.manifest` | `manifest REFUSED: partial/adaptor verification failed: manifest: signature does not verify (wallet still on v2, version floor 2)` | SIGNATURE (retired key — post-rotation delta; Ordering never consulted) |
| b. corrupt payload | v2 copy, byte flipped at offset 80 | `manifest REFUSED: timelock/deadline invariant violated: manifest: delay bound must stay strictly inside the worst-case claim window (…)` | BOUNDS (tripped before the signature check — see observation below) |
| b2. corrupt signature | v2 copy, byte flipped in the signature region | `manifest REFUSED: … signature does not verify (…)` | SIGNATURE |
| c. version-swap | `v2-VARIANT-drill-only.manifest` (validly signed, version "2", `onboarding_delay_hi_hours` 3 vs 2) | `manifest REFUSED: protocol ordering violated: manifest version must strictly increase (downgrade/replay refused) (…)` | ORDERING (the live Ordering demo TASK.md wanted from drill a) |

Both corrupt copies were scratchpad-only and deleted after the drill; the
variant manifest stays in the task folder (never committed).

**Validation-order observation (drill b):** a payload flip was refused by
the BOUNDS invariant before the signature check ran — parse/bounds precede
signature verification on the ingest path. Every arm still refuses and the
stored manifest is untouched, so this is defense-in-depth ordering, not a
bypass; flagged for the external cryptographer review packet rather than
changed unilaterally (manifest-gate ordering is review-adjacent surface).

## 6. Step-7 check (params changed in v2)

No test hardcodes "manifest == compiled params": the `95e1fb1` rewrite of
`pinned_root_manifest_ingest_via_the_cli` already asserts v1-refuses /
v2-accepts under the live pin, and the full suites ran green on the merged
tree (435 default / 477 bitcoind + clippy clean both at `cb9e20f`; re-run
green for this task's commit). The compiled-baseline fee/delay tests pin
the baseline, which v2 deliberately does not move.

## 7. Trailing fleet state (context for tasks 29/30)

* Both wallets: v2/floor 2. New onboards now draw 1–2 h maturity; the
  existing OnboardingChange units keep their write-once anchors (already
  mature). No leasable PreEncumbrance units remain (both spent by the leg-2
  swap + drill) — the next swap needs a fresh onboard, which now costs
  hours, not days.
* walletB still carries swap `8fcb1417…` in Funding pending ITS refund
  (delta_late 216 from h144508 → ~h144724, ≈05:00Z 07-19; task-25 trailing
  item). Every open during this round printed its `refund not yet
  actionable (immature, no completion)` line — correct and harmless.
