# Tester Round 1 — round log (task 30) — OPEN

The closer for round 2. Tracks the six-item DONE definition to
**PRE-ALPHA TESTNET WALLET: DONE**. Started 2026-07-19 (launch day).

## Distribution kit (ready NOW)

| Item | Where | State |
|---|---|---|
| Release package | GitHub release [`v0.1.0-prealpha`](https://github.com/abysal32-arch/switchbitcoin-site/releases/tag/v0.1.0-prealpha) | ✅ live |
| Build | `switchbitcoin-prealpha-0.1.0-f617468e8-windows-gnu.zip` | ✅ FINAL clean-HEAD build (rename + 6b02f01 soak fix + F1 quieter logs) |
| Zip SHA256 | `e8ad43d192bc14404882cc490e40b277d0e3844e0b5edccefec584528d0b86b8` | ✅ site hash === live download, verified |
| Tester guide | in-package `docs/TESTER-GUIDE.md` + web copy https://switchbitcoin.com/testers.html | ✅ |
| Bug-report template | in-package `docs/BUG-REPORT-TEMPLATE.md` | ✅ |
| Current manifest | in-package `docs/manifests/v2.manifest` + https://switchbitcoin.com/manifests/v2.manifest (id `cdda51a9…`, floor 2, onboarding delay 1–2 h) | ✅ |
| Public home | https://switchbitcoin.com (HTTPS enforced) | ✅ live 2026-07-19 |

> ✅ DECIDED + DONE (2026-07-19): cut the final package `f617468e8` from clean
> HEAD (includes F1's quieter logs), made it THE live download, and verified
> site hash === download hash. Done before any tester held a hash — the one
> free window to finalize the build. The superseded `6b02f01cf` asset is being
> removed from the release (GitHub 503 incident during the swap — a detached
> retry finishes it; the live download was consistent at every moment).

## Round brief (paste to each tester)

> You're testing **SwitchBitcoin** pre-alpha — coordinator-free Bitcoin atomic
> swaps, **testnet4 only, no real funds**. Download from
> https://switchbitcoin.com (verify the zip SHA256 on the page, and that
> `switchbitcoin-cli version` prints trust root `fedd6222…9e6ec7fe`).
> Do: `quickstart` → fund a deposit from a testnet4 faucet (≥0.0104 tBTC as
> ONE UTXO) → `onboard` (matures 1–2 h) → `manifest ingest` the v2 file →
> a swap with Joe → then the §7 watch-drill (dead-device refund). Expect
> ~half of swap attempts to refuse-and-refund BY DESIGN (retry — funds always
> come back). Send back: `switchbitcoin-cli diag` output + a filled
> BUG-REPORT for anything surprising.

## The six-item DONE gate — live status

| # | Gate item | Status | Blocker |
|---|---|---|---|
| 1 | Clean-HEAD package in ≥2 external testers' hands | ⬜ | **Joe: pick + invite testers, distribute** |
| 2 | ≥3 completed testnet4 swaps, ≥2 external testers | ⬜ | testers + Joe as counterparty; ~50% refusal = budget retries |
| 3 | ≥1 refund AND ≥1 watchtower fire by a NON-Joe tester | ⬜ | tester runs the §7 drill |
| 4 | Whole fleet on one signed manifest (no v0 provisional) | ⬜ | testers run `manifest ingest v2` (v2 already fleet-default) |
| 5 | Zero open P0/P1; P2+ triaged to backlog | ⬜ | triage loop as reports arrive |
| 6 | Evidence committed; RESUME marked DONE | ⬜ | this log + close |

## JOE CHECKPOINTS (unavoidably human — the gate can't close without these)

1. **Pick + invite** the hand-picked testers (need ≥2 external), via the
   onboarding channel (email/DM).
2. **Distribute** the package link + v2 manifest + the round brief above.
3. **Be the counterparty** for their first swaps (scheduling humans).
4. Nudge ≥1 tester through the §7 watch-drill (gate item 3).

## Internal first-tester dry-run (2026-07-19, on the PUBLISHED artifact) — PASS

Claude ran a tester's entire first-run path on the actual downloaded package
(`f617468e8`, zip `e8ad43d1…`) in a throwaway dir, to catch any day-one
packaging/onboarding bug before a real tester does. All green:

| Step | Result |
|---|---|
| Download published zip + `sha256sum -c SHA256SUMS` | ✅ 9/9 files OK |
| `version` | ✅ f617468e8, pin `fedd6222…` |
| `quickstart` / `help` / README-FIRST | ✅ clear, all verbs present |
| `init --network testnet` (scripted) | ✅ wallet created, phase-0 flow, config written, v0 provisional |
| `address` | ✅ `tb1p…` deposit address, key index 0 |
| `manifest show` (pre) | ✅ v0 baseline + LOUD provisional warning |
| **`manifest ingest v2`** (the fleet-convergence step, gate #4) | ✅ **v0→v2, onboarding_delay 24–72h → 1–2h applied** |
| `manifest show` (post) / `diag` | ✅ v2 (id `cdda51a9…`, floor 2), **diag redaction verified — no seed/passphrase/mnemonic** |
| `backup` → `restore` into fresh dir | ✅ bundle written, 4 files restored clean |
| `watch --once` (config w/o `[node]`) | ✅ clean instructive error "needs a [node] section" — correct, not a crash |

**Conclusion:** the shipped package is sound end-to-end for a tester's first
session. Gate item #4's mechanism (manifest ingest → fleet on one version) is
proven on the real artifact. The only funded steps (onboard/swap/watch-fire)
need tBTC + a node and are the external-tester legs.

## Swap attempts

_(one row per attempt as they come: who↔who, outcome, txids, notes)_

## Reports received

_(one row per report: tester, severity P0/P1/P2, disposition)_

## P2+ backlog (seed for the next phase)

- (from soak) TRACE_CAP 2000 ring untested at high /events volume — low risk.
- (from soak) serve stderr is unbounded (F1 reduced the rate; no hard cap) —
  guide note vs size cap, revisit if a tester's log grows large.
