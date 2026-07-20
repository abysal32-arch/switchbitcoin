# Tester Round 1 — round log (task 30) — OPEN

The closer for round 2. Tracks the six-item DONE definition to
**PRE-ALPHA TESTNET WALLET: DONE**. Started 2026-07-19 (launch day).

## Distribution kit (ready NOW)

| Item | Where | State |
|---|---|---|
| Release package | GitHub release [`v0.1.0-prealpha`](https://github.com/abysal32-arch/switchbitcoin-site/releases/tag/v0.1.0-prealpha) | ✅ live |
| Build | `switchbitcoin-prealpha-0.1.0-6b02f01cf-windows-gnu.zip` | ✅ clean HEAD (b41c808 rename + 6b02f01 soak fix) |
| Zip SHA256 | `3b879ede8f76847f79d281f92ba5829b6aba63be55f8f7c3b93666a012fae511` | ✅ hash-verified on the live domain |
| Tester guide | in-package `docs/TESTER-GUIDE.md` + web copy https://switchbitcoin.com/testers.html | ✅ |
| Bug-report template | in-package `docs/BUG-REPORT-TEMPLATE.md` | ✅ |
| Current manifest | in-package `docs/manifests/v2.manifest` + https://switchbitcoin.com/manifests/v2.manifest (id `cdda51a9…`, floor 2, onboarding delay 1–2 h) | ✅ |
| Public home | https://switchbitcoin.com (HTTPS enforced) | ✅ live 2026-07-19 |

> ⚠ The published package is `6b02f01cf`. The F1 log-spam fix (commit
> `44978c4`) is NOT in it — F1 is cosmetic and re-cutting churns the just-
> launched download. **Decision point:** cut a `-b` patch package from
> `44978c4` (clean HEAD, gates green) for the actual tester hand-off, OR ship
> `6b02f01cf` as-is and note the log verbosity. Recommend the `-b` cut at the
> moment Joe is ready to distribute (one `scripts/build-release.sh` run), so
> testers get the quieter logs from day one. Both are shippable (real pin).

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

## Swap attempts

_(one row per attempt as they come: who↔who, outcome, txids, notes)_

## Reports received

_(one row per report: tester, severity P0/P1/P2, disposition)_

## P2+ backlog (seed for the next phase)

- (from soak) TRACE_CAP 2000 ring untested at high /events volume — low risk.
- (from soak) serve stderr is unbounded (F1 reduced the rate; no hard cap) —
  guide note vs size cap, revisit if a tester's log grows large.
