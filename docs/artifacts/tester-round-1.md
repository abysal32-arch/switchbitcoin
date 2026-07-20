# Tester Round 1 — round log (task 30) — OPEN

The closer for round 2. Tracks the six-item DONE definition to
**PRE-ALPHA TESTNET WALLET: DONE**. Started 2026-07-19 (launch day).

## Distribution kit (ready NOW)

| Item | Where | State |
|---|---|---|
| Release package | GitHub release [`v0.1.0-prealpha`](https://github.com/abysal32-arch/switchbitcoin-site/releases/tag/v0.1.0-prealpha) | ✅ live |
| Build | `switchbitcoin-prealpha-0.1.0-d2955ba6a-windows-gnu.zip` | ✅ FINAL clean-HEAD build (rename + 6b02f01 soak fix + F1 quieter logs + wallet-UI brand fix) |
| Zip SHA256 | `25a02006d15aff68f23a978c6d14f67ea701fe3acd8070ca55070b7c59efa3dd` | ✅ site hash === live download, verified end-to-end |
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

### Live UI QA (2026-07-19) — 2 brand bugs caught + fixed → package re-cut

Loaded the shipped `SwitchBitcoin-Wallet.html` over a local HTTP server
against the running `serve` (walletA, real state). The UI rendered LIVE
correctly — build `f617468e8`, manifest v2, balance 0.02955996 BTC, all 10
coins, swap history 1 completed/1 refunded, tip, "connected to
switchbitcoin-cli serve" — and the serve API's CORS headers
(`Access-Control-Allow-Origin: *`, OPTIONS→204) make the cross-origin fetch
work as designed. **But two task-31 rebrand misses surfaced, both
tester-visible:** (1) the header wordmark still read **`SWAP·KEY`** →
fixed to `SWITCH·BITCOIN`; (2) a settlement-trace line conflated the protocol
spec version with the signed-params manifest (`manifest v3.16 verified`) →
fixed to `protocol v3.16 · signed params verified`. The HTML lives outside the
repo but ships in the package, so the package was re-cut to carry the fix
(still before any tester held a hash — the free window). See the Distribution
kit table for the final build.

## Shipped-binary swap proof (2026-07-20, regtest E2E) — PASS

Before the external round, proved the swap COMPLETES on the exact final
package `d2955ba6a`: `regtest_e2e` 4/4 green against live Core v29.4.0 regtest
— happy-path completion (both ledgers `Swapped/Unspent` = exactly D),
dead-peer refund, crash-recovery, and a refund-rate probe that **completed 3
of 4 fresh swaps (75%)**. Evidence: `docs/artifacts/swap-proof-2026-07-20.md`
+ `regtest-e2e-2026-07-20.txt` (commit `03a4cfc`). Gate items #2/#3 need
EXTERNAL testers, but the code they'll run is now proven to complete swaps,
refund, and recover — the only variable left is people + funding.

## Live testnet4 A↔B swap — ARMED, waiting on funding (2026-07-20)

Goal: a live-network completion within 3 days. Only blocker = funding (both
wallets' units spent in task-25; self-funding impossible by design; no
autonomous faucet exists — all need captcha/login, verified). Everything after
funding is automated and RUNNING:

- **`tasks/task-30-.../live-swap-pipeline.sh`** (detached, 3-day cap): watches
  deposit addr A `tb1pgsevr6w…` (key idx 22) + B `tb1pkdwh6qna…` (idx 11) via
  `scantxoutset` every 5 min; on a confirmed UTXO ≥ 1,040,000 sats it
  `onboard`s that wallet, then runs `swap --make/--take` (fast posture) every
  30 min until one COMPLETES (pre-maturity attempts refuse free; ~50–75%
  complete). Scanner tested (synthetic + live-empty, no false trigger).
- **`treasury-bridge.sh`** + re-armed **`soak-miner.sh`** (72 h): the autonomous
  path — if the host clock is fixed (`Start-Service w32time; w32tm /resync
  /force`, admin), the miner grinds min-diff blocks to sb-treasury and the
  bridge sends 0.0106 to each deposit addr → pipeline takes over. Clock still
  ~1.85 h behind at arm time (UAC pending).
- **Human action (surest sub-3-day path):** `FUND-THESE-TO-COMPLETE-THE-SWAP.md`
  — send ≥ 0.0104 tBTC (ideally ~0.021 = 2 units) as ONE UTXO to each address.

Watch `live-swap-logs/pipeline.log` for `funded deposit detected` → `ONBOARDED`
→ `SWAP COMPLETED`. Completed-swap txids land there + get transcribed below.

**Pipeline adversarially reviewed before arming (2 unattended-hang bugs caught
+ fixed):** (1) fresh-deposit `onboard` calls `phase0_gate`, which prompts
"Type ACCEPT" on stdin — the pipe carries only the passphrase, so it would
HANG the moment funding landed; fixed with `--accept-phase0` (+ `--wait-secs
1800` so the split confirms within one call across testnet's ~10-min blocks).
(2) a role↔CSV refund babysits the CSV for ~24–36 h; the old 3 h kill would
abandon the refund un-fired; now the refund route is detected early, the unit
is marked consumed, and a detached `recover`-babysitter fires the pre-armed
refund so funds return autonomously. Per-attempt ports added so a babysitting
refund can't block a later attempt. Terminal-string greps verified against the
real CLI output (`SWAP COMPLETED — our completion is confirmed`, `refund path
resolved — record terminal: Refunded`).

## LIVE RUN IN PROGRESS (2026-07-20, Joe funded + signed v3)

Funding constraint (faucet drips too small for the 0.01 tier) solved via a
**v3 test-tier manifest** (id `e962918a…`, tier_d 1,000,000→100,000; Joe signed
with the operator key, both wallets ingested — the manifest lever, same as the
v2 delay change). Deposits: A `15828f67…:0` 377,630 sats, B 369,968 sats — both
confirmed. At the small tier each deposit splits into **3 pre-encumbrance units**
(3× retry material → ~98% one completes across the role↔CSV flips).

Live state: A onboarding (split `475a86ef…` broadcast, awaiting a block →
`--accept-phase0`/`--wait-secs 1800` fixes both held); B queued (onboards after
A's onboard call returns; do_onboard is serial). Then ~1–2 h maturity → swap.
⚠ NODE CRASHED once mid-run (RPC dropped; cause unknown) — restarted + resynced
to 144959; a **`node-watchdog.ps1`** now auto-restarts bitcoind within 60 s so a
drop can't stall the pipeline. Pipeline/watchdog/node all verified running.
NOTE: pipeline does 1 swap attempt then stops+babysits on a refund; with 3
units, on a refund re-arm the swap loop for attempts 2–3 (units are unspent+
mature). Watch `live-swap-logs/pipeline.log`.

## Swap attempts (external testers)

_(one row per attempt as they come: who↔who, outcome, txids, notes)_

## Reports received

_(one row per report: tester, severity P0/P1/P2, disposition)_

## P2+ backlog (seed for the next phase)

- (from soak) TRACE_CAP 2000 ring untested at high /events volume — low risk.
- (from soak) serve stderr is unbounded (F1 reduced the rate; no hard cap) —
  guide note vs size cap, revisit if a tester's log grows large.
