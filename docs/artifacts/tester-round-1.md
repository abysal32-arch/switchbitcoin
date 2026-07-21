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

**Resume 2026-07-20 ~23:10Z (fresh session): pipeline + watchdog were BOTH dead
— two latent script bugs, found + fixed + relaunched:**
1. `live-swap-pipeline.sh` line 88: `local n="$1" A="…$n…"` on one line — bash
   expands every word of a `local` before any assignment, so `$n` was unset →
   `set -u` killed the whole script at the top of swap attempt 1 (22:07:22Z,
   the log's abrupt stop). Split into two `local` statements; repro-proven
   (old exits 127, new works). The 22:07 "attempt 1" never actually ran — no
   swap state, no unit consumed.
2. `node-watchdog.ps1`: UTF-8 em-dashes in a BOM-less file — PS 5.1 parses
   BOM-less as ANSI, garbling a string terminator (parse error at line 33).
   It had NEVER successfully run. Now pure ASCII; armed + logging 23:12:11Z.
   (bitcoind itself never died again — the earlier session's manual restart,
   ~21:47Z, was still up: synced 144972, 10 peers.)

Relaunched pipeline (fixed) 23:09:38Z: its attempt 1 ran END-TO-END for the
first time — ticket issued, B rendezvous OK, then the clean pre-maturity
refusal (`pre-encumbrance coins … still in their onboarding delay`), zero
state, free, exactly as designed. Attempts continue every 30 min; maturity
window (1–2h from 22:06/22:07Z onboards) closes by ~00:07Z, so attempt 2
(~23:40Z) or 3 (~00:10Z) proceeds for real.

## ✅ LIVE TESTNET4 SWAP COMPLETED — 2026-07-21 00:54:58Z, attempt 3

**The first live-network A↔B swap of the shipped protocol code COMPLETED on
testnet4**, maker walletA ↔ taker walletB, v3 test tier (D = 100,000 sats),
fully unattended under `live-swap-pipeline.sh`. Both ledgers terminal-correct.

Timeline + evidence (all txids on testnet4; logs `live-swap-logs/swap-3-{A,B}.log`):
- Attempt 1 (23:09Z) & 2 (23:40Z): clean pre-maturity refusals, free, zero
  state. Attempt 2 proved the dual wall+height anchoring live: A mature
  (unit `475a86ef…:2` elapsed 23:28Z, height gate met), B still in delay → B
  refused, A aborted pre-commitment (no swap record on either side, verified).
- **Attempt 3 armed 00:10:45Z** at tip 144975 — both height gates just met.
  Session `a63bcf96550f42f11cc2ccf35344d579b451625e2ed422e7b76b04ea187f61bc`,
  funding order B=First, A=Second, Block-X deadline 145119.
- B setup: `9a6f68795bd0491368f876cbbb6b622c858ba60d1599d0382f1948a1af6bfe2b`
- A setup: `03fd9154666c35c9f5d525671557f5652da97327cf133ef406de6f79e51e257c`
- A completion: `3f20116c60ad66d717936b7d4854a7074d11b253fbd4746a7900657149e104f1`
  → confirmed on chain 00:54:58Z; settlement output `:0` registered
  **100,000 sats = exact D** → A ledger `Swapped/Unspent` ✓, record Completed.
- Claim-delay privacy posture exercised LIVE on B (Minimal/flag): sampled a
  6-block hold (reveal 144982 → broadcast 144988).
- **Real crash-recovery exercise, completion path**: the pipeline `kill -9`s
  both swap procs the moment either log says COMPLETED, which orphaned B's
  still-held SL claim at tip ~144983. One `recover` run on B rebroadcast its
  completion `96ad6d0bf656dd9997e88c22679dc1a1db4a5bcbf179a94b9f4f37ea475836ed`
  ("Ctrl-C is safe; recover resumes" — proven live); babysitter re-runs
  recover until B is terminal. B record already Completed; unit `6663ead3…:0`
  consumed.
- Units remaining for future attempts: A `475a86ef…:{1,2}`, B `6663ead3…:{2,3}`
  (2 spare mature units each side).

Pipeline note for reuse: the COMPLETED kill races the taker's delayed SL
claim by design of the *script*, not the protocol — recover covers it, but a
future pipeline revision should let the taker run until its own COMPLETED
line before killing.

### ⚠ P1 FINDING (ours, from the live run): recover settles a swap WITHOUT
### registering the settlement-output coin

When the taker's swap process dies during the claim-delay hold and `recover`
finishes the claim, the swap record reaches Completed/settled but the
settlement output is NEVER registered as a ledger coin. **Funds are safe on
chain** (key is ours) but the wallet is blind to them — balance/coin-selection
will never see the output.

Evidence (2026-07-21 ~01:2xZ, wallet B):
- `96ad6d0b…:0` = 100,000 sats at `tb1puh82e83pf7mecq9eatl4xt47hs0ml8ry553uzn759rytxs3hx03s8mpvsg`,
  confirmed (5+ confs), unspent in the UTXO set (`gettxout` non-null).
- B `status`: swap `a63bcf96…` Completed; coin list has NO `96ad6d0b` entry
  (16 coins, unchanged count from pre-swap; unit `6663ead3…:0` correctly Spent).
- Re-running `recover` after deep confirmations: "settled — nothing to drive",
  still no registration → not a timing artifact.
- Control: wallet A's LIVE driver registered its own settlement output
  (`3f20116c…:0` Swapped/Unspent) before exiting — the live-driver path
  registers; the recover path doesn't.
- Repro shape: kill the taker mid-claim-hold → `recover` (re)broadcasts the
  completion → a later recover pass finds it confirmed → marks settled,
  skips coin registration. (The regtest crash-recovery test passed exact-D
  on both ledgers, so its kill point evidently exercised a different phase —
  this exact kill-during-claim-hold → recover-completes path is new coverage.)

Disposition: fix task flagged for the triage loop (recover's
confirmed-completion path must register the settlement output exactly like
the live driver does, idempotently). Until fixed, any tester whose swap
finishes via recover will "lose sight of" (not lose) their swapped coin.

**✅ RESOLVED — fix commit `256d244` (2026-07-21).** Root cause: the live
completion babysit carried its own registration path while
`apply_recovery_tick` (the recover/startup/serve tick executor) registered
only on the `Refunded` arm — the completion-side terminals registered
nothing. Fix: one registration site — `completion_babysit_step` now routes
every tick through `apply_recovery_tick`, which registers at the
confirmed-completion transition AND idempotently re-offers a `Settled`
record's exit output to the ledger on every re-scan (already-tracked is a
silent no-op), so a wallet wedged by a pre-fix binary heals on its next
`recover`/startup.

- Regression tests (all green): 3 deterministic runner tests (crash the SL
  mid-claim-hold by process death, recover settles AND registers; the
  Settled re-scan backfills a wedged blind-ledger wallet; the
  confirmed-completion tick registers at the transition) + new e2e drill
  `e2e_taker_killed_mid_claim_hold_recovers_and_tracks_the_coin` — run LIVE
  vs real bitcoind: PASS, kill landed inside the hold window.
- **WalletB's real testnet4 ledger BACKFILLED 2026-07-21** by one `recover`
  on the fixed binary: `a63bcf96…: settlement output 96ad6d0b…:0 registered
  (100000 sats)` → status now 17 coins, `96ad6d0b…:0 Swapped/Unspent`,
  swap record untouched (`Completed`). Idempotency verified: a second
  recover registers nothing new. Pre-backfill data-dir snapshot kept
  session-local (not in the repo).
- Gates at the fix commit: 439 default / 487 `--features bitcoind`, clippy
  clean both.
- ⚠ The published tester build `d2955ba6a` PREDATES this fix: a tester whose
  swap finishes via recover still goes coin-blind until a patch build ships
  (funds safe; one `recover` on a fixed build heals retroactively — proven
  on walletB). Fold into the optional `-b` patch-package cut at hand-off.

**Params follow-up (Joe-gated):** v3 was the test-tier lever (0.001 tBTC) so
faucet drips could fund units; production tier 0.01 restores via a future
**v4 manifest** re-issue when live-run testing no longer needs the small tier.

## Swap attempts (external testers)

_(one row per attempt as they come: who↔who, outcome, txids, notes)_

## Reports received

_(one row per report: tester, severity P0/P1/P2, disposition)_

## P2+ backlog (seed for the next phase)

- (from soak) TRACE_CAP 2000 ring untested at high /events volume — low risk.
- (from soak) serve stderr is unbounded (F1 reduced the rate; no hard cap) —
  guide note vs size cap, revisit if a tester's log grows large.
