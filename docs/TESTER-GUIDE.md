# SwitchBitcoin — Tester Guide (PRE-ALPHA)

*(Formerly "Swap Key", the internal codename; protocol lineage v3.16
unchanged. Task 31, 2026-07-18.)*

Welcome, and thank you for testing. This guide takes you from nothing to a
completed swap, covers the local UI and the second-device watchtower, and
tells you exactly how to report what breaks.

## 1. ⚠ LIMITATIONS BANNER — read this first, it is not optional

* **TESTNET/REGTEST ONLY — NO REAL FUNDS.** Mainnet has no config variant by
  construction; that stays true until the external cryptographer review.
  Treat every coin this wallet touches as expendable test money.
* **~HALF of swap attempts refuse and close through REFUNDS — by design.**
  The role↔CSV pre-commitment fix is deferred to the cryptographer review;
  the interim convention makes convention-mismatched attempts refuse at the
  CSV-binding guard (`swept escrow carries the wrong refund CSV
  (extract-and-race guard); refund`) and your funds come back automatically
  at the refund timelock (roughly 24–36 hours on testnet). A refunded swap
  is the safety system WORKING. Retry, don't panic.
* **Plaintext TCP peer transport** — loopback/LAN/VPN interop only; assume
  anyone on the path can watch the (non-secret) negotiation. Tor/Noise is
  post-pre-alpha.
* **Software key custody** — a BIP39/BIP32 encrypted file, not a hardware
  enclave. Your passphrase and 24-word mnemonic are the whole defense.
* **`serve` has NO auth** — loopback only, and any local process can drive
  your wallet while it runs. Don't run it on a shared machine.
* **Claim-delay privacy holds are real**: after a swap settles you may see
  `holding the SL claim until height N` for many blocks. That is the privacy
  posture working — leave the wallet running.
* **Onboarding delays are real on testnet**: each newly onboarded coin
  becomes swappable only after its OWN randomized 24–72 h decorrelation
  delay (drawn per coin, so two units rarely mature together). `status`
  annotates each unit with its maturity time and height gate
  (`[onboarding delay: matures ~… & height ≥ …]`); a swap attempted early
  refuses cleanly and leaves the coin untouched, so retrying is free.
* **testnet4 REORGS are routine** — multi-block reorgs happen there (regtest
  never reorged). If a `reorg detected: … HOLDING …` line appears mid-swap,
  the wallet is deliberately pausing until the orphaned confirmation settles.
  A reorg can only ever DELAY an exit, never fire one early. Leave it running.

## 2. Install

**Option A — the release package** (`switchbitcoin-prealpha-<version>-<git>-<platform>/`):
verify `SHA256SUMS`, put the folder somewhere convenient, and use the two
binaries directly: `switchbitcoin-cli` (the wallet) and `switchbitcoin-manifest`
(operator tooling — testers normally never need it). `README-FIRST.txt`
points back here.

**Option B — build from source** (windows-gnu is the verified host):
Rust toolchain + a MinGW gcc (Windows), then `scripts/build-release.sh` —
it runs the full test gates, refuses to package a binary with a test trust
root, and drops the package under `dist/`. Linux/macOS: same script,
best-effort (untested hosts).

Check what you have — every bug report starts with this line:

```
switchbitcoin-cli version
```

It prints the build (crate version + git hash), the pre-alpha banner, and
the pinned manifest trust root. If you EVER see an `UNSHIPPABLE BUILD`
banner, stop and report it — that binary trusts a public test key.

## 3. A Bitcoin node

You need your own Bitcoin Core **28 or newer** (P2A/TRUC support), synced on
**testnet4** — or regtest for a purely local rehearsal: two wallets (two
data dirs, two configs) on one machine against `bitcoind -regtest`, same
quickstart flow with `--network regtest`, and you mine your own blocks.

```
bitcoind -testnet4 -server=1
```

There is deliberately **no hosted RPC option**: pointing your wallet at
someone else's node hands them your addresses, your timing, and the power to
lie to you about confirmations. Pre-alpha testing assumes your own node.
Windows note: no `-daemon` on Windows builds — give bitcoind its own
terminal. Cookie auth (the default) is the easiest hookup: point
`rpc_cookie_file` at `<bitcoind datadir>/testnet4/.cookie`.

## 4. Quickstart (zero → first swap)

Run `switchbitcoin-cli quickstart` — it prints the numbered walkthrough (init →
address → faucet → onboard → swap ticket) and every wallet command tells you
the next one. Highlights and traps:

* `init` shows your **24-word mnemonic exactly once** and makes you retype
  it, then demands the Phase-0 acknowledgement (type `ACCEPT`). Write the
  words down; the file `keystore.bin` + your passphrase is the only other
  copy of your keys.
* Edit the generated `switchbitcoin.toml` and fill the `[node]` section, or
  commands will refuse with `this command needs a node: add a [node]
  section to switchbitcoin.toml`.
* Faucet amount: at least **0.011 tBTC** (one 0.01 swap unit + fees + the
  CPFP reserve the split carves). Wait for a confirmation before `onboard`.
* After `onboard` confirms, each coin matures after its own randomized
  24–72 h delay. `status` shows the unit as `PreEncumbrance/Unspent` with a
  maturity annotation (`[onboarding delay: matures ~<UTC> & height ≥ N]`,
  flipping to `delay elapsed` once the wall-clock half has passed). A swap
  attempted before both halves clear refuses cleanly and costs nothing (see
  Troubleshooting). (`coins: none — get an address…` means you skipped a step.)
* Swapping needs a partner and the **ticket flow** (one line of text):
  maker runs `swap --make <host:port>`, sends the printed `skt1…` line;
  taker runs `swap --take <ticket>`. Both sides stay running until
  `SWAP COMPLETED` or a refund resolution.

## 5. Connectivity (NAT & reachability)

A swap needs a live TCP link between the two wallets. On one machine (loopback)
or one LAN this just works. Across the internet — two homes, two offices — the
**maker** (`swap --make`, or `serve` + `/swap/offer`) runs a listener the
**taker** must reach, and home routers block inbound connections by default.

* **The ticket must advertise a REACHABLE `host:port`.** `--make 0.0.0.0:9735`
  binds every interface but the printed ticket cannot carry a dialable
  address — you'll see a `WARNING: --make advertises a non-dialable host` line.
  Put the address your partner can actually reach in the `host:port` you pass.
* **Make the maker reachable — pick ONE:**
  * **A shared LAN/VPN (simplest).** A mesh VPN (e.g. Tailscale/WireGuard) or
    both machines on the same Wi-Fi gives each a directly-dialable address —
    use that VPN/LAN IP in `--make`. No router config.
  * **Port-forward.** Forward the maker's listen port (TCP) on the router to the
    maker machine and advertise the maker's PUBLIC IP:port. Only the maker needs
    this; the taker dials out.
* **The taker retries a cold dial.** `--take` / `--connect` (and the UI's
  take/connect) redial a refused/timed-out/unreachable peer a few times
  (`--connect-retries`, default 4, ~2 s apart), so the taker can start a moment
  before the maker's listener is up. A retry only ever re-dials the FIRST
  connection — **nothing is leased or funded until both sides are connected and
  negotiating**, so a failed dial is free: fix the address and run again.
* **What a mid-swap drop means.** Once BOTH escrows fund, a dropped link cannot
  lose funds: the swap routes to its pre-armed refund and your coins come back
  at the CSV timelock (~24–36 h on testnet; banner item 2). A drop BEFORE
  funding just ends the attempt with nothing locked — retry.
* **Reading the failure:** `connection refused` → the maker isn't listening yet
  (retry, or start the maker first). `timed out` / `no taker reached …` → the
  address isn't reachable from the other side (NAT/firewall — use a VPN or
  port-forward). `handshake: peer runs different signed params` is NOT a
  connectivity problem — see section 7 (manifests).

## 6. The local UI (optional)

```
switchbitcoin-cli serve
```

then open `SwitchBitcoin-Wallet.html` (shipped in the package) in a browser. It
talks to `http://127.0.0.1:3316` — loopback only, **no auth** (limitation
banner applies). Onboarding, tickets, and live swap state all work from the
page; everything the UI does is also in the CLI.

When a backend is connected the page shows a **live status strip** that makes
the states testers most often misread legible — so you can tell a *normal*
state from a real problem before filing a bug:

* a permanent **PRE-ALPHA · TESTNET ONLY · NO REAL FUNDS** banner with the
  build version;
* **manifest** version + id, and a LOUD warning when you're on the v0
  provisional baseline (the fingerprintable partition — ingest a signed
  manifest);
* **refund reality** — a swap that routes to refund is explained, not shown as
  a bare "failed": ~half of swaps refund *by design* in this pre-alpha (a
  role↔CSV safety refusal); your funds return automatically at the CSV timeout,
  retry with another unit;
* a **claim hold** (`holding-claim`) rendered as a privacy hold until a named
  block — a deliberate delay, **not** a stuck swap;
* **alarms** shown prominently (not just in the trace), and the
  **active / max** swap count (new swaps 409 at the cap);
* the phase-0 provenance warning before your first onboard.

The page renders `/status` verbatim — it never invents state. If a surface
looks wrong, `switchbitcoin-cli status` / `manifest show` say the same thing.

## 7. Signed parameter manifests

Settlement parameters arrive on a signed, versioned manifest — never from
your config file. Two commands matter to a tester:

* `switchbitcoin-cli manifest show` — what you're running. A fresh wallet says
  version 0 with a WARNING: v0 wallets are a small, fingerprintable
  anonymity partition. Fix it by ingesting the current round's manifest:
* `switchbitcoin-cli manifest ingest <file>` — e.g. the `docs/manifests/v2.manifest`
  shipped in the package (v1 was signed by the retired first operator key —
  since the 2026-07-16 key rotation it refuses with `signature does not
  verify`, by design). Two wallets on different manifests refuse each
  other with `handshake: peer runs different signed params (manifest
  mismatch)` — so when the operator publishes a new manifest, ingest it
  promptly (everyone in a test round runs the same version).

## 8. Backup, restore, and the second-device watchtower

This is the best fund-safety demo you can run:

1. `switchbitcoin-cli backup wallet.skbak` (on your main device; refuses while the
   wallet is running).
2. Move the bundle to a second device (or second directory + own config),
   `switchbitcoin-cli restore --from wallet.skbak`.
3. `switchbitcoin-cli watch` on the second device.
4. Start a swap on the primary and kill the process mid-swap.
5. Watch the tower fire your pre-armed refund at CSV maturity — funds come
   back with the primary dead.

What a watchtower can and cannot do (from the `wallet::watch` design): it
can only ever broadcast **your own pre-armed refund** (single-signed at
negotiate time, pays your own key) and **a CPFP fee-bump of that refund** —
it holds no session key, never signs completions, never negotiates. It
cannot steal and cannot grief; two devices firing the same refund is
idempotent (same bytes, same txid).

Traps the guide must warn you about:

* `watch` holds the wallet's single-instance lock — it **cannot share a data
  dir with a running `swap`/`serve`**. If you try, you'll hit `another
  process holds this swap store (single-instance)`. Second device (or second
  dir from a restored bundle) is the design.
* A watch device with **no reserve** still fires refunds but cannot fee-bump
  under congestion — it logs `RefundStalledBelowFeeFloor: … NO leasable
  reserve exists on this watchtower device` and the refund confirms when the
  mempool clears (the timelock never expires; nothing is lost). To arm the
  silent CPFP there, onboard a small deposit on the watch device too.
* A **stale backup bundle rewinds the manifest version floor** on restore.
  Harmless for watch-only use (`watch` never negotiates), but do NOT run
  `swap`/`serve` from a stale restore without `manifest ingest`-ing the
  newest signed manifest first.
* `watch --once` does one pass and exits — cron/Task-Scheduler friendly.
  `watch` exits 0 when there's nothing guardable or every exit confirmed.

## 9. Troubleshooting (keyed to the real strings)

| You see | It means / do this |
|---|---|
| `swept escrow carries the wrong refund CSV (extract-and-race guard); refund` | The ~50% role/CSV convention mismatch (banner item 2). The swap closes through refunds. Retry a fresh swap. |
| `swap routed to the refund exit: …` then `refund path resolved` | Normal refund closure. Funds return at CSV maturity; leave the wallet running (or `recover` later). |
| `holding the SL claim until height N` | Privacy hold, not a hang. Keep running; on regtest, keep mining. |
| `reorg detected: … funding for … un-confirmed; HOLDING …` | A testnet4 reorg orphaned a confirmation your live swap depends on. The wallet holds until it re-confirms — the safety system working (a reorg can only delay an exit, never fire one early). Keep the wallet running; report only if it never clears. |
| `reorg detected: swept-escrow funding … re-confirmed at height N (was M)` | A reorg re-confirmed a funding at a new height. Chain-derived deadlines (the refund CSV) re-derive from the current chain automatically. Informational — keep running; include the line if you file a bug. |
| `another process holds this swap store (single-instance)` | Two processes on one data dir (often `serve` + `swap`, or `watch` on the primary dir). One wallet process per dir. |
| `wallet onboarding is incomplete — run switchbitcoin-cli init first` | `init` never finished (mnemonic retype/Phase-0). Re-run `init`. |
| `keystore: wrong passphrase or corrupted file` | Wrong passphrase (retype; NFC quirks are normalized) — or real file damage: restore `keystore.bin` from backup / `init --restore` from the mnemonic. |
| `keystore.bin is damaged but wallet data exists — do NOT delete it…` | Follow the message exactly. Never delete a keystore that guarded funds. |
| `this command needs a node: add a [node] section to switchbitcoin.toml` | Fill `[node]` in the config (section 3). |
| `deposit not found or not confirmed — wait for a confirmation` | The faucet tx hasn't confirmed, or the `<txid:vout>` is wrong (vout is the output INDEX paying your address). |
| `deposit does not pay any address of this wallet` | Wrong txid/vout, or coins sent to some other wallet's address. |
| `coins become leasable after their decorrelation delay (24-72h wall clock)` | The onboarding privacy delay (banner). Each unit's maturity is a separate random draw; `status` shows each unit's `matures ~…` annotation. Retry the `swap` once it reads `delay elapsed` — an early attempt refuses cleanly. |
| `timelock/deadline invariant violated: pre-encumbrance coins exist but are still in their onboarding delay` | The unit hasn't finished its randomized 24–72 h onboarding delay. NOT a bug and nothing is stuck (no lease, no broadcast) — `status` shows each unit's maturity time; wait and re-run `swap`. Units mature independently, so a spare may be ready before the first. |
| `handshake: peer runs different signed params (manifest mismatch)` | You and your partner are on different manifest versions/params. Both run `manifest show`, ingest the current manifest, retry. |
| `manifest REFUSED: … signature does not verify` | The file isn't signed by the pinned operator root (corrupt download or wrong file). Re-fetch the round's manifest. |
| `manifest REFUSED: … version must strictly increase` | You already run this (or a newer) version — probably fine; `manifest show` to confirm. |
| `ALARM (manifest open): ProvisionalFallback/RollbackDetected…` | The stored manifest was tampered/rolled back and quarantined; the wallet fell back to the compiled baseline. Re-ingest the current manifest and REPORT IT. |
| `no taker reached … before the accept timeout` / `ticket rendezvous failed` | (Maker) Partner never dialed, dialed the wrong ticket, or your `--make` host isn't reachable from their network. Re-check the advertised `host:port` and firewall — section 5 (Connectivity). |
| `could not reach the peer at …` / `dial … failed` | (Taker) The maker isn't listening yet, or its `host:port` isn't reachable from you (NAT/firewall). `--connect-retries` already redials a few times; if it still fails, fix reachability — section 5 (Connectivity). |
| `chain reconcile failed — fix the node/data dir before swapping` | The node is unreachable/out of sync. Fix `[node]`/bitcoind first; refusing to swap in that state is deliberate. |
| `FEE WEATHER WARNING: live N sat/vB exceeds baked …` | When your swap started, the live network feerate was above the baked Setup/settlement fees. NOT a hang and NOT an error — the swap proceeds; if a Setup or settlement then stalls, the reserve-CPFP backstop fee-bumps it automatically (the line names roughly how many reserve sats a bump could burn). The quiet variants `fee weather OK: …` and `fee weather: no live estimate …` need no action. |
| `ALARM — RefundStalledBelowFeeFloor: …` | Congestion + no (usable) reserve for the fee bump. If it names `NO leasable reserve exists on this watchtower device`, onboard a deposit there. The refund still fires; only confirmation waits. |
| `reserve CPFP bumps are gated off` | Startup reconcile failed on the watch device — bumps disabled, refund fires unaffected. Fix the node connection to re-arm bumps. |
| `bump child already in flight on the anchor` | A fee bump is already pending (maybe from the other device). Not an error; wait. |
| `cannot guard <sid>: …` | That record can't be watched (e.g. pre-funding phase). The OTHER swaps still are; report if it names a funded swap. |
| `standing down (completion-supersedes)` | The counterparty's completion confirmed, so the refund is moot. Correct behavior. |
| `watch step failed (retrying next pass)` / `backstop pass failed (retrying next poll)` | Transient (usually RPC). It retries on the next poll; only report if it repeats forever. |
| `ALARM: node RPC unreachable (…)` | bitcoind stopped/crashed/restarting. `serve`/`watch` keep running and announce recovery (`node RPC recovered`) by themselves — restarting bitcoind is SAFE, the wallet re-reads the fresh RPC cookie automatically. During the outage `/status` shows `node_online:false` and the tip freezes at the last seen height (frozen time never fires a deadline early); nothing can broadcast until the node returns. Report only if `node RPC recovered` never appears after the node is back. |
| `ALARM: … quarantine` / `unreadable swap record` | A sealed record failed authentication. ALWAYS report this one with `diag` output. |
| `error: unknown flag …` / `use --flag value, not --flag=value` | Typo protection — flags are strict on purpose. `switchbitcoin-cli help`. |

## 10. Reporting bugs

1. Run `switchbitcoin-cli diag` and copy the WHOLE block. It is redacted by
   construction — no seed, mnemonic, passphrase, or RPC secrets — and names
   the exact build.
2. Fill in `docs/BUG-REPORT-TEMPLATE.md` (what you did, what you expected,
   what happened, `diag` output, your Bitcoin Core version, the failing
   command's full stderr).
3. Send it to Joe through the channel you were onboarded with (pre-alpha
   testers are hand-picked; there is no public tracker yet).

Wallet output never contains secrets by construction — but if you paste
anything else (configs, terminal scrollback from `init`), CHECK IT: the
mnemonic is displayed once during `init`, and that's on you to keep out of
reports.
