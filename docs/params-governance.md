# Settlement-parameter governance (signed manifests) — pre-alpha

Task 18. How Swap Key's settlement parameters are authored, signed,
distributed, ingested, and version-governed, and what the trust model
honestly is right now. TESTNET/REGTEST pre-alpha; nothing here touches real
funds before the external cryptographer review.

## Why params are not config

Settlement parameters shape the cross-party transactions themselves: equal
escrows are the privacy linchpin (everyone in a tier must run identical
amounts), and the timelock ordering is what keeps the extract-and-race region
unreachable. A wallet whose params can drift by local edit silently breaks
both. So `swapkey.toml` deliberately cannot carry params
(`wallet::config`'s "params are NOT config" doctrine); they arrive only on
the SIGNED, VERSIONED manifest trust path (`wallet::manifest`):

* **Signed** — BIP340 over a tagged hash of the canonical 105-byte body,
  verified against the wallet's PINNED operator key on every ingest and every
  load.
* **Versioned** — a strictly-monotonic version gate, backed by a persisted
  floor (`manifest.floor`) that survives tamper-quarantine of the manifest
  file itself. Replays and downgrades are refused even when validly signed.
* **Invariant-bounded** — `Params::validate()` plus the manifest's own delay/
  jitter bounds run on EVERY compose, ingest, and load, regardless of
  signature validity: even a compromised operator key cannot push params that
  violate the timelock ordering.

## What each parameter means

All values little-endian in the signed body; amounts in satoshis, heights in
blocks, onboarding delays in hours.

| Field | Meaning |
|---|---|
| `tier_d_sats` | The exactly-equal swapped output D per tier. Equal-output is the anonymity-set guarantee. |
| `delta_fee_sats` | The baked fee margin. Consumed EXACTLY: `setup_fee + anchor + settlement_fee + anchor == delta_fee`, so the destination still receives exactly D. |
| `anchor_sats` | The P2A anchor value every contract tx carries (≥ 240-sat P2A dust floor so positive-fee parents relay standalone). |
| `setup_fee_sats` | The Setup's baked fee (measured 124 vB; must clear standalone relay). |
| `cpfp_reserve_sats` | The dedicated congestion-backstop reserve the onboarding split carves. |
| `delta_early` | SL refund maturity (relative blocks from S). |
| `margin` | `delta_late = delta_early + margin`; the SH refund matures later by this much. |
| `delta_buffer` | SH must CONFIRM its completion by `S + delta_early − delta_buffer` or abandon. Must exceed `cofunding_window` (absorbs funding skew). |
| `claim_confirm_allowance` | Blocks budgeted for the SL claim to confirm; must sit strictly inside `(0, margin − cofunding_window)` — the adversary-proof window. |
| `cofunding_window` | Both Setups must confirm within this many blocks of each other. |
| `onboarding_delay_hours` | `(lo, hi)` withdrawal↔encumbrance decorrelation delay; `0 < lo ≤ hi`. |
| `active_posture` + `delay_bounds` | The SL claim-delay privacy dial (v3.14): three (min,max) bands (minimal/moderate/aggressive) and which one is active. Bounds must stay strictly inside the worst-case claim window and be posture-monotonic. ⚠ cryptographer review item #5: today's bounds are calibrated to the loose honest-SH window; tightening them is an owner/cryptographer decision and changes signed bytes. |
| `cofunding_jitter_max` | Per-party funding jitter; two-sided (2×) must fit inside `cofunding_window`. |
| `quorum_q` | Discovery quorum size (carried for the post-review build). |

**The ordering invariant** (`Params::validate`, asserted signature-blind on
every ingest/load): margin > 0; `0 < delta_buffer < delta_early`;
`0 < claim_confirm_allowance < margin − cofunding_window`; fee components
conserve `delta_fee` with real relay floors; `delta_late` fits BIP68's 16-bit
CSV field; `delta_buffer > cofunding_window`; reserve and anchor above their
dust floors and below the tier principal. Values may be tuned; these
relations may not break — the authoring tool enforces the SAME checks at
compose time, so an invalid params file fails on the operator's machine,
never on a tester's wallet.

## Roles and tooling (who holds what)

* **`swapkey-manifest`** (ops tooling, DECISION 1) — the ONLY binary that
  touches the operator secret: `keygen`, `sign`, `reseal` (plus secret-free
  `compose-check` / `inspect`). The secret lives passphrase-SEALED
  (AES-256-GCM under a PBKDF2-600k KEK, the keystore's production work
  factor) in a file OUTSIDE every repo; it is never written as plaintext and
  never accepted as an argv value.
* **`swapkey-cli`** (the wallet) — verifies and ingests only. It has no
  operator-key input path by construction, and its trust root is the
  BUILD-TIME constant `PINNED_OPERATOR_XONLY` (DECISION 3): deliberately NOT
  a config key, because a config-file pin would let any local file writer
  repoint the root and then feed hostile-but-`validate()`-clean params (e.g.
  minimal claim-delay bounds that gut the privacy dial). "Tune without
  recompiling" survives: MANIFESTS change between rounds; the PIN does not.
* The prototype `ModeledTrustRoot` (its secret is printed in the library
  source) is tests/library-only since Task 18. A shipped wallet binary never
  trusts it.

## The issuance workflow (operator)

```
# once: generate + pin
swapkey-manifest keygen --out-dir <operator-key-dir>
#   -> operator.key (sealed secret), operator.pub (x-only hex)
#   -> pin the printed pubkey as PINNED_OPERATOR_XONLY in swapkey-cli, rebuild

# per tuning round: author, check, sign, distribute
#   edit vN-params.toml  (version MUST strictly increase; see below)
swapkey-manifest compose-check vN-params.toml
swapkey-manifest sign vN-params.toml --key operator.key --out vN.manifest
#   -> hand the 169-byte vN.manifest file to EVERY tester

# tester side (CLI-only by design, DECISION 6 — no serve endpoint):
swapkey-cli manifest ingest vN.manifest
swapkey-cli manifest show
```

Refusals surface verbatim at both ends: authoring-time (`compose` runs the
wallet's own invariants), and ingest-time (bad signature / non-increasing
version / invariant violation), with the wallet's current version and
persisted floor printed so "why was this refused" is never a mystery.

## Version-bump rules

* Versions strictly increase; gaps are fine. `version = 0` is reserved for
  the compiled provisional baseline and is unsignable by the tool.
* ANY parameter change — even one satoshi of `delta_fee` — requires a new
  version. The strictly-monotonic gate is what enforces "new params ⇒ new
  version": a re-issue of an existing version with different content is
  refused by every wallet that already holds that version (and the live
  handshake `params_digest` refuses mismatched-params peers regardless).
* One version per test round, pushed to ALL testers promptly. Manifest
  versions partition anonymity sets: two wallets on different manifests
  refuse to swap, so a straggler population is both fingerprintable and
  unswappable with the rest.
* Identical re-ingest is an idempotent no-op (safe to re-run scripts).

## Scope line (DECISION 5): what the wire enforces today

The live cross-wallet gate is the hello handshake's `params_digest`
(`wallet::runner`): a domain-separated hash over network + every
tx-shape-relevant param, refused BEFORE anything funds. It is strictly
stronger than version-identity for tx-shape safety (it hashes the params
themselves). The formal `(version, id)` gate
(`ManifestStore::refuses_swap_with`) is deliberately NOT wired into the
hello in this task: it would refuse same-params/different-version peers —
exactly the state a staggered v0→v1 rollout passes through — turning every
manifest push into a flag-day. Revisit when the watchtower era (Task 19+)
wants explicit version attestation on the wire.

## Migration off the compiled baseline (v0 → v1)

A fresh wallet runs the compiled `Params::testnet_provisional()` as manifest
version 0. v0 wallets form their own small, FINGERPRINTABLE anonymity
partition (`ManifestStore::is_provisional`; `manifest show` and `status` warn
about it). The first signed manifest — `docs/manifests/v1.manifest`, authored
from `docs/manifests/v1-params.toml` — re-issues the UNCHANGED baseline as
version 1 (DECISION 4): zero behavior change, but ingesting it moves a wallet
off the v0 partition and exercises every trust-path gate for real. Tuned
params (Task 14's live-testnet follow-up) ship later as v2+.

## Next-round reserve advice (Task 26 → v2 recommendation)

Task 26's fee calibration sanity-checks the congestion backstop against live
testnet4 fees. Conclusion for the v2 round: **leave `cpfp_reserve_sats`
unchanged at 25,000.**

What the reserve has to satisfy. The refund exit is CPFP: a low-fee refund
parent (143 vB, carrying only the baked `settlement_fee_sats` = 3,320 sats ≈
23 sat/vB) plus a child funded from the reserve (~120 vB) — a 263 vB package.
Spending the full reserve as child fee lifts the package to
`(3,320 + 25,000) / 263 ≈ 108 sat/vB`, a mainnet-congestion-grade bump.
`MAX_BUMP_FEE_SATS` = 200,000 sits far above the reserve, so that cap is a
runaway guard, never the reserve's limiter.

Live testnet4 headroom (measured 2026-07-16, leg-2 preflight):
`estimatesmartfee 2 CONSERVATIVE` returned no estimate; `6 ECONOMICAL` = 1.5
sat/vB; `mempoolminfee` = 1.0 sat/vB; mempool ~1.5 KB. Ambient testnet4
feerate is ~1–2 sat/vB, so 25,000 buys ~50–100× headroom over what the network
actually demands. No reserve shortfall is reachable on testnet in the pre-alpha
window, so the reserve stays put; revisiting it belongs to a mainnet build,
which is out of scope behind the cryptographer review.

(The three settlement vsize constants — Setup 124 / Completion 124 / Refund
143 vB — are calibrated separately against the leg-2 artifact once the live
swap lands. That is Task 26 step 1, not a signed-param change: any deviation
updates the TEST baselines + comments, never the compiled params.)

**Second v2 recommendation — testing-period onboarding delay (owner
decision, Joe, 2026-07-16):** during the testnet testing rounds,
`onboarding_delay_hours` drops 24–72 → **1–2** so timing gates stop stalling
test cycles (the leg-2 rehearsal lost ~2 days to maturity waits). The value
stays >0 and randomized per coin, so the mechanics under test — per-coin
draws, dual wall+height anchoring, the `status` maturity annotation, the
premature-swap refusal — all remain exercised, just on an hour scale.
Rationale for the lever: there is deliberately NO bypass flag in code
(eligibility anchors are write-once; params are not config) — the signed
manifest IS the tuning path, and this is its first real use. Already-written
anchors are unaffected by ingest (write-once); the production-scale delay
must be restored in the first post-testing round (mainnet-era value is a
cryptographer-review item regardless).

## Key management (honest pre-alpha story)

ONE operator key at a time; no threshold signing, no HSM — those are
post-pre-alpha. The CURRENT key (the second): generated 2026-07-16, x-only
pubkey `fedd62229b6c8a194d6d174d68ad0ce303623cbd49df4b968b9b06ea9e6ec7fe`
(pinned in `swapkey-cli`, published in `operator-key-v2\operator.pub` and
here).

**The key-loss rotation has now run FOR REAL (2026-07-16).** The first key
(`fbb01df4…a2191e`, generated 2026-07-14, signer of v1) had its reseal
passphrase lost the day after resealing. Recovery followed this section's
procedure exactly: `keygen` a fresh key → re-pin `PINNED_OPERATOR_XONLY` →
rebuild → re-issue params as v2 under the new key. Observed consequences,
all as designed: v1.manifest stops verifying under the new pin (it stays in
`docs/manifests/` as history); a wallet holding v1 falls back to the
identical compiled baseline at open (quarantine ALARM, floor KEPT) until it
ingests the new-key v2; anti-rollback holds across the transition because
the persisted floors never reset. Lesson institutionalized: the operator
passphrase now lives in the owner's password manager at keygen time, not
in human memory. What exists now:

* The secret is sealed at rest (passphrase KEK, production PBKDF2 work
  factor) in `operator-key-v2\` outside the repo (`operator-key\` holds the
  retired first key); `reseal` changes the passphrase without changing the
  keypair (no re-pin, no re-issue).
* **Key loss** (file or passphrase): no further manifests can be signed.
  Recovery = `keygen` a new key, re-pin the new pubkey, rebuild and
  redistribute wallet binaries. Wallets' persisted version FLOORS survive the
  transition, so anti-rollback holds across a re-pin (an old-root manifest
  simply stops verifying; the floor still refuses old versions if the old
  root is ever re-pinned). Exercised for real 2026-07-16 — see above.
* **Key compromise**: an attacker can sign manifests, but only within
  `validate()`'s bounds (the ordering invariant is asserted signature-blind),
  and only moving versions FORWARD. The damage envelope is bounded-but-real
  (e.g. posture/delay choices inside the legal window) — one more reason the
  bounds themselves are a cryptographer review item (#5).

## Interaction with backup/restore (Task 17)

The `backup` bundle carries `manifest.current` AND `manifest.floor`
byte-faithfully (see `wallet::backup`'s module docs). Restoring a STALE
bundle therefore rewinds the version floor along with the manifest — a
documented, self-healing window: the next NEWER signed ingest re-raises the
floor; until then, manifests older than the wallet's true history can replay
onto the restored dir. Operators should re-ingest the current round's
manifest immediately after any restore (`manifest show` tells you where the
wallet stands). The same-disk attacker who can delete both manifest files
remains the documented enclave-counter limit.

## Failure surfaces the operator will actually see

* `manifest REFUSED: ... signature does not verify` — wrong root (modeled or
  a stale pin) or a tampered file.
* `manifest REFUSED: ... version must strictly increase` — downgrade/replay,
  or a re-issued version the wallet already holds (the Δ_fee-version-swap
  refusal).
* `ALARM (manifest open): ProvisionalFallback/RollbackDetected/...` — the
  stored manifest failed verification at open (tamper or rollback-by-file-
  swap); it was quarantined, the wallet fell back to the compiled baseline,
  and the floor was KEPT. Re-ingest the current manifest.
* `handshake: peer runs different signed params (manifest mismatch)` — the
  two wallets are on different manifest content; sync versions and retry.
