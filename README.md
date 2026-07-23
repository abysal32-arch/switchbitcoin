# SwitchBitcoin — coordinator-free Bitcoin atomic swaps (pre-alpha)

**TESTNET/REGTEST ONLY · NO REAL FUNDS · external cryptographer review
pending.** Mainnet has no configuration variant — by construction, not by
convention.

SwitchBitcoin (formerly "Swap Key", the internal codename) is a pre-alpha
wallet implementing v3.16 adaptor-signature atomic swaps: MuSig2 (BIP327)
key aggregation, Taproot escrows, TRUC/v3 + P2A anchors, signed-parameter
governance, and a pre-armed-refund + second-device watchtower story built
around one load-bearing invariant: **a funded escrow always has a driven
exit — complete or refund — at all costs.**

- Website + tester kit: https://switchbitcoin.com
- Tester package: GitHub release `v0.1.0-prealpha` (zip SHA256 published on
  the site and in the release notes)
- Binaries: `switchbitcoin-cli` (the wallet), `switchbitcoin-manifest`
  (operator signing tooling — testers never need it)

## Verify a release against this repo

`switchbitcoin-cli version` prints the crate version, the **git commit the
binary was built from**, and the pinned manifest trust root:

```
fedd62229b6c8a194d6d174d68ad0ce303623cbd49df4b968b9b06ea9e6ec7fe
```

The embedded commit hash must exist in this repository (releases are
tagged), the zip SHA256 must match the site AND the release notes, and the
per-file `SHA256SUMS` inside the package must verify. A binary printing an
`UNSHIPPABLE` banner carries a test trust root and must never be run —
report it.

## Build from source

Verified host: Windows `x86_64-pc-windows-gnu` (rustup GNU toolchain +
MinGW gcc). Linux/macOS: best-effort, same script.

```bash
cargo test                       # default suite
cargo test --features bitcoind   # + the wallet binary and its gates
cargo clippy --all-targets       # clean, both configs
scripts/build-release.sh         # gates -> release build -> shippability
                                 #   gate -> dist/ package + SHA256SUMS
```

The release script refuses to package a dirty tree, a failing suite, or a
binary whose trust-root pin is not the real operator key.

## Safety posture (read before running anything)

- **Testnet4/regtest only.** The seed you generate guards worthless coins.
- **~50% of swap attempts refuse and close through refunds BY DESIGN** — a
  role↔CSV safety stop-gate held deliberately until the external
  cryptographer review clears it. Funds always come back at the refund
  timelock; retrying is free.
- Settlement parameters arrive ONLY on BIP340-signed, strictly-versioned
  manifests verified against the compile-time pin — never from config.
  See `docs/params-governance.md`.
- Onboarded coins mature behind a dual wall-clock + block-height anchor
  drawn per coin (privacy decorrelation); shifting a system clock cannot
  collapse the delay.
- The watchtower can only ever broadcast **your own pre-armed refund** (or
  a CPFP bump of it) — it holds no session keys, cannot steal, cannot
  grief. Design argument: `src/wallet/watch.rs` module docs.
- The external cryptographer review (adaptor + timelock composition,
  extraction correctness, nonce lifecycle, role↔CSV pre-commitment) is
  **pending**; its review surfaces are deliberately isolated in
  `src/crypto/` and `src/signing/`.

## Naming note (do not "fix")

`newkey-*` domain-separation tags, `NEWKEY_GIT_HASH`, the `newkey-scaffold`
folder name, and the `skt1` ticket HRP are deliberate spec literals from
the protocol lineage (v3.16) and stay verbatim across the SwitchBitcoin
rebrand — changing them breaks signed-artifact compatibility.

## Where to read

- `docs/TESTER-GUIDE.md` — the tester walkthrough (limitations banner
  first; §8 is the dead-device watchtower drill).
- `docs/params-governance.md` — why params are signed constants, the
  issuance workflow, and the per-round governance log (v1 → v3).
- `docs/artifacts/` — committed live evidence: first live testnet4 swaps,
  the ≥23 h serve soak, refund + watchtower drills, the tester-round log.
- `docs/BUG-REPORT-TEMPLATE.md` — how to report what breaks.

## License

MIT — see `LICENSE`.
