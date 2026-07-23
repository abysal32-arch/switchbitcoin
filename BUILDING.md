# Building SwitchBitcoin (and reproducing a release)

Verified host: Windows, target `x86_64-pc-windows-gnu`. TESTNET/REGTEST
ONLY — see README's safety posture first.

## Toolchain (exact — reproducibility depends on it)

| Component | Version | How |
|---|---|---|
| rustc / cargo | **1.96.1** (stable) | pinned by `rust-toolchain.toml`; rustup installs it automatically |
| target | `x86_64-pc-windows-gnu` | ditto |
| C compiler (for `secp256k1-sys`) | **WinLibs MinGW-W64 GCC 16.1.0** (x86_64-ucrt-posix-seh, Brecht Sanders build, r2) | https://winlibs.com — the exact GCC build matters for byte-identical output: a different GCC produces different (still correct) object code |
| dependency graph | locked | `Cargo.lock` is committed; build with `--locked` |

Environment (Git Bash / MSYS shell):

```bash
export PATH="$USERPROFILE/.cargo/bin:/path/to/mingw64/bin:$PATH"
export CC=gcc AR=ar
```

## Plain build

```bash
cargo build --release --features bitcoind --locked
```

Produces `target/release/switchbitcoin-cli.exe` and
`switchbitcoin-manifest.exe`. (`--features bitcoind` is required for the
wallet binary; without it only the library builds.)

## Reproducible build

The single source of nondeterminism found (and verified, 2026-07-23) is
the PE header's link timestamp. Normalize it and builds are byte-identical:

```bash
export RUSTFLAGS="-C link-args=-Wl,--no-insert-timestamp"
cargo build --release --features bitcoind --locked
sha256sum target/release/switchbitcoin-cli.exe target/release/switchbitcoin-manifest.exe
```

Evidence (2026-07-23, two independent builds at tag `v0.1.0-prealpha-c`
with the flag): `switchbitcoin-cli.exe` = `426943b7…c40b1b` both times,
`switchbitcoin-manifest.exe` = `e0a1a505…3cd6740` both times; PE timestamp
reads as the epoch. No build paths are embedded in release binaries
(checked), so the build directory does not matter.

`scripts/build-release.sh` applies the flag automatically on Windows, so
release packages from here on are cut reproducibly.

## What to compare

Compare the **per-file hashes in the package's `SHA256SUMS`** (the two
`.exe` entries) against your rebuild. Do NOT compare the zip's own hash —
zip containers embed file times and ordering; the per-file hashes are the
reproducibility claim.

## Status of published releases

- `v0.1.0-prealpha-c` (`90c01fff7`) and earlier: cut BEFORE the timestamp
  flag — the shipped exes carry a live link timestamp and will NOT
  byte-match a rebuild (everything else does; the diff is the PE
  timestamp field). Verify those releases via zip SHA256 + `SHA256SUMS` +
  the binary's embedded commit hash instead.
- The next release cut will be the first byte-for-byte reproducible one.

## Cross-machine caveats (honest list)

Byte-identity across different machines requires: the pinned rustc (auto),
`--locked` (enforced by the script), the timestamp flag (auto), AND the
same GCC build for the C dependency. If your `switchbitcoin-cli.exe` hash
differs from ours but `switchbitcoin-manifest.exe` also differs
identically, check `gcc --version` first. Divergence reports are welcome —
that's exactly the kind of finding the tester round wants
(`docs/BUG-REPORT-TEMPLATE.md`).
