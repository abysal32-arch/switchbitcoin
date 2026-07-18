#!/usr/bin/env bash
# SwitchBitcoin PRE-ALPHA release build (Task 20). TESTNET/REGTEST ONLY.
#
# Produces dist/switchbitcoin-prealpha-<version>-<git>-<platform>/ containing the
# two binaries (switchbitcoin-cli, switchbitcoin-manifest), the tester docs, the current
# signed manifest, and SHA256SUMS — after refusing to package anything that
# fails the full gates or carries a test trust root.
#
# VERIFIED HOST: x86_64-pc-windows-gnu (WinLibs MinGW gcc; run from Git
# Bash). Linux/macOS are BEST-EFFORT: the same script with the native
# toolchain (no MINGW64_BIN needed).
#
# Env knobs:
#   MINGW64_BIN          path to the MinGW gcc bin dir (Windows only;
#                        default: /c/Users/Joe/AppData/Local/mingw64/bin)
#   SWITCHBITCOIN_ALLOW_DIRTY=1  permit an uncommitted tree (version is stamped
#                        "-dirty"; NEVER hand such a build to a tester)
#   SWITCHBITCOIN_SKIP_GATES=1   skip the test/clippy gates (ONLY for repackaging
#                        a tree the gates already passed unchanged)
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -s)" in
  MINGW*|MSYS*)
    export PATH="$USERPROFILE/.cargo/bin:${MINGW64_BIN:-/c/Users/Joe/AppData/Local/mingw64/bin}:$PATH"
    export CC="${CC:-gcc}" AR="${AR:-ar}"
    EXE=".exe"; PLATFORM="windows-gnu"
    ;;
  Linux)  EXE=""; PLATFORM="linux"  ;;
  Darwin) EXE=""; PLATFORM="macos"  ;;
  *)      EXE=""; PLATFORM="unknown";;
esac

if [ -n "$(git status --porcelain)" ] && [ "${SWITCHBITCOIN_ALLOW_DIRTY:-0}" != "1" ]; then
  echo "ERROR: uncommitted changes — commit first (or SWITCHBITCOIN_ALLOW_DIRTY=1 for a"
  echo "       local-only build; a -dirty build must never reach a tester)." >&2
  exit 1
fi

if [ "${SWITCHBITCOIN_SKIP_GATES:-0}" != "1" ]; then
  echo "== gate 1/3: full default suite =="
  cargo test
  echo "== gate 2/3: full --features bitcoind suite =="
  cargo test --features bitcoind
  echo "== gate 3/3: clippy clean, both configs =="
  cargo clippy --all-targets -- -D warnings
  cargo clippy --all-targets --features bitcoind -- -D warnings
else
  echo "!! gates SKIPPED (SWITCHBITCOIN_SKIP_GATES=1) — only valid for repackaging an"
  echo "!! unchanged tree the gates already passed."
fi

echo "== release build (overflow-checks stay ON per [profile.release]) =="
cargo build --release --features bitcoind

CLI="target/release/switchbitcoin-cli${EXE}"
MANIFEST_TOOL="target/release/switchbitcoin-manifest${EXE}"

echo "== shippability: the trust-root pin must be real =="
VERSION_OUT="$("$CLI" version 2>&1)"
echo "$VERSION_OUT"
if echo "$VERSION_OUT" | grep -q "UNSHIPPABLE"; then
  echo "ERROR: the binary reports an UNSHIPPABLE trust root (test/modeled or" >&2
  echo "       invalid pin). Refusing to package." >&2
  exit 1
fi
if ! echo "$VERSION_OUT" | grep -qE "pinned manifest trust root: [0-9a-f]{64}"; then
  echo "ERROR: no pinned trust root line in 'version' output. Refusing to package." >&2
  exit 1
fi
VERSION_LINE="$(echo "$VERSION_OUT" | head -1)"                    # switchbitcoin-cli X (git H)
STAMP="$(echo "$VERSION_LINE" | sed -E 's/^switchbitcoin-cli ([^ ]+) \(git ([^)]+)\)$/\1-\2/')"

OUT="dist/switchbitcoin-prealpha-${STAMP}-${PLATFORM}"
echo "== packaging ${OUT} =="
rm -rf "$OUT"
mkdir -p "$OUT/docs"
cp "$CLI" "$MANIFEST_TOOL" "$OUT/"
cp docs/TESTER-GUIDE.md docs/BUG-REPORT-TEMPLATE.md docs/params-governance.md "$OUT/docs/"
mkdir -p "$OUT/docs/manifests"
# Ship the CURRENT round's manifest only — v1 (retired first operator key,
# no longer verifies since the 2026-07-16 rotation) stays in the repo as history.
cp docs/manifests/v2.manifest docs/manifests/v2-params.toml "$OUT/docs/manifests/"
# The local HTML UI lives one level above the crate in this workspace; ship
# it when present (serve works without it — the UI is optional).
if [ -f "../SwitchBitcoin-Wallet.html" ]; then
  cp "../SwitchBitcoin-Wallet.html" "$OUT/"
else
  echo "note: SwitchBitcoin-Wallet.html not found next to the crate — shipped without the UI file"
fi
cat > "$OUT/README-FIRST.txt" <<'EOF'
SwitchBitcoin PRE-ALPHA tester package — TESTNET/REGTEST ONLY, NO REAL FUNDS.
This software has NOT had its external cryptographer review. Expect ~half
of swap attempts to close through refunds by design (funds come back).

Start here:
  1. read docs/TESTER-GUIDE.md (the limitations banner is not optional)
  2. run: switchbitcoin-cli quickstart
Report problems with the output of: switchbitcoin-cli diag
(template: docs/BUG-REPORT-TEMPLATE.md)
EOF

( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS )
echo "== done =="
echo "package: $OUT"
cat "$OUT/SHA256SUMS"
