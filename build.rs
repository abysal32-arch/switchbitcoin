//! Build provenance stamp (Task 20, step 5): expose the git short hash (plus
//! a `-dirty` marker for an unclean tree) as `NEWKEY_GIT_HASH` so
//! `--version`, the serve `/status` snapshot, and the `diag` bundle can name
//! the EXACT build a tester is running. Never fails the build: outside a git
//! checkout (e.g. a source tarball) the stamp is `unknown`.
//!
//! NAMESPACE NOTE: deliberately NOT `SWAPKEY_*` — that prefix is the wallet
//! config's strictly-validated env namespace (`wallet::config` refuses any
//! unknown `SWAPKEY_*` variable, and cargo exposes this stamp to test
//! processes at runtime). `newkey-*` is the crate's domain-tag convention.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let hash = git(&["rev-parse", "--short=9", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = match git(&["status", "--porcelain"]) {
        Some(s) if !s.is_empty() => "-dirty",
        Some(_) => "",
        None => "",
    };
    println!("cargo:rustc-env=NEWKEY_GIT_HASH={hash}{dirty}");
    // Re-stamp when the checked-out commit moves. (The dirty marker is
    // best-effort between builds — the release script builds from clean.)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}
