//! `swapkey-cli` binary smoke test (Task 08). Feature-gated with the binary
//! itself (`required-features = ["bitcoind"]`): the default suite never
//! builds either.
//!
//! KDF note: every wallet open pays the production 600k-iteration PBKDF2
//! (~0.5s) — deliberately few invocations here (see tasks/_SHARED).
#![cfg(feature = "bitcoind")]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const PASSPHRASE: &str = "correct horse battery staple\n";

/// Run the CLI with `args`, feeding `stdin`, with every `SWAPKEY_*` variable
/// scrubbed (the config loader REFUSES unknown ones, and a developer's
/// environment must not leak into the test).
fn run_cli(config: &Path, args: &[&str], stdin: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_swapkey-cli"));
    for (name, _) in std::env::vars() {
        if name.starts_with("SWAPKEY_") {
            cmd.env_remove(&name);
        }
    }
    let mut child = cmd
        .args(args)
        .arg("--config")
        .arg(config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn swapkey-cli");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("cli exit")
}

fn text(out: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn init_creates_the_wallet_and_status_reads_it_back() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("swapkey.toml");
    let data_dir = dir.path().join("data");

    // 1. init on a fresh dir: writes the config template, creates the
    //    keystore + ledger. Non-interactive: passphrase on stdin, the Phase-0
    //    ack and backup-verification waived via their explicit flags.
    let out = run_cli(
        &config,
        &[
            "init",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--passphrase-stdin",
            "--accept-phase0",
            "--skip-backup-verification",
        ],
        PASSPHRASE,
    );
    let t = text(&out);
    assert!(out.status.success(), "init failed:\n{t}");
    assert!(t.contains("RECOVERY MNEMONIC"), "mnemonic must be displayed once:\n{t}");
    assert!(t.contains("wallet created"), "{t}");
    assert!(config.exists(), "init must write the config template");
    assert!(data_dir.join("keystore.bin").exists(), "keystore must exist");
    assert!(data_dir.join("ledger.bin").exists(), "ledger must exist");

    // 2. status round-trips the created wallet.
    let out = run_cli(&config, &["status", "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "status failed:\n{t}");
    assert!(t.contains("network:  regtest"), "{t}");
    assert!(t.contains("coins:    none"), "a fresh wallet has no coins:\n{t}");
    assert!(t.contains("swaps:    none"), "{t}");

    // 3. a second init is a no-op on an established wallet.
    let out = run_cli(&config, &["init", "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "re-init failed:\n{t}");
    assert!(t.contains("already initialized"), "{t}");

    // 4. a wrong passphrase is refused cleanly (no state change).
    let out = run_cli(&config, &["status", "--passphrase-stdin"], "wrong passphrase\n");
    assert!(!out.status.success(), "a wrong passphrase must fail:\n{}", text(&out));
}

#[test]
fn help_prints_usage() {
    let out = Command::new(env!("CARGO_BIN_EXE_swapkey-cli"))
        .arg("help")
        .output()
        .expect("cli exit");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("USAGE"));
}

#[test]
fn commands_needing_a_node_refuse_without_a_node_section() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("swapkey.toml");
    let data_dir = dir.path().join("data");
    let out = run_cli(
        &config,
        &[
            "init",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--passphrase-stdin",
            "--accept-phase0",
            "--skip-backup-verification",
        ],
        PASSPHRASE,
    );
    assert!(out.status.success(), "{}", text(&out));

    let out = run_cli(&config, &["recover", "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(!out.status.success(), "recover without [node] must refuse:\n{t}");
    assert!(t.contains("[node]"), "the refusal must point at the config:\n{t}");
}
