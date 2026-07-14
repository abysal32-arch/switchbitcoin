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
fn serve_answers_status_over_a_real_socket() {
    use std::io::{Read as _, Write as _};

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

    // A likely-free ephemeral-range port (collision risk is tiny; the test
    // fails loudly if bind loses the race).
    let port = 39316;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_swapkey-cli"));
    for (name, _) in std::env::vars() {
        if name.starts_with("SWAPKEY_") {
            cmd.env_remove(&name);
        }
    }
    let mut child = cmd
        .args(["serve", "--port", &port.to_string(), "--passphrase-stdin", "--poll-secs", "1"])
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    child.stdin.as_mut().unwrap().write_all(PASSPHRASE.as_bytes()).unwrap();

    // Wait for the socket (wallet open pays the KDF first), then GET /status.
    let mut body = String::new();
    for _ in 0..120 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else { continue };
        s.write_all(b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).ok();
        if let Some((_, b)) = raw.split_once("\r\n\r\n") {
            if b.contains("\"ready\":true") {
                body = b.to_string();
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(body.contains("\"ready\":true"), "no ready status from serve: {body:?}");
    assert!(body.contains("\"node_online\":false"), "no [node] → status-only: {body}");
    assert!(body.contains("status-only mode"), "the alarm must say so: {body}");
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

/// The Task-17 wallet-portability story end to end at the CLI surface:
/// `backup` (no passphrase) → `restore --from` into a fresh data dir (with
/// the verification open) → refused re-restore → the mnemonic-only path
/// (`init --restore --rescan`) resuming issuance past the floor.
#[test]
fn backup_restore_and_mnemonic_rescan_round_trip_via_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let config_a = dir.path().join("a.toml");
    let data_a = dir.path().join("data-a");
    let out = run_cli(
        &config_a,
        &[
            "init",
            "--data-dir",
            data_a.to_str().unwrap(),
            "--passphrase-stdin",
            "--accept-phase0",
            "--skip-backup-verification",
        ],
        PASSPHRASE,
    );
    let t = text(&out);
    assert!(out.status.success(), "init failed:\n{t}");
    // Capture the mnemonic for the mnemonic-only leg below (the line after
    // the RECOVERY MNEMONIC banner).
    let words = t
        .lines()
        .skip_while(|l| !l.starts_with("=== RECOVERY MNEMONIC"))
        .nth(1)
        .expect("mnemonic line")
        .trim()
        .to_string();
    assert_eq!(words.split(' ').count(), 24, "not a 24-word line: {words}");

    // backup: works WITHOUT a passphrase (nothing is unsealed), refuses to
    // overwrite its own bundle.
    let bundle = dir.path().join("wallet.skbak");
    let out = run_cli(&config_a, &["backup", bundle.to_str().unwrap()], "");
    let t = text(&out);
    assert!(out.status.success(), "backup failed:\n{t}");
    assert!(bundle.exists(), "bundle file must exist");
    assert!(t.contains("backup written"), "{t}");
    assert!(t.contains("bundled keystore.bin"), "{t}");
    let out = run_cli(&config_a, &["backup", bundle.to_str().unwrap()], "");
    assert!(!out.status.success(), "a second backup onto the same path must refuse");

    // restore into a FRESH data dir under its own config; the verification
    // open must succeed and point at `recover`.
    let config_b = dir.path().join("b.toml");
    let data_b = dir.path().join("data-b");
    std::fs::write(
        &config_b,
        format!("network = \"regtest\"\ndata_dir = '{}'\n", data_b.display()),
    )
    .unwrap();
    let out = run_cli(
        &config_b,
        &["restore", "--from", bundle.to_str().unwrap(), "--passphrase-stdin"],
        PASSPHRASE,
    );
    let t = text(&out);
    assert!(out.status.success(), "restore failed:\n{t}");
    assert!(data_b.join("keystore.bin").exists() && data_b.join("ledger.bin").exists(), "{t}");
    assert!(t.contains("restore complete"), "{t}");
    let out = run_cli(&config_b, &["status", "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "status on the restored wallet failed:\n{t}");
    assert!(t.contains("network:  regtest"), "{t}");

    // A second restore over the now-established dir must refuse (and fail
    // BEFORE any passphrase is consumed — the dir gate comes first).
    let out = run_cli(
        &config_b,
        &["restore", "--from", bundle.to_str().unwrap(), "--passphrase-stdin"],
        PASSPHRASE,
    );
    assert!(!out.status.success(), "restore over an established wallet must refuse");

    // Mnemonic-only leg: a THIRD wallet from the words alone, with the
    // key-index floor raised so issuance can never reuse an on-chain index.
    let config_c = dir.path().join("c.toml");
    let data_c = dir.path().join("data-c");
    let out = run_cli(
        &config_c,
        &[
            "init",
            "--restore",
            "--rescan",
            "50",
            "--data-dir",
            data_c.to_str().unwrap(),
            "--passphrase-stdin",
            "--accept-phase0",
        ],
        &format!("{PASSPHRASE}{words}\n"),
    );
    let t = text(&out);
    assert!(out.status.success(), "init --restore --rescan failed:\n{t}");
    assert!(t.contains("key-index floor raised to 50"), "{t}");
    let out = run_cli(&config_c, &["address", "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "address on the restored wallet failed:\n{t}");
    assert!(t.contains("(key index 50)"), "issuance must resume past the floor:\n{t}");

    // --rescan without --restore is a usage error, not a silent no-op.
    let out = run_cli(&config_c, &["init", "--rescan", "9", "--passphrase-stdin"], PASSPHRASE);
    assert!(!out.status.success(), "--rescan without --restore must be refused");
}

/// The Task-18 trust path at the SHIPPED binary's surface: this build pins
/// the REAL pre-alpha operator key, so the committed v1 manifest (signed by
/// the real key via swapkey-manifest) ingests, re-ingest is an idempotent
/// no-op, and a MODELED-root-signed manifest — the key printed in the library
/// source — is refused. Ingest is CLI-only (DECISION 6).
#[test]
fn pinned_root_manifest_ingest_via_the_cli() {
    use swapkey::settlement::params::Params;
    use swapkey::wallet::manifest::{
        modeled_operator_seckey, sign_manifest, ClaimDelayPosture, SignedManifest,
    };

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

    // Fresh wallet: the compiled v0 baseline, loudly marked provisional.
    let out = run_cli(&config, &["manifest", "show", "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "manifest show failed:\n{t}");
    assert!(t.contains("manifest version: 0"), "{t}");
    assert!(t.contains("fingerprintable anonymity"), "the v0 partition warning:\n{t}");

    // The COMMITTED v1 artifact (docs/manifests/v1.manifest, signed by the
    // real operator key) must ingest against this binary's pin.
    let v1 = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/manifests/v1.manifest");
    let out = run_cli(&config, &["manifest", "ingest", v1, "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "the committed v1 manifest must ingest:\n{t}");
    assert!(t.contains("manifest v1 ACCEPTED"), "{t}");
    assert!(t.contains("version floor:    1"), "the floor must advance:\n{t}");
    assert!(!t.contains("fingerprintable"), "v1 leaves the provisional partition:\n{t}");

    // Idempotent re-ingest of the identical envelope.
    let out = run_cli(&config, &["manifest", "ingest", v1, "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "idempotent re-ingest must be Ok:\n{t}");
    assert!(t.contains("already current"), "{t}");

    // A MODELED-signed v2: validly formed, wrong root — the pinned binary
    // must refuse it verbatim (the modeled secret is public in the source).
    let m2 = SignedManifest::compose(
        2,
        Params::testnet_provisional(),
        ClaimDelayPosture::Moderate,
        [(0, 6), (6, 36), (12, 72)],
        6,
        3,
    )
    .unwrap();
    let env2 = sign_manifest(&m2, &modeled_operator_seckey()).unwrap();
    let modeled_path = dir.path().join("modeled-v2.manifest");
    std::fs::write(&modeled_path, &env2).unwrap();
    let out = run_cli(
        &config,
        &["manifest", "ingest", modeled_path.to_str().unwrap(), "--passphrase-stdin"],
        PASSPHRASE,
    );
    let t = text(&out);
    assert!(!out.status.success(), "a modeled-root manifest must be refused:\n{t}");
    assert!(t.contains("signature does not verify"), "verbatim refusal:\n{t}");
    assert!(t.contains("still on v1"), "{t}");

    // A wrong-sized file is refused BEFORE it is read into memory.
    let junk = dir.path().join("junk.manifest");
    std::fs::write(&junk, vec![0u8; 4096]).unwrap();
    let out = run_cli(
        &config,
        &["manifest", "ingest", junk.to_str().unwrap(), "--passphrase-stdin"],
        PASSPHRASE,
    );
    let t = text(&out);
    assert!(!out.status.success());
    assert!(t.contains("expected exactly 169 bytes"), "{t}");

    // `status` reflects the new signed identity.
    let out = run_cli(&config, &["status", "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("manifest: v1"), "{t}");
}
