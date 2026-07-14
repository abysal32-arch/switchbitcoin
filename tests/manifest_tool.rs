//! `swapkey-manifest` binary integration test (Task 18): the FULL issuance
//! path at the process level — keygen → compose-check → sign → inspect →
//! reseal — plus every refusal the operator can hit. Runs in the DEFAULT
//! suite (the tool has no required-features; that is DECISION 1's point).
//!
//! KDF note: keygen/sign/reseal pay the production 600k-iteration PBKDF2
//! (~0.5 s each) — invocations are kept deliberately few, and the refusal
//! legs are ordered to fail BEFORE any KDF work.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use swapkey::wallet::manifest::{
    modeled_operator_seckey, sign_manifest, verify_manifest, ModeledTrustRoot, PinnedTrustRoot,
    SignedManifest,
};

const PASSPHRASE: &str = "operator pass 18\n";

fn run_tool(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swapkey-manifest"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn swapkey-manifest");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("tool exit")
}

fn text(out: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The v1 authoring input (the unchanged compiled baseline, DECISION 4) —
/// byte-for-byte the shape docs/manifests/v1-params.toml carries.
fn params_toml(version: u32) -> String {
    format!(
        r#"version = "{version}"
posture = "moderate"
quorum_q = "3"

[params]
tier_d_sats = "1000000"
delta_fee_sats = "5000"
anchor_sats = "240"
setup_fee_sats = "1200"
cpfp_reserve_sats = "25000"
delta_early = "144"
margin = "72"
delta_buffer = "24"
claim_confirm_allowance = "6"
cofunding_window = "12"
onboarding_delay_lo_hours = "24"
onboarding_delay_hi_hours = "72"

[delays]
minimal_min = "0"
minimal_max = "6"
moderate_min = "6"
moderate_max = "36"
aggressive_min = "12"
aggressive_max = "72"
cofunding_jitter_max = "6"
"#
    )
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let s = s.trim();
    assert_eq!(s.len(), 64, "not a 64-hex pubkey line: {s:?}");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn write(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
}

#[test]
fn issuance_path_end_to_end_with_every_refusal_gate() {
    let dir = tempfile::tempdir().unwrap();
    let keydir = dir.path().join("ops");
    let keydir_s = keydir.to_str().unwrap();

    // ---- keygen -----------------------------------------------------------
    let out = run_tool(&["keygen", "--out-dir", keydir_s, "--passphrase-stdin"], PASSPHRASE);
    let t = text(&out);
    assert!(out.status.success(), "keygen failed:\n{t}");
    let pub_hex = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let xonly = hex_to_32(&pub_hex);
    assert!(keydir.join("operator.key").exists(), "sealed key must exist");
    assert_eq!(
        std::fs::read_to_string(keydir.join("operator.pub")).unwrap().trim(),
        pub_hex,
        "operator.pub must carry the printed pubkey"
    );
    // The sealed file never contains the pubkey's preimage material in
    // plaintext form we could check here, but it must not be tiny/empty.
    assert!(std::fs::metadata(keydir.join("operator.key")).unwrap().len() > 80);

    // A second keygen into the same dir refuses (BEFORE any passphrase).
    let out = run_tool(&["keygen", "--out-dir", keydir_s, "--passphrase-stdin"], "");
    assert!(!out.status.success(), "keygen must never overwrite a signing key");
    assert!(text(&out).contains("refusing to overwrite"), "{}", text(&out));

    // ---- compose-check ----------------------------------------------------
    let params_ok = dir.path().join("v1.toml");
    write(&params_ok, &params_toml(1));
    let out = run_tool(&["compose-check", params_ok.to_str().unwrap()], "");
    let t = text(&out);
    assert!(out.status.success(), "compose-check failed:\n{t}");
    assert!(t.contains("composes as manifest v1"), "{t}");

    // The wallet's OWN ordering invariant fires at authoring time (margin 0).
    let params_bad = dir.path().join("bad.toml");
    write(&params_bad, &params_toml(1).replace("margin = \"72\"", "margin = \"0\""));
    let out = run_tool(&["compose-check", params_bad.to_str().unwrap()], "");
    assert!(!out.status.success(), "ordering violation must fail compose-check");
    assert!(text(&out).contains("margin"), "{}", text(&out));

    // ---- sign -------------------------------------------------------------
    let envelope_path = dir.path().join("v1.manifest");
    let envelope_s = envelope_path.to_str().unwrap();
    let key_s = keydir.join("operator.key");
    let key_s = key_s.to_str().unwrap();

    // Wrong passphrase: clean refusal, nothing written.
    let out = run_tool(
        &["sign", params_ok.to_str().unwrap(), "--key", key_s, "--out", envelope_s, "--passphrase-stdin"],
        "not the passphrase\n",
    );
    assert!(!out.status.success(), "wrong passphrase must refuse");
    assert!(text(&out).contains("wrong passphrase"), "{}", text(&out));
    assert!(!envelope_path.exists(), "no envelope may exist after a refused sign");

    // Right passphrase: a 169-byte envelope that VERIFIES against the
    // keygen-printed root and is REJECTED by the modeled root (pin symmetry).
    let out = run_tool(
        &["sign", params_ok.to_str().unwrap(), "--key", key_s, "--out", envelope_s, "--passphrase-stdin"],
        PASSPHRASE,
    );
    let t = text(&out);
    assert!(out.status.success(), "sign failed:\n{t}");
    assert!(t.contains("signed manifest v1"), "{t}");
    let envelope = std::fs::read(&envelope_path).unwrap();
    assert_eq!(envelope.len(), 169, "the fixed distribution envelope length");
    let m = verify_manifest(&envelope, &PinnedTrustRoot(xonly)).expect("must verify");
    assert_eq!(m.version(), 1);
    assert!(verify_manifest(&envelope, &ModeledTrustRoot).is_err(), "modeled root must reject");

    // Overwrite refusal (fails fast, before the passphrase/KDF).
    let out = run_tool(
        &["sign", params_ok.to_str().unwrap(), "--key", key_s, "--out", envelope_s, "--passphrase-stdin"],
        "",
    );
    assert!(!out.status.success());
    assert!(text(&out).contains("refusing to overwrite"), "{}", text(&out));

    // ---- inspect ----------------------------------------------------------
    let out = run_tool(&["inspect", envelope_s], "");
    let t = text(&out);
    assert!(out.status.success(), "inspect failed:\n{t}");
    assert!(t.contains("manifest version: 1"), "{t}");
    assert!(t.contains("tier_d_sats") && t.contains("1000000"), "{t}");
    assert!(t.contains("NOT CHECKED"), "without --root the signature is not judged:\n{t}");

    let out = run_tool(&["inspect", envelope_s, "--root", &pub_hex], "");
    let t = text(&out);
    assert!(out.status.success(), "inspect --root failed:\n{t}");
    assert!(t.contains("VERIFIES"), "{t}");

    // Wrong root: the signature check fails loudly.
    let wrong_root = "ee".repeat(32);
    let out = run_tool(&["inspect", envelope_s, "--root", &wrong_root], "");
    assert!(!out.status.success(), "a wrong root must fail inspect --root");

    // A truncated file is refused by the exact-length gate.
    let torn = dir.path().join("torn.manifest");
    std::fs::write(&torn, &envelope[..100]).unwrap();
    let out = run_tool(&["inspect", torn.to_str().unwrap()], "");
    assert!(!out.status.success());
    assert!(text(&out).contains("169"), "{}", text(&out));

    // ---- library-side ingest sanity for the SIGNED artifact ----------------
    // (The full store round trip lives in the tool's unit tests; here we
    // prove THE artifact this test signed ingests under its own root.)
    let store_dir = tempfile::tempdir().unwrap();
    let root = PinnedTrustRoot(xonly);
    let (mut store, _) =
        swapkey::wallet::manifest::ManifestStore::open(store_dir.path(), &root).unwrap();
    store.ingest(&envelope, &root).expect("the tool's envelope must ingest");
    assert_eq!(store.current().version(), 1);

    // A modeled-signed v2 is refused by the pinned store: the pre-alpha
    // "anyone who read the source" key has no authority under a real pin.
    let m2 = SignedManifest::compose(
        2,
        swapkey::settlement::params::Params::testnet_provisional(),
        swapkey::wallet::manifest::ClaimDelayPosture::Moderate,
        [(0, 6), (6, 36), (12, 72)],
        6,
        3,
    )
    .unwrap();
    let env2_modeled = sign_manifest(&m2, &modeled_operator_seckey()).unwrap();
    assert!(store.ingest(&env2_modeled, &root).is_err());

    // ---- reseal -----------------------------------------------------------
    // stdin mode: current passphrase then the new one. Afterwards the OLD
    // passphrase must stop signing and the NEW one must sign — under the
    // SAME pubkey (no re-pin).
    let out = run_tool(
        &["reseal", "--key", key_s, "--passphrase-stdin"],
        &format!("{PASSPHRASE}new operator pass\n"),
    );
    let t = text(&out);
    assert!(out.status.success(), "reseal failed:\n{t}");
    assert!(t.contains("keypair is unchanged"), "{t}");

    let envelope2 = dir.path().join("v2.manifest");
    let params_v2 = dir.path().join("v2.toml");
    write(&params_v2, &params_toml(2));
    let out = run_tool(
        &["sign", params_v2.to_str().unwrap(), "--key", key_s, "--out", envelope2.to_str().unwrap(), "--passphrase-stdin"],
        PASSPHRASE,
    );
    assert!(!out.status.success(), "the OLD passphrase must stop working after reseal");
    let out = run_tool(
        &["sign", params_v2.to_str().unwrap(), "--key", key_s, "--out", envelope2.to_str().unwrap(), "--passphrase-stdin"],
        "new operator pass\n",
    );
    assert!(out.status.success(), "the NEW passphrase must sign:\n{}", text(&out));
    let env2 = std::fs::read(&envelope2).unwrap();
    let m2 = verify_manifest(&env2, &PinnedTrustRoot(xonly))
        .expect("same keypair after reseal — the original root still verifies");
    assert_eq!(m2.version(), 2);
    // And the store accepts the post-reseal v2 over v1 (monotonic forward).
    store.ingest(&env2, &root).expect("v2 moves forward");
    assert_eq!(store.current().version(), 2);
}

#[test]
fn usage_errors_are_loud_and_secretless() {
    // Unknown flags/verbs are hard errors (never silently ignored).
    let out = run_tool(&["sign", "x.toml", "--kye", "k"], "");
    assert!(!out.status.success());
    assert!(text(&out).contains("unknown flag"), "{}", text(&out));

    let out = run_tool(&["frobnicate"], "");
    assert!(!out.status.success());
    assert!(text(&out).contains("unknown subcommand"), "{}", text(&out));

    // --flag=value is rejected (the shared CLI convention).
    let out = run_tool(&["keygen", "--out-dir=/tmp/x"], "");
    assert!(!out.status.success());
    assert!(text(&out).contains("--flag value"), "{}", text(&out));

    // help prints usage and the never-argv passphrase rule.
    let out = run_tool(&["help"], "");
    assert!(out.status.success());
    let t = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(t.contains("USAGE"), "{t}");
    assert!(t.contains("NEVER pass a"), "the never-argv passphrase rule must be in help: {t}");
}
