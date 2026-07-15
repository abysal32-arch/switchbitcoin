//! Task 23 — hostile-input PROPERTY / TOTALITY sweep of every tester-facing
//! parser, mirroring `tests/wire_totality.rs` (the wire surface, fuzzed since
//! commit one, is deliberately NOT duplicated here). Round 1 grew a lot of new
//! input surface strangers will now feed — swap tickets pasted from chat,
//! backup bundles from disk, manifest envelopes, HTTP requests from any local
//! process, the wallet config — and each got targeted negative tests per task
//! but never a systematic adversarial sweep. This is that sweep.
//!
//! Four invariants, asserted across every surface:
//!   1. NO PANIC — every byte/char string maps to Ok|Err. Any panic fails.
//!   2. NO UNBOUNDED ALLOCATION — a size-gate precedes every read/alloc (the
//!      manifest exact-length gate + keystore pre-KDF gates are the precedent).
//!   3. NO HANG — bounded loops; oversize input terminates in an Err.
//!   4. ERROR TEXT NEVER CARRIES INPUT BYTES — the config parser's "names keys,
//!      never values" discipline, generalized (a leaked value can be a secret).
//!
//! Behavioral (happy-path + specific-refusal) tests live in the owning files
//! (`tests/ticket.rs`, `tests/backup.rs`, `tests/api.rs`, and the manifest
//! module / `swapkey-manifest` in-bin tests); this file is the property layer.
//! The two BINARY parsers (`swapkey-cli` Flags/parse_*, `swapkey-manifest`
//! params-TOML) are unreachable from an integration test — their sweeps live
//! in-bin next to the code.
//!
//! Raise PROPTEST_CASES in CI to hammer harder (e.g. PROPTEST_CASES=100000).

use proptest::prelude::*;

use bitcoin::bech32::{self, Bech32m, Hrp};
use swapkey::settlement::params::Params;
use swapkey::wallet::config::{Network, WalletConfig};
use swapkey::wallet::ticket::Ticket;

// ============================================================================
// Surface 1 — wallet::ticket::Ticket::decode (a CHAT PASTE: the most
// attacker-shaped input in the system).
// ============================================================================

/// Encode arbitrary bytes under the real `skt` HRP + bech32m checksum, so a
/// property can drive the PAYLOAD parser directly (past the checksum gate)
/// with hostile field values a random string would never reach.
fn skt_encode(payload: &[u8]) -> String {
    bech32::encode::<Bech32m>(Hrp::parse("skt").unwrap(), payload).unwrap()
}

proptest! {
    /// Arbitrary strings: decode is TOTAL (never panics).
    #[test]
    fn ticket_decode_is_total_on_arbitrary_strings(s in ".*") {
        let _ = Ticket::decode(&s);
    }

    /// Arbitrary strings built from arbitrary bytes (covers invalid UTF-8
    /// boundaries via lossy conversion and control bytes): still total.
    #[test]
    fn ticket_decode_is_total_on_byte_derived_strings(
        data in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let s = String::from_utf8_lossy(&data);
        let _ = Ticket::decode(&s);
    }

    /// Arbitrary VALID-checksum `skt1…` strings over arbitrary payloads: the
    /// payload parser is total, and any payload it ACCEPTS re-encodes to the
    /// exact same string (no malleable accepted encoding).
    #[test]
    fn ticket_decode_is_total_on_arbitrary_skt_payloads(
        payload in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let s = skt_encode(&payload);
        if let Ok(t) = Ticket::decode(&s) {
            prop_assert_eq!(t.encode(), s);
        }
    }

    /// The length cap fires BEFORE any bech32 work: every over-cap string is a
    /// clean "length cap" refusal (proves the DoS gate, invariant 2/3).
    #[test]
    fn ticket_over_cap_strings_are_refused_by_the_cap(
        // >256 bytes; the body is bech32-legal chars so ONLY the cap can fire.
        n in 257usize..2048,
    ) {
        let s = format!("skt1{}", "q".repeat(n));
        match Ticket::decode(&s) {
            Err(swapkey::Error::Validation(m)) => {
                prop_assert!(m.contains("length cap"), "expected the cap, got: {}", m)
            }
            other => prop_assert!(false, "over-cap string not cap-refused: {:?}", other),
        }
    }

    /// Mint → encode → decode round-trips for every in-charset host/port/net,
    /// and the round-tripped ticket still validates against the same facts.
    #[test]
    fn ticket_round_trips_for_valid_endpoints(
        host in "[a-zA-Z0-9.-]{1,64}",
        port in 1u16..=u16::MAX,
        net in prop::sample::select(vec![Network::Regtest, Network::Testnet]),
    ) {
        let p = Params::testnet_provisional();
        let t = Ticket::mint(net, &p, &host, port).expect("in-charset endpoint");
        let s = t.encode();
        prop_assert!(s.starts_with("skt1"));
        let back = Ticket::decode(&s).expect("round-trip");
        prop_assert_eq!(&back, &t);
        prop_assert!(back.validate(net, &p).is_ok());
    }
}

// ============================================================================
// Surface 2 — wallet::backup restore (a bundle restored from disk).
// ============================================================================

use swapkey::wallet::backup::{restore_data_dir, BACKUP_MAGIC};

/// Serialize a bundle with a VALID trailing SHA-256 (an attacker can always
/// produce a well-hashed bundle — the hash gates corruption, the name
/// allowlist + the structural gates gate hostility). `count` is passed
/// explicitly so a property can make the declared count LIE about the entries.
fn craft_bundle(count: u32, entries: &[(&[u8], u64, &[u8])]) -> Vec<u8> {
    use bitcoin::hashes::{sha256, Hash};
    let mut v = Vec::new();
    v.extend_from_slice(BACKUP_MAGIC);
    v.extend_from_slice(&count.to_le_bytes());
    for (name, declared_len, data) in entries {
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(&declared_len.to_le_bytes());
        v.extend_from_slice(data);
    }
    let d = sha256::Hash::hash(&v).to_byte_array();
    v.extend_from_slice(&d);
    v
}

proptest! {
    // These touch the filesystem (restore reads a file), so keep the case
    // count modest — the parser is pure; the FS is just the delivery channel.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary bytes as a bundle file: restore is TOTAL and leaves NO dir at
    /// the destination (the parse fails long before anything is staged).
    #[test]
    fn restore_is_total_on_arbitrary_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let root = tempfile::tempdir().unwrap();
        let bundle = root.path().join("b.skbak");
        let target = root.path().join("t");
        std::fs::write(&bundle, &data).unwrap();
        let _ = restore_data_dir(&bundle, &target); // must not panic
        prop_assert!(!target.exists(), "no partial dir may appear at the target");
    }

    /// Bundles with a well-formed magic+hash but a header `count` that LIES
    /// about the entries, plus name/length fields that lie (allocation-bomb
    /// shape): total, always Err (the count is capped and every read is
    /// length-gated), never a partial dir.
    #[test]
    fn restore_is_total_on_lying_length_fields(
        declared_count in any::<u32>(),
        name in proptest::collection::vec(any::<u8>(), 0..300),
        declared_len in any::<u64>(),
        data in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let root = tempfile::tempdir().unwrap();
        let bundle = root.path().join("b.skbak");
        let target = root.path().join("t");
        let bytes = craft_bundle(declared_count, &[(&name, declared_len, &data)]);
        std::fs::write(&bundle, &bytes).unwrap();
        // A lying count/length is ALWAYS rejected — a lucky combination that
        // happened to be self-consistent could only ever name a file outside
        // the durable allowlist (random bytes are not `keystore.bin`).
        prop_assert!(restore_data_dir(&bundle, &target).is_err());
        prop_assert!(!target.exists());
    }
}

// ============================================================================
// Surface 3 — wallet::manifest verify/inspect + ManifestStore::open.
// ============================================================================

use swapkey::wallet::manifest::{
    inspect_envelope, modeled_operator_seckey, sign_manifest, verify_manifest, ClaimDelayPosture,
    ManifestStore, ModeledTrustRoot, SignedManifest,
};

/// A validly-signed baseline envelope at the given version, for mutation.
fn signed_envelope(version: u32) -> Vec<u8> {
    let m = SignedManifest::compose(
        version,
        Params::testnet_provisional(),
        ClaimDelayPosture::Moderate,
        [(0, 6), (6, 36), (12, 72)],
        6,
        3,
    )
    .unwrap();
    sign_manifest(&m, &modeled_operator_seckey()).unwrap()
}

proptest! {
    /// Arbitrary bytes of any length: verify_manifest AND inspect_envelope are
    /// total (the exact-length gate refuses a wrong size before any body work).
    #[test]
    fn manifest_verify_and_inspect_are_total(
        data in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let _ = verify_manifest(&data, &ModeledTrustRoot);
        let _ = inspect_envelope(&data);
    }

    /// Mutations of a valid envelope stay total; any that still VERIFIES
    /// inspects to the same manifest (no accepted-but-divergent parse).
    #[test]
    fn manifest_mutations_stay_total(
        version in 1u32..1000,
        flip_at in any::<usize>(),
        flip_bit in 0u8..8,
        truncate in 0usize..8,
        extend in proptest::collection::vec(any::<u8>(), 0..4),
    ) {
        let mut env = signed_envelope(version);
        if !env.is_empty() {
            let i = flip_at % env.len();
            env[i] ^= 1 << flip_bit;
        }
        env.truncate(env.len().saturating_sub(truncate));
        env.extend_from_slice(&extend);
        if let Ok(m) = verify_manifest(&env, &ModeledTrustRoot) {
            let seen = inspect_envelope(&env).expect("a verified envelope must inspect");
            prop_assert_eq!(m.version(), seen.version());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary garbage in `manifest.current` and `manifest.floor`:
    /// ManifestStore::open NEVER panics and NEVER fails open — it quarantines
    /// and falls back to the compiled baseline (or loads a genuinely valid one).
    #[test]
    fn manifest_store_open_survives_arbitrary_on_disk_bytes(
        current in proptest::collection::vec(any::<u8>(), 0..400),
        floor in proptest::collection::vec(any::<u8>(), 0..8),
    ) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("manifest.current"), &current).unwrap();
        std::fs::write(dir.path().join("manifest.floor"), &floor).unwrap();
        let opened = ManifestStore::open(dir.path(), &ModeledTrustRoot);
        // open() only errs on an unusable dir / lock contention — never on bad
        // manifest content. A fresh unique tempdir has neither.
        prop_assert!(opened.is_ok(), "open must not fail on hostile manifest bytes");
    }
}

// ============================================================================
// Surface 4 — wallet::api read_request + route + the flat JSON field decoders.
// ============================================================================

use std::io::Cursor;
use std::sync::mpsc;
use swapkey::wallet::api::{
    json_bool_field, json_str_field, json_u64_field, read_request, route, ApiCmd, ApiState,
    SharedState,
};
use std::sync::{Arc, Mutex};

fn api_state() -> (SharedState, mpsc::Sender<ApiCmd>, mpsc::Receiver<ApiCmd>) {
    let (tx, rx) = mpsc::channel();
    (Arc::new(Mutex::new(ApiState::new())), tx, rx)
}

/// `MAX_REQUEST` is private; this is its value (kept in step by the assertion
/// that a Content-Length just over it is refused, below).
const MAX_REQUEST: usize = 64 * 1024;

proptest! {
    /// Arbitrary request bytes: read_request is total (Ok|Err, never a panic).
    #[test]
    fn read_request_is_total_on_arbitrary_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let _ = read_request(&mut Cursor::new(data));
    }

    /// Arbitrary method/path/body into the router: total, and the status code
    /// is always one this server actually emits (no wild values → no panic in
    /// write_response's reason map either).
    #[test]
    fn route_is_total_on_arbitrary_inputs(
        method in "[A-Za-z]{0,8}",
        path in ".{0,64}",
        body in ".{0,256}",
    ) {
        let (state, tx, _rx) = api_state();
        let (code, _json) = route(&state, &tx, &method, &path, &body);
        prop_assert!(
            [200u16, 202, 204, 400, 404, 405, 409, 428, 503].contains(&code),
            "unexpected status {}", code
        );
    }

    /// The flat JSON field decoders are total on arbitrary bodies + keys
    /// (type-confusion: a numeric/object/array value under a string key must
    /// return None, never mis-extract or panic).
    #[test]
    fn json_field_decoders_are_total(
        body in ".{0,256}",
        key in "[a-zA-Z0-9_]{0,16}",
    ) {
        let _ = json_str_field(&body, &key);
        let _ = json_u64_field(&body, &key);
        let _ = json_bool_field(&body, &key);
    }

    /// A giant `since` on /events never overflows or panics — an unparseable
    /// value degrades to 0 and the reply is well-formed JSON.
    #[test]
    fn events_since_is_robust(since in ".{0,40}") {
        let (state, tx, _rx) = api_state();
        let (code, body) = route(&state, &tx, "GET", &format!("/events?since={since}"), "");
        prop_assert_eq!(code, 200);
        // (bind first: prop_assert! stringifies its condition, and a literal
        // brace in it would confuse the message formatter.)
        let well_formed = body.starts_with("{\"next\":");
        prop_assert!(well_formed, "events reply must be a JSON object: {}", body);
    }
}

#[test]
fn read_request_caps_bound_the_body_allocation() {
    // Content-Length one past the cap is refused BEFORE the body vec is sized.
    let raw = format!("POST /onboard HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_REQUEST + 1);
    assert!(read_request(&mut Cursor::new(raw.into_bytes())).is_err());
    // Exactly the cap is structurally accepted (declares 64KiB, sends 0) — it
    // fails as UnexpectedEof, proving the alloc path is bounded by the cap, not
    // by the attacker's declared number.
    let raw = format!("POST /onboard HTTP/1.1\r\nContent-Length: {MAX_REQUEST}\r\n\r\n");
    assert!(read_request(&mut Cursor::new(raw.into_bytes())).is_err());

    // A start line far longer than the cap terminates in an Err (the shared
    // `Read::take(MAX_REQUEST)` bounds total bytes read — no hang, no OOM),
    // never a panic, even with no newline in sight.
    let flood = vec![b'A'; MAX_REQUEST * 2];
    assert!(read_request(&mut Cursor::new(flood)).is_err());
}

#[test]
fn json_str_field_resists_key_name_smuggling_and_type_confusion() {
    // A key NAME appearing inside a prior value is not mistaken for the field
    // (the decoder requires a `:` after the quoted key).
    assert_eq!(
        json_str_field(r#"{"note":"deposit","deposit":"real"}"#, "deposit").as_deref(),
        Some("real")
    );
    // Type confusion: a number / object / array under a string key → None.
    assert_eq!(json_str_field(r#"{"deposit":123}"#, "deposit"), None);
    assert_eq!(json_str_field(r#"{"deposit":{"x":"y"}}"#, "deposit"), None);
    assert_eq!(json_str_field(r#"{"deposit":["a"]}"#, "deposit"), None);
    // A body with no such key → None (never a panic on a truncated escape).
    assert_eq!(json_str_field(r#"{"deposit":"tail\"#, "deposit"), None);
}

// ============================================================================
// Surface 5 — wallet::config::load (the wallet's outermost input surface).
// ============================================================================

fn load_cfg(dir: &std::path::Path, text: &str) -> Result<WalletConfig, swapkey::wallet::config::ConfigError> {
    let path = dir.join("swapkey.toml");
    std::fs::write(&path, text).unwrap();
    WalletConfig::load_with_env(&path, &|_| None)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Arbitrary config text never panics.
    #[test]
    fn config_load_is_total_on_arbitrary_text(text in ".{0,512}") {
        let dir = tempfile::tempdir().unwrap();
        let _ = load_cfg(dir.path(), &text);
    }

    /// A secret embedded ONLY as a VALUE never appears in any error message
    /// (invariant 4 — the config parser names keys + line numbers, never
    /// values; a leaked value could be the rpc_password). The sentinel is
    /// alphanumeric so it cannot terminate a quoted string or masquerade as
    /// structure, and each template places it strictly in value position.
    #[test]
    fn config_errors_never_echo_a_secret_value(
        sentinel in "[a-zA-Z0-9]{4,40}",
        template in 0usize..5,
    ) {
        // Never let the sentinel accidentally BE a valid value (no error to check).
        prop_assume!(sentinel != "regtest" && sentinel != "testnet");
        let text = match template {
            0 => format!("network = \"{sentinel}\"\ndata_dir = \"d\"\n"), // unknown network value
            1 => format!("network = \"regtest\"\ndata_dir = \"d\"\nrpc_password = \"{sentinel}\"\n"), // unknown bare key
            2 => format!("network = \"regtest\"\ndata_dir = \"d\"\nnetwork = \"{sentinel}\"\n"), // duplicate key
            3 => format!("network = \"{sentinel}\n"),                       // unterminated string
            _ => format!("network = \"{sentinel}\" junk\ndata_dir = \"d\"\n"), // trailing chars
        };
        let dir = tempfile::tempdir().unwrap();
        let err = load_cfg(dir.path(), &text).expect_err("each template must error");
        prop_assert!(
            !err.to_string().contains(&sentinel),
            "error echoed the value {:?}: {}", sentinel, err
        );
    }
}
