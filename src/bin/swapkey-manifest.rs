//! `swapkey-manifest` — Swap Key manifest ISSUANCE ops tooling (Task 18).
//!
//! The ONLY binary that ever touches the operator manifest-signing secret
//! (DECISION 1): `keygen` / `sign` / `reseal` here; the wallet binary
//! (`swapkey-cli`) has NO operator-key input path by construction — it only
//! ingests signed envelopes against its BUILD-TIME pinned trust root. This is
//! `wallet::manifest`'s own doctrine ("the wallet never holds
//! `operator_seckey`; the signing half lives only in ops tooling") made
//! structural.
//!
//! Subcommands (run `swapkey-manifest help`):
//!   keygen         generate the REAL operator keypair; the secret is sealed
//!                  (AES-256-GCM under a PBKDF2 passphrase KEK at the
//!                  keystore's production work factor) to `operator.key`,
//!                  NEVER written as plaintext; the x-only PUBKEY goes to
//!                  `operator.pub` and stdout (it is public — that is what a
//!                  wallet binary pins).
//!   sign           compose+validate a manifest from a params TOML and sign
//!                  it into its 169-byte distribution envelope. The SAME
//!                  `Params::validate()` / manifest invariants every wallet
//!                  asserts at ingest run here FIRST — invalid params fail at
//!                  authoring time, never on a tester's wallet.
//!   compose-check  the validation half of `sign`, secret-free.
//!   inspect        print an envelope's contents (display only; pass
//!                  `--root <xonly-hex>` to also verify the signature).
//!   reseal         change the sealed key file's passphrase (same keypair —
//!                  no re-pin, no re-issue).
//!
//! SECRET HYGIENE: the operator secret exists only (a) sealed on disk and
//! (b) transiently in zeroized memory during `sign`/`reseal`. Passphrases are
//! read from stdin (NFC-normalized, echoed — the pre-alpha convention shared
//! with `swapkey-cli`), NEVER accepted as argv (process lists / shell
//! history). Nothing secret is ever printed.
//!
//! PRE-ALPHA / TESTNET ONLY: one operator key, no rotation or threshold
//! signing (see docs/params-governance.md for the honest key-management
//! story, including key loss = re-pin + redistribute binaries).

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use bitcoin::secp256k1::{Keypair, Secp256k1};
use swapkey::settlement::params::Params;
use swapkey::wallet::keystore::{DEFAULT_PBKDF2_ITERS, MAX_PBKDF2_ITERS};
use swapkey::wallet::manifest::{
    inspect_envelope, sign_manifest, verify_manifest, ClaimDelayPosture, PinnedTrustRoot,
    SignedManifest, ENVELOPE_LEN,
};

/// Sealed operator-key file name written by `keygen` (inside `--out-dir`).
const KEY_FILE: &str = "operator.key";
/// Public x-only key file (hex, one line) written next to it.
const PUB_FILE: &str = "operator.pub";

/// File magic for the sealed operator key. Format mirrors `keystore.bin`
/// (magic || 16-byte salt || 4-byte LE iters || sealed payload) with a
/// 32-byte secret instead of the 64-byte seed.
const MAGIC: &[u8; 22] = b"newkey-operator-key-v1";
const SALT_LEN: usize = 16;
/// 12-byte GCM nonce + 32-byte secret + 16-byte GCM tag (`crypto::storage`).
const SEALED_SECKEY_LEN: usize = 12 + 32 + 16;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(()) => 0,
        Err(UsageError(msg)) => {
            eprintln!("error: {msg}");
            eprintln!("run `swapkey-manifest help` for usage");
            2
        }
    };
    std::process::exit(code);
}

/// Every failure funnels here as a printable line. `Debug` (for test
/// unwraps) carries the same message — never any secret by construction.
#[derive(Debug)]
struct UsageError(String);

impl From<swapkey::Error> for UsageError {
    fn from(e: swapkey::Error) -> Self {
        UsageError(e.to_string())
    }
}
impl From<std::io::Error> for UsageError {
    fn from(e: std::io::Error) -> Self {
        UsageError(format!("io: {e}"))
    }
}
impl From<String> for UsageError {
    fn from(s: String) -> Self {
        UsageError(s)
    }
}
impl From<&str> for UsageError {
    fn from(s: &str) -> Self {
        UsageError(s.to_string())
    }
}

type CliResult = Result<(), UsageError>;

fn run(args: &[String]) -> CliResult {
    let Some((cmd, rest)) = args.split_first() else {
        return Err("no subcommand".into());
    };
    let flags = Flags::parse(rest)?;
    match cmd.as_str() {
        "keygen" => cmd_keygen(&flags),
        "sign" => cmd_sign(&flags),
        "compose-check" => cmd_compose_check(&flags),
        "inspect" => cmd_inspect(&flags),
        "reseal" => cmd_reseal(&flags),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown subcommand `{other}`").into()),
    }
}

const HELP: &str = "\
swapkey-manifest — Swap Key manifest issuance (OPERATOR ops tooling; the only
binary that touches the manifest-signing secret. TESTNET pre-alpha.)

USAGE: swapkey-manifest <COMMAND> [FLAGS]

COMMANDS
  keygen    Generate the operator keypair. The secret is passphrase-SEALED to
            <dir>/operator.key (never plaintext); the x-only pubkey goes to
            <dir>/operator.pub and stdout — pin THAT in the wallet binary.
            Keep the dir OUTSIDE any repo; never commit operator.key.
            --out-dir <dir>     directory for the key files (required)
  sign <params.toml>  Compose + validate a manifest from the params file
            (the wallet's OWN invariants run here first — bad params fail at
            authoring time) and sign it into its distribution envelope.
            --key <operator.key>  the sealed signing key (required)
            --out <file>          envelope to write (required; never overwritten)
  compose-check <params.toml>  Validate authoring input; no key involved.
  inspect <envelope>  Print a manifest envelope's contents (display only).
            --root <xonly-hex>  also verify the signature against this root
  reseal    Change the sealed key's passphrase in place (same keypair, so the
            pinned pubkey and issued manifests are untouched).
            --key <operator.key>  the sealed signing key (required)

COMMON FLAGS
  --passphrase-stdin  read passphrase(s) from stdin lines instead of an
                      interactive prompt (keygen/sign: one line; reseal: the
                      current passphrase then the new one). NEVER pass a
                      passphrase as an argument.
";

// ---------------------------------------------------------------------------
// flag parsing / prompts (mirrors swapkey-cli's strict parser: an unknown or
// misspelled flag is a hard usage error, never silently ignored)
// ---------------------------------------------------------------------------

struct Flags {
    positional: Vec<String>,
    values: HashMap<String, String>,
    switches: Vec<String>,
}

const VALUE_FLAGS: &[&str] = &["--out-dir", "--key", "--out", "--root"];
const KNOWN_SWITCHES: &[&str] = &["--passphrase-stdin"];

impl Flags {
    fn parse(args: &[String]) -> Result<Flags, UsageError> {
        let mut f = Flags { positional: Vec::new(), values: HashMap::new(), switches: Vec::new() };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if let Some(name) = a.strip_prefix("--") {
                if a.contains('=') {
                    return Err(format!("{a}: use `--flag value`, not `--flag=value`").into());
                }
                if VALUE_FLAGS.contains(&a.as_str()) {
                    let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
                    if f.values.insert(name.to_string(), v.clone()).is_some() {
                        return Err(format!("{a} given twice").into());
                    }
                } else if KNOWN_SWITCHES.contains(&a.as_str()) {
                    f.switches.push(name.to_string());
                } else {
                    return Err(format!("unknown flag `{a}`").into());
                }
            } else {
                f.positional.push(a.clone());
            }
        }
        Ok(f)
    }
    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(|s| s.as_str())
    }
    fn required(&self, name: &str) -> Result<&str, UsageError> {
        self.value(name).ok_or_else(|| format!("--{name} is required").into())
    }
    fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }
}

/// Prompt for one line, returned zeroize-on-drop (in this tool every prompt
/// is a passphrase — the read buffer must not outlive it on the freed heap).
fn prompt_line(msg: &str) -> Result<Zeroizing<String>, UsageError> {
    eprint!("{msg}");
    std::io::stderr().flush().ok();
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    if line.is_empty() {
        return Err("stdin closed".into());
    }
    while line.ends_with(['\r', '\n']) {
        line.pop();
    }
    Ok(line)
}

/// Read + NFC-normalize ONE operator passphrase (the `read_passphrase`
/// contract shared with swapkey-cli: interactive echoed prompt by default,
/// `--passphrase-stdin` first-line mode for scripting, confirm-repeat only
/// interactively). Empty passphrases are refused — this seals the trust
/// root's signing half.
fn read_passphrase(flags: &Flags, prompt: &str, confirm: bool) -> Result<Zeroizing<String>, UsageError> {
    let raw = if flags.switch("passphrase-stdin") {
        prompt_line("")?
    } else {
        prompt_line(prompt)?
    };
    let first = Zeroizing::new(raw.as_str().nfc().collect::<String>());
    drop(raw); // zeroizes the pre-normalization buffer
    if first.is_empty() {
        return Err("empty operator-key passphrase refused".into());
    }
    if confirm && !flags.switch("passphrase-stdin") {
        let raw2 = prompt_line("Repeat passphrase: ")?;
        let again = Zeroizing::new(raw2.as_str().nfc().collect::<String>());
        drop(raw2);
        if *first != *again {
            return Err("passphrases do not match".into());
        }
    }
    Ok(first)
}

// ---------------------------------------------------------------------------
// sealed operator-key file
// ---------------------------------------------------------------------------

/// KEK = PBKDF2-HMAC-SHA256(passphrase, salt, iters), 32 bytes — identical
/// construction (and production work factor) to the wallet keystore's.
fn derive_kek(passphrase: &str, salt: &[u8; SALT_LEN], iters: u32) -> Zeroizing<[u8; 32]> {
    let mut kek = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase.as_bytes(), salt, iters, kek.as_mut());
    kek
}

/// Seal `seckey` to a NEW file at `path` (atomic `create_new` — an existing
/// operator key is NEVER overwritten; it may already be pinned in shipped
/// binaries).
fn seal_operator_key(
    path: &Path,
    seckey: &Zeroizing<[u8; 32]>,
    passphrase: &str,
    iters: u32,
) -> Result<(), UsageError> {
    if iters == 0 || iters > MAX_PBKDF2_ITERS {
        return Err("pbkdf2 iteration count out of range".into());
    }
    let mut salt = [0u8; SALT_LEN];
    rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut salt)
        .map_err(|_| "OS randomness unavailable; cannot seal the operator key")?;
    let kek = derive_kek(passphrase, &salt, iters);
    let sealed = swapkey::crypto::storage::seal(&kek, seckey.as_ref())?;

    let mut buf = Vec::with_capacity(MAGIC.len() + SALT_LEN + 4 + sealed.len());
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(&iters.to_le_bytes());
    buf.extend_from_slice(&sealed);

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{} already exists — refusing to overwrite a signing key", path.display())
            } else {
                format!("operator key file create failed: {e}")
            }
        })?;
    f.write_all(&buf).and_then(|()| f.sync_all())?;
    Ok(())
}

/// Open a sealed operator key. Pre-KDF header gates mirror the keystore's
/// (magic / iters cap / exact sealed length are checked BEFORE any KDF burn);
/// a wrong passphrase or tampering fails the GCM tag — clean Err, never
/// partial plaintext.
fn unseal_operator_key(path: &Path, passphrase: &str) -> Result<Zeroizing<[u8; 32]>, UsageError> {
    let raw = std::fs::read(path)
        .map_err(|e| format!("operator key file {} unreadable: {e}", path.display()))?;
    let header = MAGIC.len() + SALT_LEN + 4;
    if raw.len() < header || &raw[..MAGIC.len()] != MAGIC {
        return Err("not an operator key file (bad magic/length)".into());
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw[MAGIC.len()..MAGIC.len() + SALT_LEN]);
    let iters = u32::from_le_bytes(raw[MAGIC.len() + SALT_LEN..header].try_into().expect("4 bytes"));
    if iters == 0 || iters > MAX_PBKDF2_ITERS {
        return Err("operator key: iteration count out of range (corrupted header?)".into());
    }
    if raw.len() - header != SEALED_SECKEY_LEN {
        return Err("operator key: sealed payload has wrong length".into());
    }
    let kek = derive_kek(passphrase, &salt, iters);
    let plain = Zeroizing::new(
        swapkey::crypto::storage::open(&kek, &raw[header..])
            .map_err(|_| "operator key: wrong passphrase or corrupted file")?,
    );
    if plain.len() != 32 {
        return Err("operator key: sealed payload has wrong secret length".into());
    }
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&plain);
    Ok(sk)
}

/// The x-only public key for a secret, via the same pinned secp stack the
/// signing uses. Err (never panic) on an out-of-group secret.
fn xonly_of(seckey: &[u8; 32]) -> Result<[u8; 32], UsageError> {
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_slice(&secp, seckey)
        .map_err(|_| "operator secret is not a valid scalar")?;
    Ok(kp.x_only_public_key().0.serialize())
}

// ---------------------------------------------------------------------------
// params TOML (the authoring input)
// ---------------------------------------------------------------------------

/// Every key the params file must contain — ALL are REQUIRED and anything
/// else is an error. No defaults: the operator signs exactly what they wrote,
/// never what a missing line silently fell back to.
const REQUIRED_KEYS: [&str; 22] = [
    "version",
    "posture",
    "quorum_q",
    "params.tier_d_sats",
    "params.delta_fee_sats",
    "params.anchor_sats",
    "params.setup_fee_sats",
    "params.cpfp_reserve_sats",
    "params.delta_early",
    "params.margin",
    "params.delta_buffer",
    "params.claim_confirm_allowance",
    "params.cofunding_window",
    "params.onboarding_delay_lo_hours",
    "params.onboarding_delay_hi_hours",
    "delays.minimal_min",
    "delays.minimal_max",
    "delays.moderate_min",
    "delays.moderate_max",
    "delays.aggressive_min",
    "delays.aggressive_max",
    "delays.cofunding_jitter_max",
];

/// Parse the same deliberately tiny TOML subset `wallet::config` hand-parses
/// (quoted string values, `[section]` headers, `#` comments, BOM tolerated;
/// unknown keys/sections and duplicates are errors), with `[params]` /
/// `[delays]` sections. Every value is a STRING in the file; numeric
/// conversion happens per-key afterwards so errors can name the key.
fn parse_params_toml(text: &str) -> Result<BTreeMap<String, String>, UsageError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = BTreeMap::new();
    let mut section: Option<&str> = None;
    for (idx, raw_line) in text.lines().enumerate() {
        let n = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let Some(name) = rest.strip_suffix(']') else {
                return Err(format!("line {n}: unterminated section header").into());
            };
            section = match name.trim() {
                "params" => Some("params"),
                "delays" => Some("delays"),
                other => {
                    return Err(format!(
                        "line {n}: unknown section [{other}] (expected [params] or [delays])"
                    )
                    .into())
                }
            };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {n}: expected `key = \"value\"`").into());
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("line {n}: bad key name").into());
        }
        let value = parse_string_value(value.trim(), n)?;
        let full = match section {
            Some(s) => format!("{s}.{key}"),
            None => key.to_string(),
        };
        if !REQUIRED_KEYS.contains(&full.as_str()) {
            return Err(format!("line {n}: unknown key `{full}`").into());
        }
        if out.insert(full.clone(), value).is_some() {
            return Err(format!("line {n}: duplicate key `{full}`").into());
        }
    }
    for k in REQUIRED_KEYS {
        if !out.contains_key(k) {
            return Err(format!(
                "missing key `{k}` — every manifest field must be explicit (no silent defaults)"
            )
            .into());
        }
    }
    Ok(out)
}

/// One quoted string value; the remainder of the line may only be a comment.
/// (The config.rs grammar: double quotes with escapes, single quotes literal.)
fn parse_string_value(v: &str, n: usize) -> Result<String, UsageError> {
    let mut chars = v.chars();
    match chars.next() {
        Some('"') => {
            let mut out = String::new();
            loop {
                match chars.next() {
                    None => return Err(format!("line {n}: unterminated string").into()),
                    Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some('\\') => out.push('\\'),
                        Some('"') => out.push('"'),
                        Some('n') => out.push('\n'),
                        Some('r') => out.push('\r'),
                        Some('t') => out.push('\t'),
                        _ => return Err(format!("line {n}: unsupported escape").into()),
                    },
                    Some(c) => out.push(c),
                }
            }
            only_comment_after(chars.as_str(), n)?;
            Ok(out)
        }
        Some('\'') => {
            let rest = chars.as_str();
            let Some(end) = rest.find('\'') else {
                return Err(format!("line {n}: unterminated string").into());
            };
            only_comment_after(&rest[end + 1..], n)?;
            Ok(rest[..end].to_string())
        }
        _ => Err(format!("line {n}: values must be quoted strings").into()),
    }
}

fn only_comment_after(rest: &str, n: usize) -> Result<(), UsageError> {
    let rest = rest.trim_start();
    if rest.is_empty() || rest.starts_with('#') {
        Ok(())
    } else {
        Err(format!("line {n}: unexpected trailing characters after string value").into())
    }
}

fn num<T: std::str::FromStr>(map: &BTreeMap<String, String>, key: &str) -> Result<T, UsageError> {
    map.get(key)
        .expect("presence checked by parse_params_toml")
        .parse()
        .map_err(|_| format!("`{key}` is not a valid number in range").into())
}

/// Build (and thereby VALIDATE — `compose` runs the identical checks every
/// wallet asserts at ingest) the manifest the params file describes. This is
/// the "reject at authoring time" gate: anything a wallet would refuse fails
/// right here, before any signature exists.
fn compose_from_file(path: &Path) -> Result<SignedManifest, UsageError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("params file {} unreadable: {e}", path.display()))?;
    let map = parse_params_toml(&text)?;

    let posture = match map.get("posture").expect("presence checked").as_str() {
        "minimal" => ClaimDelayPosture::Minimal,
        "moderate" => ClaimDelayPosture::Moderate,
        "aggressive" => ClaimDelayPosture::Aggressive,
        _ => return Err("`posture` must be minimal, moderate, or aggressive".into()),
    };
    let params = Params {
        tier_d_sats: num(&map, "params.tier_d_sats")?,
        delta_fee_sats: num(&map, "params.delta_fee_sats")?,
        anchor_sats: num(&map, "params.anchor_sats")?,
        setup_fee_sats: num(&map, "params.setup_fee_sats")?,
        cpfp_reserve_sats: num(&map, "params.cpfp_reserve_sats")?,
        delta_early: num(&map, "params.delta_early")?,
        margin: num(&map, "params.margin")?,
        delta_buffer: num(&map, "params.delta_buffer")?,
        claim_confirm_allowance: num(&map, "params.claim_confirm_allowance")?,
        cofunding_window: num(&map, "params.cofunding_window")?,
        onboarding_delay_hours: (
            num(&map, "params.onboarding_delay_lo_hours")?,
            num(&map, "params.onboarding_delay_hi_hours")?,
        ),
    };
    let delay_bounds = [
        (num(&map, "delays.minimal_min")?, num(&map, "delays.minimal_max")?),
        (num(&map, "delays.moderate_min")?, num(&map, "delays.moderate_max")?),
        (num(&map, "delays.aggressive_min")?, num(&map, "delays.aggressive_max")?),
    ];
    let manifest = SignedManifest::compose(
        num(&map, "version")?,
        params,
        posture,
        delay_bounds,
        num(&map, "delays.cofunding_jitter_max")?,
        num(&map, "quorum_q")?,
    )?;
    if manifest.version() == 0 {
        // Version 0 is the compiled provisional baseline's identity; ingest
        // is strictly monotonic, so a signed v0 could never take effect
        // anywhere. Refuse at authoring time with the reason spelled out.
        return Err("version 0 is reserved for the compiled provisional baseline — \
                    signed manifests start at version 1"
            .into());
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// hex helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode32(s: &str) -> Result<[u8; 32], UsageError> {
    let s = s.trim();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("expected 64 hex characters (an x-only public key)".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).expect("hexdigit checked");
        let lo = (chunk[1] as char).to_digit(16).expect("hexdigit checked");
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// verbs
// ---------------------------------------------------------------------------

fn cmd_keygen(flags: &Flags) -> CliResult {
    if !flags.positional.is_empty() {
        return Err("keygen takes no positional arguments".into());
    }
    let dir = PathBuf::from(flags.required("out-dir")?);
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join(KEY_FILE);
    let pub_path = dir.join(PUB_FILE);
    if key_path.exists() {
        return Err(format!(
            "{} already exists — refusing to overwrite a signing key (use `reseal` to \
             change its passphrase)",
            key_path.display()
        )
        .into());
    }

    let passphrase = read_passphrase(
        flags,
        "New operator-key passphrase (echoed — pre-alpha): ",
        true,
    )?;

    // Fresh secret from the OS CSPRNG. An out-of-group draw is a ~2^-128
    // event; a bounded retry keeps a systemically broken RNG from looping
    // forever instead of failing loudly.
    let mut seckey = Zeroizing::new([0u8; 32]);
    let mut xonly = None;
    for _ in 0..8 {
        rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, seckey.as_mut())
            .map_err(|_| "OS randomness unavailable; cannot generate the operator key")?;
        if let Ok(x) = xonly_of(&seckey) {
            xonly = Some(x);
            break;
        }
    }
    let Some(xonly) = xonly else {
        return Err("OS randomness produced no valid key in 8 draws — refusing (broken RNG?)".into());
    };

    // The PUBLIC half first: a leftover operator.pub with no key is harmless
    // and gets rewritten by a re-run, while a sealed key whose pubkey never
    // got recorded would strand the pin.
    std::fs::write(&pub_path, format!("{}\n", hex_encode(&xonly)))?;
    seal_operator_key(&key_path, &seckey, &passphrase, DEFAULT_PBKDF2_ITERS)?;

    eprintln!("[swapkey-manifest] sealed operator key written: {}", key_path.display());
    eprintln!("[swapkey-manifest] KEEP IT OUT OF EVERY REPO; the passphrase is unrecoverable");
    eprintln!("[swapkey-manifest] x-only public key (pin this in the wallet binary):");
    println!("{}", hex_encode(&xonly));
    Ok(())
}

fn cmd_sign(flags: &Flags) -> CliResult {
    let [params_file] = flags.positional.as_slice() else {
        return Err("sign takes exactly one argument: the params TOML file".into());
    };
    let key_path = PathBuf::from(flags.required("key")?);
    let out_path = PathBuf::from(flags.required("out")?);
    if out_path.exists() {
        // Fail fast, BEFORE the passphrase prompt and the KDF burn (the
        // atomic create_new below remains the real race-safe guard).
        return Err(format!("{} already exists — refusing to overwrite", out_path.display()).into());
    }

    // Compose FIRST (secret-free): invalid params must fail before any
    // passphrase is asked for or any key material touches memory.
    let manifest = compose_from_file(Path::new(params_file))?;

    let passphrase = read_passphrase(flags, "Operator-key passphrase (echoed — pre-alpha): ", false)?;
    let seckey = unseal_operator_key(&key_path, &passphrase)?;
    let envelope = sign_manifest(&manifest, &seckey)?;

    // Self-check before anything ships: the envelope must verify against the
    // root derived from this very key (a never-verifying artifact is a bug
    // here, not a tester support case).
    let root = PinnedTrustRoot(xonly_of(&seckey)?);
    verify_manifest(&envelope, &root)
        .map_err(|e| format!("post-sign self-verification failed ({e}) — nothing written"))?;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{} already exists — refusing to overwrite", out_path.display())
            } else {
                format!("output create failed: {e}")
            }
        })?;
    f.write_all(&envelope).and_then(|()| f.sync_all())?;

    eprintln!(
        "[swapkey-manifest] signed manifest v{} written: {} ({} bytes)",
        manifest.version(),
        out_path.display(),
        envelope.len()
    );
    eprintln!("[swapkey-manifest] id: {}", hex_encode(&manifest.id()));
    eprintln!("[swapkey-manifest] distribute to ALL testers promptly (one version per test round)");
    eprintln!("[swapkey-manifest] testers ingest with: swapkey-cli manifest ingest <file>");
    Ok(())
}

fn cmd_compose_check(flags: &Flags) -> CliResult {
    let [params_file] = flags.positional.as_slice() else {
        return Err("compose-check takes exactly one argument: the params TOML file".into());
    };
    let manifest = compose_from_file(Path::new(params_file))?;
    eprintln!(
        "[swapkey-manifest] OK: composes as manifest v{} (id {}) — every wallet-side \
         invariant holds",
        manifest.version(),
        hex_encode(&manifest.id())
    );
    print_manifest(&manifest);
    Ok(())
}

fn cmd_inspect(flags: &Flags) -> CliResult {
    let [envelope_file] = flags.positional.as_slice() else {
        return Err("inspect takes exactly one argument: the manifest envelope file".into());
    };
    let path = Path::new(envelope_file);
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("envelope {} unreadable: {e}", path.display()))?;
    if meta.len() != ENVELOPE_LEN as u64 {
        return Err(format!(
            "not a manifest envelope: expected exactly {ENVELOPE_LEN} bytes, found {}",
            meta.len()
        )
        .into());
    }
    let envelope = std::fs::read(path)?;
    let manifest = inspect_envelope(&envelope)?;
    print_manifest(&manifest);
    match flags.value("root") {
        Some(hex) => {
            let root = PinnedTrustRoot(hex_decode32(hex)?);
            verify_manifest(&envelope, &root)?;
            println!("signature:        VERIFIES against root {}", hex.trim());
        }
        None => {
            println!("signature:        NOT CHECKED (pass --root <xonly-hex> to verify)");
        }
    }
    Ok(())
}

fn print_manifest(m: &SignedManifest) {
    let p = m.params();
    println!("manifest version: {}", m.version());
    println!("id:               {}", hex_encode(&m.id()));
    println!("network:          testnet (pre-alpha; the body's network byte is fixed)");
    println!("params:");
    println!("  tier_d_sats:             {}", p.tier_d_sats);
    println!("  delta_fee_sats:          {}", p.delta_fee_sats);
    println!("  anchor_sats:             {}", p.anchor_sats);
    println!("  setup_fee_sats:          {}", p.setup_fee_sats);
    println!("  cpfp_reserve_sats:       {}", p.cpfp_reserve_sats);
    println!("  delta_early:             {}", p.delta_early);
    println!("  margin:                  {}", p.margin);
    println!("  delta_buffer:            {}", p.delta_buffer);
    println!("  claim_confirm_allowance: {}", p.claim_confirm_allowance);
    println!("  cofunding_window:        {}", p.cofunding_window);
    println!(
        "  onboarding_delay_hours:  {}..{}",
        p.onboarding_delay_hours.0, p.onboarding_delay_hours.1
    );
    println!("active posture:   {:?}", m.active_posture());
    println!(
        "delay bounds:     minimal {:?} | moderate {:?} | aggressive {:?}",
        m.delay_bounds(ClaimDelayPosture::Minimal),
        m.delay_bounds(ClaimDelayPosture::Moderate),
        m.delay_bounds(ClaimDelayPosture::Aggressive),
    );
    println!("cofunding jitter: {}", m.cofunding_jitter_max());
    println!("quorum q:         {}", m.quorum_q());
}

fn cmd_reseal(flags: &Flags) -> CliResult {
    if !flags.positional.is_empty() {
        return Err("reseal takes no positional arguments".into());
    }
    let key_path = PathBuf::from(flags.required("key")?);
    // stdin mode: current passphrase on line 1, new on line 2 (no confirm);
    // interactive: prompt current, then new + confirm-repeat.
    let current = read_passphrase(flags, "Current operator-key passphrase (echoed): ", false)?;
    let seckey = unseal_operator_key(&key_path, &current)?;
    let new = read_passphrase(flags, "New operator-key passphrase (echoed): ", true)?;

    // Write the re-sealed file beside the original, then atomically replace.
    // Both files hold the SAME secret, so any crash leaves one complete,
    // openable file — never a lost key.
    let tmp = key_path.with_extension("key.tmp");
    if tmp.exists() {
        return Err(format!(
            "{} exists (an interrupted reseal?) — inspect and remove it first",
            tmp.display()
        )
        .into());
    }
    seal_operator_key(&tmp, &seckey, &new, DEFAULT_PBKDF2_ITERS)?;
    std::fs::rename(&tmp, &key_path)
        .map_err(|e| format!("reseal rename failed: {e} (the re-sealed key is at {})", tmp.display()))?;
    eprintln!(
        "[swapkey-manifest] operator key re-sealed under the new passphrase: {}",
        key_path.display()
    );
    eprintln!("[swapkey-manifest] the keypair is unchanged — no re-pin, no re-issue needed");
    Ok(())
}

// ---------------------------------------------------------------------------
// tests (run in the DEFAULT suite — this bin has no required-features)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use swapkey::wallet::manifest::{modeled_operator_seckey, ManifestStore, ModeledTrustRoot};

    /// Low work factor for the seal-format tests; the CLI layer always uses
    /// DEFAULT_PBKDF2_ITERS (same discipline as the keystore's TEST_ITERS).
    const TEST_ITERS: u32 = 16;

    /// The v1 authoring input: the UNCHANGED compiled baseline as a signed
    /// manifest (DECISION 4) — also exactly what docs/manifests/v1-params.toml
    /// carries.
    fn baseline_toml(version: u32) -> String {
        format!(
            r#"
version = "{version}"
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

    fn write_params(dir: &Path, text: &str) -> PathBuf {
        let p = dir.join("params.toml");
        std::fs::write(&p, text).unwrap();
        p
    }

    // -- negative tests FIRST (hostile input → clean Err, never a panic) ----

    #[test]
    fn hostile_params_files_are_rejected_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let cases: &[(&str, &str)] = &[
            // (line appended to the baseline — inside [delays], the last
            // section — and the expected error fragment)
            ("cofunding_jitter_max = \"6\"", "duplicate key"),
            ("cofunding_jitter_mux = \"6\"", "unknown key"), // typo key
            ("[wat]\nx = \"1\"", "unknown section"),
            ("tier_d_sats = \"1\"", "unknown key"), // params key in [delays]
        ];
        for (extra, fragment) in cases {
            let text = format!("{}\n{extra}\n", baseline_toml(1));
            let p = write_params(dir.path(), &text);
            let err = compose_from_file(&p).unwrap_err();
            assert!(err.0.contains(fragment), "for {extra:?}: {}", err.0);
        }

        // Missing key: drop one required line.
        let text = baseline_toml(1).replace("quorum_q = \"3\"\n", "");
        let p = write_params(dir.path(), &text);
        let err = compose_from_file(&p).unwrap_err();
        assert!(err.0.contains("missing key `quorum_q`"), "{}", err.0);

        // Non-numeric / out-of-range values name the key, never panic.
        for (needle, bad) in [
            ("tier_d_sats = \"1000000\"", "tier_d_sats = \"lots\""),
            ("margin = \"72\"", "margin = \"-1\""),
            ("quorum_q = \"3\"", "quorum_q = \"70000\""), // > u16
        ] {
            let text = baseline_toml(1).replace(needle, bad);
            let p = write_params(dir.path(), &text);
            assert!(compose_from_file(&p).is_err(), "must reject {bad}");
        }

        // Unquoted value: the string grammar refuses.
        let text = baseline_toml(1).replace("posture = \"moderate\"", "posture = moderate");
        let p = write_params(dir.path(), &text);
        assert!(compose_from_file(&p).unwrap_err().0.contains("quoted"));

        // Unknown posture.
        let text = baseline_toml(1).replace("\"moderate\"", "\"yolo\"");
        let p = write_params(dir.path(), &text);
        assert!(compose_from_file(&p).unwrap_err().0.contains("posture"));

        // Garbage file.
        let p = write_params(dir.path(), "\x00\x01 not toml at all");
        assert!(compose_from_file(&p).is_err());
    }

    #[test]
    fn authoring_rejects_what_the_wallet_would_reject() {
        let dir = tempfile::tempdir().unwrap();

        // Ordering-invariant violation (margin 0): the SAME validate() gate
        // the wallet runs at ingest fires at authoring time.
        let text = baseline_toml(3).replace("margin = \"72\"", "margin = \"0\"");
        let p = write_params(dir.path(), &text);
        let err = compose_from_file(&p).unwrap_err();
        assert!(err.0.contains("margin"), "{}", err.0);

        // Unsafe delay bound (max reaches the worst-case claim window).
        let text = baseline_toml(3).replace("aggressive_max = \"72\"", "aggressive_max = \"78\"");
        let p = write_params(dir.path(), &text);
        let err = compose_from_file(&p).unwrap_err();
        assert!(err.0.contains("claim window"), "{}", err.0);

        // Version 0 is reserved for the compiled baseline.
        let p = write_params(dir.path(), &baseline_toml(0));
        let err = compose_from_file(&p).unwrap_err();
        assert!(err.0.contains("version 0 is reserved"), "{}", err.0);
    }

    #[test]
    fn sealed_key_round_trips_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILE);
        let seckey = Zeroizing::new(modeled_operator_seckey());
        seal_operator_key(&path, &seckey, "правильная pass", TEST_ITERS).unwrap();

        // Round trip.
        let re = unseal_operator_key(&path, "правильная pass").unwrap();
        assert_eq!(*re, *seckey);

        // Never overwrite.
        assert!(seal_operator_key(&path, &seckey, "x", TEST_ITERS).is_err());

        // Wrong passphrase / empty: clean Err.
        assert!(unseal_operator_key(&path, "wrong").is_err());
        assert!(unseal_operator_key(&path, "").is_err());

        // The file never contains the plaintext secret.
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(8).any(|w| seckey.windows(8).any(|s| s == w)));

        // Tampered ciphertext fails the GCM tag.
        let mut bad = raw.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        std::fs::write(&path, &bad).unwrap();
        assert!(unseal_operator_key(&path, "правильная pass").is_err());

        // Iters header tampered to u32::MAX: rejected BEFORE any KDF burn.
        let mut bad = raw.clone();
        bad[MAGIC.len() + SALT_LEN..MAGIC.len() + SALT_LEN + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &bad).unwrap();
        let t0 = std::time::Instant::now();
        assert!(unseal_operator_key(&path, "правильная pass").is_err());
        assert!(t0.elapsed().as_secs() < 5, "iters cap must reject without a KDF burn");

        // Truncation / bad magic / padding: total rejection.
        std::fs::write(&path, &raw[..10]).unwrap();
        assert!(unseal_operator_key(&path, "правильная pass").is_err());
        let mut bad = raw.clone();
        bad[0] ^= 0xff;
        std::fs::write(&path, &bad).unwrap();
        assert!(unseal_operator_key(&path, "правильная pass").is_err());
        let mut bad = raw.clone();
        bad.push(0);
        std::fs::write(&path, &bad).unwrap();
        assert!(unseal_operator_key(&path, "правильная pass").is_err());
    }

    // -- the end-to-end authoring path ---------------------------------------

    /// THE Task-18 acceptance path at the library gate: tool-composed,
    /// tool-signed envelope → the wallet's own ManifestStore ACCEPTS it and
    /// its params take effect; every refusal gate holds against the real tool.
    #[test]
    fn tool_signed_manifest_round_trips_through_the_wallet_store() {
        let dir = tempfile::tempdir().unwrap();

        // A REAL (non-modeled) operator key, sealed and unsealed like the
        // tool does it.
        let key_path = dir.path().join(KEY_FILE);
        let mut sk = Zeroizing::new([0u8; 32]);
        rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, sk.as_mut()).unwrap();
        while xonly_of(&sk).is_err() {
            rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, sk.as_mut()).unwrap();
        }
        seal_operator_key(&key_path, &sk, "op pass", TEST_ITERS).unwrap();
        let seckey = unseal_operator_key(&key_path, "op pass").unwrap();
        let root = PinnedTrustRoot(xonly_of(&seckey).unwrap());

        // Author v1 = the unchanged compiled baseline (DECISION 4).
        let p = write_params(dir.path(), &baseline_toml(1));
        let m1 = compose_from_file(&p).unwrap();
        let env1 = sign_manifest(&m1, &seckey).unwrap();
        assert_eq!(env1.len(), ENVELOPE_LEN);

        // The wallet-side store, pinned to the REAL root, ingests it and the
        // params take effect (identical values, but now version 1 — off the
        // fingerprintable v0 partition).
        let store_dir = tempfile::tempdir().unwrap();
        let (mut store, _) = ManifestStore::open(store_dir.path(), &root).unwrap();
        assert!(store.is_provisional());
        store.ingest(&env1, &root).expect("the tool's v1 must ingest");
        assert!(!store.is_provisional());
        assert_eq!(store.current().version(), 1);
        assert_eq!(store.current().params(), &Params::testnet_provisional());

        // DOWNGRADE: v1 again (or anything <= floor) refuses.
        let p2 = write_params(dir.path(), &baseline_toml(2));
        let m2 = compose_from_file(&p2).unwrap();
        let env2 = sign_manifest(&m2, &seckey).unwrap();
        store.ingest(&env2, &root).expect("v2 moves forward");
        assert!(matches!(
            store.ingest(&env1, &root).unwrap_err(),
            swapkey::Error::Ordering(_)
        ));

        // Δ_fee-VERSION SWAP: changed params under a NON-bumped version must
        // refuse (the strictly-monotonic gate is what enforces "new params ⇒
        // new version"). Also covers a hostile equal-version re-issue.
        let text = baseline_toml(2).replace("delta_fee_sats = \"5000\"", "delta_fee_sats = \"4900\"");
        let p2b = write_params(dir.path(), &text);
        let m2b = compose_from_file(&p2b).unwrap();
        let env2b = sign_manifest(&m2b, &seckey).unwrap();
        assert!(matches!(
            store.ingest(&env2b, &root).unwrap_err(),
            swapkey::Error::Ordering(_)
        ));

        // WRONG KEY: the same manifest signed by a DIFFERENT real key is
        // refused by the pinned store (and vice versa below).
        let other = Zeroizing::new([0x33u8; 32]);
        let p3 = write_params(dir.path(), &baseline_toml(3));
        let m3 = compose_from_file(&p3).unwrap();
        let env3_wrong = sign_manifest(&m3, &other).unwrap();
        assert!(matches!(
            store.ingest(&env3_wrong, &root).unwrap_err(),
            swapkey::Error::Verification(_)
        ));

        // PIN SYMMETRY: a pinned-real-root store rejects modeled-signed
        // manifests; a modeled-root store rejects real-signed ones.
        let env3_modeled = sign_manifest(&m3, &modeled_operator_seckey()).unwrap();
        assert!(store.ingest(&env3_modeled, &root).is_err());
        let modeled_dir = tempfile::tempdir().unwrap();
        let (mut modeled_store, _) =
            ManifestStore::open(modeled_dir.path(), &ModeledTrustRoot).unwrap();
        let env3_real = sign_manifest(&m3, &seckey).unwrap();
        assert!(modeled_store.ingest(&env3_real, &ModeledTrustRoot).is_err());
        assert!(modeled_store.ingest(&env3_modeled, &ModeledTrustRoot).is_ok());
    }

    #[test]
    fn inspect_and_hex_helpers_are_total() {
        // inspect_envelope on garbage: clean Err (wrong length, torn body).
        assert!(inspect_envelope(&[]).is_err());
        assert!(inspect_envelope(&[0u8; ENVELOPE_LEN]).is_err());

        // A valid envelope inspects without any root.
        let p = tempfile::tempdir().unwrap();
        let file = write_params(p.path(), &baseline_toml(1));
        let m = compose_from_file(&file).unwrap();
        let env = sign_manifest(&m, &modeled_operator_seckey()).unwrap();
        let seen = inspect_envelope(&env).unwrap();
        assert_eq!(seen.version(), 1);
        assert_eq!(seen.id(), m.id());

        // hex helpers.
        assert_eq!(hex_decode32(&hex_encode(&[0xabu8; 32])).unwrap(), [0xabu8; 32]);
        assert!(hex_decode32("xyz").is_err());
        assert!(hex_decode32(&"a".repeat(63)).is_err());
        assert!(hex_decode32(&"g".repeat(64)).is_err());
    }

    #[test]
    fn reseal_keeps_the_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILE);
        let seckey = Zeroizing::new(modeled_operator_seckey());
        seal_operator_key(&path, &seckey, "old", TEST_ITERS).unwrap();

        // Reseal (the verb's core, minus prompts): unseal + seal-to-tmp + rename.
        let sk = unseal_operator_key(&path, "old").unwrap();
        let tmp = path.with_extension("key.tmp");
        seal_operator_key(&tmp, &sk, "new", TEST_ITERS).unwrap();
        std::fs::rename(&tmp, &path).unwrap();

        assert!(unseal_operator_key(&path, "old").is_err(), "old passphrase must stop working");
        let re = unseal_operator_key(&path, "new").unwrap();
        assert_eq!(xonly_of(&re).unwrap(), xonly_of(&seckey).unwrap(), "same keypair");
    }

    // -- Task 23: hostile-input property sweep of the params-TOML parser ------

    proptest! {
        /// Arbitrary authoring text: the params-TOML parser is TOTAL — every
        /// string maps to Ok|Err, never a panic (the section/key/quote grammar
        /// is hand-rolled, so this is its fuzz contract).
        #[test]
        fn params_toml_parse_is_total(text in ".{0,600}") {
            let _ = parse_params_toml(&text);
        }

        /// The same, one hop up: composing from an arbitrary file never panics
        /// (parse → per-key numeric conversion → the wallet's own invariants).
        #[test]
        fn compose_from_file_is_total(text in ".{0,600}") {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("params.toml");
            std::fs::write(&p, &text).unwrap();
            let _ = compose_from_file(&p);
        }

        /// A secret placed ONLY in VALUE position never appears in a parse
        /// error (the "names keys + line numbers, never values" discipline the
        /// wallet config parser established — a leaked value can be a secret).
        /// The sentinel is alphanumeric so it cannot terminate a quote or pose
        /// as structure, and every template keeps it strictly a value.
        #[test]
        fn params_toml_errors_never_echo_a_value(
            sentinel in "[a-zA-Z0-9]{4,40}",
            template in 0usize..5,
        ) {
            let text = match template {
                0 => format!("foo = \"{sentinel}\"\n"),              // unknown key
                1 => format!("quorum_q = \"3\"\nquorum_q = \"{sentinel}\"\n"), // duplicate key
                2 => format!("version = \"{sentinel}\n"),            // unterminated string
                3 => format!("version = \"{sentinel}\" junk\n"),     // trailing chars
                _ => format!("version = {sentinel}\n"),              // unquoted value
            };
            let err = parse_params_toml(&text).expect_err("each template must error");
            prop_assert!(
                !err.0.contains(&sentinel),
                "error echoed the value {:?}: {}", sentinel, err.0
            );
        }
    }
}
