//! `swapkey-cli` — the runnable pre-alpha wallet (Task 08).
//!
//! A THIN composition over the library seams: [`Wallet`] (config + keystore +
//! engine, Task 07), [`BitcoinCoreChainView`] (real node, Task 03),
//! [`TcpTransport`] (real peer, Tasks 04/05), and the runner module's
//! negotiation + tick→broadcast loop. All decisions live in the library
//! drivers; this binary owns ONLY user I/O, the process loop, and broadcasts
//! (the engine boundary).
//!
//! REGTEST/TESTNET ONLY — mainnet has no config variant by construction, and
//! the peer transport is plaintext TCP (LAN/loopback interop). No real funds
//! before the external cryptographer review.
//!
//! Subcommands (run `swapkey-cli help`):
//!   init      create (or resume creating) the wallet: keystore + mnemonic
//!             backup + Phase-0 acknowledgement + ledger; writes a config
//!             template if none exists. `--restore` re-seals from a mnemonic.
//!   address   issue a fresh deposit address.
//!   status    coins / reserve / swap records / operator alarms.
//!   onboard   register a confirmed deposit, split it (mints the CPFP
//!             reserve), broadcast the split, wait, confirm.
//!   swap      run ONE swap against a peer (--listen or --connect).
//!   recover   startup reconcile + crash-recovery scan; drives each tick's
//!             broadcast.
//!   backup    write one portable, integrity-hashed bundle of the data dir's
//!             durable files (refused while the wallet runs; no passphrase).
//!   restore   unpack a bundle into a fresh data dir (verify-then-rename
//!             atomic) and verify the wallet opens; --rescan raises the
//!             key-index floor when the bundle may be stale.
//!   watch     standalone watchtower (second-device dead-device refund guard).
//!   serve     localhost JSON API for SwapKey-Wallet.html (loopback, no auth).
//!   manifest  show/ingest the signed-params manifest. Verification is
//!             against the BUILD-TIME pinned operator key
//!             (`PINNED_OPERATOR_XONLY`); authoring/signing lives in the
//!             separate `swapkey-manifest` ops tool — this binary has no
//!             operator-key input path.
//!
//! Logging: plain lines to stderr, no secrets — the mnemonic is printed ONCE
//! (deliberately, to the terminal, for backup) by `init`; passphrases are
//! read from stdin and never echoed back.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use unicode_normalization::UnicodeNormalization;

use swapkey::chain::{AuthoritativeChainView, ChainView};
use swapkey::settlement::state_machine::PeerSession;
use swapkey::wallet::config::{Network, WalletConfig, CONFIG_FILE};
use swapkey::wallet::keys::KeyPurpose;
use swapkey::wallet::manifest::{
    ClaimDelayPosture, ManifestOpenReport, PinnedTrustRoot, ENVELOPE_LEN,
};
use swapkey::wallet::ledger::{acknowledge_phase0, SystemClock, PHASE0_WARNING};
use swapkey::wallet::runner::{
    self, apply_recovery_tick, backstop_step, hex32, negotiate_swap, refund_babysit_step,
    swap_step, RunOptions, SwapOutcome, SwapStepOutcome,
};
use swapkey::wallet::runtime::{FirstRunError, OpenedWallet, Wallet};
use swapkey::wallet::ticket::{maker_rendezvous, taker_rendezvous, Ticket};
use swapkey::wallet::transport::{
    negotiation_io_timeout, TcpTransport, DEFAULT_CONNECT_RETRIES, DIAL_RETRY_BACKOFF,
    RENDEZVOUS_LEASH,
};
use swapkey::wallet::SoftwareKeyStore;
use swapkey::wallet::SwapApp;

/// Deposit-address recognition scan bound (`onboard` maps the chain-reported
/// funding spk back to its key index; the ledger's counter is monotonic, so
/// real indices are small).
const KEY_SCAN_LIMIT: u32 = 10_000;

/// The BUILD-TIME manifest trust root (Task 18, DECISION 3): the REAL
/// pre-alpha operator x-only public key, hex
/// `fbb01df4f947cf69e8a24e4e907c60e8c903eb199e6dd949a2fabe5a5ea2191e`.
/// Generated 2026-07-14 by `swapkey-manifest keygen`; the sealed SECRET half
/// lives outside the repo (`operator-key\`, never committed) — this constant
/// is the public verification key only. Every `Wallet` open in this binary —
/// init, status, address, onboard, swap, recover, WATCH, serve, backup's
/// restore verification, manifest — pins it via [`Wallet::open_with_root`];
/// the prototype `ModeledTrustRoot` (whose secret is printed in the library
/// source) remains tests/library-only. DELIBERATELY not a config key: a
/// `swapkey.toml` pin would reduce the signed-manifest trust path to
/// config-file security (any local file writer could repoint the root, then
/// feed hostile-but-`validate()`-clean params). Key loss/rotation = re-pin +
/// rebuild + redistribute (docs/params-governance.md).
const PINNED_OPERATOR_XONLY: [u8; 32] = [
    0xfb, 0xb0, 0x1d, 0xf4, 0xf9, 0x47, 0xcf, 0x69, 0xe8, 0xa2, 0x4e, 0x4e, 0x90, 0x7c, 0x60,
    0xe8, 0xc9, 0x03, 0xeb, 0x19, 0x9e, 0x6d, 0xd9, 0x49, 0xa2, 0xfa, 0xbe, 0x5a, 0x5e, 0xa2,
    0x19, 0x1e,
];

/// The pinned root, boxed for [`Wallet::open_with_root`].
fn pinned_root() -> Box<PinnedTrustRoot> {
    Box::new(PinnedTrustRoot(PINNED_OPERATOR_XONLY))
}

/// The wall-clock the LEASE-eligibility reads use, by network. REGTEST ONLY:
/// reads fast-forward +73h so the onboarding decorrelation delay's WALL
/// anchor (24–72h) is immediately satisfied — on a mine-on-demand chain wall
/// time carries no decorrelation value, while the HEIGHT anchor (the same
/// delay in blocks) stays fully load-bearing and must be mined out. Anchor
/// WRITES (`confirm_split`) always use the real [`SystemClock`], and
/// testnet keeps real delays (mainnet has no config variant at all).
struct LeaseClock(Network);
impl swapkey::wallet::ledger::WalletClock for LeaseClock {
    fn now_unix(&self) -> u64 {
        let now = swapkey::wallet::ledger::WalletClock::now_unix(&SystemClock);
        match self.0 {
            Network::Regtest => now.saturating_add(73 * 3600),
            Network::Testnet => now,
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(()) => 0,
        Err(UsageError(msg)) => {
            eprintln!("error: {msg}");
            eprintln!("run `swapkey-cli help` for usage");
            2
        }
    };
    std::process::exit(code);
}

/// Every failure funnels here as a printable line (library errors keep their
/// Display text; no values/secrets ride in them by construction).
struct UsageError(String);

impl From<swapkey::Error> for UsageError {
    fn from(e: swapkey::Error) -> Self {
        UsageError(e.to_string())
    }
}
impl From<swapkey::wallet::config::ConfigError> for UsageError {
    fn from(e: swapkey::wallet::config::ConfigError) -> Self {
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
    // Shippability guard (Task 20): a build whose trust-root pin is invalid
    // or still the publicly-known modeled TEST key must be unmistakable on
    // EVERY invocation — never a silent fallback (anyone who read the library
    // source could sign manifests for such a wallet).
    if let Some(reason) = test_root_reason() {
        eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        eprintln!("!!! UNSHIPPABLE BUILD: {reason}.");
        eprintln!("!!! Anyone can forge signed manifests for this wallet. DO NOT");
        eprintln!("!!! DISTRIBUTE; rebuild with the real operator pubkey pinned in");
        eprintln!("!!! PINNED_OPERATOR_XONLY (see scripts/build-release.sh).");
        eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    }
    let Some((cmd, rest)) = args.split_first() else {
        return Err("no subcommand".into());
    };
    let flags = Flags::parse(rest)?;
    match cmd.as_str() {
        "init" => cmd_init(&flags),
        "address" => cmd_address(&flags),
        "status" => cmd_status(&flags),
        "onboard" => cmd_onboard(&flags),
        "swap" => cmd_swap(&flags),
        "recover" => cmd_recover(&flags),
        "watch" => cmd_watch(&flags),
        "serve" => cmd_serve(&flags),
        "backup" => cmd_backup(&flags),
        "restore" => cmd_restore(&flags),
        "manifest" => cmd_manifest(&flags),
        "quickstart" => cmd_quickstart(&flags),
        "diag" => cmd_diag(&flags),
        "version" | "--version" | "-V" => cmd_version(&flags),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown subcommand `{other}`").into()),
    }
}

/// `Some(reason)` when this binary's pin is unshippable: not a valid x-only
/// key, or equal to the modeled TEST root (whose SECRET is printed in the
/// library source). One cheap curve derivation per process start.
fn test_root_reason() -> Option<&'static str> {
    use swapkey::wallet::manifest::{ManifestTrustRoot, ModeledTrustRoot};
    if bitcoin::secp256k1::XOnlyPublicKey::from_slice(&PINNED_OPERATOR_XONLY).is_err() {
        return Some("the pinned trust root is not a valid x-only key");
    }
    if PINNED_OPERATOR_XONLY == ModeledTrustRoot.operator_xonly() {
        return Some("the pinned trust root is the PUBLIC modeled/test key");
    }
    None
}

const HELP: &str = "\
swapkey-cli — Swap Key pre-alpha wallet (REGTEST/TESTNET ONLY, no real funds)

USAGE: swapkey-cli <COMMAND> [FLAGS]

COMMANDS
  init      Create the wallet (keystore + mnemonic backup + Phase-0 ack +
            ledger). Writes a swapkey.toml template if none exists.
            --data-dir <path>   data dir for a fresh config template
            --network <net>     regtest|testnet for a fresh template (default regtest)
            --restore           restore the keystore from a BIP39 mnemonic
            --rescan <floor>    with --restore: raise the ledger key-index
                                floor afterwards — a mnemonic-only restore
                                rewinds issuance to 0, and without a floor new
                                addresses REUSE old on-chain indices
            --skip-backup-verification   waive the retype-the-words check (DANGER)
  address   Issue a fresh deposit address.
  status    Show coins, reserve, swap records, and operator alarms.
  onboard <txid:vout>  Register + split a CONFIRMED deposit, broadcast the
            split, wait for confirmation, confirm. Requires [node].
            --split-fee <sats>  split tx fee (default 2000)
            --key-index <n>     skip the address scan (index from `address`)
            --wait-secs <n>     confirmation wait budget (default 600)
  swap      Run ONE swap against a peer (to a CONFIRMED terminal). Requires [node].
            Deliberately single-swap (the scripted one-off path); CONCURRENT
            swaps live in `serve` (--max-swaps). A `swap` and a `serve` on the
            same data dir cannot run together (the store single-instance lock).
            Exactly one addressing mode (explicit flags outrank [peer] config):
            --make <host:port>  bind + mint a paste-able swap TICKET (printed on
                                stdout) and wait for a taker to dial it
            --take <ticket>     decode+validate a partner's ticket, then dial it
            --listen <addr> | --connect <addr>   raw address (no ticket)
            --feerate <sat/vB>  backstop CPFP feerate override (default: live
                                node estimate, fallback 2)
            --block-x-delta <blocks>  funding no-show deadline (default 144)
            --jitter <blocks>   co-funding jitter (default 0)
            --poll-secs <n>     chain poll cadence (default 5; the peer i/o
                                deadline scales with it)
            --accept-timeout-secs <n>  --listen wait budget (default 600)
            --connect-retries <n>  redial a refused/timed-out/unreachable peer
                                on --connect/--take before giving up (default 4,
                                ~2s apart); only the FIRST connect retries —
                                nothing is leased until both sides negotiate
            --assume-congested  manual congestion fallback when the node gives
                                no estimate: treat a relayed refund as below the
                                fee floor (fires the silent refund CPFP)
            --claim-posture <fast|balanced|private>  SL claim-delay privacy
                                (default: the signed manifest's active posture;
                                 maps to the manifest minimal/moderate/aggressive
                                 bands — a randomized, ceiling-clamped hold)
  recover   Startup reconcile + crash-recovery scan; drive each tick.
            --dry-run           decide but never broadcast
            --assume-congested  as for swap
  watch     Standalone watchtower (second-device dead-device refund guard):
            guard every persisted swap's escrow, firing ONLY this wallet's own
            pre-armed refunds at CSV maturity and standing down when a
            completion wins. Never negotiates, never signs or broadcasts a
            completion, never claims. Typically run against a data dir
            restored from a `backup` bundle on a second device (the
            delegation packet — see wallet::watch). Requires [node]. Exits
            once every guarded escrow's exit confirms.
            --poll-secs <n>     chain poll cadence (default 10)
            --feerate <sat/vB>  silent refund-CPFP feerate override (default:
                                live node estimate, fallback 2)
            --assume-congested  as for swap (treat a relayed refund as below
                                the fee floor; fires the silent refund CPFP)
            --once              one pass then exit (cron/scripting)
  backup <path>  Write a portable backup bundle of the wallet data dir's
            durable files to <path>. Sealed files stay sealed; the swap
            template sidecars / manifest ride public-by-design — the bundle
            cannot move funds but reveals swap METADATA (treat as
            restore-only material). Refused while the wallet is running;
            never overwrites <path>; needs no passphrase.
  restore   Unpack a bundle into the config's data_dir (must be fresh) and
            verify the wallet opens. The unpack is verify-then-rename atomic:
            a corrupt bundle leaves nothing behind. Then run `recover` to
            re-enter any in-flight swap.
            --from <bundle>     the file `backup` wrote (required)
            --rescan <floor>    raise the key-index floor after opening — use
                                when the bundle may be OLDER than the last
                                address this wallet ever issued
  manifest <show|ingest <file>>  The signed-params trust path (operator
            manifests are authored/signed by the SEPARATE swapkey-manifest
            tool; this wallet only verifies + ingests against its BUILD-TIME
            pinned operator key — the pin is deliberately not configurable).
            show                current version, id, params, and whether this
                                wallet still runs the fingerprintable v0
                                compiled baseline
            ingest <file>       verify + apply a signed manifest envelope;
                                refusals (bad signature, non-increasing
                                version, invariant violation) are printed
                                verbatim
  quickstart  Print the zero-to-first-swap walkthrough for new testers
            (node setup, init, faucet, onboard, swap ticket — each step
            names the next command). Start here.
  diag      Print a REDACTED support bundle for bug reports: build version,
            network, tip, manifest state, coin/record summary, alarms.
            NEVER contains the seed, mnemonic, passphrase, or RPC secrets.
  version   Print the build version (crate + git hash) and the pinned
            manifest trust root. PRE-ALPHA, TESTNET/REGTEST ONLY.
  serve     Localhost JSON API for SwapKey-Wallet.html (LOOPBACK ONLY, no
            auth — any local process can drive the wallet; pre-alpha).
            --port <n>          bind 127.0.0.1:<n> (default 3316)
            --poll-secs / --feerate / --assume-congested / --connect-retries
                                as for swap
            --claim-posture <fast|balanced|private>  as for swap (default: the
                                signed manifest's active posture)
            --max-swaps <n>     concurrent-swap cap (default 4); a swap past
                                the cap is a loud 409, never silently dropped
            Endpoints: GET /status /events?since=N /swap/<sid>;
            POST /onboard {deposit, ack_phase0, split_fee?},
            POST /swap/begin {connect|listen},
            POST /swap/offer {listen}  (mint a ticket; it appears in /status
                                as offer_ticket), POST /swap/take {ticket}
            /status lists every live swap in active_swaps (the legacy `swap`
            field carries the first).

COMMON FLAGS
  --config <path>        config file (default ./swapkey.toml)
  --passphrase-stdin     read the passphrase as the first stdin line
                         (scripting; default is an interactive prompt)
  --accept-phase0        acknowledge the Phase-0 warning without a prompt
";

// ---------------------------------------------------------------------------
// flag parsing / prompts
// ---------------------------------------------------------------------------

struct Flags {
    positional: Vec<String>,
    values: HashMap<String, String>,
    switches: Vec<String>,
}

/// Flags that take a value; everything else must be a KNOWN boolean switch —
/// an unknown/misspelled flag is a hard usage error, never silently ignored
/// (a typo'd `--dry-run` must not run a live swap; Fable review).
const VALUE_FLAGS: &[&str] = &[
    "--config",
    "--data-dir",
    "--network",
    "--split-fee",
    "--key-index",
    "--wait-secs",
    "--listen",
    "--connect",
    "--make",
    "--take",
    "--feerate",
    "--block-x-delta",
    "--jitter",
    "--poll-secs",
    "--accept-timeout-secs",
    "--connect-retries",
    "--port",
    "--claim-posture",
    "--max-swaps",
    "--from",
    "--rescan",
];

/// Every boolean switch any subcommand accepts.
const KNOWN_SWITCHES: &[&str] = &[
    "--passphrase-stdin",
    "--accept-phase0",
    "--skip-backup-verification",
    "--restore",
    "--dry-run",
    "--assume-congested",
    "--once",
];

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
    fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }
    fn num<T: FromStr>(&self, name: &str, default: T) -> Result<T, UsageError> {
        match self.value(name) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| format!("--{name}: not a number").into()),
        }
    }
    /// Presence-detecting numeric flag: `Some(n)` when given, `None` when
    /// absent (so a caller can distinguish "operator set it" from "use auto").
    fn num_opt<T: FromStr>(&self, name: &str) -> Result<Option<T>, UsageError> {
        match self.value(name) {
            None => Ok(None),
            Some(v) => v.parse().map(Some).map_err(|_| format!("--{name}: not a number").into()),
        }
    }
    fn config_path(&self) -> PathBuf {
        PathBuf::from(self.value("config").unwrap_or(CONFIG_FILE))
    }
}

/// Map a `--claim-posture` value to a signed-manifest band. The friendly names
/// (fast/balanced/private) and the manifest's own names (minimal/moderate/
/// aggressive) both work; anything else names the accepted values.
fn parse_claim_posture(v: &str) -> Result<ClaimDelayPosture, UsageError> {
    match v {
        "fast" | "minimal" => Ok(ClaimDelayPosture::Minimal),
        "balanced" | "moderate" => Ok(ClaimDelayPosture::Moderate),
        "private" | "aggressive" => Ok(ClaimDelayPosture::Aggressive),
        other => Err(format!(
            "--claim-posture: unknown posture `{other}` (accepted: fast|balanced|private)"
        )
        .into()),
    }
}

fn log(msg: &str) {
    eprintln!("[swapkey] {msg}");
}

/// A dial-failure message that names the likely cause and points at the guide's
/// connectivity section (Task 24). Testers hit refused/unreachable far more
/// often than any protocol error, and a bare transport abort sends them looking
/// in the wrong place.
fn dial_failed_hint(addr: &str, e: swapkey::Error) -> UsageError {
    format!(
        "could not reach the peer at {addr}: {e}. Likely the maker isn't \
         listening yet, or its host:port isn't reachable from here (home \
         NAT/firewall). The maker must advertise a REACHABLE address — \
         port-forward the listen port, or put both partners on one LAN/VPN. \
         See docs/TESTER-GUIDE.md, the \"Connectivity\" section."
    )
    .into()
}

/// The maker-side twin: an accept window elapsed with no taker. Usually the
/// taker never dialed, dialed the wrong ticket, or — most common on home
/// networks — could not REACH the advertised address.
fn no_taker_hint(advertised: &str) -> UsageError {
    format!(
        "no taker reached {advertised} before the accept timeout. Check the \
         taker actually dialed, and that your advertised host:port is reachable \
         from THEIR network (a home connection usually needs a port-forward or a \
         shared LAN/VPN). See docs/TESTER-GUIDE.md, the \"Connectivity\" section."
    )
    .into()
}

fn prompt_line(msg: &str) -> Result<String, UsageError> {
    eprint!("{msg}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if line.is_empty() {
        return Err("stdin closed".into());
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Read + NFC-normalize the wallet passphrase (the Task-07 input-boundary
/// contract: `Wallet::open` receives the normalized form). Interactive by
/// default; `--passphrase-stdin` takes the first stdin line for scripting.
/// NOTE (pre-alpha): the interactive prompt does not suppress terminal echo.
fn read_passphrase(flags: &Flags, confirm: bool) -> Result<String, UsageError> {
    let first = if flags.switch("passphrase-stdin") {
        prompt_line("")?
    } else {
        prompt_line("Wallet passphrase (echoed — pre-alpha): ")?
    };
    let first: String = first.nfc().collect();
    if confirm && !flags.switch("passphrase-stdin") {
        let again: String = prompt_line("Repeat passphrase: ")?.nfc().collect();
        if first != again {
            return Err("passphrases do not match".into());
        }
    }
    Ok(first)
}

/// Display the Phase-0 warning and gate on the user's acknowledgement, then
/// hand back the VERBATIM copy for the echo-typed APIs. `--accept-phase0`
/// records the operator's standing acknowledgement (scripting).
fn phase0_gate(flags: &Flags) -> Result<&'static str, UsageError> {
    eprintln!("\n=== PHASE-0 WARNING ===\n{PHASE0_WARNING}\n=======================");
    if flags.switch("accept-phase0") {
        log("phase-0 warning acknowledged via --accept-phase0");
        return Ok(PHASE0_WARNING);
    }
    let answer = prompt_line("Type ACCEPT to acknowledge: ")?;
    if answer.trim() != "ACCEPT" {
        return Err("phase-0 warning not acknowledged".into());
    }
    Ok(PHASE0_WARNING)
}

// ---------------------------------------------------------------------------
// wallet/config/chain plumbing
// ---------------------------------------------------------------------------

fn load_config(flags: &Flags) -> Result<WalletConfig, UsageError> {
    Ok(WalletConfig::load(&flags.config_path())?)
}

/// Open an ESTABLISHED wallet (everything but `init` expects `Ready`),
/// always under the BUILD-TIME pinned trust root, and surface the manifest
/// open report's abnormal variants as ALARMS before anything else runs.
fn open_ready(flags: &Flags) -> Result<Wallet, UsageError> {
    let config = load_config(flags)?;
    let passphrase = read_passphrase(flags, false)?;
    match Wallet::open_with_root(config, &passphrase, pinned_root())? {
        OpenedWallet::Ready(w) => {
            log_manifest_alarm(&w);
            Ok(*w)
        }
        OpenedWallet::FirstRun(_) => {
            Err("wallet onboarding is incomplete — run `swapkey-cli init` first".into())
        }
    }
}

/// The manifest-store open report's abnormal variants are operator ALARMS
/// (the wallet's params changed underneath the user — it fell back to the
/// compiled baseline, or a rollback was quarantined). Loaded/Fresh are the
/// quiet normal cases.
fn log_manifest_alarm(wallet: &Wallet) {
    match wallet.manifest_open_report() {
        ManifestOpenReport::ProvisionalFresh | ManifestOpenReport::Loaded { .. } => {}
        report @ ManifestOpenReport::ProvisionalFallback { .. } => log(&format!(
            "ALARM (manifest open): {report:?} — the stored manifest failed verification and \
             was quarantined; running the compiled baseline. Re-ingest the current signed \
             manifest (`manifest ingest <file>`)"
        )),
        report @ ManifestOpenReport::RollbackDetected { .. } => log(&format!(
            "ALARM (manifest open): {report:?} — a validly-signed but OLD manifest file was \
             restored over a newer one (rollback) and quarantined; running the compiled \
             baseline. Re-ingest the current signed manifest"
        )),
        report @ ManifestOpenReport::ProvisionalTransient { .. } => log(&format!(
            "ALARM (manifest open): {report:?} — the stored manifest could not be read this \
             session (transient I/O); running the compiled baseline FOR THIS SESSION only"
        )),
    }
}

fn chain_view(
    config: &WalletConfig,
) -> Result<swapkey::chain::BitcoinCoreChainView<swapkey::chain::HttpTransport>, UsageError> {
    let node = config
        .node
        .as_ref()
        .ok_or("this command needs a node: add a [node] section to swapkey.toml")?;
    Ok(node.chain_view()?)
}

/// Startup steps 2+3 with the operator-alarm surfacing the Task-E contract
/// demands. Returns whether the reconcile succeeded (lease/bump actions —
/// including a new swap's funding lease — must be gated on it).
fn startup_with_alarms(
    wallet: &mut Wallet,
    chain: &impl AuthoritativeChainView,
    opts: &RunOptions,
) -> Result<bool, UsageError> {
    for action in wallet.open_actions() {
        log(&format!("ALARM (store open): {action:?}"));
    }
    let (reconcile, scan) = wallet.startup(chain)?;
    let reconcile_ok = match reconcile {
        Ok(r) => {
            if !r.reserves_swept.is_empty() {
                log(&format!("reconcile: swept {} phantom reserve(s)", r.reserves_swept.len()));
            }
            true
        }
        Err(e) => {
            log(&format!("ALARM: chain reconcile failed ({e}); lease/bump actions are gated off"));
            false
        }
    };
    for path in &scan.unreadable {
        log(&format!("ALARM: unreadable swap record {}", path.display()));
    }
    for (sid, e) in &scan.failed {
        log(&format!("ALARM: recovery re-entry failed for {}: {e}", hex32(sid)));
    }
    let data_dir = wallet.config().data_dir.clone();
    let mut sink = |line: String| log(&line);
    for (sid, tick) in &scan.ticks {
        if let Err(e) =
            apply_recovery_tick(wallet.engine_mut(), chain, &data_dir, sid, tick, opts, &mut sink)
        {
            log(&format!("ALARM: driving recovery tick for {} failed: {e}", hex32(sid)));
        }
    }
    Ok(reconcile_ok)
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn cmd_init(flags: &Flags) -> CliResult {
    let config_path = flags.config_path();
    if !config_path.exists() {
        write_config_template(flags, &config_path)?;
    }
    let config = load_config(flags)?;

    let restoring = flags.switch("restore");
    let rescan_floor = flags.num_opt::<u32>("rescan")?;
    if rescan_floor.is_some() && !restoring {
        return Err("--rescan applies to `init --restore` (or to `restore --from`)".into());
    }

    // ONE passphrase read serves restore AND open — a second prompt would
    // break the documented --passphrase-stdin single-line contract and can
    // seal/open under different strings (Fable review).
    let passphrase = read_passphrase(flags, true)?;

    if restoring {
        // Dead-device recovery: re-seal the seed from the mnemonic into the
        // data dir, then fall through to the normal open (which resumes the
        // first-run ledger creation under the established-wallet guards).
        std::fs::create_dir_all(&config.data_dir)?;
        let words = prompt_line("BIP39 mnemonic (24 words, single line): ")?;
        SoftwareKeyStore::restore(&config.data_dir, &words, &passphrase)?;
        log("keystore restored from mnemonic");
        log("NOTE: the mnemonic recovers the SEED only. If you have a `backup` bundle,");
        log("      use `swapkey-cli restore --from <bundle>` instead — it brings back the");
        log("      coin ledger, swap records, and key index too.");
    }

    let mut first_run = match Wallet::open_with_root(config, &passphrase, pinned_root())? {
        OpenedWallet::Ready(w) => {
            log("wallet already initialized");
            log_manifest_alarm(&w);
            print_status(&w);
            return Ok(());
        }
        OpenedWallet::FirstRun(fr) => *fr,
    };

    // Acknowledgement loop: a Refused echo (a retype typo) hands the SAME
    // FirstRun back with the mnemonic STILL displayable — retry here instead
    // of exiting, which would resume as mnemonic-less and silently waive the
    // backup verification on the re-run (Fable review, HIGH).
    for attempt in 1..=3 {
        let backup_echo: Option<String> = match first_run.mnemonic() {
            Some(words) => {
                eprintln!("\n=== RECOVERY MNEMONIC (write it down now) ===");
                eprintln!("{words}");
                eprintln!("=============================================");
                if flags.switch("skip-backup-verification") {
                    log("WARNING: --skip-backup-verification waives the retype check; if you did");
                    log("         not back up the words above, this wallet is unrecoverable.");
                    Some(words.to_string())
                } else {
                    Some(prompt_line("Retype the 24 words to confirm your backup: ")?)
                }
            }
            None => {
                log("resuming an interrupted first run — the mnemonic was shown by the original");
                log("attempt and cannot be re-derived; if it was never backed up, start a fresh");
                log("data dir instead of continuing.");
                None
            }
        };
        let phase0 = phase0_gate(flags)?;

        match first_run.complete(phase0, backup_echo.as_deref()) {
            Ok(mut wallet) => {
                log("wallet created");
                if restoring {
                    match rescan_floor {
                        Some(floor) => {
                            wallet.engine_mut().ledger_mut().raise_key_index_floor(floor)?;
                            log(&format!(
                                "key-index floor raised to {floor} — issuance resumes past every index this wallet ever used"
                            ));
                        }
                        None => {
                            log("WARNING: a mnemonic-only restore rewinds key issuance to index 0. If this");
                            log("         wallet EVER issued an address, new addresses will REUSE on-chain");
                            log("         indices — re-run with --rescan <floor> (any generous over-estimate");
                            log("         of addresses ever issued is safe; gaps are never a problem).");
                        }
                    }
                }
                print_status(&wallet);
                log("next: edit swapkey.toml's [node] section if you haven't, then");
                log("      `swapkey-cli address` to get a deposit address");
                log("      (full walkthrough: `swapkey-cli quickstart`)");
                return Ok(());
            }
            Err(FirstRunError::Refused { first_run: fr, error }) => {
                first_run = *fr;
                log(&format!("onboarding refused ({error}) — attempt {attempt}/3"));
            }
            Err(FirstRunError::Fatal(e)) => {
                return Err(format!(
                    "onboarding failed past the point of no return ({e}); the ledger exists — \
                     the next `init`/open resumes as an established wallet"
                )
                .into())
            }
        }
    }
    Err("onboarding refused three times; nothing durable was created — re-run `init`".into())
}

fn write_config_template(flags: &Flags, path: &Path) -> CliResult {
    let network = match flags.value("network").unwrap_or("regtest") {
        "regtest" => Network::Regtest,
        "testnet" => Network::Testnet,
        other => return Err(format!("--network: unknown network `{other}`").into()),
    };
    let data_dir = match flags.value("data-dir") {
        Some(d) => PathBuf::from(d),
        None => std::env::current_dir()?.join("swapkey-data"),
    };
    let data_dir_str = data_dir.display().to_string();
    if data_dir_str.contains('\'') {
        // The template quotes the path as a single-quoted TOML literal.
        return Err("--data-dir must not contain a single-quote character".into());
    }
    let port = network.default_rpc_port();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let template = format!(
        "# swapkey.toml — Swap Key pre-alpha wallet (REGTEST/TESTNET only).\n\
         # Strings are quoted; single quotes are literal (Windows paths need no escaping).\n\
         # Unknown keys are load errors. Env overrides: SWAPKEY_* (see wallet::config).\n\
         network = \"{network}\"\n\
         data_dir = '{data_dir_str}'\n\
         \n\
         # Uncomment and fill to connect a local bitcoind (required by\n\
         # onboard/swap/recover). Prefer SWAPKEY_RPC_PASSWORD or cookie auth over\n\
         # writing a password here.\n\
         #[node]\n\
         #rpc_url = \"http://127.0.0.1:{port}\"\n\
         #rpc_user = \"user\"\n\
         #rpc_password = \"pass\"\n\
         #rpc_cookie_file = 'C:\\path\\to\\.cookie'\n\
         \n\
         # Peer defaults for `swap` (flags --listen/--connect override).\n\
         #[peer]\n\
         #listen = \"127.0.0.1:9735\"\n\
         #connect = \"127.0.0.1:9735\"\n"
    );
    std::fs::write(path, template)?;
    log(&format!("wrote config template {}", path.display()));
    Ok(())
}

// ---------------------------------------------------------------------------
// address / status
// ---------------------------------------------------------------------------

fn cmd_address(flags: &Flags) -> CliResult {
    let mut wallet = open_ready(flags)?;
    let network = wallet.config().network.to_bitcoin();
    let (index, spk) = wallet.engine_mut().issue_deposit_address()?;
    let address = bitcoin::Address::from_script(spk.as_script(), network)
        .map_err(|_| "derived spk is not addressable")?;
    println!("deposit address (key index {index}): {address}");
    println!("after it CONFIRMS: swapkey-cli onboard <txid:vout> --key-index {index}");
    Ok(())
}

fn cmd_status(flags: &Flags) -> CliResult {
    let wallet = open_ready(flags)?;
    print_status(&wallet);
    Ok(())
}

fn print_status(wallet: &Wallet) {
    let config = wallet.config();
    let params = wallet.params();
    println!("network:  {}", config.network);
    println!("data dir: {}", config.data_dir.display());
    println!(
        "params:   tier D {} sats | escrow {} sats | pre-encumbrance unit {} sats",
        params.tier_d_sats,
        params.escrow_amount_sats(),
        params.pre_encumbrance_sats()
    );
    let manifest = wallet.engine().manifest();
    if manifest.is_provisional() {
        println!(
            "manifest: v0 compiled baseline (PROVISIONAL — a fingerprintable anonymity \
             partition; see `manifest show`)"
        );
    } else {
        println!(
            "manifest: v{} (id {})",
            manifest.current().version(),
            hex32(&manifest.current().id())
        );
    }

    let ledger = wallet.engine().ledger();
    let coins = ledger.coins();
    if coins.is_empty() {
        println!("coins:    none — get an address (`address`) and onboard a deposit");
    } else {
        println!("coins ({}):", coins.len());
        for c in coins {
            println!(
                "  {:>12} sats  {:?}/{:?}  {}:{}",
                c.amount_sats, c.class, c.state, c.outpoint.txid, c.outpoint.vout
            );
        }
    }
    println!(
        "reserve:  {}",
        if ledger.has_leasable_reserve(1) { "leasable (backstop armed)" } else { "NONE (backstop inert)" }
    );

    match wallet.engine().store().list() {
        Ok((records, unreadable)) => {
            if records.is_empty() {
                println!("swaps:    none");
            } else {
                println!("swaps ({}):", records.len());
                for r in &records {
                    println!("  {}  {:?}", hex32(&r.swap_session_id), r.phase);
                }
            }
            for p in unreadable {
                println!("ALARM: unreadable swap record {}", p.display());
            }
        }
        Err(e) => println!("ALARM: could not enumerate the swap store: {e}"),
    }
    for action in wallet.open_actions() {
        println!("ALARM (store open): {action:?}");
    }
}

// ---------------------------------------------------------------------------
// onboard
// ---------------------------------------------------------------------------

fn parse_outpoint(s: &str) -> Result<bitcoin::OutPoint, UsageError> {
    let (txid, vout) = s.split_once(':').ok_or("deposit must be <txid>:<vout>")?;
    let txid = bitcoin::Txid::from_str(txid).map_err(|_| "deposit txid is not valid hex")?;
    let vout: u32 = vout.parse().map_err(|_| "deposit vout is not a number")?;
    Ok(bitcoin::OutPoint::new(txid, vout))
}

/// Split a `host:port` address (the LAST colon separates the port, so IPv4 and
/// hostnames work; an IPv6 literal would fail the ticket's host charset gate
/// downstream — IPv6 is out of scope pre-alpha).
fn split_host_port(addr: &str) -> Result<(String, u16), UsageError> {
    // Serves both `swap --make <addr>` and `POST /swap/offer {listen}`.
    let (host, port) = addr.rsplit_once(':').ok_or("listen address must be <host:port>")?;
    let port: u16 = port.parse().map_err(|_| "listen port is not a valid u16")?;
    Ok((host.to_string(), port))
}

fn cmd_onboard(flags: &Flags) -> CliResult {
    let deposit = parse_outpoint(
        flags.positional.first().ok_or("onboard needs a <txid:vout> argument")?,
    )?;
    let split_fee: u64 = flags.num("split-fee", 2_000)?;
    let wait_secs: u64 = flags.num("wait-secs", 600)?;

    let mut wallet = open_ready(flags)?;
    let chain = chain_view(wallet.config())?;
    let params = wallet.params().clone();

    // Resume routing for an already-tracked deposit: mid-split resumes the
    // broadcast/confirm; registered-but-unsplit (an earlier split_deposit
    // failure, e.g. a bad --split-fee) resumes at the SPLIT step instead of
    // wedging on "already tracked" (Fable review).
    {
        use swapkey::wallet::ledger::{CoinClass, CoinState};
        if let Some(coin) = wallet.engine().ledger().find(&deposit) {
            match (coin.class, coin.state, coin.split_attempts.last().cloned()) {
                (_, CoinState::SplitPending, Some(attempt)) => {
                    log("deposit already registered with a pending split — resuming");
                    chain.broadcast(&attempt.tx_bytes)?; // idempotent
                    return wait_and_confirm_split(&mut wallet, &chain, attempt.txid, wait_secs);
                }
                (CoinClass::Deposit, CoinState::Unspent, _) => {
                    log("deposit already registered but not yet split — resuming at the split");
                }
                _ => return Err("deposit already tracked by the ledger".into()),
            }
        } else {
            // Fresh deposit: the chain is the source of truth for its facts.
            let height = chain
                .funding_height(deposit)
                .ok_or("deposit not found or not confirmed — wait for a confirmation")?;
            let amount = chain
                .funding_amount(deposit)
                .ok_or("node did not report the deposit amount")?;
            let spk = chain
                .funding_spk(deposit)
                .ok_or("node did not report the deposit scriptPubKey")?;

            // Map the spk back to OUR key index (issued by `address`);
            // --key-index skips the scan. Either way register_deposit
            // re-validates the binding.
            let key_index = match flags.value("key-index") {
                Some(v) => v.parse::<u32>().map_err(|_| "--key-index: not a number")?,
                None => {
                    let keys = wallet.engine().keys();
                    let mut found = None;
                    for i in 0..KEY_SCAN_LIMIT {
                        if runner::derived_spk(keys, KeyPurpose::Deposit, i)? == spk {
                            found = Some(i);
                            break;
                        }
                    }
                    found.ok_or("deposit does not pay any address of this wallet")?
                }
            };

            // The FIRST deposit demands its own Phase-0 acknowledgement
            // (distinct from init's); later deposits ignore the ack.
            let ack = acknowledge_phase0(phase0_gate(flags)?)?;
            wallet
                .engine_mut()
                .register_deposit(deposit, amount, height, key_index, &spk, Some(ack))?;
            log(&format!(
                "deposit registered: {amount} sats at height {height} (key index {key_index})"
            ));
        }
    }

    let plan = wallet.engine_mut().split_deposit(deposit, &params, split_fee)?;
    log(&format!(
        "split built: {} pre-encumbrance unit(s), reserve {} sats, change {} sats, fee {split_fee} sats",
        plan.pre_encumbrance_count, plan.reserve_sats, plan.change_sats
    ));
    let txid = chain.broadcast(&plan.tx_bytes)?;
    log(&format!("split broadcast: {txid}"));
    wait_and_confirm_split(&mut wallet, &chain, plan.txid, wait_secs)
}

/// Poll until the split confirms, then anchor the onboarding delays
/// (`confirm_split`). Bounded: on timeout, re-running `onboard` resumes.
fn wait_and_confirm_split(
    wallet: &mut Wallet,
    chain: &impl AuthoritativeChainView,
    split_txid: bitcoin::Txid,
    wait_secs: u64,
) -> CliResult {
    let probe = bitcoin::OutPoint::new(split_txid, 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(wait_secs);
    let height = loop {
        if let Some(h) = chain.funding_height(probe) {
            break h;
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "split {split_txid} not confirmed within {wait_secs}s — re-run `onboard` \
                 with the same deposit to resume"
            )
            .into());
        }
        std::thread::sleep(Duration::from_secs(5));
    };
    wallet.engine_mut().ledger_mut().confirm_split(split_txid, height, &SystemClock)?;
    log(&format!("split confirmed at height {height}; onboarding delays anchored"));
    log("coins become leasable after their decorrelation delay (24-72h wall clock) — check `status`");
    Ok(())
}

// ---------------------------------------------------------------------------
// swap
// ---------------------------------------------------------------------------

fn cmd_swap(flags: &Flags) -> CliResult {
    // A dry-run swap is REFUSED rather than half-honored: the negotiation is
    // a live two-party exchange that leases a coin and leaves the peer to
    // fund and wait out a CSV refund — nothing about it can be "dry" (Fable
    // review). Decision observation without broadcasts is `recover --dry-run`.
    if flags.switch("dry-run") {
        return Err(
            "swap does not support --dry-run (negotiation is a live two-party exchange); \
             use `recover --dry-run` to observe decisions"
                .into(),
        );
    }
    let opts = RunOptions {
        target_feerate_sat_vb: flags.num_opt("feerate")?,
        dry_run: false,
        refund_congested: flags.switch("assume-congested"),
    };
    let block_x_delta: u32 = flags.num("block-x-delta", 144)?;
    let jitter: u32 = flags.num("jitter", 0)?;
    let poll_secs: u64 = flags.num("poll-secs", 5)?;
    let poll = Duration::from_secs(poll_secs);
    let accept_timeout = Duration::from_secs(flags.num("accept-timeout-secs", 600)?);
    let connect_retries: u32 = flags.num("connect-retries", DEFAULT_CONNECT_RETRIES)?;

    let mut wallet = open_ready(flags)?;
    // Operator claim-delay posture override (else the signed manifest's active
    // posture). It only selects among the manifest's signed bands; the runtime
    // ceiling clamp binds regardless.
    if let Some(v) = flags.value("claim-posture") {
        wallet.engine_mut().set_claim_posture(Some(parse_claim_posture(v)?));
    }
    let chain = chain_view(wallet.config())?;
    let network = wallet.config().network;
    let data_dir = wallet.config().data_dir.clone();

    // Canonical startup first; the negotiation LEASES a coin, so it is gated
    // on the reconcile succeeding (the Task-E caller contract).
    if !startup_with_alarms(&mut wallet, &chain, &opts)? {
        return Err("chain reconcile failed — fix the node/data dir before swapping".into());
    }

    // Fee-weather preflight (Task 26): read the live estimate and WARN-AND-
    // PROCEED if congestion outruns the baked Setup/settlement feerates. NO gate
    // (the reserve-CPFP backstop bridges the gap after the fact) — this is only
    // a heads-up before funding into bad weather, so a stranded Setup does not
    // read to a tester as a mystery hang.
    {
        use swapkey::wallet::fee_weather::FeeWeather;
        let fw = FeeWeather::assess(wallet.params(), chain.estimated_feerate_sat_vb());
        log(&fw.log_line());
    }

    // Peer transport. EXPLICIT FLAGS OUTRANK THE CONFIG ENTIRELY: an operator
    // typing --listen must never be silently dialed out by a leftover [peer]
    // connect value (Fable review). Exactly ONE addressing mode is allowed;
    // --make/--take (the ticket flows) NEVER fall back to [peer] config.
    let peer_cfg = wallet.config().peer.clone();
    let make = flags.value("make").map(str::to_string);
    let take = flags.value("take").map(str::to_string);
    let listen_flag = flags.value("listen").map(str::to_string);
    let connect_flag = flags.value("connect").map(str::to_string);
    let modes_set = [&make, &take, &listen_flag, &connect_flag].iter().filter(|m| m.is_some()).count();
    if modes_set > 1 {
        return Err("choose exactly one of --make, --take, --listen, --connect".into());
    }
    let mut transport = if let Some(make_addr) = make {
        // MAKER: bind the given host:port, mint + PRINT a ticket, wait for the
        // taker, then run the maker-half rendezvous BEFORE any lease. A failed
        // rendezvous (port scan / wrong ticket) is a clean error here.
        let (host, port) = split_host_port(&make_addr)?;
        if host == "0.0.0.0" || host == "::" || host.contains(':') {
            log("WARNING: --make advertises a non-dialable host (0.0.0.0/::) — the ticket must");
            log("         carry an address your peer can actually reach");
        }
        let ticket = Ticket::mint(network, wallet.params(), &host, port)?;
        let encoded = ticket.encode();
        let listener = std::net::TcpListener::bind(make_addr.as_str())
            .map_err(|e| format!("bind {make_addr}: {e}"))?;
        log(&format!("swap ticket (send this whole line to your taker): {encoded}"));
        // Bare stdout line too, so a script can capture the ticket cleanly.
        println!("{encoded}");
        log(&format!("listening on {make_addr} (waiting up to {}s)", accept_timeout.as_secs()));
        // Keep accepting until the deadline: a port scan or wrong-ticket dial
        // is DROPPED without burning the offer (mirrors the serve path) — only
        // a peer that passes the maker-half rendezvous gets the swap.
        let deadline = std::time::Instant::now() + accept_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(no_taker_hint(&make_addr));
            }
            let mut t = TcpTransport::accept_timeout(&listener, remaining)
                .map_err(|_| no_taker_hint(&make_addr))?;
            // Short leash for the rendezvous so a silent dialer can't hang us.
            match t
                .set_io_timeout(Some(RENDEZVOUS_LEASH))
                .and_then(|()| maker_rendezvous(&mut t, &ticket.nonce))
            {
                Ok(()) => {
                    log("ticket rendezvous ok — negotiating");
                    break t;
                }
                Err(e) => {
                    log(&format!("ticket rendezvous failed ({e}); connection dropped, still listening"));
                }
            }
        }
    } else if let Some(take_str) = take {
        // TAKER: decode + validate against THIS wallet's network + params
        // BEFORE dialing — a mismatch is a clean refusal, not a hung socket.
        let ticket = Ticket::decode(take_str.trim())?;
        ticket.validate(network, wallet.params())?;
        let addr = ticket.addr();
        log(&format!("dialing swap-ticket peer at {addr}"));
        let mut t =
            TcpTransport::connect_retrying(&addr, connect_retries, DIAL_RETRY_BACKOFF, &mut |m| {
                log(&m)
            })
            .map_err(|e| dial_failed_hint(&addr, e))?;
        t.set_io_timeout(Some(RENDEZVOUS_LEASH))?;
        taker_rendezvous(&mut t, &ticket.nonce)?;
        log("ticket rendezvous ok — negotiating");
        t
    } else {
        // Legacy raw --listen/--connect (flags outrank [peer] config).
        let (listen, connect) = match (listen_flag, connect_flag) {
            (Some(_), Some(_)) => {
                return Err("--listen and --connect are mutually exclusive".into())
            }
            (Some(l), None) => (Some(l), None),
            (None, Some(c)) => (None, Some(c)),
            (None, None) => match (peer_cfg.listen, peer_cfg.connect) {
                (Some(_), Some(_)) => {
                    return Err(
                        "config sets both [peer] listen and connect — pass --listen or --connect"
                            .into(),
                    )
                }
                other => other,
            },
        };
        match (listen, connect) {
            (_, Some(addr)) => {
                log(&format!("connecting to peer {addr}"));
                TcpTransport::connect_retrying(
                    addr.as_str(),
                    connect_retries,
                    DIAL_RETRY_BACKOFF,
                    &mut |m| log(&m),
                )
                .map_err(|e| dial_failed_hint(&addr, e))?
            }
            (Some(addr), None) => {
                let listener = std::net::TcpListener::bind(addr.as_str())
                    .map_err(|e| format!("bind {addr}: {e}"))?;
                log(&format!("listening on {addr} (waiting up to {}s)", accept_timeout.as_secs()));
                TcpTransport::accept_timeout(&listener, accept_timeout)
                    .map_err(|_| no_taker_hint(&addr))?
            }
            (None, None) => {
                return Err(
                    "swap needs --make/--take/--listen/--connect (or a [peer] config section)"
                        .into(),
                )
            }
        }
    };
    // Whole-frame budget: the Phase-A rendezvous skew between the two sides
    // is bounded by the SLOWER side's poll cadence, so the deadline must
    // scale with it (a fixed budget under a large --poll-secs would abort
    // healthy funded swaps to refund; Fable review). This ALSO restores the
    // normal budget after any short ticket-rendezvous leash above.
    let io_timeout = negotiation_io_timeout(poll);
    transport.set_io_timeout(Some(io_timeout))?;

    // Ephemeral session key (module docs in wallet::runner).
    let session_seckey = secp::Scalar::random(&mut rand::rng());
    let negotiated = negotiate_swap(
        &mut transport,
        wallet.engine_mut(),
        &chain,
        &LeaseClock(network),
        network,
        &data_dir,
        session_seckey,
    )?;
    let sid = negotiated.artifacts.session_id;
    log(&format!("negotiated swap session {}", hex32(&sid)));

    let peer = PeerSession::new(sid, Box::new(transport));
    let block_x = chain.tip_height() + block_x_delta;
    let mut app =
        SwapApp::begin(wallet.engine(), negotiated.ctx, peer, block_x, jitter)?;
    if let Some(order) = app.funding_order() {
        log(&format!("funding order: {order:?} (Block X at height {block_x})"));
    }
    // The SL claim privacy posture (randomized, ceiling-clamped claim delay,
    // wallet::claim_scheduler) IS applied now: the run loop holds the SL claim
    // broadcast until the sampled target height (Task 13).
    {
        let posture = wallet.engine().effective_claim_posture();
        let source = if flags.value("claim-posture").is_some() { "flag" } else { "manifest" };
        log(&format!(
            "claim-delay privacy posture active: {posture:?} ({source}) — the SL claim broadcast \
             is held for a randomized, ceiling-clamped delay"
        ));
    }

    let artifacts = negotiated.artifacts;
    let mut state = swapkey::wallet::SwapRunState::new();
    let mut sink = |line: String| log(&line);
    let mut iter: u64 = 0;

    // The run loop: poll + backstop on one cadence; drivers decide, we
    // broadcast, terminals exit. FUND-EXPOSURE DISCIPLINE: once our Setup is
    // on the wire, a hard error must never exit the process — it degrades to
    // the backstop guard loop (the live tower is what fires the dead-device
    // refund) instead of abandoning a funded escrow (Fable review, HIGH).
    let outcome = loop {
        match swap_step(&mut app, wallet.engine_mut(), &chain, &artifacts, &mut state, &opts, &mut sink)
        {
            Ok(SwapStepOutcome::Done(outcome)) => break outcome,
            Ok(SwapStepOutcome::Continue(tick)) => {
                // Every poll acts; log the wait states on a slow cadence.
                if iter.is_multiple_of(6) {
                    log(&format!("tick: {tick:?}"));
                }
            }
            // Holding the SL claim for the privacy posture: fall through to the
            // backstop/recovery/sleep tail EXACTLY like Continue — the backstop
            // guarding every refund deadline through the hold is load-bearing.
            Ok(SwapStepOutcome::Holding { broadcast_at_height }) => {
                if iter.is_multiple_of(6) {
                    log(&format!(
                        "holding the SL claim until height {broadcast_at_height} (tip {})",
                        chain.tip_height()
                    ));
                }
            }
            Err(e) if state.setup_on_wire => {
                log(&format!("ALARM: swap loop failed with our escrow exposed: {e}"));
                return guard_funded_escrow(&mut wallet, &chain, &app, &data_dir, &opts, poll);
            }
            Err(e) => return Err(e.into()),
        }
        // Task 22: on testnet4 a reorg is routine (regtest never reorged under
        // us). The drivers HOLD conservatively through one — but a silent hold
        // looks like a hang, so surface it loudly. Pure observation; the poll
        // above owns every decision.
        if iter.is_multiple_of(6) {
            if let Ok(Some(rec)) = wallet.engine().store().get(&sid) {
                if let Some(sig) = swapkey::wallet::observe_reorg(&rec, &chain) {
                    log(&sig.describe(&sid));
                }
            }
        }
        if let Err(e) = backstop_step(&app, wallet.engine_mut(), &chain, &opts, &mut sink) {
            log(&format!("backstop pass failed (retrying next poll): {e}"));
        }
        // Other swaps' persisted deadlines stay driven during a long swap
        // (Fable review): a periodic whole-wallet recovery pass, excluding
        // the live swap (its ticks belong to the app above).
        if iter.is_multiple_of(12) && iter > 0 {
            recovery_pass(&mut wallet, &chain, &data_dir, &opts, &[sid]);
        }
        iter += 1;
        std::thread::sleep(poll);
    };

    match outcome {
        SwapOutcome::Completed { completion_txid } => {
            log(&format!(
                "completion {completion_txid} is on the wire; babysitting until it CONFIRMS"
            ));
            loop {
                if let Err(e) = backstop_step(&app, wallet.engine_mut(), &chain, &opts, &mut sink) {
                    log(&format!("backstop pass failed (retrying next poll): {e}"));
                }
                match swapkey::wallet::runner::completion_babysit_step(
                    wallet.engine_mut(),
                    &chain,
                    &data_dir,
                    &sid,
                    &opts,
                    &mut sink,
                ) {
                    Ok(Some(())) => {
                        log("SWAP COMPLETED — our completion is confirmed on chain");
                        return Ok(());
                    }
                    Ok(None) => {}
                    Err(e) => log(&format!("completion babysit failed (retrying): {e}")),
                }
                std::thread::sleep(poll);
            }
        }
        SwapOutcome::Aborted { reason } => {
            log(&format!("swap aborted cleanly, nothing was locked: {reason}"));
            Ok(())
        }
        SwapOutcome::Refunding { reason } => {
            log(&format!("swap routed to the refund exit: {reason}"));
            log("babysitting the refund until it confirms (Ctrl-C is safe; `recover` resumes)");
            loop {
                // The backstop keeps guarding (dead-device fire, CPFP bump)
                // until the refund confirms — the AppTick::Refunding contract.
                if let Err(e) = backstop_step(&app, wallet.engine_mut(), &chain, &opts, &mut sink) {
                    log(&format!("backstop pass failed (retrying next poll): {e}"));
                }
                match refund_babysit_step(wallet.engine_mut(), &chain, &data_dir, &sid, &opts, &mut sink)
                {
                    Ok(Some(phase)) => {
                        log(&format!("refund path resolved — record terminal: {phase:?}"));
                        return Ok(());
                    }
                    Ok(None) => {}
                    Err(e) => log(&format!("babysit step failed (retrying next poll): {e}")),
                }
                std::thread::sleep(poll);
            }
        }
    }
}

/// Terminal degradation for a hard swap-loop error with our escrow exposed:
/// keep the process alive running ONLY the backstop (the dead-device refund
/// fires from the live ctx even with no store record) plus refund babysit
/// attempts, until the escrow's spend CONFIRMS. Exits nonzero — the swap did
/// not complete; `recover` reconciles the records afterwards.
fn guard_funded_escrow(
    wallet: &mut Wallet,
    chain: &impl AuthoritativeChainView,
    app: &SwapApp,
    data_dir: &Path,
    opts: &RunOptions,
    poll: Duration,
) -> CliResult {
    let escrow = app.our_escrow();
    let sid_hint = "guard";
    log("entering the escrow guard loop: this process keeps the refund guarded until the");
    log("escrow's exit confirms — do NOT kill it unless the refund is already on chain");
    let mut sink = |line: String| log(&line);
    loop {
        if let Err(e) = backstop_step(app, wallet.engine_mut(), chain, opts, &mut sink) {
            log(&format!("[{sid_hint}] backstop pass failed (retrying): {e}"));
        }
        recovery_pass(wallet, chain, data_dir, opts, &[]);
        if matches!(chain.spend_status(escrow), swapkey::chain::SpendStatus::Confirmed(_)) {
            log("escrow exit confirmed; run `recover` to reconcile the records");
            return Err("swap errored after funding; the escrow was resolved via its exit".into());
        }
        std::thread::sleep(poll);
    }
}

/// One whole-wallet recovery pass (scan + drive each tick), best-effort —
/// used inside long-running loops so OTHER swaps' deadlines are never
/// starved by the live one. `exclude` skips the live swap's own record.
fn recovery_pass(
    wallet: &mut Wallet,
    chain: &impl AuthoritativeChainView,
    data_dir: &Path,
    opts: &RunOptions,
    exclude: &[[u8; 32]],
) {
    let mut sink = |line: String| log(&line);
    match SwapApp::recover(wallet.engine(), chain) {
        Ok(scan) => {
            for (sid, tick) in &scan.ticks {
                if exclude.contains(sid) {
                    continue;
                }
                if let Err(e) = apply_recovery_tick(
                    wallet.engine_mut(),
                    chain,
                    data_dir,
                    sid,
                    tick,
                    opts,
                    &mut sink,
                ) {
                    log(&format!("recovery tick for {} failed: {e}", hex32(sid)));
                }
            }
        }
        Err(e) => log(&format!("recovery pass failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// recover
// ---------------------------------------------------------------------------

fn cmd_recover(flags: &Flags) -> CliResult {
    let opts = RunOptions {
        target_feerate_sat_vb: flags.num_opt("feerate")?,
        dry_run: flags.switch("dry-run"),
        refund_congested: flags.switch("assume-congested"),
    };
    let mut wallet = open_ready(flags)?;
    let chain = chain_view(wallet.config())?;
    startup_with_alarms(&mut wallet, &chain, &opts)?;
    log("recovery scan driven; re-run as the chain advances until every swap is terminal");
    Ok(())
}

// ---------------------------------------------------------------------------
// watch — the standalone watchtower (Task 19); see wallet::watch for the
// delegation-packet decision and the theft/grief argument
// ---------------------------------------------------------------------------

fn cmd_watch(flags: &Flags) -> CliResult {
    // Same rule as swap/serve (Fable review lineage): a watch tick's PURPOSE
    // is to fire the dead-device refund — nothing about it can be "dry".
    if flags.switch("dry-run") {
        return Err(
            "watch does not support --dry-run (a tick fires the dead-device refund); \
             use `recover --dry-run` to observe decisions"
                .into(),
        );
    }
    let poll = Duration::from_secs(flags.num("poll-secs", 10)?);
    let once = flags.switch("once");

    let mut wallet = open_ready(flags)?;
    let chain = chain_view(wallet.config())?;
    let data_dir = wallet.config().data_dir.clone();

    for action in wallet.open_actions() {
        log(&format!("ALARM (store open): {action:?}"));
    }
    // Reconcile ONLY — deliberately NOT the full startup_with_alarms: driving
    // recovery ticks would broadcast completions (`Extract`/`Rebroadcast`),
    // which stay the owning wallet's business; a watchtower fires nothing but
    // its own pre-armed refunds. The reconcile gates reserve leases per the
    // Task-E caller contract; its failure gates the CPFP off but never the
    // refund FIRE (a pure chain action the tower performs regardless).
    let allow_bump = match wallet.engine_mut().reconcile_with_chain(&chain) {
        Ok(r) => {
            if !r.reserves_swept.is_empty() {
                log(&format!("reconcile: swept {} phantom reserve(s)", r.reserves_swept.len()));
            }
            true
        }
        Err(e) => {
            log(&format!(
                "ALARM: chain reconcile failed ({e}); reserve CPFP bumps are gated off — \
                 refund fires are unaffected"
            ));
            false
        }
    };

    let opts = swapkey::wallet::watch::WatchOptions {
        target_feerate_sat_vb: flags.num_opt("feerate")?,
        refund_congested: flags.switch("assume-congested"),
        allow_bump,
    };
    let set = swapkey::wallet::watch::arm_guards(wallet.engine())?;
    for p in &set.unreadable {
        log(&format!("ALARM: unreadable swap record {}", p.display()));
    }
    for (sid, why) in &set.unguardable {
        log(&format!("ALARM: cannot guard {}: {why}", hex32(sid)));
    }
    let mut guards = set.guards;
    if guards.is_empty() {
        log("no guardable swaps in the store — nothing to watch");
        return Ok(());
    }
    log(&format!(
        "watchtower armed: guarding {} escrow(s) — this process fires ONLY this wallet's \
         own pre-armed refunds and stands down on completions",
        guards.len()
    ));
    for g in &guards {
        log(&format!(
            "  guarding {} escrow {}:{} ({:?})",
            hex32(g.sid()),
            g.escrow().txid,
            g.escrow().vout,
            g.phase_at_arm()
        ));
    }
    let mut sink = |line: String| log(&line);
    loop {
        let remaining = swapkey::wallet::watch::watch_pass(
            &mut guards,
            wallet.engine_mut(),
            &chain,
            &data_dir,
            &opts,
            &mut sink,
        );
        if remaining == 0 {
            log("every guarded escrow's exit is confirmed — watchtower standing down");
            return Ok(());
        }
        if once {
            log(&format!("--once: {remaining} escrow(s) still guarded — re-run to keep guarding"));
            return Ok(());
        }
        std::thread::sleep(poll);
    }
}

// ---------------------------------------------------------------------------
// backup / restore (Task 17) — see wallet::backup for the format + decisions
// ---------------------------------------------------------------------------

fn cmd_backup(flags: &Flags) -> CliResult {
    let [dest] = flags.positional.as_slice() else {
        return Err("backup takes exactly one argument: the bundle file to write".into());
    };
    let config = load_config(flags)?;
    let dest = PathBuf::from(dest);
    // Deliberately NO passphrase: the bundle is a byte-faithful snapshot of
    // files that are already sealed at rest — backup must stay runnable from
    // a script/cron without unlocking the wallet.
    let summary = swapkey::wallet::backup_data_dir(&config.data_dir, &dest)?;
    for (name, len) in &summary.files {
        log(&format!("  bundled {name} ({len} bytes)"));
    }
    log(&format!(
        "backup written: {} ({} files, {} bytes)",
        dest.display(),
        summary.files.len(),
        summary.total_bytes()
    ));
    log("NOTE: sealed files stay encrypted in the bundle; the swap-template sidecars");
    log("      and manifest ride public-by-design. The bundle alone cannot move funds,");
    log("      but it reveals swap METADATA — treat it as restore-only material.");
    Ok(())
}

fn cmd_restore(flags: &Flags) -> CliResult {
    let Some(bundle) = flags.value("from") else {
        return Err("restore needs --from <bundle> (use `init --restore` for the mnemonic-only path)".into());
    };
    if !flags.positional.is_empty() {
        return Err("restore takes no positional arguments (did you mean --from <bundle>?)".into());
    }
    let rescan_floor = flags.num_opt::<u32>("rescan")?;
    let config = load_config(flags)?;
    let data_dir = config.data_dir.clone();

    let summary = swapkey::wallet::restore_data_dir(Path::new(bundle), &data_dir)?;
    log(&format!(
        "restored {} files ({} bytes) into {}",
        summary.files.len(),
        summary.total_bytes(),
        data_dir.display()
    ));

    // Verification open — the acceptance gate: a restored dir must open
    // cleanly, and any store-open alarms must reach the operator NOW.
    let passphrase = read_passphrase(flags, false)?;
    let mut wallet = match Wallet::open_with_root(config, &passphrase, pinned_root()) {
        Ok(OpenedWallet::Ready(w)) => *w,
        Ok(OpenedWallet::FirstRun(_)) => {
            return Err(
                "restore: the restored dir routed to first-run — the bundle was not an established wallet"
                    .into(),
            )
        }
        Err(e) => {
            return Err(format!(
                "the files were restored, but the wallet did not open ({e}) — check the passphrase; the restored dir was left in place"
            )
            .into())
        }
    };
    log_manifest_alarm(&wallet);
    for action in wallet.open_actions() {
        log(&format!("ALARM (store open): {action:?}"));
    }
    match rescan_floor {
        Some(floor) => {
            wallet.engine_mut().ledger_mut().raise_key_index_floor(floor)?;
            log(&format!(
                "key-index floor raised to {floor} — issuance resumes past every index this wallet ever used"
            ));
        }
        None => {
            log("NOTE: if this bundle is OLDER than the last address this wallet issued, key");
            log("      issuance has rewound — re-run `restore` guidance: raise the floor with");
            log("      --rescan <floor> (a generous over-estimate is safe; gaps never hurt).");
        }
    }
    print_status(&wallet);
    log("restore complete — run `swapkey-cli recover` to re-enter any in-flight swap");
    Ok(())
}

// ---------------------------------------------------------------------------
// manifest — the wallet-side (secret-free) half of the Task-18 trust path.
// Authoring/signing lives in the SEPARATE swapkey-manifest tool; this wallet
// binary has no operator-key input path by construction (DECISION 1) and
// verifies only against its build-time pinned root (DECISION 3). Ingest is
// CLI-only — deliberately no `serve` endpoint (DECISION 6).
// ---------------------------------------------------------------------------

fn cmd_manifest(flags: &Flags) -> CliResult {
    match flags.positional.first().map(String::as_str) {
        Some("show") => {
            if flags.positional.len() != 1 {
                return Err("manifest show takes no further arguments".into());
            }
            let wallet = open_ready(flags)?;
            print_manifest_state(&wallet);
            Ok(())
        }
        Some("ingest") => {
            let file = match flags.positional.as_slice() {
                [_, file] => PathBuf::from(file),
                _ => return Err("manifest ingest takes exactly one argument: the envelope file".into()),
            };
            // Exact-length gate BEFORE the read: the envelope is fixed-size
            // by construction, so anything else is refused without pulling
            // an arbitrarily large file into memory.
            let meta = std::fs::metadata(&file)
                .map_err(|e| format!("manifest file {} unreadable: {e}", file.display()))?;
            if meta.len() != ENVELOPE_LEN as u64 {
                return Err(format!(
                    "not a manifest envelope: expected exactly {ENVELOPE_LEN} bytes, found {}",
                    meta.len()
                )
                .into());
            }
            let envelope = std::fs::read(&file)?;

            let mut wallet = open_ready(flags)?;
            let before = wallet.engine().manifest().current().clone();
            // The store enforces every gate (BIP340 vs the pinned root, the
            // ordering invariant, the strictly-monotonic version vs current
            // AND the persisted floor); refusals surface VERBATIM below.
            let root = PinnedTrustRoot(PINNED_OPERATOR_XONLY);
            match wallet.engine_mut().manifest_mut().ingest(&envelope, &root) {
                Ok(m) if *m == before => {
                    log(&format!(
                        "manifest v{} is already current — idempotent re-ingest, no change",
                        m.version()
                    ));
                    Ok(())
                }
                Ok(m) => {
                    log(&format!(
                        "manifest v{} ACCEPTED (was v{}) — persisted; every future open runs it",
                        m.version(),
                        before.version()
                    ));
                    print_manifest_state(&wallet);
                    Ok(())
                }
                Err(e) => Err(format!(
                    "manifest REFUSED: {e} (wallet still on v{}, version floor {})",
                    wallet.engine().manifest().current().version(),
                    wallet.engine().manifest().floor()
                )
                .into()),
            }
        }
        _ => Err("manifest needs a verb: `manifest show` or `manifest ingest <file>`".into()),
    }
}

/// Print the wallet's current signed-params state (the `manifest show` body,
/// also shown after a successful ingest).
fn print_manifest_state(wallet: &Wallet) {
    let store = wallet.engine().manifest();
    let m = store.current();
    let p = m.params();
    println!("manifest version: {}", m.version());
    println!("id:               {}", hex32(&m.id()));
    println!("version floor:    {} (persisted; ingest requires a strictly higher version)", store.floor());
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
    println!("cofunding jitter: {}", m.cofunding_jitter_max());
    println!("quorum q:         {}", m.quorum_q());
    if store.is_provisional() {
        println!(
            "WARNING: running the version-0 COMPILED BASELINE — v0 wallets form their own \
             small, fingerprintable anonymity partition. Ingest the operator's current \
             signed manifest before swapping: swapkey-cli manifest ingest <file>"
        );
    }
}

// ---------------------------------------------------------------------------
// version / quickstart / diag — tester-facing provenance + onboarding + the
// redacted support bundle (Task 20)
// ---------------------------------------------------------------------------

fn cmd_version(flags: &Flags) -> CliResult {
    if !flags.positional.is_empty() {
        return Err("version takes no arguments".into());
    }
    println!("swapkey-cli {}", api::BUILD_VERSION);
    println!("Swap Key PRE-ALPHA — REGTEST/TESTNET ONLY, NO REAL FUNDS");
    println!("(mainnet has no config variant by construction; external cryptographer review pending)");
    println!("pinned manifest trust root: {}", hex32(&PINNED_OPERATOR_XONLY));
    Ok(())
}

fn cmd_quickstart(flags: &Flags) -> CliResult {
    if !flags.positional.is_empty() {
        return Err("quickstart takes no arguments".into());
    }
    // Static walkthrough by design: printing instructions can never touch
    // funds, and every command below is the same one the tester will run
    // (each of those already prints its own next step). Full detail:
    // docs/TESTER-GUIDE.md.
    print!("{QUICKSTART}");
    Ok(())
}

const QUICKSTART: &str = "\
Swap Key quickstart — zero to your first swap (PRE-ALPHA)
==========================================================

READ THIS FIRST — the two realities every tester must know up front:
 * TESTNET/REGTEST ONLY, NO REAL FUNDS. This software has not had its
   external cryptographer review. Phase-0 warning: treat every coin in this
   wallet as expendable test money, because it is.
 * ~HALF of swap attempts refuse at the role/CSV guard and close through
   REFUNDS. That is BY DESIGN pre-alpha (the fix is cryptographer-gated).
   Your funds come back at the refund timelock (~24-36h on testnet) — a
   refunded swap is the system working, not a bug. Just retry.

STEP 0 — a Bitcoin node (once)
   Install Bitcoin Core 28+ and run it on testnet4 (or regtest for a purely
   local rehearsal): bitcoind -testnet4 -server=1
   Wait for sync. Details + config: docs/TESTER-GUIDE.md section 2.

STEP 1 — create your wallet
   swapkey-cli init --network testnet --data-dir <where wallet data lives>
   This writes swapkey.toml next to you, prompts for a NEW passphrase,
   shows your 24-word recovery mnemonic ONCE (write it down, retype it),
   and shows the Phase-0 warning (type ACCEPT).
   Then EDIT swapkey.toml: uncomment [node] and point it at your bitcoind
   (rpc_url + rpc_user/rpc_password, or rpc_cookie_file).
   next: swapkey-cli address

STEP 2 — get a deposit address
   swapkey-cli address
   next: send testnet coins to it (STEP 3)

STEP 3 — get testnet coins (faucet)
   Send at least 0.011 tBTC (1,100,000 sats) to your deposit address —
   enough for one swap unit (0.01) + fee margin + the CPFP reserve. Any
   testnet4 faucet works (search: \"bitcoin testnet4 faucet\"; e.g. the
   mempool.space or coinfaucet.eu testnet4 faucets at the time of writing).
   Wait for 1 confirmation, note the funding txid and output index.
   next: swapkey-cli onboard <txid:vout>

STEP 4 — onboard the deposit
   swapkey-cli onboard <txid:vout>
   This splits your deposit into swap-ready units + the fee reserve, then
   anchors the privacy delay: coins become swappable after a randomized
   24-72h decorrelation delay (testnet keeps real delays; regtest
   fast-forwards the wall clock). Check readiness anytime with:
   swapkey-cli status

STEP 5 — swap with a partner (the ticket flow)
   One of you MAKES the offer (binds a port, prints a one-line ticket):
     swapkey-cli swap --make <your-reachable-host:port>
   Send the printed skt1... ticket line to your partner, who TAKES it:
     swapkey-cli swap --take <ticket>
   Both wallets negotiate, fund, and settle automatically. Leave both
   running until you see SWAP COMPLETED (or a refund resolution — see the
   refund reality above; retry after a refund).

STEP 6 — optional but recommended: the second-device safety net
   swapkey-cli backup <bundle-file>          (on this device)
   swapkey-cli restore --from <bundle-file>  (on a second device/dir)
   swapkey-cli watch                         (on that second device)
   The watchtower fires your pre-armed refund even if this device dies
   mid-swap. Full story: docs/TESTER-GUIDE.md section 7.

If anything breaks: swapkey-cli diag   (redacted support bundle), then file
a report per docs/BUG-REPORT-TEMPLATE.md. Full guide: docs/TESTER-GUIDE.md.
";

fn cmd_diag(flags: &Flags) -> CliResult {
    if !flags.positional.is_empty() {
        return Err("diag takes no arguments".into());
    }
    // REDACTION CONTRACT (asserted by tests/cli.rs): this output may never
    // contain the seed, the mnemonic, any passphrase, or RPC credentials.
    // Structurally enforced — nothing below touches those values: the node
    // block prints the URL (which config validation guarantees carries no
    // userinfo) and the auth MODE only.
    let wallet = open_ready(flags)?;
    let config = wallet.config();
    println!("=== swapkey diag (redacted support bundle) ===");
    println!("version:      swapkey-cli {}", api::BUILD_VERSION);
    println!("trust root:   {}", hex32(&PINNED_OPERATOR_XONLY));
    println!("network:      {}", config.network);
    println!("data dir:     {}", config.data_dir.display());
    match &config.node {
        None => println!("node:         none configured"),
        Some(n) => {
            let auth = match &n.auth {
                swapkey::wallet::config::RpcAuth::UserPass { .. } => "user/pass (redacted)",
                swapkey::wallet::config::RpcAuth::CookieFile(_) => "cookie file",
            };
            println!("node:         {} (auth: {auth})", n.url);
            match chain_view(config) {
                Ok(chain) => {
                    println!("tip height:   {}", chain.tip_height());
                    if let Some(e) = chain.last_rpc_error() {
                        println!("node error:   {e}");
                    }
                }
                Err(e) => println!("tip height:   node unreachable ({})", e.0),
            }
        }
    }
    let manifest = wallet.engine().manifest();
    println!(
        "manifest:     v{} (id {}, floor {}, provisional: {})",
        manifest.current().version(),
        hex32(&manifest.current().id()),
        manifest.floor(),
        manifest.is_provisional(),
    );
    println!("manifest open report: {:?}", wallet.manifest_open_report());
    println!("claim posture: {:?}", wallet.engine().effective_claim_posture());

    let ledger = wallet.engine().ledger();
    let coins = ledger.coins();
    println!("coins ({}):", coins.len());
    for c in coins {
        println!(
            "  {:>12} sats  {:?}/{:?}  {}:{}",
            c.amount_sats, c.class, c.state, c.outpoint.txid, c.outpoint.vout
        );
    }
    println!(
        "reserve:      {}",
        if ledger.has_leasable_reserve(1) { "leasable" } else { "NONE (backstop inert)" }
    );
    match wallet.engine().store().list() {
        Ok((records, unreadable)) => {
            println!("swap records ({}):", records.len());
            for r in &records {
                println!("  {}  {:?}", hex32(&r.swap_session_id), r.phase);
            }
            for p in unreadable {
                println!("  ALARM unreadable record: {}", p.display());
            }
        }
        Err(e) => println!("swap records: store enumeration failed: {e}"),
    }
    for action in wallet.open_actions() {
        println!("ALARM (store open): {action:?}");
    }
    println!("=== end diag — paste this whole block into your bug report ===");
    println!("(also note your Bitcoin Core version and re-run the failing command");
    println!(" with its full stderr captured; see docs/BUG-REPORT-TEMPLATE.md)");
    Ok(())
}

// ---------------------------------------------------------------------------
// serve — the localhost JSON API for SwapKey-Wallet.html (Task 09)
// ---------------------------------------------------------------------------

use swapkey::wallet::api::{
    self, route, status_snapshot, ApiCmd, ApiState, SharedState, SwapView, DEFAULT_API_PORT,
};
use swapkey::wallet::runner::{completion_babysit_step, SwapArtifacts};
use swapkey::wallet::SwapRunState;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};

type NodeChain = swapkey::chain::BitcoinCoreChainView<swapkey::chain::HttpTransport>;

/// The worker's live activity — one command at a time (`busy` gates the API).
enum Live {
    Idle,
    /// `swap/begin {listen}` or `swap/offer {listen}`: waiting for the peer to
    /// dial in. `expected_nonce` is `Some` ONLY for the ticket-offer path — on
    /// accept, the maker-half rendezvous must pass before `begin_swap`, and a
    /// failed/scan dial is dropped WITHOUT burning the offer (keep accepting
    /// until the deadline). `None` is the legacy raw-listen path (no ticket).
    Accepting {
        listener: std::net::TcpListener,
        deadline: std::time::Instant,
        expected_nonce: Option<[u8; 16]>,
    },
    /// A swap driving through `swap_step`.
    Running { app: Box<SwapApp>, artifacts: Box<SwapArtifacts>, run: SwapRunState },
    /// Post-`Completed`: babysit our completion to CONFIRMED.
    BabysitCompletion { app: Box<SwapApp>, sid: [u8; 32] },
    /// Post-`Refunding`: babysit the refund to its terminal.
    BabysitRefund { app: Box<SwapApp>, sid: [u8; 32] },
    /// Hard error with funds exposed: backstop-only guard (fund-exposure
    /// discipline — never drop a funded escrow).
    Guard { app: Box<SwapApp> },
}

fn cmd_serve(flags: &Flags) -> CliResult {
    // Same rule as `swap` (Fable review): a dry-run intent must never run a
    // live wallet; serve broadcasts for real, so the flag is refused, not
    // silently ignored.
    if flags.switch("dry-run") {
        return Err("serve does not support --dry-run; use `recover --dry-run`".into());
    }
    let port: u16 = flags.num("port", DEFAULT_API_PORT)?;
    let poll = Duration::from_secs(flags.num("poll-secs", 3)?);
    let opts = RunOptions {
        target_feerate_sat_vb: flags.num_opt("feerate")?,
        dry_run: false,
        refund_congested: flags.switch("assume-congested"),
    };
    let block_x_delta: u32 = flags.num("block-x-delta", 144)?;
    let jitter: u32 = flags.num("jitter", 0)?;
    // Concurrency cap (Task 16): loud and bounded, never silent. 0 would be a
    // serve that can never swap — refuse it as the config error it is.
    let max_swaps: usize = flags.num("max-swaps", swapkey::wallet::api::DEFAULT_MAX_SWAPS)?;
    if max_swaps == 0 {
        return Err("--max-swaps must be at least 1".into());
    }
    let connect_retries: u32 = flags.num("connect-retries", DEFAULT_CONNECT_RETRIES)?;

    let mut wallet = open_ready(flags)?;
    // Operator claim-delay posture override (else the signed manifest's active
    // posture); it only selects among the manifest's signed bands.
    if let Some(v) = flags.value("claim-posture") {
        wallet.engine_mut().set_claim_posture(Some(parse_claim_posture(v)?));
    }
    // The node is OPTIONAL for serve: without [node] the API is status-only
    // (onboard/swap need the chain and report it).
    let chain: Option<NodeChain> = match wallet.config().node.as_ref() {
        Some(_) => Some(chain_view(wallet.config())?),
        None => None,
    };
    let network = wallet.config().network;
    let data_dir = wallet.config().data_dir.clone();
    let mut alarms: Vec<String> =
        wallet.open_actions().iter().map(|a| format!("store open: {a:?}")).collect();
    // The abnormal manifest-open variants are ALARMS the /status surface must
    // carry too (stderr alone never reaches the HTML UI): params changed
    // underneath the user — fallback, rollback, or a transient read failure.
    match wallet.manifest_open_report() {
        ManifestOpenReport::ProvisionalFresh | ManifestOpenReport::Loaded { .. } => {}
        report => alarms.push(format!("manifest open: {report:?}")),
    }
    let mut reconcile_ok = false;
    if let Some(chain) = &chain {
        reconcile_ok = startup_with_alarms(&mut wallet, chain, &opts)?;
        if !reconcile_ok {
            alarms.push("chain reconcile failed: lease/bump actions gated off".into());
        }
    } else {
        alarms.push("no [node] configured: status-only mode".into());
    }

    let state: SharedState = Arc::new(Mutex::new(ApiState::new()));
    state.lock().unwrap().max_swaps = max_swaps;
    log(&format!("swap concurrency cap: {max_swaps} (--max-swaps)"));
    let (tx, rx) = std::sync::mpsc::channel::<ApiCmd>();

    // HTTP accept loop (spawned); the worker below owns the wallet.
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("bind 127.0.0.1:{port}: {e}"))?;
    log(&format!(
        "serving http://127.0.0.1:{port} — LOOPBACK ONLY, NO AUTH (pre-alpha): any local \
         process can drive this wallet"
    ));
    {
        let state = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = state.clone();
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(stream, &state, &tx);
                });
            }
        });
    }

    serve_worker(
        &mut wallet, chain.as_ref(), network, &data_dir, &state, rx, &opts, poll,
        block_x_delta, jitter, connect_retries, reconcile_ok, alarms, max_swaps,
    )
}

fn handle_conn(
    stream: std::net::TcpStream,
    state: &SharedState,
    cmds: &std::sync::mpsc::Sender<ApiCmd>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    match api::read_request(&mut reader) {
        Ok((method, path, body)) => {
            let (code, response) = route(state, cmds, &method, &path, &body);
            api::write_response(&mut writer, code, &response)
        }
        Err(_) => api::write_response(&mut writer, 400, "{\"error\":\"bad request\"}"),
    }
}

/// The worker loop: owns the wallet + chain, drains commands, drives the
/// live activity one step per tick, refreshes the status snapshot, and
/// mirrors the `swap`/`onboard` command semantics (including the
/// fund-exposure guard discipline).
#[allow(clippy::too_many_arguments)]
fn serve_worker(
    wallet: &mut Wallet,
    chain: Option<&NodeChain>,
    network: Network,
    data_dir: &Path,
    state: &SharedState,
    rx: Receiver<ApiCmd>,
    opts: &RunOptions,
    poll: Duration,
    block_x_delta: u32,
    jitter: u32,
    connect_retries: u32,
    reconcile_ok: bool,
    alarms: Vec<String>,
    max_swaps: usize,
) -> CliResult {
    // The live swap SLOTS (Task 16): each is its own state machine over the
    // ONE shared wallet, stepped in turn every tick by this single thread —
    // concurrency is interleaving, so every ledger call stays serialized and
    // the lease/reserve gates (Unspent-only pickers flipping to Leased inside
    // one transact) hold by construction.
    let mut slots: Vec<Slot> = Vec::new();
    // A split whose confirmation we poll: (txid, signed bytes, start iter).
    let mut pending_split: Option<(bitcoin::Txid, Vec<u8>, u64)> = None;
    // Unique view keys for not-yet-negotiated slots ("pending-N"): two
    // accepting offers must never collide on one "pending" view entry.
    let mut pending_seq: u64 = 0;
    let mut iter: u64 = 0;

    loop {
        let sink_state = state.clone();
        let mut sink = move |line: String| {
            log(&line);
            sink_state.lock().unwrap().push_trace(line);
        };

        // 1. Commands (one DISPATCH per tick; `busy` was set by the route and
        //    is cleared here the moment a swap command lands in a slot or is
        //    refused — only onboard holds it through its split tail).
        if pending_split.is_none() {
            match rx.try_recv() {
                Ok(ApiCmd::Onboard { deposit, split_fee }) => match chain {
                    Some(chain) => {
                        match serve_onboard(wallet, chain, &deposit, split_fee, &mut sink) {
                            Ok((txid, tx_bytes)) => {
                                pending_split = Some((txid, tx_bytes, iter));
                            }
                            Err(e) => {
                                sink(format!("onboard failed: {}", e.0));
                                state.lock().unwrap().busy = None;
                            }
                        }
                    }
                    None => {
                        sink("onboard refused: no [node] configured".into());
                        state.lock().unwrap().busy = None;
                    }
                },
                Ok(cmd) => {
                    // A swap command (begin/offer/take). The route already
                    // gated on the cap; re-check here (defense against a
                    // route/worker count race) and dispatch into a NEW slot.
                    if let Some(slot) = dispatch_swap(
                        cmd, wallet, chain, network, data_dir, state, poll, block_x_delta,
                        jitter, connect_retries, reconcile_ok, max_swaps, &slots,
                        &mut pending_seq, &mut sink,
                    ) {
                        slots.push(slot);
                    }
                    // The dispatch latch releases NOW — the swap itself no
                    // longer holds the worker (that is the whole point of the
                    // slots) — and the route's cap gate sees the new count.
                    {
                        let mut st = state.lock().unwrap();
                        st.busy = None;
                        st.active_swaps = slots.len();
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    return Err("api accept loop died".into());
                }
            }
        }

        // 2. Onboard tail: poll the split confirmation, REBROADCASTING on a
        //    slow cadence (an evicted split otherwise never confirms) and
        //    timing out instead of holding `busy` forever (Fable review;
        //    re-POSTing /onboard resumes via the mid-split arm).
        if let (Some((txid, tx_bytes, started)), Some(chain)) = (&pending_split, chain) {
            if let Some(h) = chain.funding_height(bitcoin::OutPoint::new(*txid, 0)) {
                match wallet.engine_mut().ledger_mut().confirm_split(*txid, h, &SystemClock) {
                    Ok(()) => sink(format!("split {txid} confirmed at {h}; delays anchored")),
                    Err(e) => sink(format!("confirm_split failed: {e}")),
                }
                pending_split = None;
                state.lock().unwrap().busy = None;
            } else if iter.saturating_sub(*started) > 400 {
                sink(format!(
                    "onboard timed out waiting for split {txid} to confirm; POST /onboard \
                     again with the same deposit to resume"
                ));
                pending_split = None;
                state.lock().unwrap().busy = None;
            } else if iter.saturating_sub(*started) % 10 == 9 {
                if let Err(e) = chain.broadcast(tx_bytes) {
                    sink(format!("split rebroadcast refused ({e}); still waiting"));
                }
            }
        }

        // 3. Advance EVERY live swap one step; a slot that reaches Idle
        //    retires. The exclude set (all live sids) is computed BEFORE
        //    stepping so a Guard slot's whole-wallet recovery pass cannot
        //    re-enter a SIBLING swap's record (a mid-HOLD `Completed` record
        //    would rebroadcast the completion, defeating the posture hold).
        let exclude = live_sids(&slots);
        let mut next_slots: Vec<Slot> = Vec::with_capacity(slots.len());
        for mut slot in slots {
            let live = step_live(
                slot.live, wallet, chain, data_dir, state, &mut slot.active, opts, poll,
                block_x_delta, jitter, &exclude, &mut sink,
            );
            if !matches!(live, Live::Idle) {
                next_slots.push(Slot { active: slot.active, live });
            }
        }
        slots = next_slots;

        // 4. Whole-wallet recovery pass on a slow cadence: every CRASHED (or
        //    otherwise recordful) swap stays driven while the live ones run.
        //    EXCLUDE every live slot's record — their ticks belong to
        //    `step_live` above (the Task-13 hold-rebroadcast lesson,
        //    generalized to N slots).
        if let Some(chain) = chain {
            if iter.is_multiple_of(10) && iter > 0 {
                let exclude = live_sids(&slots);
                recovery_pass(wallet, chain, data_dir, opts, &exclude);
            }
        }

        // 5. Snapshot refresh: every slot's view + the shared worker facts.
        {
            let params = wallet.params().clone();
            let mut st = state.lock().unwrap();
            st.active_swaps = slots.len();
            let views: Vec<SwapView> = slots
                .iter()
                .filter_map(|s| s.active.as_ref().and_then(|k| st.swaps.get(k)).cloned())
                .collect();
            let offer_ticket = st.offer_ticket.clone();
            st.status_json = status_snapshot(
                wallet.engine(),
                &params,
                network,
                chain.map(|c| c.tip_height()),
                chain.is_some(),
                &views,
                st.busy,
                &alarms,
                offer_ticket.as_deref(),
                max_swaps,
                chain.and_then(|c| c.estimated_feerate_sat_vb()),
            );
        }

        iter += 1;
        std::thread::sleep(poll);
    }
}

/// One live swap slot: its `Live` state machine plus ITS OWN view key in
/// `ApiState.swaps` (`pending-N` until negotiation derives the sid).
struct Slot {
    active: Option<String>,
    live: Live,
}

/// Every live slot's session id — the exclude set for whole-wallet recovery
/// passes and the keep-set for orphan-lease heals. Accepting slots have no
/// sid yet; Guard slots deliberately stay OUT (their records are recovery's
/// to drive — the guard itself only runs the backstop).
fn live_sids(slots: &[Slot]) -> Vec<[u8; 32]> {
    slots
        .iter()
        .filter_map(|s| match &s.live {
            Live::Running { artifacts, .. } => Some(artifacts.session_id),
            Live::BabysitCompletion { sid, .. } | Live::BabysitRefund { sid, .. } => Some(*sid),
            _ => None,
        })
        .collect()
}

/// Dispatch one swap command (begin/offer/take) into a fresh slot. Returns
/// `None` when the command was refused or failed before becoming a live slot
/// (the view records the failure; the caller clears the dispatch latch).
#[allow(clippy::too_many_arguments)]
fn dispatch_swap(
    cmd: ApiCmd,
    wallet: &mut Wallet,
    chain: Option<&NodeChain>,
    network: Network,
    data_dir: &Path,
    state: &SharedState,
    poll: Duration,
    block_x_delta: u32,
    jitter: u32,
    connect_retries: u32,
    reconcile_ok: bool,
    max_swaps: usize,
    slots: &[Slot],
    pending_seq: &mut u64,
    sink: &mut dyn FnMut(String),
) -> Option<Slot> {
    if slots.len() >= max_swaps {
        sink(format!(
            "swap refused: concurrency cap reached ({} of {max_swaps} active)",
            slots.len()
        ));
        return None;
    }
    let chain = match (chain, reconcile_ok) {
        (Some(c), true) => c,
        _ => {
            sink("swap refused: node offline or reconcile failed".into());
            return None;
        }
    };
    // Fee-weather preflight (Task 26): the same warn-and-proceed heads-up as
    // the CLI `swap`, surfaced in the serve trace before any lease. NOT a gate.
    {
        use swapkey::wallet::fee_weather::FeeWeather;
        sink(FeeWeather::assess(wallet.params(), chain.estimated_feerate_sat_vb()).log_line());
    }
    // Sibling live sids: a failed dispatch heals orphaned leases, and the
    // heal must keep every sibling's lease — including the record-less
    // negotiate→Setup-broadcast window (see reconcile_leases_with_chain_keeping).
    let live = live_sids(slots);
    *pending_seq += 1;
    let mut active: Option<String> = Some(format!("pending-{pending_seq}"));
    let next = match cmd {
        ApiCmd::SwapBegin { listen, connect } => {
            if let Some(addr) = connect {
                match TcpTransport::connect_retrying(
                    addr.as_str(),
                    connect_retries,
                    DIAL_RETRY_BACKOFF,
                    sink,
                ) {
                    Ok(t) => begin_swap(
                        wallet, chain, network, data_dir, t, poll, block_x_delta, jitter,
                        state, &mut active, &live, sink,
                    ),
                    Err(e) => {
                        sink(format!(
                            "dial {addr} failed: {e} — is the maker listening and its \
                             host:port reachable? (NAT/port-forward: TESTER-GUIDE Connectivity)"
                        ));
                        Live::Idle
                    }
                }
            } else if let Some(addr) = listen {
                match std::net::TcpListener::bind(addr.as_str()) {
                    Ok(l) => {
                        sink(format!("listening on {addr} for a swap peer (10 min)"));
                        let key = active.clone().unwrap_or_else(|| "pending".into());
                        set_swap_view(state, &mut active, &key, "accepting", None);
                        Live::Accepting {
                            listener: l,
                            deadline: std::time::Instant::now() + Duration::from_secs(600),
                            expected_nonce: None,
                        }
                    }
                    Err(e) => {
                        sink(format!("bind {addr} failed: {e}"));
                        Live::Idle
                    }
                }
            } else {
                Live::Idle
            }
        }
        ApiCmd::SwapOffer { listen } => {
            // Mint the ticket over THIS wallet's network + params (the
            // advertised address is the given listen addr), then bind and
            // wait — a taker must pass the maker-half rendezvous before any
            // lease.
            match offer_ticket(wallet, network, &listen) {
                Ok((ticket, encoded)) => match std::net::TcpListener::bind(listen.as_str()) {
                    Ok(l) => {
                        sink(format!("swap ticket offered on {listen}: {encoded}"));
                        state.lock().unwrap().offer_ticket = Some(encoded);
                        let key = active.clone().unwrap_or_else(|| "pending".into());
                        set_swap_view(state, &mut active, &key, "offering", None);
                        Live::Accepting {
                            listener: l,
                            deadline: std::time::Instant::now() + Duration::from_secs(600),
                            expected_nonce: Some(ticket.nonce),
                        }
                    }
                    Err(e) => {
                        sink(format!("bind {listen} failed: {e}"));
                        Live::Idle
                    }
                },
                Err(e) => {
                    sink(format!("swap offer refused: {}", e.0));
                    Live::Idle
                }
            }
        }
        ApiCmd::SwapTake { ticket } => take_ticket(
            wallet, chain, network, data_dir, &ticket, poll, block_x_delta, jitter,
            connect_retries, state, &mut active, &live, sink,
        ),
        ApiCmd::Onboard { .. } => Live::Idle, // routed elsewhere; unreachable
    };
    match next {
        Live::Idle => None,
        live => Some(Slot { active, live }),
    }
}

/// Update (or create) the active swap's view.
fn set_swap_view(
    state: &SharedState,
    active: &mut Option<String>,
    sid: &str,
    phase: &str,
    outcome: Option<String>,
) {
    let mut st = state.lock().unwrap();
    // A "pending" placeholder is replaced once the real sid derives.
    if let Some(old) = active.as_ref() {
        if old != sid {
            st.swaps.remove(old);
        }
    }
    *active = Some(sid.to_string());
    st.swaps.insert(
        sid.to_string(),
        SwapView { sid: sid.to_string(), phase: phase.to_string(), outcome },
    );
}

/// Release leases orphaned by a failed swap attempt. The negotiate/begin
/// contract heals orphaned leases at the NEXT `SwapEngine::open` — right for
/// the one-shot `swap` command, but a long-running serve process would leak
/// one coin per failed attempt until restart (Fable review, HIGH). This runs
/// the same chain-aware reconcile in-process.
///
/// `also_live` (Task 16): SIBLING slots' sids. A sibling's lease can exist
/// with NO store record yet (leased at negotiate; the record lands with its
/// Setup broadcast — the funding-order waiter sits in that window for many
/// ticks), and the store-only keep-set would release it into a later
/// double-lease. The failed attempt's OWN sid must NOT be in this set, or its
/// orphan survives the heal.
fn heal_orphan_leases(
    wallet: &mut Wallet,
    chain: &NodeChain,
    also_live: &[[u8; 32]],
    sink: &mut dyn FnMut(String),
) {
    if let Err(e) = wallet.engine_mut().reconcile_leases_with_chain_keeping(chain, also_live) {
        sink(format!(
            "ALARM: orphan-lease heal failed ({e}); a pre-encumbrance coin may stay leased \
             until the next restart"
        ));
    }
}

/// Mint a swap ticket for a `/swap/offer {listen}` request: the advertised
/// address is the given listen `host:port`, minted over THIS wallet's network
/// and signed params. Returns the ticket (its nonce seeds the maker
/// rendezvous) and its encoded string (surfaced in `/status` as `offer_ticket`).
fn offer_ticket(
    wallet: &Wallet,
    network: Network,
    listen: &str,
) -> Result<(Ticket, String), UsageError> {
    let (host, port) = split_host_port(listen)?;
    let ticket = Ticket::mint(network, wallet.params(), &host, port)?;
    let encoded = ticket.encode();
    Ok((ticket, encoded))
}

/// Take a swap by ticket (`/swap/take {ticket}`): decode + validate against
/// this wallet's network + params BEFORE dialing (a mismatch is a clean
/// refusal, not a hung socket), dial, run the taker-half rendezvous under a
/// short leash, then hand off to `begin_swap`. Every early refusal clears
/// `busy` and returns to `Idle` (no lease was taken).
#[allow(clippy::too_many_arguments)]
fn take_ticket(
    wallet: &mut Wallet,
    chain: &NodeChain,
    network: Network,
    data_dir: &Path,
    ticket_str: &str,
    poll: Duration,
    block_x_delta: u32,
    jitter: u32,
    connect_retries: u32,
    state: &SharedState,
    active: &mut Option<String>,
    live: &[[u8; 32]],
    sink: &mut dyn FnMut(String),
) -> Live {
    let ticket = match Ticket::decode(ticket_str) {
        Ok(t) => t,
        Err(e) => {
            sink(format!("swap take refused: {e}"));
            return Live::Idle;
        }
    };
    if let Err(e) = ticket.validate(network, wallet.params()) {
        sink(format!("swap take refused: {e}"));
        return Live::Idle;
    }
    let addr = ticket.addr();
    let mut t = match TcpTransport::connect_retrying(&addr, connect_retries, DIAL_RETRY_BACKOFF, sink)
    {
        Ok(t) => t,
        Err(e) => {
            sink(format!(
                "dial {addr} failed: {e} — is the maker listening and reachable? \
                 (NAT/port-forward: TESTER-GUIDE Connectivity)"
            ));
            return Live::Idle;
        }
    };
    // Short leash for the rendezvous so a silent maker can't hang us; begin_swap
    // restores the normal poll-scaled budget.
    if let Err(e) = t.set_io_timeout(Some(RENDEZVOUS_LEASH)) {
        sink(format!("transport setup failed: {e}"));
        return Live::Idle;
    }
    if let Err(e) = taker_rendezvous(&mut t, &ticket.nonce) {
        sink(format!("swap ticket rendezvous failed: {e}"));
        return Live::Idle;
    }
    sink("ticket rendezvous ok — negotiating".into());
    begin_swap(
        wallet, chain, network, data_dir, t, poll, block_x_delta, jitter, state, active, live,
        sink,
    )
}

/// Negotiate + begin over an established transport; returns the next state.
/// `live` is the SIBLING slots' sid set — the keep-set a failure heal must
/// respect (never the sid THIS attempt derives; its own orphan must release).
#[allow(clippy::too_many_arguments)]
fn begin_swap(
    wallet: &mut Wallet,
    chain: &NodeChain,
    network: Network,
    data_dir: &Path,
    mut transport: TcpTransport,
    poll: Duration,
    block_x_delta: u32,
    jitter: u32,
    state: &SharedState,
    active: &mut Option<String>,
    live: &[[u8; 32]],
    sink: &mut dyn FnMut(String),
) -> Live {
    // This slot's view key while the sid is still unknown (unique per slot —
    // two negotiating slots must not share one "pending" view entry).
    let pending_key = active.clone().unwrap_or_else(|| "pending".to_string());
    let io_timeout = negotiation_io_timeout(poll);
    if let Err(e) = transport.set_io_timeout(Some(io_timeout)) {
        sink(format!("transport setup failed: {e}"));
        return Live::Idle;
    }
    set_swap_view(state, active, &pending_key, "negotiating", None);
    let session_seckey = secp::Scalar::random(&mut rand::rng());
    let negotiated = match negotiate_swap(
        &mut transport,
        wallet.engine_mut(),
        chain,
        &LeaseClock(network),
        network,
        data_dir,
        session_seckey,
    ) {
        Ok(n) => n,
        Err(e) => {
            sink(format!("negotiation failed: {e}"));
            heal_orphan_leases(wallet, chain, live, sink);
            set_swap_view(state, active, &pending_key, "failed", Some(format!("negotiation: {e}")));
            return Live::Idle;
        }
    };
    let sid = negotiated.artifacts.session_id;
    let sid_hex = hex32(&sid);
    sink(format!("negotiated swap session {sid_hex}"));
    sink(format!(
        "claim-delay privacy posture active: {:?} — the SL claim broadcast is held for a \
         randomized, ceiling-clamped delay",
        wallet.engine().effective_claim_posture()
    ));
    let peer = PeerSession::new(sid, Box::new(transport));
    let block_x = chain.tip_height() + block_x_delta;
    match SwapApp::begin(wallet.engine(), negotiated.ctx, peer, block_x, jitter) {
        Ok(app) => {
            set_swap_view(state, active, &sid_hex, "funding", None);
            Live::Running {
                app: Box::new(app),
                artifacts: Box::new(negotiated.artifacts),
                run: SwapRunState::new(),
            }
        }
        Err(e) => {
            sink(format!("SwapApp::begin failed: {e}"));
            heal_orphan_leases(wallet, chain, live, sink);
            set_swap_view(state, active, &sid_hex, "failed", Some(format!("begin: {e}")));
            Live::Idle
        }
    }
}

/// One tick of ONE slot's live-activity state machine (the serve twin of
/// `cmd_swap`'s loops, incl. the fund-exposure guard discipline). `exclude`
/// is every live slot's sid (computed before the tick's step loop): the
/// Guard arm's whole-wallet recovery pass must not re-enter a SIBLING's
/// record, and a pre-fund failure's orphan heal must keep the siblings'
/// leases while releasing its own.
#[allow(clippy::too_many_arguments)]
fn step_live(
    live: Live,
    wallet: &mut Wallet,
    chain: Option<&NodeChain>,
    data_dir: &Path,
    state: &SharedState,
    active: &mut Option<String>,
    opts: &RunOptions,
    poll: Duration,
    block_x_delta: u32,
    jitter: u32,
    exclude: &[[u8; 32]],
    sink: &mut dyn FnMut(String),
) -> Live {
    let Some(chain) = chain else { return live };
    match live {
        Live::Idle => Live::Idle,
        Live::Accepting { listener, deadline, expected_nonce } => {
            match TcpTransport::accept_timeout(&listener, Duration::from_millis(900)) {
                Ok(mut t) => match expected_nonce {
                    // Ticket offer: the maker-half rendezvous MUST pass before
                    // any lease. A wrong-nonce / port-scan dial is DROPPED and
                    // we keep accepting until the deadline — a scan must never
                    // burn the offer.
                    Some(nonce) => {
                        if let Err(e) = t.set_io_timeout(Some(RENDEZVOUS_LEASH)) {
                            sink(format!("transport setup failed ({e}); still offering"));
                            return Live::Accepting { listener, deadline, expected_nonce };
                        }
                        match maker_rendezvous(&mut t, &nonce) {
                            Ok(()) => {
                                sink("ticket rendezvous ok — negotiating".into());
                                state.lock().unwrap().offer_ticket = None;
                                let network = wallet.config().network;
                                let dir = wallet.config().data_dir.clone();
                                begin_swap(
                                    wallet, chain, network, &dir, t, poll, block_x_delta, jitter,
                                    state, active, exclude, sink,
                                )
                            }
                            Err(e) => {
                                sink(format!(
                                    "ticket rendezvous failed ({e}); connection dropped, still offering"
                                ));
                                Live::Accepting { listener, deadline, expected_nonce }
                            }
                        }
                    }
                    // Legacy raw-listen path: no ticket, negotiate straight away.
                    None => {
                        let network = wallet.config().network;
                        let dir = wallet.config().data_dir.clone();
                        begin_swap(
                            wallet, chain, network, &dir, t, poll, block_x_delta, jitter, state,
                            active, exclude, sink,
                        )
                    }
                },
                Err(_) if std::time::Instant::now() < deadline => {
                    Live::Accepting { listener, deadline, expected_nonce }
                }
                Err(_) => {
                    sink("no peer connected before the deadline".into());
                    if expected_nonce.is_some() {
                        state.lock().unwrap().offer_ticket = None;
                    }
                    let key = active.clone().unwrap_or_else(|| "pending".into());
                    set_swap_view(state, active, &key, "failed", Some("no peer".into()));
                    Live::Idle
                }
            }
        }
        Live::Running { mut app, artifacts, mut run } => {
            let sid = artifacts.session_id;
            let sid_hex = hex32(&sid);
            if let Err(e) = backstop_step(&app, wallet.engine_mut(), chain, opts, sink) {
                sink(format!("backstop pass failed (retrying): {e}"));
            }
            match swap_step(&mut app, wallet.engine_mut(), chain, &artifacts, &mut run, opts, sink)
            {
                Ok(SwapStepOutcome::Continue(tick)) => {
                    set_swap_view(state, active, &sid_hex, &format!("{tick:?}"), None);
                    Live::Running { app, artifacts, run }
                }
                Ok(SwapStepOutcome::Holding { broadcast_at_height }) => {
                    set_swap_view(
                        state,
                        active,
                        &sid_hex,
                        &format!("holding-claim(until {broadcast_at_height})"),
                        None,
                    );
                    Live::Running { app, artifacts, run }
                }
                Ok(SwapStepOutcome::Done(SwapOutcome::Completed { .. })) => {
                    set_swap_view(state, active, &sid_hex, "babysit-completion", None);
                    Live::BabysitCompletion { app, sid }
                }
                Ok(SwapStepOutcome::Done(SwapOutcome::Refunding { reason })) => {
                    sink(format!("refund exit: {reason}"));
                    set_swap_view(state, active, &sid_hex, "babysit-refund", None);
                    Live::BabysitRefund { app, sid }
                }
                Ok(SwapStepOutcome::Done(SwapOutcome::Aborted { reason })) => {
                    sink(format!("swap aborted cleanly: {reason}"));
                    set_swap_view(state, active, &sid_hex, "aborted", Some(reason.to_string()));
                    Live::Idle
                }
                Err(e) if run.setup_on_wire => {
                    sink(format!("ALARM: swap failed with the escrow exposed: {e}; guarding"));
                    set_swap_view(state, active, &sid_hex, "guard", None);
                    Live::Guard { app }
                }
                Err(e) => {
                    sink(format!("swap failed before fund exposure: {e}"));
                    // Keep the SIBLINGS' leases; release only OUR orphan (the
                    // failing sid must not shield its own lease from the heal).
                    let keep: Vec<[u8; 32]> =
                        exclude.iter().copied().filter(|s| s != &sid).collect();
                    heal_orphan_leases(wallet, chain, &keep, sink);
                    set_swap_view(state, active, &sid_hex, "failed", Some(e.to_string()));
                    Live::Idle
                }
            }
        }
        Live::BabysitCompletion { app, sid } => {
            let sid_hex = hex32(&sid);
            if let Err(e) = backstop_step(&app, wallet.engine_mut(), chain, opts, sink) {
                sink(format!("backstop pass failed (retrying): {e}"));
            }
            match completion_babysit_step(wallet.engine_mut(), chain, data_dir, &sid, opts, sink) {
                Ok(Some(())) => {
                    sink("SWAP COMPLETED — completion confirmed on chain".into());
                    set_swap_view(state, active, &sid_hex, "completed", Some("completed".into()));
                    Live::Idle
                }
                Ok(None) => Live::BabysitCompletion { app, sid },
                Err(e) => {
                    sink(format!("completion babysit failed (retrying): {e}"));
                    Live::BabysitCompletion { app, sid }
                }
            }
        }
        Live::BabysitRefund { app, sid } => {
            let sid_hex = hex32(&sid);
            if let Err(e) = backstop_step(&app, wallet.engine_mut(), chain, opts, sink) {
                sink(format!("backstop pass failed (retrying): {e}"));
            }
            match refund_babysit_step(wallet.engine_mut(), chain, data_dir, &sid, opts, sink) {
                Ok(Some(phase)) => {
                    sink(format!("refund resolved — record terminal {phase:?}"));
                    set_swap_view(state, active, &sid_hex, "refunded", Some(format!("{phase:?}")));
                    Live::Idle
                }
                Ok(None) => Live::BabysitRefund { app, sid },
                Err(e) => {
                    sink(format!("refund babysit failed (retrying): {e}"));
                    Live::BabysitRefund { app, sid }
                }
            }
        }
        Live::Guard { app } => {
            if let Err(e) = backstop_step(&app, wallet.engine_mut(), chain, opts, sink) {
                sink(format!("guard backstop failed (retrying): {e}"));
            }
            // Whole-wallet recovery keeps running from the guard (its OWN
            // record is recovery's to drive), but SIBLING live swaps stay
            // excluded — their ticks belong to their own slots.
            recovery_pass(wallet, chain, data_dir, opts, exclude);
            if matches!(
                chain.spend_status(app.our_escrow()),
                swapkey::chain::SpendStatus::Confirmed(_)
            ) {
                sink("escrow exit confirmed; run recover to reconcile records".into());
                if let Some(sid_hex) = active.clone() {
                    set_swap_view(state, active, &sid_hex, "guard-resolved", Some("refunded".into()));
                }
                Live::Idle
            } else {
                Live::Guard { app }
            }
        }
    }
}

/// The API-side onboard front half: register (with the route-verified
/// Phase-0 ack) + split + broadcast. Returns the split txid + signed bytes
/// (the worker tail rebroadcasts them until confirmation).
fn serve_onboard(
    wallet: &mut Wallet,
    chain: &NodeChain,
    deposit: &str,
    split_fee: u64,
    sink: &mut dyn FnMut(String),
) -> Result<(bitcoin::Txid, Vec<u8>), UsageError> {
    let deposit = parse_outpoint(deposit)?;
    let params = wallet.params().clone();
    {
        use swapkey::wallet::ledger::{CoinClass, CoinState};
        if let Some(coin) = wallet.engine().ledger().find(&deposit) {
            match (coin.class, coin.state, coin.split_attempts.last().cloned()) {
                (_, CoinState::SplitPending, Some(attempt)) => {
                    sink("deposit mid-split — resuming".into());
                    chain.broadcast(&attempt.tx_bytes)?;
                    return Ok((attempt.txid, attempt.tx_bytes));
                }
                (CoinClass::Deposit, CoinState::Unspent, _) => {
                    sink("deposit registered but unsplit — resuming at the split".into());
                }
                _ => return Err("deposit already tracked".into()),
            }
        } else {
            let height = chain
                .funding_height(deposit)
                .ok_or("deposit not found or not confirmed")?;
            let amount = chain.funding_amount(deposit).ok_or("node did not report the amount")?;
            let spk = chain.funding_spk(deposit).ok_or("node did not report the spk")?;
            let keys = wallet.engine().keys();
            let mut key_index = None;
            for i in 0..KEY_SCAN_LIMIT {
                if runner::derived_spk(keys, KeyPurpose::Deposit, i)? == spk {
                    key_index = Some(i);
                    break;
                }
            }
            let key_index = key_index.ok_or("deposit does not pay any address of this wallet")?;
            // The route enforced ack_phase0 AND /status carries the warning
            // copy for the UI to display — that pair is the display contract.
            let ack = acknowledge_phase0(PHASE0_WARNING)?;
            wallet
                .engine_mut()
                .register_deposit(deposit, amount, height, key_index, &spk, Some(ack))?;
            sink(format!("deposit registered: {amount} sats at height {height}"));
        }
    }
    let plan = wallet.engine_mut().split_deposit(deposit, &params, split_fee)?;
    let txid = chain.broadcast(&plan.tx_bytes)?;
    sink(format!(
        "split broadcast {txid}: {} unit(s), reserve {} sats",
        plan.pre_encumbrance_count, plan.reserve_sats
    ));
    Ok((plan.txid, plan.tx_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Task-20 shippability: THIS build's pin must be a valid x-only key and
    /// must NOT be the publicly-known modeled/test root. If this fails, the
    /// binary prints the UNSHIPPABLE banner on every run — and the release
    /// script (scripts/build-release.sh) refuses to package it.
    #[test]
    fn pinned_trust_root_is_real_and_shippable() {
        assert!(
            test_root_reason().is_none(),
            "unshippable pin: {:?}",
            test_root_reason()
        );
    }

    // -- Task 23: hostile-input sweep of the argv parser + the parse_* helpers.
    // The CLI is the one surface a tester drives BY HAND, so a fat-fingered
    // flag must be a clean usage error, never a panic. These functions are the
    // whole tester-facing argv attack surface (Flags::parse gates everything).

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_parse_rejects_malformed_argv_cleanly() {
        // A value flag with no following value.
        assert!(Flags::parse(&argv(&["--config"])).is_err());
        // The `--flag=value` form is refused (we take `--flag value`).
        assert!(Flags::parse(&argv(&["--config=x"])).is_err());
        // Unknown / misspelled flag: hard error, never silently ignored (a
        // typo'd --dry-run must not run a live swap).
        assert!(Flags::parse(&argv(&["--dry-runn"])).is_err());
        assert!(Flags::parse(&argv(&["--unknown"])).is_err());
        // A value flag given twice.
        assert!(Flags::parse(&argv(&["--config", "a", "--config", "b"])).is_err());
        // A well-formed mix parses: positional + value flag + known switch.
        // (UsageError is not Debug, so match rather than unwrap.)
        match Flags::parse(&argv(&["pos", "--listen", "1.2.3.4:9", "--dry-run"])) {
            Ok(f) => {
                assert_eq!(f.positional, vec!["pos".to_string()]);
                assert_eq!(f.value("listen"), Some("1.2.3.4:9"));
                assert!(f.switch("dry-run"));
                assert!(!f.switch("assume-congested"));
            }
            Err(_) => panic!("a well-formed argv must parse"),
        }
    }

    #[test]
    fn parse_helpers_reject_malformed_input_cleanly() {
        // outpoint
        assert!(parse_outpoint("no-colon").is_err());
        assert!(parse_outpoint("nothex:0").is_err());
        assert!(parse_outpoint(":").is_err());
        assert!(parse_outpoint(&format!("{}:x", "ab".repeat(32))).is_err()); // bad vout
        assert!(parse_outpoint(&format!("{}:0", "ab".repeat(32))).is_ok());
        // host:port (the LAST colon splits, so IPv4/hostnames work)
        assert!(split_host_port("no-port").is_err());
        assert!(split_host_port("h:99999").is_err()); // > u16
        assert!(split_host_port("h:-1").is_err());
        assert!(
            matches!(split_host_port("1.2.3.4:9735"), Ok((ref h, 9735)) if h == "1.2.3.4"),
            "a valid host:port must split"
        );
        // claim posture
        assert!(parse_claim_posture("balanced").is_ok());
        assert!(parse_claim_posture("YOLO").is_err());
        assert!(parse_claim_posture("").is_err());
    }

    proptest! {
        /// Arbitrary argv strings: Flags::parse is TOTAL (Ok|Err, never a
        /// panic) — the front door every subcommand goes through.
        #[test]
        fn flags_parse_is_total_on_arbitrary_argv(
            args in proptest::collection::vec(".*", 0..8),
        ) {
            let _ = Flags::parse(&args);
        }

        /// Arbitrary strings into each argument parser: total.
        #[test]
        fn parse_helpers_are_total(s in ".*") {
            let _ = parse_outpoint(&s);
            let _ = split_host_port(&s);
            let _ = parse_claim_posture(&s);
        }
    }
}
