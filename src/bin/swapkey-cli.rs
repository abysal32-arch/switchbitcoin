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
use swapkey::wallet::manifest::ClaimDelayPosture;
use swapkey::wallet::ledger::{acknowledge_phase0, SystemClock, PHASE0_WARNING};
use swapkey::wallet::runner::{
    self, apply_recovery_tick, backstop_step, hex32, negotiate_swap, refund_babysit_step,
    swap_step, RunOptions, SwapOutcome, SwapStepOutcome,
};
use swapkey::wallet::runtime::{FirstRunError, OpenedWallet, Wallet};
use swapkey::wallet::transport::TcpTransport;
use swapkey::wallet::SoftwareKeyStore;
use swapkey::wallet::SwapApp;

/// Deposit-address recognition scan bound (`onboard` maps the chain-reported
/// funding spk back to its key index; the ledger's counter is monotonic, so
/// real indices are small).
const KEY_SCAN_LIMIT: u32 = 10_000;

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
        "serve" => cmd_serve(&flags),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown subcommand `{other}`").into()),
    }
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
            --skip-backup-verification   waive the retype-the-words check (DANGER)
  address   Issue a fresh deposit address.
  status    Show coins, reserve, swap records, and operator alarms.
  onboard <txid:vout>  Register + split a CONFIRMED deposit, broadcast the
            split, wait for confirmation, confirm. Requires [node].
            --split-fee <sats>  split tx fee (default 2000)
            --key-index <n>     skip the address scan (index from `address`)
            --wait-secs <n>     confirmation wait budget (default 600)
  swap      Run ONE swap against a peer (to a CONFIRMED terminal). Requires [node].
            --listen <addr> | --connect <addr>   (flags outrank [peer] config)
            --feerate <sat/vB>  backstop CPFP feerate override (default: live
                                node estimate, fallback 2)
            --block-x-delta <blocks>  funding no-show deadline (default 144)
            --jitter <blocks>   co-funding jitter (default 0)
            --poll-secs <n>     chain poll cadence (default 5; the peer i/o
                                deadline scales with it)
            --accept-timeout-secs <n>  --listen wait budget (default 600)
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
  serve     Localhost JSON API for SwapKey-Wallet.html (LOOPBACK ONLY, no
            auth — any local process can drive the wallet; pre-alpha).
            --port <n>          bind 127.0.0.1:<n> (default 3316)
            --poll-secs / --feerate / --assume-congested as for swap
            --claim-posture <fast|balanced|private>  as for swap (default: the
                                signed manifest's active posture)
            Endpoints: GET /status /events?since=N /swap/<sid>;
            POST /onboard {deposit, ack_phase0, split_fee?},
            POST /swap/begin {connect|listen}

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
    "--feerate",
    "--block-x-delta",
    "--jitter",
    "--poll-secs",
    "--accept-timeout-secs",
    "--port",
    "--claim-posture",
];

/// Every boolean switch any subcommand accepts.
const KNOWN_SWITCHES: &[&str] = &[
    "--passphrase-stdin",
    "--accept-phase0",
    "--skip-backup-verification",
    "--restore",
    "--dry-run",
    "--assume-congested",
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

/// Open an ESTABLISHED wallet (everything but `init` expects `Ready`).
fn open_ready(flags: &Flags) -> Result<Wallet, UsageError> {
    let config = load_config(flags)?;
    let passphrase = read_passphrase(flags, false)?;
    match Wallet::open(config, &passphrase)? {
        OpenedWallet::Ready(w) => Ok(*w),
        OpenedWallet::FirstRun(_) => {
            Err("wallet onboarding is incomplete — run `swapkey-cli init` first".into())
        }
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

    // ONE passphrase read serves restore AND open — a second prompt would
    // break the documented --passphrase-stdin single-line contract and can
    // seal/open under different strings (Fable review).
    let passphrase = read_passphrase(flags, true)?;

    if flags.switch("restore") {
        // Dead-device recovery: re-seal the seed from the mnemonic into the
        // data dir, then fall through to the normal open (which resumes the
        // first-run ledger creation under the established-wallet guards).
        std::fs::create_dir_all(&config.data_dir)?;
        let words = prompt_line("BIP39 mnemonic (24 words, single line): ")?;
        SoftwareKeyStore::restore(&config.data_dir, &words, &passphrase)?;
        log("keystore restored from mnemonic");
        log("NOTE: restore recovers the SEED only. Restore ledger.bin from backup too, or");
        log("      key issuance rewinds into address reuse (Ledger::raise_key_index_floor).");
    }

    let mut first_run = match Wallet::open(config, &passphrase)? {
        OpenedWallet::Ready(w) => {
            log("wallet already initialized");
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
            Ok(wallet) => {
                log("wallet created");
                print_status(&wallet);
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

    // Peer transport. EXPLICIT FLAGS OUTRANK THE CONFIG ENTIRELY: an operator
    // typing --listen must never be silently dialed out by a leftover [peer]
    // connect value (Fable review). Within one source, both set = ambiguous.
    let peer_cfg = wallet.config().peer.clone();
    let (listen, connect) = match (flags.value("listen"), flags.value("connect")) {
        (Some(_), Some(_)) => return Err("--listen and --connect are mutually exclusive".into()),
        (Some(l), None) => (Some(l.to_string()), None),
        (None, Some(c)) => (None, Some(c.to_string())),
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
    let mut transport = match (listen, connect) {
        (_, Some(addr)) => {
            log(&format!("connecting to peer {addr}"));
            TcpTransport::connect(addr.as_str())?
        }
        (Some(addr), None) => {
            let listener = std::net::TcpListener::bind(addr.as_str())
                .map_err(|e| format!("bind {addr}: {e}"))?;
            log(&format!("listening on {addr} (waiting up to {}s)", accept_timeout.as_secs()));
            TcpTransport::accept_timeout(&listener, accept_timeout)?
        }
        (None, None) => {
            return Err("swap needs --listen or --connect (or a [peer] config section)".into())
        }
    };
    // Whole-frame budget: the Phase-A rendezvous skew between the two sides
    // is bounded by the SLOWER side's poll cadence, so the deadline must
    // scale with it (a fixed budget under a large --poll-secs would abort
    // healthy funded swaps to refund; Fable review).
    let io_timeout = Duration::from_secs(120.max(poll_secs.saturating_mul(3)));
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
        if let Err(e) = backstop_step(&app, wallet.engine_mut(), &chain, &opts, &mut sink) {
            log(&format!("backstop pass failed (retrying next poll): {e}"));
        }
        // Other swaps' persisted deadlines stay driven during a long swap
        // (Fable review): a periodic whole-wallet recovery pass, excluding
        // the live swap (its ticks belong to the app above).
        if iter.is_multiple_of(12) && iter > 0 {
            recovery_pass(&mut wallet, &chain, &data_dir, &opts, Some(&sid));
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
        recovery_pass(wallet, chain, data_dir, opts, None);
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
    exclude: Option<&[u8; 32]>,
) {
    let mut sink = |line: String| log(&line);
    match SwapApp::recover(wallet.engine(), chain) {
        Ok(scan) => {
            for (sid, tick) in &scan.ticks {
                if exclude == Some(sid) {
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
    /// `swap/begin {listen}`: waiting for the peer to dial in.
    Accepting { listener: std::net::TcpListener, deadline: std::time::Instant },
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
        block_x_delta, jitter, reconcile_ok, alarms,
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
    reconcile_ok: bool,
    alarms: Vec<String>,
) -> CliResult {
    let mut live = Live::Idle;
    // A split whose confirmation we poll: (txid, signed bytes, start iter).
    let mut pending_split: Option<(bitcoin::Txid, Vec<u8>, u64)> = None;
    let mut active_sid_hex: Option<String> = None;
    let mut iter: u64 = 0;

    loop {
        let sink_state = state.clone();
        let mut sink = move |line: String| {
            log(&line);
            sink_state.lock().unwrap().push_trace(line);
        };

        // 1. Commands (one at a time; `busy` was set by the route).
        if matches!(live, Live::Idle) && pending_split.is_none() {
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
                Ok(ApiCmd::SwapBegin { listen, connect }) => match (chain, reconcile_ok) {
                    (Some(node), true) => {
                        if let Some(addr) = connect {
                            match TcpTransport::connect(addr.as_str()) {
                                Ok(t) => {
                                    live = begin_swap(
                                        wallet, node, network, data_dir, t, poll, block_x_delta,
                                        jitter, state, &mut active_sid_hex, &mut sink,
                                    );
                                }
                                Err(e) => {
                                    sink(format!("connect {addr} failed: {e}"));
                                    state.lock().unwrap().busy = None;
                                }
                            }
                        } else if let Some(addr) = listen {
                            match std::net::TcpListener::bind(addr.as_str()) {
                                Ok(l) => {
                                    sink(format!("listening on {addr} for a swap peer (10 min)"));
                                    set_swap_view(
                                        state, &mut active_sid_hex, "pending", "accepting", None,
                                    );
                                    live = Live::Accepting {
                                        listener: l,
                                        deadline: std::time::Instant::now()
                                            + Duration::from_secs(600),
                                    };
                                }
                                Err(e) => {
                                    sink(format!("bind {addr} failed: {e}"));
                                    state.lock().unwrap().busy = None;
                                }
                            }
                        }
                    }
                    _ => {
                        sink("swap refused: node offline or reconcile failed".into());
                        state.lock().unwrap().busy = None;
                    }
                },
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

        // 3. Advance the live swap one step.
        live = step_live(
            live, wallet, chain, data_dir, state, &mut active_sid_hex, opts, poll,
            block_x_delta, jitter, &mut sink,
        );

        // 4. Whole-wallet recovery pass on a slow cadence (other swaps'
        //    deadlines stay driven while this one runs). EXCLUDE the live
        //    swap's own record: its ticks belong to `step_live` above, and a
        //    recovery pass would re-enter a mid-HOLD `Completed` record and
        //    REBROADCAST the completion immediately — defeating the posture
        //    hold. Copy the sid out of `live` FIRST so the reference borrow ends
        //    before `recovery_pass` takes `&mut wallet`.
        let exclude_sid: Option<[u8; 32]> = match &live {
            Live::Running { artifacts, .. } => Some(artifacts.session_id),
            Live::BabysitCompletion { sid, .. } | Live::BabysitRefund { sid, .. } => Some(*sid),
            _ => None,
        };
        if let Some(chain) = chain {
            if iter.is_multiple_of(10) && iter > 0 {
                recovery_pass(wallet, chain, data_dir, opts, exclude_sid.as_ref());
            }
        }

        // 5. Snapshot refresh.
        {
            let params = wallet.params().clone();
            let mut st = state.lock().unwrap();
            let active = active_sid_hex.as_ref().and_then(|s| st.swaps.get(s)).cloned();
            st.status_json = status_snapshot(
                wallet.engine(),
                &params,
                network,
                chain.map(|c| c.tip_height()),
                chain.is_some(),
                active.as_ref(),
                st.busy,
                &alarms,
            );
        }

        iter += 1;
        std::thread::sleep(poll);
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
fn heal_orphan_leases(wallet: &mut Wallet, chain: &NodeChain, sink: &mut dyn FnMut(String)) {
    if let Err(e) = wallet.engine_mut().reconcile_leases_with_chain(chain) {
        sink(format!(
            "ALARM: orphan-lease heal failed ({e}); a pre-encumbrance coin may stay leased \
             until the next restart"
        ));
    }
}

/// Negotiate + begin over an established transport; returns the next state.
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
    sink: &mut dyn FnMut(String),
) -> Live {
    let io_timeout = Duration::from_secs(120.max(poll.as_secs().saturating_mul(3)));
    if let Err(e) = transport.set_io_timeout(Some(io_timeout)) {
        sink(format!("transport setup failed: {e}"));
        state.lock().unwrap().busy = None;
        return Live::Idle;
    }
    set_swap_view(state, active, "pending", "negotiating", None);
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
            heal_orphan_leases(wallet, chain, sink);
            set_swap_view(state, active, "pending", "failed", Some(format!("negotiation: {e}")));
            state.lock().unwrap().busy = None;
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
            heal_orphan_leases(wallet, chain, sink);
            set_swap_view(state, active, &sid_hex, "failed", Some(format!("begin: {e}")));
            state.lock().unwrap().busy = None;
            Live::Idle
        }
    }
}

/// One tick of the live-activity state machine (the serve twin of
/// `cmd_swap`'s loops, incl. the fund-exposure guard discipline).
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
    sink: &mut dyn FnMut(String),
) -> Live {
    let Some(chain) = chain else { return live };
    match live {
        Live::Idle => Live::Idle,
        Live::Accepting { listener, deadline } => {
            match TcpTransport::accept_timeout(&listener, Duration::from_millis(900)) {
                Ok(t) => {
                    let network = wallet.config().network;
                    let dir = wallet.config().data_dir.clone();
                    begin_swap(
                        wallet, chain, network, &dir, t, poll, block_x_delta, jitter, state,
                        active, sink,
                    )
                }
                Err(_) if std::time::Instant::now() < deadline => {
                    Live::Accepting { listener, deadline }
                }
                Err(_) => {
                    sink("no peer connected before the deadline".into());
                    set_swap_view(state, active, "pending", "failed", Some("no peer".into()));
                    state.lock().unwrap().busy = None;
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
                    state.lock().unwrap().busy = None;
                    Live::Idle
                }
                Err(e) if run.setup_on_wire => {
                    sink(format!("ALARM: swap failed with the escrow exposed: {e}; guarding"));
                    set_swap_view(state, active, &sid_hex, "guard", None);
                    Live::Guard { app }
                }
                Err(e) => {
                    sink(format!("swap failed before fund exposure: {e}"));
                    heal_orphan_leases(wallet, chain, sink);
                    set_swap_view(state, active, &sid_hex, "failed", Some(e.to_string()));
                    state.lock().unwrap().busy = None;
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
                    state.lock().unwrap().busy = None;
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
                    state.lock().unwrap().busy = None;
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
            recovery_pass(wallet, chain, data_dir, opts, None);
            if matches!(
                chain.spend_status(app.our_escrow()),
                swapkey::chain::SpendStatus::Confirmed(_)
            ) {
                sink("escrow exit confirmed; run recover to reconcile records".into());
                if let Some(sid_hex) = active.clone() {
                    set_swap_view(state, active, &sid_hex, "guard-resolved", Some("refunded".into()));
                }
                state.lock().unwrap().busy = None;
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
