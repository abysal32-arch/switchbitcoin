//! Regtest two-wallet END-TO-END harness (Task 10): two real `switchbitcoin-cli`
//! processes against a real `bitcoind -regtest` — no SimChain anywhere.
//!
//! Every test is `#[ignore]` (needs a node binary + minutes of wall clock);
//! run them manually per `tasks/PRE-ALPHA-RUNBOOK.md`:
//!
//! ```text
//! # bitcoind on PATH, or BITCOIND_EXE=C:\path\to\bitcoind.exe
//! cargo test --features bitcoind --test regtest_e2e -- --ignored --nocapture --test-threads 1
//! ```
//!
//! What is proven (the pre-alpha "done" definition):
//! * `e2e_happy_path_swap_completes` — init + onboard both wallets, run
//!   `swap --listen` / `swap --connect`, mine to a terminal. The role↔CSV
//!   interim convention means ~half of attempts REFUSE at the CSV-binding
//!   guard and close through refunds (by design) — the harness retries
//!   attempts until one COMPLETES, asserting every non-completing attempt
//!   closed forward-or-refund.
//! * `e2e_dead_peer_routes_to_refund` — kill wallet B after both Setups are
//!   in the mempool; wallet A's own loop (backstop + babysit) must fire and
//!   confirm the pre-armed refund on the real chain.
//! * `e2e_crash_recovery_reenters_from_the_store` — SIGKILL wallet A after
//!   its Setup broadcast; `recover` on a fresh process must re-enter from
//!   the persisted store alone and drive the refund to `Refunded`.
//! * `e2e_taker_killed_mid_claim_hold_recovers_and_tracks_the_coin` — SIGKILL
//!   the SL during its claim-delay posture hold (the live-run P1 kill point);
//!   `recover` must finish the claim AND register the settlement coin in the
//!   ledger, not just mark the record settled.
//!
//! Timing note: the onboarding delay's HEIGHT anchor (144–432 blocks) is
//! mined out; its WALL anchor is fast-forwarded by the binary's
//! regtest-only lease clock (see `LeaseClock` in switchbitcoin-cli).
#![cfg(feature = "bitcoind")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const PASSPHRASE: &str = "e2e harness passphrase\n";
/// Blocks that satisfy the onboarding delay's height anchor (72h/600s = 432).
const ONBOARD_DELAY_BLOCKS: u64 = 440;

// ---------------------------------------------------------------------------
// bitcoind
// ---------------------------------------------------------------------------

struct Node {
    child: Child,
    rpc_url: String,
    auth: String, // base64(user:pass) — fixed creds, harness-local node
    _datadir: tempfile::TempDir,
    miner_addr: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bitcoind_exe() -> String {
    std::env::var("BITCOIND_EXE").unwrap_or_else(|_| "bitcoind".into())
}

/// Base64 for the basic-auth header (no dep; RFC 4648 standard alphabet).
fn b64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

impl Node {
    /// Spawn a fresh regtest node on harness-chosen ports and wait for RPC.
    fn start(rpc_port: u16, p2p_port: u16) -> Node {
        let datadir = tempfile::tempdir().expect("node datadir");
        let child = Command::new(bitcoind_exe())
            .args([
                "-regtest",
                &format!("-datadir={}", datadir.path().display()),
                &format!("-rpcport={rpc_port}"),
                &format!("-port={p2p_port}"),
                "-rpcuser=e2e",
                "-rpcpassword=e2e",
                "-txindex=1",
                "-fallbackfee=0.0001",
                "-listen=1",
                "-server=1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect(
                "spawn bitcoind — install Bitcoin Core and put bitcoind on PATH or set \
                 BITCOIND_EXE (see tasks/PRE-ALPHA-RUNBOOK.md)",
            );
        let mut node = Node {
            child,
            rpc_url: format!("127.0.0.1:{rpc_port}"),
            auth: b64(b"e2e:e2e"),
            _datadir: datadir,
            miner_addr: String::new(),
        };
        // Wait for RPC readiness (initial block index etc.).
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if node.try_call("getblockchaininfo", json!([])).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "bitcoind RPC never became ready");
            std::thread::sleep(Duration::from_millis(500));
        }
        node.call("createwallet", json!(["miner"]));
        node.miner_addr = node.call("getnewaddress", json!([]))
            .as_str()
            .expect("miner address")
            .to_string();
        // Coinbase maturity: 101 blocks makes the first reward spendable.
        node.mine(101);
        node
    }

    /// One raw JSON-RPC call over a fresh loopback connection (the miner
    /// wallet is the node's only wallet, so the root endpoint routes to it).
    fn try_call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body =
            json!({"jsonrpc":"1.0","id":"e2e","method":method,"params":params}).to_string();
        let mut stream =
            TcpStream::connect(&self.rpc_url).map_err(|e| format!("connect: {e}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.auth,
            body.len(),
            body
        )
        .map_err(|e| format!("write: {e}"))?;
        let mut raw = String::new();
        stream.read_to_string(&mut raw).map_err(|e| format!("read: {e}"))?;
        let json_body = raw.split("\r\n\r\n").nth(1).ok_or("no body")?;
        let v: Value = serde_json::from_str(json_body.trim()).map_err(|e| e.to_string())?;
        if !v["error"].is_null() {
            return Err(v["error"].to_string());
        }
        Ok(v["result"].clone())
    }

    fn call(&self, method: &str, params: Value) -> Value {
        self.try_call(method, params.clone())
            .unwrap_or_else(|e| panic!("rpc {method} {params}: {e}"))
    }

    fn mine(&self, n: u64) {
        self.call("generatetoaddress", json!([n, self.miner_addr]));
    }

    fn mempool_len(&self) -> usize {
        self.call("getrawmempool", json!([])).as_array().map(|a| a.len()).unwrap_or(0)
    }

    /// Send `btc` to `addr`; return `(txid, vout)` of the payment output.
    fn send(&self, addr: &str, btc: f64) -> (String, u32) {
        let txid = self.call("sendtoaddress", json!([addr, btc]));
        let txid = txid.as_str().expect("txid").to_string();
        let tx = self.call("getrawtransaction", json!([txid, true]));
        let vout = tx["vout"]
            .as_array()
            .expect("vouts")
            .iter()
            .find(|o| {
                o["scriptPubKey"]["address"].as_str() == Some(addr)
            })
            .and_then(|o| o["n"].as_u64())
            .expect("payment vout") as u32;
        (txid, vout)
    }
}

// ---------------------------------------------------------------------------
// switchbitcoin-cli wallets
// ---------------------------------------------------------------------------

struct Wallet {
    name: &'static str,
    config: PathBuf,
    _dir: tempfile::TempDir,
}

fn cli_cmd(config: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_switchbitcoin-cli"));
    for (name, _) in std::env::vars() {
        if name.starts_with("SWITCHBITCOIN_") || name.starts_with("SWAPKEY_") {
            cmd.env_remove(&name);
        }
    }
    cmd.args(args).arg("--config").arg(config);
    cmd
}

fn run_cli(config: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = cli_cmd(config, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn switchbitcoin-cli");
    child.stdin.as_mut().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().expect("cli exit")
}

fn text(out: &Output) -> String {
    format!("{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

impl Wallet {
    fn create(name: &'static str, rpc_port: u16) -> Wallet {
        let dir = tempfile::tempdir().expect("wallet dir");
        let config = dir.path().join("switchbitcoin.toml");
        let data_dir = dir.path().join("data");
        std::fs::write(
            &config,
            format!(
                "network = \"regtest\"\ndata_dir = '{}'\n[node]\nrpc_url = \"http://127.0.0.1:{rpc_port}\"\nrpc_user = \"e2e\"\nrpc_password = \"e2e\"\n",
                data_dir.display()
            ),
        )
        .unwrap();
        let out = run_cli(
            &config,
            &[
                "init",
                "--passphrase-stdin",
                "--accept-phase0",
                "--skip-backup-verification",
            ],
            PASSPHRASE,
        );
        assert!(out.status.success(), "[{name}] init failed:\n{}", text(&out));
        Wallet { name, config, _dir: dir }
    }

    /// Issue a deposit address; returns (key_index, address).
    fn address(&self) -> (u32, String) {
        let out = run_cli(&self.config, &["address", "--passphrase-stdin"], PASSPHRASE);
        assert!(out.status.success(), "[{}] address failed:\n{}", self.name, text(&out));
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        // "deposit address (key index N): <addr>"
        let line = stdout.lines().find(|l| l.contains("deposit address")).expect("address line");
        let index: u32 = line
            .split("key index ")
            .nth(1)
            .and_then(|r| r.split(')').next())
            .and_then(|n| n.parse().ok())
            .expect("key index");
        let addr = line.split(": ").nth(1).expect("addr").trim().to_string();
        (index, addr)
    }

    /// Onboard a confirmed deposit, mining while the CLI waits for the split
    /// confirmation, then mine out the delay's height anchor.
    fn onboard(&self, node: &Node, outpoint: &str, key_index: u32) {
        let mut child = cli_cmd(
            &self.config,
            &[
                "onboard",
                outpoint,
                "--key-index",
                &key_index.to_string(),
                "--passphrase-stdin",
                "--accept-phase0",
                "--wait-secs",
                "120",
            ],
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn onboard");
        child.stdin.as_mut().unwrap().write_all(PASSPHRASE.as_bytes()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            match child.try_wait().expect("try_wait") {
                Some(_) => break,
                None => {
                    node.mine(1);
                    assert!(Instant::now() < deadline, "[{}] onboard timed out", self.name);
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
        let out = child.wait_with_output().expect("onboard output");
        assert!(out.status.success(), "[{}] onboard failed:\n{}", self.name, text(&out));
        node.mine(ONBOARD_DELAY_BLOCKS); // the height anchor, mined out
    }

    fn status(&self) -> String {
        let out = run_cli(&self.config, &["status", "--passphrase-stdin"], PASSPHRASE);
        assert!(out.status.success(), "[{}] status failed:\n{}", self.name, text(&out));
        text(&out)
    }

    /// Spawn `swap` with stderr redirected to a per-run file (scannable
    /// mid-run). The child is reaped on Drop so an assertion panic never
    /// leaks a live wallet process (Fable review — once a Setup is on the
    /// wire the CLI deliberately loops forever guarding the escrow).
    fn spawn_swap(&self, label: &str, args: &[&str]) -> (Reap, PathBuf) {
        let log = self._dir.path().join(format!("swap-{label}.log"));
        let log_file = std::fs::File::create(&log).expect("log file");
        let mut full = vec!["swap"];
        full.extend_from_slice(args);
        full.extend_from_slice(&["--passphrase-stdin", "--poll-secs", "1"]);
        let mut child = cli_cmd(&self.config, &full)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn swap");
        child.stdin.as_mut().unwrap().write_all(PASSPHRASE.as_bytes()).unwrap();
        (Reap(child), log)
    }
}

/// Kill-on-Drop child guard (panics must reap spawned wallets).
struct Reap(Child);
impl Reap {
    fn done(&mut self) -> bool {
        self.0.try_wait().expect("try_wait").is_some()
    }
    fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for Reap {
    fn drop(&mut self) {
        self.kill();
    }
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Fund + onboard one wallet with enough units for several attempts (the
/// role↔CSV convention refunds ~half of them).
fn provision(node: &Node, wallet: &Wallet, btc: f64) {
    let (index, addr) = wallet.address();
    let (txid, vout) = node.send(&addr, btc);
    node.mine(1);
    wallet.onboard(node, &format!("{txid}:{vout}"), index);
    let status = wallet.status();
    assert!(
        status.contains("PreEncumbrance/Unspent"),
        "[{}] onboarding must mint pre-encumbrance units:\n{status}",
        wallet.name
    );
    assert!(
        status.contains("leasable (backstop armed)"),
        "[{}] onboarding must carve the CPFP reserve:\n{status}",
        wallet.name
    );
}

/// Drive one A-listen/B-connect attempt to both terminals; returns the two
/// logs. The miner keeps the chain moving the whole time.
fn run_attempt(node: &Node, a: &Wallet, b: &Wallet, peer_port: u16) -> (String, String) {
    let (mut ca, log_a) =
        a.spawn_swap(&format!("a-{peer_port}"), &["--listen", &format!("127.0.0.1:{peer_port}")]);
    std::thread::sleep(Duration::from_secs(2));
    let (mut cb, log_b) =
        b.spawn_swap(&format!("b-{peer_port}"), &["--connect", &format!("127.0.0.1:{peer_port}")]);

    let deadline = Instant::now() + Duration::from_secs(900);
    loop {
        if ca.done() && cb.done() {
            break;
        }
        assert!(Instant::now() < deadline, "attempt timed out\nA:\n{}\nB:\n{}",
            read_log(&log_a), read_log(&log_b));
        node.mine(2);
        std::thread::sleep(Duration::from_secs(1));
    }
    (read_log(&log_a), read_log(&log_b))
}

/// Classify one attempt's terminal from the two swap logs: `Some(true)` = both
/// sides COMPLETED, `Some(false)` = both REFUNDED (the role↔CSV convention
/// mismatch, by design), `None` = neither — a forward-or-refund VIOLATION the
/// caller must reject. Mirrors the happy-path proof's log predicates.
fn attempt_terminal(la: &str, lb: &str) -> Option<bool> {
    let both_completed = la.contains("SWAP COMPLETED") && lb.contains("SWAP COMPLETED");
    let both_refunded =
        la.contains("refund path resolved") && lb.contains("refund path resolved");
    if both_completed {
        Some(true)
    } else if both_refunded {
        Some(false)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// the three E2E proofs
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs bitcoind (see tasks/PRE-ALPHA-RUNBOOK.md)"]
fn e2e_happy_path_swap_completes() {
    let node = Node::start(28843, 28844);
    let a = Wallet::create("A", 28843);
    let b = Wallet::create("B", 28843);
    // ~10 units each (unit = D + Δfee = 0.01005 BTC) + split fee headroom.
    provision(&node, &a, 0.115);
    provision(&node, &b, 0.115);

    let mut completed = false;
    for attempt in 0..8 {
        let (la, lb) = run_attempt(&node, &a, &b, 29000 + attempt);
        let both_completed =
            la.contains("SWAP COMPLETED") && lb.contains("SWAP COMPLETED");
        let both_refunded = la.contains("refund path resolved") && lb.contains("refund path resolved");
        assert!(
            both_completed || both_refunded,
            "attempt {attempt} must close forward-or-refund on BOTH sides\nA:\n{la}\nB:\n{lb}"
        );
        if both_completed {
            completed = true;
            break;
        }
        // The refunded branch is the role↔CSV convention mismatch — by
        // design (~50%); retry with the next pre-encumbrance units.
        eprintln!("attempt {attempt}: convention mismatch, closed via refunds; retrying");
    }
    assert!(completed, "no attempt completed in 8 tries (P(mismatch)^8 ≈ 0.4%)");

    // Each side received exactly D at a fresh destination, ledger-tracked.
    for w in [&a, &b] {
        let status = w.status();
        assert!(
            status.contains("Swapped/Unspent"),
            "[{}] the settlement output must be ledger-tracked:\n{status}",
            w.name
        );
        assert!(status.contains("Completed"), "[{}] record terminal:\n{status}", w.name);
    }
}

#[test]
#[ignore = "needs bitcoind (see tasks/PRE-ALPHA-RUNBOOK.md)"]
fn e2e_dead_peer_routes_to_refund() {
    let node = Node::start(28853, 28854);
    let a = Wallet::create("A", 28853);
    let b = Wallet::create("B", 28853);
    provision(&node, &a, 0.035);
    provision(&node, &b, 0.035);

    let (mut ca, log_a) = a.spawn_swap("a-refund", &["--listen", "127.0.0.1:29100"]);
    std::thread::sleep(Duration::from_secs(2));
    let (mut cb, log_b) = b.spawn_swap("b-refund", &["--connect", "127.0.0.1:29100"]);

    // Both Setups on the wire, observed via the LOGS: the funding order
    // staggers broadcasts (the Second funder waits for the First's Setup to
    // CONFIRM), so the mempool never holds both at once — mine single blocks
    // to feed the go-signal, and kill B once BOTH sides have broadcast.
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let a_broadcast = read_log(&log_a).contains("setup broadcast:");
        let b_broadcast = read_log(&log_b).contains("setup broadcast:");
        if a_broadcast && b_broadcast {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "setups never went on the wire\nA:\n{}\nB:\n{}",
            read_log(&log_a),
            read_log(&log_b)
        );
        if node.mempool_len() >= 1 {
            node.mine(1); // confirm the first funder's Setup → go-signal
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    cb.kill();
    node.mine(1); // confirm the remaining Setup

    // A alone must reach the refund terminal: the CSV matures (144–216
    // blocks), the backstop/babysit fires + confirms the pre-armed refund.
    let deadline = Instant::now() + Duration::from_secs(900);
    while !ca.done() {
        assert!(
            Instant::now() < deadline,
            "A never resolved after B died\nA:\n{}",
            read_log(&log_a)
        );
        node.mine(4);
        std::thread::sleep(Duration::from_secs(1));
    }
    let la = read_log(&log_a);
    assert!(
        la.contains("refund path resolved") || la.contains("Refunded"),
        "A must close through the refund on a real chain:\n{la}"
    );
    let status = a.status();
    assert!(status.contains("Refunded"), "record terminal:\n{status}");
    assert!(
        status.contains("Swapped/Unspent"),
        "the reclaimed refund output must be ledger-tracked:\n{status}"
    );
}

#[test]
#[ignore = "needs bitcoind (see tasks/PRE-ALPHA-RUNBOOK.md)"]
fn e2e_crash_recovery_reenters_from_the_store() {
    let node = Node::start(28863, 28864);
    let a = Wallet::create("A", 28863);
    let b = Wallet::create("B", 28863);
    provision(&node, &a, 0.035);
    provision(&node, &b, 0.035);

    let (mut ca, log_a) = a.spawn_swap("a-crash", &["--listen", "127.0.0.1:29200"]);
    std::thread::sleep(Duration::from_secs(2));
    let (mut cb, _log_b) = b.spawn_swap("b-crash", &["--connect", "127.0.0.1:29200"]);

    // SIGKILL A the moment its Setup broadcast is confirmed in its log (the
    // early Funding record is durable from that point).
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if read_log(&log_a).contains("setup broadcast") {
            break;
        }
        assert!(Instant::now() < deadline, "A never broadcast its Setup\n{}", read_log(&log_a));
        if node.mempool_len() >= 1 {
            node.mine(1);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    ca.kill();
    cb.kill(); // B cannot proceed either; this run is about A
    node.mine(1);

    // Mine past CSV maturity, then a fresh process re-enters from the store
    // alone. `recover` is single-pass: run it until the record is terminal.
    node.mine(250);
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let out = run_cli(&a.config, &["recover", "--passphrase-stdin"], PASSPHRASE);
        assert!(out.status.success(), "recover failed:\n{}", text(&out));
        node.mine(2);
        let status = a.status();
        if status.contains("Refunded") {
            assert!(
                status.contains("Swapped/Unspent"),
                "recovery must register the reclaimed output:\n{status}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "recovery never drove the crashed swap to Refunded:\n{status}"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Live-run P1 (testnet4, 2026-07-21): a taker killed during its claim-delay
/// hold, whose swap `recover` then finished, reached a settled record with the
/// settlement coin NEVER ledger-tracked. This drill reproduces that exact kill
/// point against a real chain: both sides run `--claim-posture private`
/// (sampled hold >= 12 blocks — a wide window against the harness miner), the
/// SL is SIGKILLed the moment it announces its hold, the SH finishes alone,
/// and `recover` on the killed wallet must both settle the swap AND surface
/// the received coin as `Swapped/Unspent` in `status`.
#[test]
#[ignore = "needs bitcoind (see tasks/PRE-ALPHA-RUNBOOK.md)"]
fn e2e_taker_killed_mid_claim_hold_recovers_and_tracks_the_coin() {
    const HOLD_LINE: &str = "claim-delay posture hold:";
    let node = Node::start(28873, 28874);
    let a = Wallet::create("A", 28873);
    let b = Wallet::create("B", 28873);
    provision(&node, &a, 0.115);
    provision(&node, &b, 0.115);

    // Retry attempts until one COMPLETES with an observable SL hold (the
    // role↔CSV convention refunds ~half of attempts by design; the SH never
    // holds, so exactly the SL side can trip the kill).
    let mut killed: Option<(&Wallet, PathBuf)> = None;
    for attempt in 0..8 {
        let port = 29300 + attempt;
        let posture: &[&str] = &["--claim-posture", "private"];
        let mut args_a = vec!["--listen"];
        let listen = format!("127.0.0.1:{port}");
        args_a.push(&listen);
        args_a.extend_from_slice(posture);
        let (mut ca, log_a) = a.spawn_swap(&format!("a-hold-{port}"), &args_a);
        std::thread::sleep(Duration::from_secs(2));
        let mut args_b = vec!["--connect"];
        args_b.push(&listen);
        args_b.extend_from_slice(posture);
        let (mut cb, log_b) = b.spawn_swap(&format!("b-hold-{port}"), &args_b);

        let deadline = Instant::now() + Duration::from_secs(900);
        let mut crashed_is_a: Option<bool> = None;
        loop {
            // Check for the hold BEFORE mining again, so the kill lands
            // inside the (>= 12 block) hold window.
            if read_log(&log_a).contains(HOLD_LINE) {
                ca.kill();
                crashed_is_a = Some(true);
            } else if read_log(&log_b).contains(HOLD_LINE) {
                cb.kill();
                crashed_is_a = Some(false);
            }
            if crashed_is_a.is_some() || (ca.done() && cb.done()) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "attempt never resolved\nA:\n{}\nB:\n{}",
                read_log(&log_a),
                read_log(&log_b)
            );
            // Single blocks + a fast poll: a >= 12-block hold then spans many
            // loop iterations, so the kill lands INSIDE it rather than racing
            // the whole hold+confirm+register tail between two reads.
            node.mine(1);
            std::thread::sleep(Duration::from_millis(100));
        }
        if let Some(is_a) = crashed_is_a {
            // The survivor (the SH — its completion produced the reveal) must
            // still finish its own leg unaided.
            let (survivor, survivor_log) =
                if is_a { (&mut cb, &log_b) } else { (&mut ca, &log_a) };
            let deadline = Instant::now() + Duration::from_secs(900);
            while !survivor.done() {
                assert!(
                    Instant::now() < deadline,
                    "the surviving SH never finished:\n{}",
                    read_log(survivor_log)
                );
                node.mine(2);
                std::thread::sleep(Duration::from_millis(500));
            }
            assert!(
                read_log(survivor_log).contains("SWAP COMPLETED"),
                "the surviving SH must complete:\n{}",
                read_log(survivor_log)
            );
            killed = Some(if is_a { (&a, log_a) } else { (&b, log_b) });
            break;
        }
        eprintln!("attempt {attempt}: convention mismatch, closed via refunds; retrying");
    }
    let (crashed, crashed_log) =
        killed.expect("no attempt completed with an observable hold in 8 tries");

    // If the kill raced the hold's tail the coin may already be tracked (the
    // live babysit registered it before dying) — the drill then only proves
    // recover's idempotency; the deterministic runner tests pin the exact
    // mid-hold state. Note it rather than fail a live-timing race.
    if crashed.status().contains("Swapped/Unspent") {
        eprintln!("NOTE: kill landed after registration; exercising recover idempotency only");
    }

    // The P1 under test: `recover` on a fresh process must finish the claim
    // AND register the settlement coin — a settled record alone is the bug.
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let out = run_cli(&crashed.config, &["recover", "--passphrase-stdin"], PASSPHRASE);
        assert!(out.status.success(), "recover failed:\n{}", text(&out));
        node.mine(2);
        let status = crashed.status();
        if status.contains("Swapped/Unspent") {
            assert!(status.contains("Completed"), "record terminal:\n{status}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "recover settled the swap without registering the settlement coin \
             (live-run P1):\n{status}\ncrashed swap log:\n{}",
            read_log(&crashed_log)
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ---------------------------------------------------------------------------
// role↔CSV refund-rate measurement (Deliverable B)
// ---------------------------------------------------------------------------

/// Live analogue of `runner::measure_role_csv_refund_rate`: run EXACTLY N
/// attempts of the A-listen/B-connect flow (env `SWITCHBITCOIN_RATE_ATTEMPTS`,
/// default 4 — live attempts are minutes each) WITHOUT stopping at the first
/// completion, record each terminal, and print a machine-greppable summary.
///
/// No statistical bound (N is small); the test passes iff EVERY attempt closes
/// forward-or-refund — the same per-attempt assertion the happy-path proof
/// makes for its non-completing attempts.
#[test]
#[ignore = "needs bitcoind; N-attempt role↔CSV refund-rate measurement (SWITCHBITCOIN_RATE_ATTEMPTS, default 4)"]
fn e2e_measure_refund_rate() {
    let n: u16 = std::env::var("SWITCHBITCOIN_RATE_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(4);

    let node = Node::start(28873, 28874);
    let a = Wallet::create("A", 28873);
    let b = Wallet::create("B", 28873);
    // One pre-encumbrance unit per attempt (unit = D + Δfee = 0.01005 BTC) plus
    // the one-time CPFP reserve + split headroom; the convention refunds ~half,
    // so every attempt consumes a fresh unit and none are reused.
    let units_btc = 0.0115 * f64::from(n) + 0.02;
    provision(&node, &a, units_btc);
    provision(&node, &b, units_btc);

    let mut completed = 0u16;
    for attempt in 0..n {
        let (la, lb) = run_attempt(&node, &a, &b, 29300 + attempt);
        let terminal = attempt_terminal(&la, &lb);
        assert!(
            terminal.is_some(),
            "attempt {attempt} must close forward-or-refund on BOTH sides\nA:\n{la}\nB:\n{lb}"
        );
        let done = terminal == Some(true);
        if done {
            completed += 1;
        }
        eprintln!(
            "ROLE-CSV attempt {}/{n} (regtest): {}",
            attempt + 1,
            if done { "completed" } else { "refunded" }
        );
    }

    let refunded = n - completed;
    let pct = 100.0 * f64::from(completed) / f64::from(n);
    println!(
        "ROLE-CSV RATE (regtest): completed {completed}/{n} ({pct:.1}%), refunded {refunded}/{n}"
    );
}
