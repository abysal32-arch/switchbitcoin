//! Localhost JSON API core (Task 09): the router, state, HTTP framing, and
//! status snapshot the `switchbitcoin-cli serve` mode exposes to the local
//! `SwitchBitcoin-Wallet.html` frontend.
//!
//! DESIGN: everything here is chain-agnostic and I/O-thin so it unit-tests
//! against a seeded engine + `SimChain` in the default build (no serde, no
//! HTTP framework — the API is five endpoints of hand-rolled JSON; a full
//! parser stack is far more surface than they need). The BINARY owns the
//! sockets and the worker thread that actually drives the wallet:
//!
//! ```text
//!  HTTP conns ──▶ read_request ─▶ route(state, cmds) ─▶ write_response
//!                                    │        │
//!                       Arc<Mutex<ApiState>>  └──▶ mpsc ApiCmd ──▶ worker
//!  worker (owns Wallet+chain): drains cmds, drives the swap/onboard state
//!  machine with the Task-08 runner fns, refreshes `status_json`, pushes
//!  trace lines.
//! ```
//!
//! SECURITY (pre-alpha, documented): loopback-only binding is the caller's
//! job (the binary binds `127.0.0.1` and nothing else), there is NO auth —
//! any local process can drive the wallet — and responses carry
//! `Access-Control-Allow-Origin: *` so the `file://`-served HTML can fetch.
//! Nothing secret ever enters `ApiState`: no seed, no passphrase, no RPC
//! credentials — by construction the state only holds JSON the UI may see.
//!
//! PHASE-0 GATE OVER THE API: `POST /onboard` demands `"ack_phase0": true`.
//! The warning COPY rides in `/status` (`phase0_warning`) so the UI can
//! display it verbatim; the ack field is the UI's proof-of-display, and the
//! worker mints the typed [`acknowledge_phase0`] from it — same contract as
//! the CLI prompt, one hop removed.
//!
//! [`acknowledge_phase0`]: crate::wallet::ledger::acknowledge_phase0

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crate::settlement::params::Params;
use crate::wallet::config::Network;
use crate::wallet::engine::SwapEngine;
use crate::wallet::manifest::ClaimDelayPosture;
use crate::wallet::runner::hex32;

/// Conventional local port (0x0CF4 = 3316, the spec version tag).
pub const DEFAULT_API_PORT: u16 = 3316;

/// The build provenance string (Task 20): crate version + git short hash
/// (stamped by build.rs; `unknown` outside a git checkout, `-dirty` on an
/// unclean tree). This is what a tester report must name — it rides in
/// `switchbitcoin-cli --version`, the `/status` snapshot, and the `diag` bundle.
pub const BUILD_VERSION: &str =
    concat!(env!("CARGO_PKG_VERSION"), " (git ", env!("NEWKEY_GIT_HASH"), ")");

/// Default `--max-swaps` concurrency cap (Task 16). Small on purpose: every
/// live swap holds a leased pre-encumbrance coin, and the CPFP reserve pool
/// that guards their refunds is shared — a generous cap would let a tester
/// oversubscribe the reserve long before the ledger runs out of coins.
pub const DEFAULT_MAX_SWAPS: usize = 4;

/// Trace ring-buffer cap (old lines are dropped; `/events` reports `next`).
const TRACE_CAP: usize = 2_000;
/// Max lines a single `/events` reply carries.
const EVENTS_PAGE: usize = 500;
/// Hard cap on an accepted request (start line + headers + body).
const MAX_REQUEST: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// State + commands
// ---------------------------------------------------------------------------

/// A queued instruction for the worker thread (the ONLY writer of wallet
/// state — HTTP handlers never touch the wallet directly).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiCmd {
    /// Register + split + confirm a deposit. `deposit` is `txid:vout`
    /// (validated syntactically at the route; semantically by the worker).
    Onboard { deposit: String, split_fee: u64 },
    /// Start ONE swap (exactly one of listen/connect, enforced at the route).
    SwapBegin { listen: Option<String>, connect: Option<String> },
    /// Offer a swap by TICKET: bind `listen`, mint a ticket, expose it in
    /// `/status` (`offer_ticket`), and wait for a taker to rendezvous.
    SwapOffer { listen: String },
    /// Take a swap by TICKET. The route pre-decodes the string (garbage → 400);
    /// the worker re-decodes and validates network + params against THIS wallet
    /// before dialing.
    SwapTake { ticket: String },
}

/// One swap as the UI sees it.
#[derive(Clone, Debug, Default)]
pub struct SwapView {
    /// 64-hex session id ("pending" until negotiation derives it).
    pub sid: String,
    /// Coarse phase string ("negotiating", "funding", "settling",
    /// "babysit-completion", "babysit-refund", "guard", or a terminal).
    pub phase: String,
    /// Terminal outcome, once reached.
    pub outcome: Option<String>,
}

/// Shared server state: the worker writes, HTTP reads (plus command
/// enqueueing). Everything in here is UI-safe by construction.
pub struct ApiState {
    /// The last full `/status` JSON object, composed by the worker via
    /// [`status_snapshot`]. Staleness is bounded by the worker poll cadence.
    pub status_json: String,
    /// `(seq, line)` trace ring — the runner `log` sink, timestamped by seq.
    trace: Vec<(u64, String)>,
    next_seq: u64,
    /// Swap views by sid hex (the active one also flagged in the snapshot).
    pub swaps: HashMap<String, SwapView>,
    /// The in-flight worker command, if any. Since Task 16 this is a SHORT
    /// dispatch latch for swap commands (set at the route, cleared by the
    /// worker the moment the command lands in a slot or is refused); only
    /// `onboard` still holds it through its whole split tail.
    pub busy: Option<&'static str>,
    /// The currently-offered swap ticket (a `skt1…` string) while a
    /// `SwapOffer` waits for its taker; cleared once a taker rendezvouses or
    /// the offer deadline passes. Surfaced in `/status` so the UI can show it.
    pub offer_ticket: Option<String>,
    /// Worker-maintained count of LIVE swap slots (accepting/offering/running/
    /// babysitting/guarding). The route's cap gate reads it; the worker
    /// refreshes it every dispatch and every tick.
    pub active_swaps: usize,
    /// The serve concurrency cap (`--max-swaps`); set once at startup.
    pub max_swaps: usize,
}

impl Default for ApiState {
    fn default() -> Self {
        ApiState {
            status_json: "{\"ready\":false}".into(),
            trace: Vec::new(),
            next_seq: 0,
            swaps: HashMap::new(),
            busy: None,
            offer_ticket: None,
            active_swaps: 0,
            max_swaps: DEFAULT_MAX_SWAPS,
        }
    }
}

impl ApiState {
    pub fn new() -> ApiState {
        ApiState::default()
    }

    /// Append a trace line (the worker's `log` sink target). Returns its seq.
    /// Seqs start at 1 so a fresh client's `since=0` reads from the top
    /// (`/events` filters strictly-greater; `next` is the last assigned seq,
    /// passed back verbatim as the client's new `since`).
    pub fn push_trace(&mut self, line: String) -> u64 {
        self.next_seq += 1;
        let seq = self.next_seq;
        self.trace.push((seq, line));
        if self.trace.len() > TRACE_CAP {
            let drop = self.trace.len() - TRACE_CAP;
            self.trace.drain(..drop);
        }
        seq
    }

    /// Lines with seq > `since`, capped to a page. When the page truncates,
    /// `next` is the LAST INCLUDED seq — a client resuming from it walks the
    /// backlog instead of skipping everything between (which would drop
    /// ALARM lines from the UI; Fable review).
    fn events_after(&self, since: u64) -> (u64, Vec<(u64, String)>) {
        let lines: Vec<(u64, String)> = self
            .trace
            .iter()
            .filter(|(s, _)| *s > since)
            .take(EVENTS_PAGE)
            .cloned()
            .collect();
        let next = if lines.len() == EVENTS_PAGE {
            lines.last().map(|(s, _)| *s).unwrap_or(self.next_seq)
        } else {
            self.next_seq
        };
        (next, lines)
    }
}

pub type SharedState = Arc<Mutex<ApiState>>;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Route one parsed request to `(http_status, json_body)`. Pure over the
/// shared state + command queue — the unit-testable core.
pub fn route(
    state: &SharedState,
    cmds: &Sender<ApiCmd>,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, String) {
    // CORS preflight for the file://-served frontend.
    if method == "OPTIONS" {
        return (204, String::new());
    }
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    };
    match (method, path) {
        ("GET", "/status") => (200, state.lock().unwrap().status_json.clone()),
        ("GET", "/events") => {
            let since = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("since="))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let (next, lines) = state.lock().unwrap().events_after(since);
            let mut out = String::from("{\"next\":");
            out.push_str(&next.to_string());
            out.push_str(",\"lines\":[");
            for (i, (seq, line)) in lines.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('[');
                out.push_str(&seq.to_string());
                out.push(',');
                out.push_str(&json_string(line));
                out.push(']');
            }
            out.push_str("]}");
            (200, out)
        }
        ("GET", p) if p.starts_with("/swap/") => {
            let sid = &p["/swap/".len()..];
            match state.lock().unwrap().swaps.get(sid) {
                Some(v) => (200, swap_view_json(v)),
                None => (404, err_json("unknown swap id")),
            }
        }
        ("POST", "/onboard") => {
            let Some(deposit) = json_str_field(body, "deposit") else {
                return (400, err_json("body needs {\"deposit\":\"txid:vout\", ...}"));
            };
            if !deposit_shape_ok(&deposit) {
                return (400, err_json("deposit must be <64-hex-txid>:<vout>"));
            }
            // The Phase-0 display contract: the UI shows /status's
            // phase0_warning verbatim; this field is its proof.
            if !json_bool_field(body, "ack_phase0").unwrap_or(false) {
                return (428, err_json("ack_phase0 must be true (display the phase0_warning first)"));
            }
            let split_fee = json_u64_field(body, "split_fee").unwrap_or(2_000);
            enqueue(state, cmds, "onboard", ApiCmd::Onboard { deposit, split_fee })
        }
        ("POST", "/swap/begin") => {
            let listen = json_str_field(body, "listen");
            let connect = json_str_field(body, "connect");
            match (&listen, &connect) {
                (Some(_), Some(_)) | (None, None) => {
                    return (400, err_json("exactly one of listen/connect required"))
                }
                (Some(a), None) | (None, Some(a)) if a.is_empty() || !a.contains(':') => {
                    return (400, err_json("peer address must be host:port"))
                }
                _ => {}
            }
            enqueue_swap(state, cmds, ApiCmd::SwapBegin { listen, connect })
        }
        ("POST", "/swap/offer") => {
            let Some(listen) = json_str_field(body, "listen") else {
                return (400, err_json("body needs {\"listen\":\"host:port\"}"));
            };
            if listen.is_empty() || !listen.contains(':') {
                return (400, err_json("listen must be host:port"));
            }
            enqueue_swap(state, cmds, ApiCmd::SwapOffer { listen })
        }
        ("POST", "/swap/take") => {
            let Some(ticket) = json_str_field(body, "ticket") else {
                return (400, err_json("body needs {\"ticket\":\"skt1...\"}"));
            };
            // Pre-decode at the route so garbage is a 400 that never enqueues.
            // The route cannot check network/params (it has no engine) — the
            // WORKER re-decodes and validates those before dialing.
            if let Err(e) = crate::wallet::ticket::Ticket::decode(&ticket) {
                return (400, err_json(&e.to_string()));
            }
            enqueue_swap(state, cmds, ApiCmd::SwapTake { ticket })
        }
        ("GET", _) | ("POST", _) => (404, err_json("unknown endpoint")),
        _ => (405, err_json("method not allowed")),
    }
}

/// Reserve the worker (409 if something is already in flight) and enqueue.
fn enqueue(
    state: &SharedState,
    cmds: &Sender<ApiCmd>,
    label: &'static str,
    cmd: ApiCmd,
) -> (u16, String) {
    let mut st = state.lock().unwrap();
    if let Some(busy) = st.busy {
        return (409, err_json(&format!("worker busy with {busy}")));
    }
    if cmds.send(cmd).is_err() {
        return (503, err_json("worker is gone"));
    }
    st.busy = Some(label);
    st.push_trace(format!("api: {label} accepted"));
    (202, "{\"accepted\":true}".into())
}

/// Reserve the worker for a SWAP command (Task 16: swaps are concurrent, so
/// the gates differ from [`enqueue`]). Checked under ONE lock: the short
/// dispatch latch (`busy` — one command in flight at a time; the worker clears
/// it the moment the command lands in a slot), then the concurrency cap
/// (`active_swaps < max_swaps`, worker-maintained), then — for an offer — the
/// one-outstanding-offer rule (there is a single `offer_ticket` surface). A
/// capped swap is a loud 409, never a silent drop.
fn enqueue_swap(state: &SharedState, cmds: &Sender<ApiCmd>, cmd: ApiCmd) -> (u16, String) {
    let mut st = state.lock().unwrap();
    if let Some(busy) = st.busy {
        return (409, err_json(&format!("worker busy with {busy}")));
    }
    if st.active_swaps >= st.max_swaps {
        return (
            409,
            err_json(&format!(
                "swap cap reached ({} of {} active) — wait for a swap to finish or raise --max-swaps",
                st.active_swaps, st.max_swaps
            )),
        );
    }
    if matches!(cmd, ApiCmd::SwapOffer { .. }) && st.offer_ticket.is_some() {
        return (409, err_json("an offer is already outstanding (one ticket at a time)"));
    }
    if cmds.send(cmd).is_err() {
        return (503, err_json("worker is gone"));
    }
    st.busy = Some("swap");
    st.push_trace("api: swap accepted".to_string());
    (202, "{\"accepted\":true}".into())
}

fn deposit_shape_ok(s: &str) -> bool {
    match s.split_once(':') {
        Some((txid, vout)) => {
            txid.len() == 64
                && txid.chars().all(|c| c.is_ascii_hexdigit())
                && vout.parse::<u32>().is_ok()
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Status snapshot (worker-side composer)
// ---------------------------------------------------------------------------

/// Compose the full `/status` JSON from the engine + live worker facts. The
/// worker calls this each tick under the state lock and stores the result.
#[allow(clippy::too_many_arguments)]
pub fn status_snapshot(
    engine: &SwapEngine,
    params: &Params,
    network: Network,
    tip_height: Option<u32>,
    node_online: bool,
    active: &[SwapView],
    busy: Option<&str>,
    alarms: &[String],
    offer_ticket: Option<&str>,
    max_swaps: usize,
    fee_estimate: Option<u64>,
) -> String {
    let ledger = engine.ledger();
    let mut coins = String::from("[");
    let mut spendable_sats: u64 = 0;
    for (i, c) in ledger.coins().iter().enumerate() {
        use crate::wallet::ledger::CoinState;
        if c.state == CoinState::Unspent {
            spendable_sats += c.amount_sats;
        }
        if i > 0 {
            coins.push(',');
        }
        coins.push_str(&format!(
            "{{\"outpoint\":{},\"sats\":{},\"class\":{},\"state\":{}}}",
            json_string(&format!("{}:{}", c.outpoint.txid, c.outpoint.vout)),
            c.amount_sats,
            json_string(&format!("{:?}", c.class)),
            json_string(&format!("{:?}", c.state)),
        ));
    }
    coins.push(']');

    let mut swaps = String::from("[");
    let mut unreadable = 0usize;
    if let Ok((records, bad)) = engine.store().list() {
        unreadable = bad.len();
        for (i, r) in records.iter().enumerate() {
            if i > 0 {
                swaps.push(',');
            }
            swaps.push_str(&format!(
                "{{\"sid\":{},\"phase\":{}}}",
                json_string(&hex32(&r.swap_session_id)),
                json_string(&format!("{:?}", r.phase)),
            ));
        }
    }
    swaps.push(']');

    let mut alarms_json = String::from("[");
    for (i, a) in alarms.iter().enumerate() {
        if i > 0 {
            alarms_json.push(',');
        }
        alarms_json.push_str(&json_string(a));
    }
    alarms_json.push(']');

    // Every live slot's view (Task 16) — accepting/offering slots included,
    // so the UI sees a pending offer before its sid derives.
    let mut active_json = String::from("[");
    for (i, v) in active.iter().enumerate() {
        if i > 0 {
            active_json.push(',');
        }
        active_json.push_str(&swap_view_json(v));
    }
    active_json.push(']');

    // The SL claim-delay posture is now wired into the run loop (Task 13), so
    // this is `true` and the ACTIVE posture (override else the manifest's) is
    // reported lowercase for the UI.
    let claim_posture = match engine.effective_claim_posture() {
        ClaimDelayPosture::Minimal => "minimal",
        ClaimDelayPosture::Moderate => "moderate",
        ClaimDelayPosture::Aggressive => "aggressive",
    };

    // Build provenance (Task 20) — APPENDED at the tail of the snapshot
    // (fields are append-only; the UI and the tests/api.rs needles key on
    // names, never positions).
    let version = json_string(BUILD_VERSION);

    // Manifest trust state (Task 28) — APPENDED so the UI can render the active
    // signed-params version + id and shout the v0 provisional partition (a
    // fingerprintable anonymity set) LOUDLY. Mirrors `manifest show`; the wallet
    // never invents this — it is read straight off the ingested/floored store.
    let manifest = engine.manifest();
    let manifest_json = format!(
        "{{\"version\":{},\"id\":{},\"provisional\":{},\"floor\":{}}}",
        manifest.current().version(),
        json_string(&hex32(&manifest.current().id())),
        manifest.is_provisional(),
        manifest.floor(),
    );

    // Fee weather (Task 26) — APPENDED at the tail like every other field.
    // Warn-and-proceed advisory; `fee_estimate` is the caller's live
    // `estimated_feerate_sat_vb()` (None when the node has no data).
    let fee_weather = crate::wallet::fee_weather::FeeWeather::assess(params, fee_estimate).json();

    format!(
        "{{\"ready\":true,\"network\":{},\"tip\":{},\"node_online\":{},\
         \"spendable_sats\":{spendable_sats},\"reserve_leasable\":{},\
         \"tier_d_sats\":{},\"escrow_sats\":{},\"pre_encumbrance_sats\":{},\
         \"coins\":{coins},\"records\":{swaps},\"unreadable_records\":{unreadable},\
         \"swap\":{},\"busy\":{},\"alarms\":{alarms_json},\
         \"phase0_warning\":{},\"claim_posture_applied\":true,\"claim_posture\":{},\
         \"offer_ticket\":{},\"active_swaps\":{active_json},\"max_swaps\":{max_swaps},\
         \"version\":{version},\"manifest\":{manifest_json},\"fee_weather\":{fee_weather}}}",
        json_string(network.as_str()),
        tip_height.map(|h| h.to_string()).unwrap_or_else(|| "null".into()),
        node_online,
        ledger.has_leasable_reserve(1),
        params.tier_d_sats,
        params.escrow_amount_sats(),
        params.pre_encumbrance_sats(),
        // Legacy single-swap field the UI predates Task 16 on: the FIRST
        // active view (null when idle). The full list rides in active_swaps.
        active.first().map(swap_view_json).unwrap_or_else(|| "null".into()),
        busy.map(json_string).unwrap_or_else(|| "null".into()),
        json_string(crate::wallet::ledger::PHASE0_WARNING),
        json_string(claim_posture),
        offer_ticket.map(json_string).unwrap_or_else(|| "null".into()),
    )
}

fn swap_view_json(v: &SwapView) -> String {
    format!(
        "{{\"sid\":{},\"phase\":{},\"outcome\":{}}}",
        json_string(&v.sid),
        json_string(&v.phase),
        v.outcome.as_deref().map(json_string).unwrap_or_else(|| "null".into()),
    )
}

fn err_json(msg: &str) -> String {
    format!("{{\"error\":{}}}", json_string(msg))
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers (encode always; decode = flat string/number/bool
// fields only, which is the entire request schema)
// ---------------------------------------------------------------------------

/// Encode a string as a JSON string literal.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Extract a top-level `"key": "value"` string field. Handles the JSON
/// escapes [`json_string`] emits; anything fancier (nested objects sharing
/// the key name) is out of schema and may mis-extract — the router validates
/// every extracted value before use.
pub fn json_str_field(body: &str, key: &str) -> Option<String> {
    let value = field_value(body, key)?;
    let rest = value.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    let code = u32::from_str_radix(&hex, 16).ok()?;
                    out.push(char::from_u32(code)?);
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
}

pub fn json_u64_field(body: &str, key: &str) -> Option<u64> {
    let value = field_value(body, key)?;
    let digits: String = value.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub fn json_bool_field(body: &str, key: &str) -> Option<bool> {
    let value = field_value(body, key)?;
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// The raw text following `"key" :` (whitespace tolerated), if present.
fn field_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let mut at = 0usize;
    while let Some(pos) = body[at..].find(&needle) {
        let after = at + pos + needle.len();
        let rest = body[after..].trim_start();
        if let Some(rest) = rest.strip_prefix(':') {
            return Some(rest.trim_start());
        }
        at = after;
    }
    None
}

// ---------------------------------------------------------------------------
// HTTP framing (deliberately tiny: HTTP/1.1, Content-Length bodies only,
// Connection: close)
// ---------------------------------------------------------------------------

/// Read one request. Enforces [`MAX_REQUEST`] across start line + headers +
/// body; only `Content-Length` bodies are supported (the frontend sends
/// nothing else). The cap binds DURING reading (`Read::take`), so a client
/// streaming newline-less bytes cannot grow a line buffer without bound
/// (Fable review: an unbounded `read_line` would let any local process OOM
/// the serve worker — which may be the live refund guard).
pub fn read_request(stream: &mut impl BufRead) -> std::io::Result<(String, String, String)> {
    use std::io::{Error, ErrorKind, Read as _};
    let bad = |m: &str| Error::new(ErrorKind::InvalidData, m.to_string());
    let mut stream = stream.take(MAX_REQUEST as u64);

    let mut start = String::new();
    stream.read_line(&mut start)?;
    if start.len() > MAX_REQUEST {
        return Err(bad("request line too long"));
    }
    let mut parts = start.split_whitespace();
    let method = parts.next().ok_or_else(|| bad("missing method"))?.to_string();
    let path = parts.next().ok_or_else(|| bad("missing path"))?.to_string();

    let mut content_length = 0usize;
    let mut header_bytes = start.len();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line)?;
        header_bytes += line.len();
        if header_bytes > MAX_REQUEST {
            return Err(bad("headers too long"));
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| bad("bad content-length"))?;
            }
        }
    }
    if content_length > MAX_REQUEST {
        return Err(bad("body too long"));
    }
    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body)?;
    let body = String::from_utf8(body).map_err(|_| bad("body not utf-8"))?;
    Ok((method, path, body))
}

/// Write one JSON response and close-worthy headers (CORS for file://).
pub fn write_response(stream: &mut impl Write, code: u16, body: &str) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        428 => "Precondition Required",
        503 => "Service Unavailable",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}
