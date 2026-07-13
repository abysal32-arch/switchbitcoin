//! Bitcoin Core JSON-RPC chain backend — the first REAL [`ChainView`]
//! (feature `bitcoind`; regtest first, testnet-compatible).
//!
//! # Trust model — why this type carries the self-verifying markers
//! [`BitcoinCoreChainView`] is the operator's OWN fully-validating node,
//! reached over a trusted link (localhost / operator-controlled host). Such a
//! node validates PoW headers, all scripts and all consensus rules itself —
//! a strictly STRONGER honesty property than the BIP157/158 filter client the
//! dual-source rule names as its self-verifying example. It therefore
//! implements [`SelfVerifyingSource`] and [`AuthoritativeChainView`]: for
//! regtest the node IS the authority, `authoritative_funding_height` equals
//! `funding_height`, and `Source::self_verifying(view)` type-checks.
//! A REMOTE third-party RPC endpoint (an explorer's node, a paid API) is an
//! explorer *claim*, not a self-verifying source — do NOT wire one through
//! this type; pair it as `Source::untrusted` inside a `DualSourceChainView`.
//! A real BIP157/158 second source is rank-8/out of scope for pre-alpha.
//!
//! # Spend detection — the DECIDED design (Task 03)
//! Core keeps no "who spends outpoint X" index, so this view maintains a
//! small LAZY spend index over exactly the outpoints the wallet asks about:
//!   * `gettxout(op, include_mempool=true)`  Some ⇒ **Unspent** (nothing
//!     spends it, not even in the mempool);
//!   * `gettxout(op, false)` Some while the mempool view says spent ⇒ the
//!     spender is IN THE MEMPOOL — found by scanning `getrawmempool` +
//!     `getrawtransaction` (regtest/testnet mempools are small);
//!   * both None with a CONFIRMED funding tx ⇒ the spender is CONFIRMED —
//!     found by scanning `getblock(hash, 2)` from the funding height to the
//!     tip (bounded; runs once per outpoint, then cached).
//! Every discovered spend is cached with its full tx (for
//! [`ChainView::spending_witness_sig`] — witness first element, first 64
//! bytes, exactly SimChain's semantics) and revalidated per query against
//! `getblockheader.confirmations > 0`, so a reorged-away spend drops out of
//! the cache instead of being reported forever.
//!
//! # Node requirements
//! `txindex=1` is REQUIRED for spent-funding lookups (`getrawtransaction` of
//! an arbitrary confirmed tx); without it, reads of a still-unspent funding
//! output work via `gettxout`, and `submit_package` needs Core 26+
//! (`submitpackage`, general-purpose since PR #27609). Recommended regtest line:
//! `bitcoind -regtest -txindex=1 -rpcuser=… -rpcpassword=…` (runbook: Task 10).
//!
//! # Degraded mode (node unreachable)
//! Non-`Result` trait reads must answer something. The policy is
//! CONSERVATIVE-OR-STALE, never fabricated: `tip_height` returns the last
//! tip seen (time appears frozen ⇒ deadlines don't fire early), funding
//! reads return None/cached (gates WAIT), spend reads return the cached
//! record if any, else `Unspent` (the refund path re-polls; a broadcast
//! against a dead node fails loudly with [`Error::Rpc`]). The last transport
//! error is kept for the operator via [`BitcoinCoreChainView::last_rpc_error`].
//!
//! # Error classes
//! Node rejections with SETTLEMENT semantics map onto the SAME `Error`
//! classes SimChain uses, so driver behavior (congestion backstop, CPFP,
//! completion-supersedes) is identical against a real node:
//! fee-floor ⇒ `Deadline`, timelock immaturity ⇒ `Deadline`, conflicting /
//! already-spent inputs ⇒ `Abort`, dust ⇒ `Validation`, already-known tx ⇒
//! idempotent `Ok`. Everything else surfaces as `Error::Rpc(reason)`.

use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use serde_json::{json, Value};

use super::{AuthoritativeChainView, ChainView, SelfVerifyingSource, SpendStatus};
use crate::{Error, Result};

// ===== Transport ============================================================

/// A JSON-RPC transport failure, split so callers can tell "the node ANSWERED
/// no/with an error" (actionable) from "the node is UNREACHABLE" (degraded
/// mode — never treat as a chain fact).
#[derive(Debug, Clone)]
pub enum RpcClientError {
    /// Connection/HTTP/parse layer failed — no verdict from the node.
    Transport(String),
    /// The node answered with a JSON-RPC error object.
    Node { code: i64, message: String },
}

impl std::fmt::Display for RpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcClientError::Transport(m) => write!(f, "transport: {m}"),
            RpcClientError::Node { code, message } => write!(f, "node error {code}: {message}"),
        }
    }
}

/// Minimal JSON-RPC call seam. The ChainView logic is written against THIS,
/// so it is unit-testable against canned JSON with no node (the mock in the
/// tests below) — the HTTP client is one small impl, not the design.
pub trait RpcTransport {
    fn call(&self, method: &str, params: &[Value]) -> core::result::Result<Value, RpcClientError>;
}

/// JSON-RPC over plain HTTP/1.1 with basic auth — bitcoind's native surface.
/// Plain HTTP is CORRECT here, not a shortcut: the backend is for a LOCAL
/// operator-owned node (localhost), where TLS adds nothing; never point this
/// at a node across an untrusted network.
pub struct HttpTransport {
    agent: ureq::Agent,
    url: String,
    auth: String,
}

impl HttpTransport {
    /// `url` like `http://127.0.0.1:18443` (regtest default port 18443,
    /// testnet3 18332) with `rpcuser`/`rpcpassword` credentials.
    pub fn new(url: impl Into<String>, rpc_user: &str, rpc_password: &str) -> Self {
        use base64::Engine as _;
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("{rpc_user}:{rpc_password}"));
        HttpTransport {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(15))
                .build(),
            url: url.into(),
            auth: format!("Basic {token}"),
        }
    }

    /// Cookie auth: bitcoind writes `<datadir>/<network>/.cookie` containing
    /// `__cookie__:<random>` — exactly the basic-auth pair.
    pub fn from_cookie_file(
        url: impl Into<String>,
        cookie_path: &std::path::Path,
    ) -> core::result::Result<Self, RpcClientError> {
        let cookie = std::fs::read_to_string(cookie_path)
            .map_err(|e| RpcClientError::Transport(format!("cookie file: {e}")))?;
        let (user, pass) = cookie
            .trim()
            .split_once(':')
            .ok_or_else(|| RpcClientError::Transport("cookie file: expected user:pass".into()))?;
        Ok(Self::new(url, user, pass))
    }
}

/// Read a response body WITHOUT ureq's 10 MiB `into_string` cap: a
/// verbosity-2 `getblock` of a large (testnet) block exceeds that cap, and a
/// truncation there must not masquerade as "node unreachable" forever (it
/// would blind the confirmed-spend scan). 64 MiB comfortably covers any
/// single-block JSON (a ≤4 MB serialized block is ~10–25 MB as JSON+hex).
fn read_body(resp: ureq::Response) -> core::result::Result<String, RpcClientError> {
    use std::io::Read as _;
    const CAP: u64 = 64 * 1024 * 1024;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(CAP)
        .read_to_end(&mut buf)
        .map_err(|e| RpcClientError::Transport(format!("read response: {e}")))?;
    if buf.len() as u64 == CAP {
        return Err(RpcClientError::Transport("response exceeds the 64 MiB cap".into()));
    }
    String::from_utf8(buf)
        .map_err(|_| RpcClientError::Transport("response is not valid UTF-8".into()))
}

impl RpcTransport for HttpTransport {
    fn call(&self, method: &str, params: &[Value]) -> core::result::Result<Value, RpcClientError> {
        let body =
            json!({ "jsonrpc": "1.0", "id": "swapkey", "method": method, "params": params })
                .to_string();
        let resp = self
            .agent
            .post(&self.url)
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .send_string(&body);
        let (http_status, text) = match resp {
            Ok(r) => (200u16, read_body(r)?),
            // bitcoind reports RPC-level errors as HTTP 500/404/400 WITH a
            // JSON body — that body is the verdict, so read it, don't bail.
            Err(ureq::Error::Status(code, r)) => (code, read_body(r)?),
            Err(e) => return Err(RpcClientError::Transport(e.to_string())),
        };
        // Auth (401) / whitelist (403) failures carry NO JSON body — surface
        // the HTTP status instead of a bare parse error.
        let v: Value = serde_json::from_str(&text).map_err(|e| {
            RpcClientError::Transport(format!(
                "undecodable JSON-RPC response (http {http_status}): {e}"
            ))
        })?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(RpcClientError::Node {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err.get("message").and_then(Value::as_str).unwrap_or("").to_string(),
            });
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}

// ===== The view =============================================================

/// A spend of a watched outpoint, discovered by the lazy index. The full tx
/// is retained for witness-signature extraction (SL's extraction input).
struct SpendRecord {
    txid: Txid,
    /// `Some((height, spend-block hash))` = confirmed; `None` = mempool.
    confirmed: Option<(u32, BlockHash)>,
    tx: Transaction,
}

struct IndexState {
    spends: HashMap<OutPoint, SpendRecord>,
    /// Confirmed funding txs by txid: (tx, containing block, height) —
    /// amount/spk reads are exact from RAW bytes (never the RPC's BTC-decimal
    /// floats), and the block hash lets a reorg be detected per query.
    funding_txs: HashMap<Txid, (Transaction, BlockHash, u32)>,
    /// Last tip the node reported — the degraded-mode answer (frozen time is
    /// the conservative direction: no deadline fires early on an outage).
    last_tip: u32,
    /// Last RPC failure, for the operator (`last_rpc_error`).
    last_error: Option<String>,
}

/// [`ChainView`]/[`AuthoritativeChainView`] over a trusted local Bitcoin Core
/// node. Generic over [`RpcTransport`] so every trait method is unit-tested
/// against canned JSON; production uses [`HttpTransport`].
pub struct BitcoinCoreChainView<T: RpcTransport> {
    rpc: T,
    state: Mutex<IndexState>,
}

/// Tri-state fetch result: the node's "no" is a fact; its unreachability is
/// NOT — the two must never collapse into each other (a dropped connection
/// must not read as "unspent"/"unknown" and flush caches).
enum Fetch<V> {
    Yes(V),
    No,
    Unavailable,
}

/// Funding confirmation as this node sees it.
enum FundingConf {
    Confirmed { height: u32, blockhash: Option<BlockHash> },
    /// The funding tx itself is still in the mempool.
    InMempool,
    /// The node does not know the tx / the vout is out of range / reorged.
    Unknown,
    /// Node unreachable — no verdict.
    Unavailable,
}

fn as_u32(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok())
}

fn parse_blockhash(v: &Value) -> Option<BlockHash> {
    v.as_str()?.parse().ok()
}

fn tx_from_hex(v: &Value) -> Option<Transaction> {
    let bytes = Vec::<u8>::from_hex(v.as_str()?).ok()?;
    bitcoin::consensus::encode::deserialize(&bytes).ok()
}

/// Does this verbose-tx JSON spend `want_txid:vout`? (Coinbase vins carry no
/// "txid" — the getters just miss.)
fn vin_spends(txv: &Value, want_txid: &str, vout: u32) -> bool {
    txv.get("vin").and_then(Value::as_array).is_some_and(|vins| {
        vins.iter().any(|vin| {
            vin.get("txid").and_then(Value::as_str) == Some(want_txid)
                && vin.get("vout").and_then(Value::as_u64) == Some(u64::from(vout))
        })
    })
}

impl<T: RpcTransport> BitcoinCoreChainView<T> {
    pub fn new(rpc: T) -> Self {
        BitcoinCoreChainView {
            rpc,
            state: Mutex::new(IndexState {
                spends: HashMap::new(),
                funding_txs: HashMap::new(),
                last_tip: 0,
                last_error: None,
            }),
        }
    }

    /// The most recent RPC failure (transport or node error), for operator
    /// diagnostics — degraded-mode reads are silent by design, this is not.
    pub fn last_rpc_error(&self) -> Option<String> {
        self.state.lock().unwrap().last_error.clone()
    }

    fn call(
        &self,
        st: &mut IndexState,
        method: &str,
        params: &[Value],
    ) -> core::result::Result<Value, RpcClientError> {
        let r = self.rpc.call(method, params);
        if let Err(e) = &r {
            st.last_error = Some(format!("{method}: {e}"));
        }
        r
    }

    /// `gettxout`: Yes(txout) iff the output exists and is UNSPENT on the
    /// queried view. Null ⇒ spent-or-nonexistent (on that view) ⇒ No.
    fn fetch_txout(&self, st: &mut IndexState, op: OutPoint, include_mempool: bool) -> Fetch<Value> {
        match self.call(
            st,
            "gettxout",
            &[json!(op.txid.to_string()), json!(op.vout), json!(include_mempool)],
        ) {
            Ok(Value::Null) => Fetch::No,
            Ok(v) => Fetch::Yes(v),
            Err(_) => Fetch::Unavailable,
        }
    }

    /// Verbose `getrawtransaction` (verbosity 1 — the param is NUMERIC in
    /// Core; bools are only grandfathered). "No such transaction" (code -5)
    /// is the node's honest No; other failures are Unavailable.
    fn fetch_tx_verbose(&self, st: &mut IndexState, txid: Txid) -> Fetch<Value> {
        match self.call(st, "getrawtransaction", &[json!(txid.to_string()), json!(1)]) {
            Ok(Value::Null) => Fetch::No,
            Ok(v) => Fetch::Yes(v),
            Err(RpcClientError::Node { code: -5, .. }) => Fetch::No,
            Err(_) => Fetch::Unavailable,
        }
    }

    /// `getblockheader`: (height, in_active_chain). `confirmations == -1`
    /// means the block was reorged out of the main chain.
    fn header_info(&self, st: &mut IndexState, hash: &BlockHash) -> Fetch<(u32, bool)> {
        match self.call(st, "getblockheader", &[json!(hash.to_string())]) {
            Ok(v) => {
                let (Some(height), Some(conf)) =
                    (v.get("height").and_then(as_u32), v.get("confirmations").and_then(Value::as_i64))
                else {
                    return Fetch::Unavailable;
                };
                Fetch::Yes((height, conf > 0))
            }
            Err(RpcClientError::Node { code: -5, .. }) => Fetch::No,
            Err(_) => Fetch::Unavailable,
        }
    }

    fn tip(&self, st: &mut IndexState) -> u32 {
        match self.call(st, "getblockcount", &[]) {
            Ok(v) => {
                if let Some(h) = as_u32(&v) {
                    st.last_tip = h;
                }
                st.last_tip
            }
            Err(_) => st.last_tip,
        }
    }

    /// Verbose `getrawtransaction` WITH an explicit blockhash — works without
    /// txindex, and doubles as the tx-IS-in-this-block proof (the node answers
    /// -5 when the block does not contain the tx).
    fn fetch_tx_in_block(&self, st: &mut IndexState, txid: Txid, bh: &BlockHash) -> Fetch<Value> {
        match self.call(
            st,
            "getrawtransaction",
            &[json!(txid.to_string()), json!(1), json!(bh.to_string())],
        ) {
            Ok(Value::Null) => Fetch::No,
            Ok(v) => Fetch::Yes(v),
            Err(RpcClientError::Node { code: -5, .. }) => Fetch::No,
            Err(_) => Fetch::Unavailable,
        }
    }

    /// Funding confirmation for `op`, reorg-checked. Order of attempts:
    /// cached-and-revalidate → `gettxout` (works WITHOUT txindex while the
    /// output is unspent) → `getrawtransaction` (txindex, or mempool).
    fn funding_confirmation(&self, st: &mut IndexState, op: OutPoint) -> FundingConf {
        if let Some((nout, bh, h)) =
            st.funding_txs.get(&op.txid).map(|(t, b, h)| (t.output.len(), *b, *h))
        {
            // The cache is keyed by TXID; the queried vout must exist on the
            // cached tx (SimChain parity: a nonexistent outpoint reads None).
            if (op.vout as usize) >= nout {
                return FundingConf::Unknown;
            }
            match self.header_info(st, &bh) {
                Fetch::Yes((height, true)) => {
                    return FundingConf::Confirmed { height, blockhash: Some(bh) }
                }
                // Reorged away — forget and re-resolve from the node.
                Fetch::Yes((_, false)) | Fetch::No => {
                    st.funding_txs.remove(&op.txid);
                }
                // Stale-but-consistent beats fabricated-unconfirmed.
                Fetch::Unavailable => {
                    return FundingConf::Confirmed { height: h, blockhash: Some(bh) }
                }
            }
        }

        // Unspent path: gettxout(confirmed view) gives bestblock+confirmations,
        // from which the funding height is exact: header(bestblock).height
        // − confirmations + 1 (both from the SAME utxo-set snapshot).
        match self.fetch_txout(st, op, false) {
            Fetch::Yes(v) => {
                let bb = v.get("bestblock").and_then(parse_blockhash);
                let conf = v.get("confirmations").and_then(Value::as_u64).unwrap_or(0);
                if let (Some(bb), true) = (bb, conf >= 1) {
                    if let Fetch::Yes((hb, _)) = self.header_info(st, &bb) {
                        if let Some(hf) = (u64::from(hb) + 1)
                            .checked_sub(conf)
                            .and_then(|x| u32::try_from(x).ok())
                        {
                            // Bind the funding to its containing block ONLY
                            // with proof: getblockhash(hf) reads the CURRENT
                            // chain, so a reorg between the two reads could
                            // hand back a rival block. fetch_tx_in_block is
                            // the tx-is-in-this-block check; a hit also
                            // populates the cache so an outage later serves
                            // the STALE confirmation instead of a fabricated
                            // "unconfirmed" (degraded-mode consistency with
                            // the spend cache).
                            let bh_f = self
                                .call(st, "getblockhash", &[json!(hf)])
                                .ok()
                                .as_ref()
                                .and_then(parse_blockhash);
                            if let Some(bh_f) = bh_f {
                                return match self.fetch_tx_in_block(st, op.txid, &bh_f) {
                                    Fetch::Yes(vt) => {
                                        if let Some(tx) = vt.get("hex").and_then(tx_from_hex) {
                                            st.funding_txs.insert(op.txid, (tx, bh_f, hf));
                                        }
                                        FundingConf::Confirmed { height: hf, blockhash: Some(bh_f) }
                                    }
                                    // The block at hf does NOT contain the tx:
                                    // a reorg raced the two reads. WAIT — the
                                    // next poll reads the settled truth. Never
                                    // bind (and never cache) the wrong block.
                                    Fetch::No => FundingConf::Unknown,
                                    // No verdict on the binding: report the
                                    // snapshot-consistent height, bind nothing.
                                    Fetch::Unavailable => {
                                        FundingConf::Confirmed { height: hf, blockhash: None }
                                    }
                                };
                            }
                            return FundingConf::Confirmed { height: hf, blockhash: None };
                        }
                    }
                }
                FundingConf::Unknown
            }
            Fetch::Unavailable => FundingConf::Unavailable,
            // Spent or unconfirmed or unknown: ask for the tx itself.
            Fetch::No => match self.fetch_tx_verbose(st, op.txid) {
                Fetch::Yes(v) => {
                    let nvout =
                        v.get("vout").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
                    if (op.vout as usize) >= nvout {
                        return FundingConf::Unknown;
                    }
                    match v.get("blockhash").and_then(parse_blockhash) {
                        Some(bh) => match self.header_info(st, &bh) {
                            Fetch::Yes((height, true)) => {
                                // Cache the raw tx for exact amount/spk reads.
                                if let Some(tx) = v.get("hex").and_then(tx_from_hex) {
                                    st.funding_txs.insert(op.txid, (tx, bh, height));
                                }
                                FundingConf::Confirmed { height, blockhash: Some(bh) }
                            }
                            Fetch::Yes((_, false)) | Fetch::No => FundingConf::Unknown,
                            Fetch::Unavailable => FundingConf::Unavailable,
                        },
                        None => FundingConf::InMempool,
                    }
                }
                Fetch::No => FundingConf::Unknown,
                Fetch::Unavailable => FundingConf::Unavailable,
            },
        }
    }

    /// The CONFIRMED funding output itself, decoded from raw bytes (exact
    /// sats + spk — the encumbrance and anti-substitution inputs, never
    /// reconstructed from the RPC's BTC-decimal floats).
    fn funding_output(&self, st: &mut IndexState, op: OutPoint) -> Option<TxOut> {
        let (blockhash, height) = match self.funding_confirmation(st, op) {
            FundingConf::Confirmed { height, blockhash } => (blockhash, height),
            // Unconfirmed/unknown/unreachable: report nothing — the gate
            // WAITS (SimChain parity: only confirmed funding has amount/spk).
            _ => return None,
        };
        if let Some((tx, _, _)) = st.funding_txs.get(&op.txid) {
            return tx.output.get(op.vout as usize).cloned();
        }
        // Plain fetch works with txindex or for mempool txs; the blockhash
        // form works without txindex once we know the containing block.
        let raw = match self.call(st, "getrawtransaction", &[json!(op.txid.to_string()), json!(0)])
        {
            Ok(v) => Some(v),
            Err(_) => blockhash.and_then(|bh| {
                self.call(
                    st,
                    "getrawtransaction",
                    &[json!(op.txid.to_string()), json!(0), json!(bh.to_string())],
                )
                .ok()
            }),
        }?;
        let tx = tx_from_hex(&raw)?;
        let out = tx.output.get(op.vout as usize).cloned();
        if let Some(bh) = blockhash {
            st.funding_txs.insert(op.txid, (tx, bh, height));
        }
        out
    }

    /// Scan the mempool for the tx spending `op`. Small on regtest/testnet;
    /// runs only when `gettxout` already proved a mempool spend exists.
    fn scan_mempool_for_spend(&self, st: &mut IndexState, op: OutPoint) -> Option<(Transaction, Txid)> {
        let want = op.txid.to_string();
        let list = self.call(st, "getrawmempool", &[]).ok()?;
        for tv in list.as_array()? {
            let Some(txid) = tv.as_str().and_then(|s| s.parse::<Txid>().ok()) else { continue };
            // A tx may confirm/evict mid-scan — just skip it.
            let Ok(v) = self.call(st, "getrawtransaction", &[json!(txid.to_string()), json!(1)])
            else {
                continue;
            };
            if vin_spends(&v, &want, op.vout) {
                if let Some(tx) = v.get("hex").and_then(tx_from_hex) {
                    return Some((tx, txid));
                }
            }
        }
        None
    }

    /// Scan blocks `from..=to` for the confirmed tx spending `op`. Bounded by
    /// the funding height (nothing can spend earlier); runs once per outpoint
    /// and is then served from the cache.
    fn scan_blocks_for_spend(
        &self,
        st: &mut IndexState,
        op: OutPoint,
        from: u32,
        to: u32,
    ) -> Option<(Transaction, Txid, u32, BlockHash)> {
        let want = op.txid.to_string();
        for h in from..=to {
            let bh = parse_blockhash(&self.call(st, "getblockhash", &[json!(h)]).ok()?)?;
            let block = self.call(st, "getblock", &[json!(bh.to_string()), json!(2)]).ok()?;
            for txv in block.get("tx").and_then(Value::as_array)? {
                if !vin_spends(txv, &want, op.vout) {
                    continue;
                }
                let txid = txv.get("txid").and_then(Value::as_str)?.parse::<Txid>().ok()?;
                // Verbosity 2 carries each tx's raw hex; refetch defensively
                // if a node build omits it (blockhash form: no txindex needed).
                let tx = match txv.get("hex").and_then(tx_from_hex) {
                    Some(t) => t,
                    None => tx_from_hex(
                        &self
                            .call(
                                st,
                                "getrawtransaction",
                                &[json!(txid.to_string()), json!(0), json!(bh.to_string())],
                            )
                            .ok()?,
                    )?,
                };
                return Some((tx, txid, h, bh));
            }
        }
        None
    }

    /// The spend-status resolution described in the module docs: revalidate
    /// the cache, else classify via the two `gettxout` views, else find the
    /// spender (mempool scan / block scan) and cache it.
    fn resolve_spend(&self, st: &mut IndexState, op: OutPoint) -> SpendStatus {
        // --- 1) Cached record: revalidate cheaply instead of re-scanning ----
        if let Some((txid, confirmed)) = st.spends.get(&op).map(|r| (r.txid, r.confirmed)) {
            match confirmed {
                Some((h, bh)) => match self.header_info(st, &bh) {
                    Fetch::Yes((_, true)) => return SpendStatus::Confirmed(h),
                    // The spend's block was reorged away — re-resolve fresh.
                    Fetch::Yes((_, false)) | Fetch::No => {
                        st.spends.remove(&op);
                    }
                    // Node unreachable: stale-but-consistent.
                    Fetch::Unavailable => return SpendStatus::Confirmed(h),
                },
                None => match self.fetch_tx_verbose(st, txid) {
                    Fetch::Yes(v) => match v.get("blockhash").and_then(parse_blockhash) {
                        Some(bh) => match self.header_info(st, &bh) {
                            Fetch::Yes((h, true)) => {
                                if let Some(rec) = st.spends.get_mut(&op) {
                                    rec.confirmed = Some((h, bh));
                                }
                                return SpendStatus::Confirmed(h);
                            }
                            Fetch::Yes((_, false)) | Fetch::No => {
                                st.spends.remove(&op);
                            }
                            Fetch::Unavailable => return SpendStatus::InMempool,
                        },
                        None => return SpendStatus::InMempool,
                    },
                    // Evicted or replaced — forget it and look again.
                    Fetch::No => {
                        st.spends.remove(&op);
                    }
                    Fetch::Unavailable => return SpendStatus::InMempool,
                },
            }
        }

        // --- 2) Fresh classification via the two gettxout views -------------
        match self.fetch_txout(st, op, true) {
            Fetch::Yes(_) => return SpendStatus::Unspent,
            // Degraded: no verdict — Unspent is the conservative WAIT (the
            // drivers re-poll; nothing irreversible keys on Unspent alone).
            Fetch::Unavailable => return SpendStatus::Unspent,
            Fetch::No => {}
        }
        let confirmed_unspent = match self.fetch_txout(st, op, false) {
            Fetch::Yes(_) => true,
            Fetch::No => false,
            Fetch::Unavailable => return SpendStatus::Unspent,
        };
        if confirmed_unspent {
            // Spent on the mempool view but not the confirmed view ⇒ the
            // spender is in the mempool right now.
            if let Some((tx, txid)) = self.scan_mempool_for_spend(st, op) {
                st.spends.insert(op, SpendRecord { txid, confirmed: None, tx });
                return SpendStatus::InMempool;
            }
            // Raced (it confirmed between the two reads) — fall through to
            // the confirmed-spend path below.
        }

        // --- 3) Confirmed spend (or unknown/unconfirmed funding) ------------
        match self.funding_confirmation(st, op) {
            FundingConf::Confirmed { height: hf, .. } => {
                let tip = self.tip(st);
                if let Some((tx, txid, h, bh)) = self.scan_blocks_for_spend(st, op, hf, tip) {
                    st.spends.insert(op, SpendRecord { txid, confirmed: Some((h, bh)), tx });
                    return SpendStatus::Confirmed(h);
                }
                // Scan came up empty (mid-scan reorg/race): report Unspent
                // and let the next poll converge — never fabricate a spend.
                SpendStatus::Unspent
            }
            FundingConf::InMempool => {
                // Unconfirmed funding whose output is spent ⇒ the spender can
                // only be another mempool tx (a package child / CPFP chain).
                if let Some((tx, txid)) = self.scan_mempool_for_spend(st, op) {
                    st.spends.insert(op, SpendRecord { txid, confirmed: None, tx });
                    return SpendStatus::InMempool;
                }
                SpendStatus::Unspent
            }
            // Unknown outpoint reads Unspent — SimChain parity.
            FundingConf::Unknown | FundingConf::Unavailable => SpendStatus::Unspent,
        }
    }
}

impl<T: RpcTransport> ChainView for BitcoinCoreChainView<T> {
    fn tip_height(&self) -> u32 {
        let mut st = self.state.lock().unwrap();
        self.tip(&mut st)
    }

    fn funding_height(&self, outpoint: OutPoint) -> Option<u32> {
        let mut st = self.state.lock().unwrap();
        match self.funding_confirmation(&mut st, outpoint) {
            FundingConf::Confirmed { height, .. } => Some(height),
            _ => None,
        }
    }

    fn funding_amount(&self, outpoint: OutPoint) -> Option<u64> {
        let mut st = self.state.lock().unwrap();
        self.funding_output(&mut st, outpoint).map(|o| o.value.to_sat())
    }

    fn funding_spk(&self, outpoint: OutPoint) -> Option<ScriptBuf> {
        let mut st = self.state.lock().unwrap();
        self.funding_output(&mut st, outpoint).map(|o| o.script_pubkey)
    }

    fn spend_status(&self, escrow_outpoint: OutPoint) -> SpendStatus {
        let mut st = self.state.lock().unwrap();
        self.resolve_spend(&mut st, escrow_outpoint)
    }

    fn spend_txid(&self, outpoint: OutPoint) -> Option<Txid> {
        let mut st = self.state.lock().unwrap();
        match self.resolve_spend(&mut st, outpoint) {
            SpendStatus::Unspent => None,
            _ => st.spends.get(&outpoint).map(|r| r.txid),
        }
    }

    fn spending_witness_sig(&self, outpoint: OutPoint) -> Option<[u8; 64]> {
        let mut st = self.state.lock().unwrap();
        if matches!(self.resolve_spend(&mut st, outpoint), SpendStatus::Unspent) {
            return None;
        }
        let rec = st.spends.get(&outpoint)?;
        // SimChain semantics exactly: the input spending the outpoint, its
        // witness's FIRST element, FIRST 64 bytes (a key-path schnorr sig;
        // a 65-byte sig-with-sighash-flag still yields its first 64).
        let input = rec.tx.input.iter().find(|i| i.previous_output == outpoint)?;
        let elem = input.witness.iter().next()?;
        elem.get(..64)?.try_into().ok()
    }

    // `verified_funding_reading` and `authoritative_funding_height` keep the
    // trait defaults DELIBERATELY: a single trusted local node is its own
    // authority and never disagrees with itself (module docs, trust model).

    fn broadcast(&self, tx_bytes: &[u8]) -> Result<Txid> {
        let tx: Transaction = bitcoin::consensus::encode::deserialize(tx_bytes)
            .map_err(|_| Error::Validation("broadcast: undecodable transaction"))?;
        let txid = tx.compute_txid();
        let hex = tx_bytes.to_lower_hex_string();
        let mut st = self.state.lock().unwrap();
        match self.call(&mut st, "sendrawtransaction", &[json!(hex)]) {
            Ok(_) => Ok(txid),
            Err(RpcClientError::Node { code, message }) => map_send_error(txid, code, &message),
            Err(e @ RpcClientError::Transport(_)) => {
                Err(Error::Rpc(format!("sendrawtransaction: {e}")))
            }
        }
    }

    fn submit_package(&self, parent_bytes: &[u8], child_bytes: &[u8]) -> Result<(Txid, Txid)> {
        let parent: Transaction = bitcoin::consensus::encode::deserialize(parent_bytes)
            .map_err(|_| Error::Validation("package: undecodable parent"))?;
        let child: Transaction = bitcoin::consensus::encode::deserialize(child_bytes)
            .map_err(|_| Error::Validation("package: undecodable child"))?;
        let (pid, cid) = (parent.compute_txid(), child.compute_txid());
        let hexes = json!([parent_bytes.to_lower_hex_string(), child_bytes.to_lower_hex_string()]);
        let mut st = self.state.lock().unwrap();
        match self.call(&mut st, "submitpackage", &[hexes]) {
            Ok(v) => {
                if v.get("package_msg").and_then(Value::as_str) == Some("success") {
                    Ok((pid, cid))
                } else {
                    Err(map_package_result(&v))
                }
            }
            // submitpackage left regtest-only in Core 26 (PR #27609) — say so
            // loudly rather than silently broadcasting the parent alone.
            Err(RpcClientError::Node { code: -32601, .. }) => {
                Err(Error::Unimplemented("submitpackage requires Bitcoin Core 26+"))
            }
            Err(RpcClientError::Node { code, message }) => {
                match classify_reject(&message.to_ascii_lowercase()) {
                    Some(e) => Err(e),
                    None => Err(Error::Rpc(format!("submitpackage: node error {code}: {message}"))),
                }
            }
            Err(e @ RpcClientError::Transport(_)) => {
                Err(Error::Rpc(format!("submitpackage: {e}")))
            }
        }
    }
}

/// Fee-floor rejection classes — the `congested` signal the backstop keys on
/// (SimChain parity: these are its `Deadline` broadcasts).
fn is_fee_floor_reject(lower: &str) -> bool {
    lower.contains("min relay fee not met")
        || lower.contains("mempool min fee not met")
        || lower.contains("package-fee-too-low")
        || lower.contains("package: below min relay feerate")
}

/// Classify a node reject string onto SimChain's error CLASSES. Shared by the
/// single-tx AND package paths — the drivers (congestion backstop, CPFP,
/// completion-supersedes) key on the class, and a rejection with settlement
/// semantics must carry the same class no matter which submission path saw it.
fn classify_reject(lower: &str) -> Option<Error> {
    if is_fee_floor_reject(lower) {
        return Some(Error::Deadline("broadcast: fee below the current relay threshold"));
    }
    if lower.contains("non-bip68-final") {
        return Some(Error::Deadline("broadcast: relative timelock not matured"));
    }
    if lower.contains("non-final") {
        return Some(Error::Deadline("broadcast: transaction not final"));
    }
    if lower.contains("insufficient fee, rejecting replacement") {
        return Some(Error::Abort("broadcast: output already in mempool (fee too low to replace)"));
    }
    if lower.contains("txn-mempool-conflict") {
        return Some(Error::Abort("broadcast: conflicting spend in the mempool"));
    }
    if lower.contains("bad-txns-inputs-missingorspent") || lower.contains("missing inputs") {
        return Some(Error::Abort("broadcast: inputs missing or already spent"));
    }
    if lower.contains("dust") {
        return Some(Error::Validation("policy: dust output"));
    }
    None
}

/// Map a `sendrawtransaction` node error onto SimChain's error classes.
fn map_send_error(txid: Txid, code: i64, message: &str) -> Result<Txid> {
    let m = message.to_ascii_lowercase();
    // Idempotency (SimChain `AlreadyKnown`): a tx the chain already has is
    // success, and MUST NOT read as a failure to the retry loops.
    if code == -27 // RPC_VERIFY_ALREADY_IN_UTXO_SET (pre-28: ALREADY_IN_CHAIN)
        || m.contains("txn-already-in-mempool")
        || m.contains("txn-already-known")
        || m.contains("already in block chain")
        || m.contains("outputs already in utxo set")
    {
        return Ok(txid);
    }
    match classify_reject(&m) {
        Some(e) => Err(e),
        None => Err(Error::Rpc(format!("sendrawtransaction: node error {code}: {message}"))),
    }
}

/// Map a non-success `submitpackage` RESULT (RPC succeeded, package refused)
/// through the SAME class mapping as single-tx broadcasts — a CSV-immature
/// parent must be `Deadline` and a conflicting/spent input `Abort` on the
/// package path too (SimChain's `submit_package` routes through the same
/// physics checks as `broadcast`).
fn map_package_result(v: &Value) -> Error {
    let mut reasons: Vec<String> = Vec::new();
    if let Some(msg) = v.get("package_msg").and_then(Value::as_str) {
        reasons.push(msg.to_string());
    }
    if let Some(results) = v.get("tx-results").and_then(Value::as_object) {
        for (_, txr) in results {
            if let Some(e) = txr.get("error").and_then(Value::as_str) {
                reasons.push(e.to_string());
            }
        }
    }
    let joined = reasons.join("; ");
    match classify_reject(&joined.to_ascii_lowercase()) {
        Some(e) => e,
        None => Error::Rpc(format!("submitpackage: {joined}")),
    }
}

// ===== The self-verifying markers (see module docs, trust model) ============

/// The operator's OWN fully-validating node: validates PoW headers and every
/// consensus rule itself — strictly stronger than the BIP157/158 client the
/// dual-source rule names. Justified ONLY for a trusted local node; a remote
/// third-party endpoint must be wired as `Source::untrusted` instead.
impl<T: RpcTransport> SelfVerifyingSource for BitcoinCoreChainView<T> {}

/// Same justification: for regtest/testnet the local node IS the authority
/// (`authoritative_funding_height` == `funding_height` by the trait default).
impl<T: RpcTransport> AuthoritativeChainView for BitcoinCoreChainView<T> {}

// ===== Tests (canned JSON — no node) ========================================

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{
        absolute, transaction::Version, Amount, Sequence, TxIn, Witness,
    };
    use std::collections::VecDeque;

    // ---- mock transport ----------------------------------------------------

    /// Canned-JSON transport. Responses are keyed by `"method [params]"`
    /// (exact) with a bare-`"method"` fallback. A queue with >1 entries is
    /// consumed in order; the LAST entry is sticky (repeated polls). Any
    /// un-programmed call is a Transport error — the degraded-mode path.
    struct MockTransport {
        responses: Mutex<HashMap<String, VecDeque<core::result::Result<Value, RpcClientError>>>>,
    }

    impl MockTransport {
        fn new() -> Self {
            MockTransport { responses: Mutex::new(HashMap::new()) }
        }
        fn key(method: &str, params: &Value) -> String {
            format!("{method} {params}")
        }
        /// Program an exact-params response (push onto the queue).
        fn on(&self, method: &str, params: Value, resp: Value) {
            self.responses
                .lock()
                .unwrap()
                .entry(Self::key(method, &params))
                .or_default()
                .push_back(Ok(resp));
        }
        /// Program a method-wide response (any params).
        fn on_method(&self, method: &str, resp: Value) {
            self.responses.lock().unwrap().entry(method.to_string()).or_default().push_back(Ok(resp));
        }
        fn on_method_err(&self, method: &str, code: i64, message: &str) {
            self.responses
                .lock()
                .unwrap()
                .entry(method.to_string())
                .or_default()
                .push_back(Err(RpcClientError::Node { code, message: message.to_string() }));
        }
        /// Program an exact-params node error.
        fn on_err(&self, method: &str, params: Value, code: i64, message: &str) {
            self.responses
                .lock()
                .unwrap()
                .entry(Self::key(method, &params))
                .or_default()
                .push_back(Err(RpcClientError::Node { code, message: message.to_string() }));
        }
        /// Program an exact-params TRANSPORT failure (an outage mid-sequence).
        fn on_transport_err(&self, method: &str, params: Value) {
            self.responses
                .lock()
                .unwrap()
                .entry(Self::key(method, &params))
                .or_default()
                .push_back(Err(RpcClientError::Transport("mock: outage".into())));
        }
    }

    impl RpcTransport for MockTransport {
        fn call(&self, method: &str, params: &[Value]) -> core::result::Result<Value, RpcClientError> {
            let exact = Self::key(method, &Value::Array(params.to_vec()));
            let mut map = self.responses.lock().unwrap();
            let key = if map.get(&exact).is_some_and(|q| !q.is_empty()) {
                exact
            } else {
                method.to_string()
            };
            let q = map
                .get_mut(&key)
                .filter(|q| !q.is_empty())
                .ok_or_else(|| RpcClientError::Transport(format!("mock: unexpected call {method}")))?;
            if q.len() == 1 {
                q.front().unwrap().clone() // sticky last response
            } else {
                q.pop_front().unwrap()
            }
        }
    }

    // ---- fixtures -----------------------------------------------------------

    fn txid_n(seed: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([seed; 32]))
    }
    fn bh_n(seed: u8) -> BlockHash {
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([seed; 32]))
    }
    fn p2tr_spk(seed: u8) -> ScriptBuf {
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[seed; 32]);
        ScriptBuf::from_bytes(v)
    }

    /// A funding tx with one output of `sats` at `spk` (its own computed txid
    /// is irrelevant — the node returns it keyed by the queried txid, exactly
    /// like SimChain's `fund_with_spk` synthesis).
    fn funding_tx(sats: u64, spk: ScriptBuf) -> Transaction {
        Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut { value: Amount::from_sat(sats), script_pubkey: spk }],
        }
    }

    /// A spender of `op` whose witness's first element is `wit_first`.
    fn spender_of(op: OutPoint, wit_first: &[u8]) -> Transaction {
        let mut w = Witness::new();
        if !wit_first.is_empty() {
            w.push(wit_first);
        }
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: w,
            }],
            output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: p2tr_spk(0x77) }],
        }
    }

    fn hex_of(tx: &Transaction) -> String {
        bitcoin::consensus::encode::serialize_hex(tx)
    }

    /// Verbose-getrawtransaction-shaped JSON for a spender (mempool form: no
    /// blockhash; confirmed form: caller adds it).
    fn spender_json(tx: &Transaction, op: OutPoint) -> Value {
        json!({
            "txid": tx.compute_txid().to_string(),
            "vin": [ { "txid": op.txid.to_string(), "vout": op.vout } ],
            "hex": hex_of(tx),
        })
    }

    fn op0(seed: u8) -> OutPoint {
        OutPoint::new(txid_n(seed), 0)
    }

    // ---- reads ---------------------------------------------------------------

    #[test]
    fn tip_height_maps_getblockcount_and_survives_outage() {
        let mock = MockTransport::new();
        mock.on_method("getblockcount", json!(123));
        mock.on_method_err("getblockcount", -28, "Loading block index...");
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.tip_height(), 123);
        // Node stops answering: the LAST KNOWN tip is served — frozen time is
        // the conservative direction (no deadline fires early on an outage).
        assert_eq!(view.tip_height(), 123);
        assert!(view.last_rpc_error().is_some());
    }

    #[test]
    fn degraded_transport_is_conservative_everywhere() {
        // No fixtures at all: every call is a transport failure.
        let view = BitcoinCoreChainView::new(MockTransport::new());
        let op = op0(1);
        assert_eq!(view.tip_height(), 0, "no tip ever seen -> frozen at 0");
        assert_eq!(view.funding_height(op), None);
        assert_eq!(view.funding_amount(op), None);
        assert_eq!(view.funding_spk(op), None);
        assert_eq!(view.spend_status(op), SpendStatus::Unspent);
        assert_eq!(view.spend_txid(op), None);
        assert_eq!(view.spending_witness_sig(op), None);
        assert!(matches!(view.broadcast(&[0u8; 4]), Err(Error::Validation(_))));
        let tx = funding_tx(1_000, p2tr_spk(1));
        let bytes = bitcoin::consensus::encode::serialize(&tx);
        assert!(matches!(view.broadcast(&bytes), Err(Error::Rpc(_))));
        assert!(view.last_rpc_error().is_some(), "the outage is visible to the operator");
    }

    #[test]
    fn funding_height_via_utxo_read_is_exact() {
        // gettxout(confirmed view): 21 confirmations at bestblock height 120
        // -> funding height 100 (120 - 21 + 1), then the tx-in-block proof
        // binds (and caches) the funding to its actual block.
        let op = op0(2);
        let ftx = funding_tx(100_000, p2tr_spk(2));
        let mock = MockTransport::new();
        mock.on(
            "gettxout",
            json!([op.txid.to_string(), 0, false]),
            json!({ "bestblock": bh_n(0xBB).to_string(), "confirmations": 21, "value": 0.001 }),
        );
        mock.on(
            "getblockheader",
            json!([bh_n(0xBB).to_string()]),
            json!({ "height": 120, "confirmations": 1 }),
        );
        mock.on("getblockhash", json!([100]), json!(bh_n(100).to_string()));
        mock.on(
            "getrawtransaction",
            json!([op.txid.to_string(), 1, bh_n(100).to_string()]),
            json!({ "vout": [ {} ], "blockhash": bh_n(100).to_string(), "hex": hex_of(&ftx) }),
        );
        mock.on(
            "getblockheader",
            json!([bh_n(100).to_string()]),
            json!({ "height": 100, "confirmations": 21 }),
        );
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.funding_height(op), Some(100));
        // The single-source authoritative read is the same read (cached now).
        assert_eq!(view.authoritative_funding_height(op), Some(100));
    }

    /// The HIGH review finding: `getblockhash(height)` reads the CURRENT
    /// chain, so a reorg between the utxo read and the block lookup can hand
    /// back a RIVAL block. The tx-in-block proof must fail closed — Unknown
    /// (wait for the next poll), never a confirmation bound to a wrong block
    /// that the cache would then revalidate forever.
    #[test]
    fn funding_binding_race_reads_unknown_not_wrong_block() {
        let op = op0(12);
        let mock = MockTransport::new();
        mock.on(
            "gettxout",
            json!([op.txid.to_string(), 0, false]),
            json!({ "bestblock": bh_n(0xBB).to_string(), "confirmations": 1 }),
        );
        mock.on(
            "getblockheader",
            json!([bh_n(0xBB).to_string()]),
            json!({ "height": 100, "confirmations": 1 }),
        );
        // The rival branch's block at the computed height…
        mock.on("getblockhash", json!([100]), json!(bh_n(0xEE).to_string()));
        // …which does NOT contain the funding tx.
        mock.on_err(
            "getrawtransaction",
            json!([op.txid.to_string(), 1, bh_n(0xEE).to_string()]),
            -5,
            "No such transaction found in the provided block",
        );
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.funding_height(op), None, "a reorg-raced funding must read as WAIT");
    }

    /// Degraded-mode consistency (review finding): once a funding
    /// confirmation has been read while healthy it is CACHED, so an outage
    /// serves the STALE confirmation — same policy as the spend cache —
    /// instead of flipping to a fabricated "unconfirmed" while spend reads
    /// stay Confirmed (the inconsistent pair that mis-fired reserve healing).
    #[test]
    fn outage_serves_stale_funding_confirmation_once_cached() {
        let op = op0(13);
        let ftx = funding_tx(70_000, p2tr_spk(13));
        let mock = MockTransport::new();
        mock.on(
            "gettxout",
            json!([op.txid.to_string(), 0, false]),
            json!({ "bestblock": bh_n(0xBB).to_string(), "confirmations": 3 }),
        );
        mock.on(
            "getblockheader",
            json!([bh_n(0xBB).to_string()]),
            json!({ "height": 102, "confirmations": 1 }),
        );
        mock.on("getblockhash", json!([100]), json!(bh_n(100).to_string()));
        mock.on(
            "getrawtransaction",
            json!([op.txid.to_string(), 1, bh_n(100).to_string()]),
            json!({ "vout": [ {} ], "blockhash": bh_n(100).to_string(), "hex": hex_of(&ftx) }),
        );
        // The outage: revalidation of the cached confirmation gets no verdict.
        mock.on_transport_err("getblockheader", json!([bh_n(100).to_string()]));
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.funding_height(op), Some(100), "healthy read populates the cache");
        assert_eq!(view.funding_height(op), Some(100), "outage serves the stale confirmation");
        // The cache is keyed by txid — a vout the cached tx does not have
        // must keep reading unconfirmed (SimChain parity), not inherit the
        // sibling's confirmation.
        let foreign = OutPoint::new(op.txid, 7);
        assert_eq!(view.funding_height(foreign), None);
        assert_eq!(view.funding_amount(foreign), None);
    }

    #[test]
    fn funding_amount_and_spk_are_exact_from_raw_tx() {
        // Amount/spk come from RAW tx bytes — never the RPC's BTC float.
        let op = op0(3);
        let spk = p2tr_spk(0x42);
        let ftx = funding_tx(123_456, spk.clone());
        let mock = MockTransport::new();
        mock.on(
            "gettxout",
            json!([op.txid.to_string(), 0, false]),
            json!({ "bestblock": bh_n(0xBB).to_string(), "confirmations": 5 }),
        );
        mock.on(
            "getblockheader",
            json!([bh_n(0xBB).to_string()]),
            json!({ "height": 104, "confirmations": 1 }),
        );
        mock.on("getblockhash", json!([100]), json!(bh_n(100).to_string()));
        // The tx-in-block proof supplies the raw hex — amount/spk are decoded
        // from BYTES, and the tx is cached under (tx, block, height).
        mock.on(
            "getrawtransaction",
            json!([op.txid.to_string(), 1, bh_n(100).to_string()]),
            json!({ "vout": [ {} ], "blockhash": bh_n(100).to_string(), "hex": hex_of(&ftx) }),
        );
        mock.on(
            "getblockheader",
            json!([bh_n(100).to_string()]),
            json!({ "height": 100, "confirmations": 5 }),
        );
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.funding_amount(op), Some(123_456));
        assert_eq!(view.funding_spk(op), Some(spk));
        // Cached path (header revalidation only) still answers.
        assert_eq!(view.funding_amount(op), Some(123_456));
        // The default single-source reading composes height + amount.
        match view.verified_funding_reading(op) {
            super::super::FundingReading::Confirmed { height, amount } => {
                assert_eq!(height, 100);
                assert_eq!(amount, Some(123_456));
            }
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    #[test]
    fn unknown_outpoint_reads_unspent_and_unconfirmed() {
        let op = op0(4);
        let mock = MockTransport::new();
        mock.on("gettxout", json!([op.txid.to_string(), 0, false]), Value::Null);
        mock.on("gettxout", json!([op.txid.to_string(), 0, true]), Value::Null);
        mock.on_method_err("getrawtransaction", -5, "No such mempool or blockchain transaction");
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.funding_height(op), None);
        assert_eq!(view.spend_status(op), SpendStatus::Unspent, "SimChain parity");
        assert_eq!(view.spend_txid(op), None);
    }

    #[test]
    fn unspent_via_mempool_view_gettxout() {
        let op = op0(5);
        let mock = MockTransport::new();
        mock.on("gettxout", json!([op.txid.to_string(), 0, true]), json!({ "confirmations": 3 }));
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.spend_status(op), SpendStatus::Unspent);
    }

    #[test]
    fn mempool_spend_is_detected_with_txid_and_witness() {
        let op = op0(6);
        let sig = [0x42u8; 64];
        let sp = spender_of(op, &sig);
        let sp_txid = sp.compute_txid();
        let mock = MockTransport::new();
        mock.on("gettxout", json!([op.txid.to_string(), 0, true]), Value::Null);
        mock.on(
            "gettxout",
            json!([op.txid.to_string(), 0, false]),
            json!({ "bestblock": bh_n(0xBB).to_string(), "confirmations": 2 }),
        );
        mock.on_method("getrawmempool", json!([sp_txid.to_string()]));
        mock.on("getrawtransaction", json!([sp_txid.to_string(), 1]), spender_json(&sp, op));
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.spend_status(op), SpendStatus::InMempool);
        assert_eq!(view.spend_txid(op), Some(sp_txid));
        assert_eq!(view.spending_witness_sig(op), Some(sig), "mempool-first reveal observation");
    }

    #[test]
    fn mempool_spend_transitions_to_confirmed() {
        let op = op0(7);
        let sp = spender_of(op, &[0x24u8; 64]);
        let sp_txid = sp.compute_txid();
        let mock = MockTransport::new();
        mock.on("gettxout", json!([op.txid.to_string(), 0, true]), Value::Null);
        mock.on(
            "gettxout",
            json!([op.txid.to_string(), 0, false]),
            json!({ "bestblock": bh_n(0xBB).to_string(), "confirmations": 2 }),
        );
        mock.on_method("getrawmempool", json!([sp_txid.to_string()]));
        // 1st verbose read: in the mempool; 2nd (cache revalidation): mined
        // into block bh_n(9) at height 103.
        mock.on("getrawtransaction", json!([sp_txid.to_string(), 1]), spender_json(&sp, op));
        let mut confirmed = spender_json(&sp, op);
        confirmed["blockhash"] = json!(bh_n(9).to_string());
        mock.on("getrawtransaction", json!([sp_txid.to_string(), 1]), confirmed);
        mock.on(
            "getblockheader",
            json!([bh_n(9).to_string()]),
            json!({ "height": 103, "confirmations": 1 }),
        );
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.spend_status(op), SpendStatus::InMempool);
        assert_eq!(view.spend_status(op), SpendStatus::Confirmed(103));
        // Sticky: stays confirmed on further polls (header keeps agreeing).
        assert_eq!(view.spend_status(op), SpendStatus::Confirmed(103));
    }

    /// The block-scan indexer: both gettxout views say gone, the funding tx
    /// is confirmed at 100, the spender sits in block 103 — found, cached,
    /// witness extracted; height/txid exact.
    #[test]
    fn confirmed_spend_found_by_block_scan() {
        let op = op0(8);
        let sig = [0x99u8; 64];
        let sp = spender_of(op, &sig);
        let sp_txid = sp.compute_txid();
        let ftx = funding_tx(50_000, p2tr_spk(8));
        let mock = MockTransport::new();
        mock.on("gettxout", json!([op.txid.to_string(), 0, true]), Value::Null);
        mock.on("gettxout", json!([op.txid.to_string(), 0, false]), Value::Null);
        // Funding tx: confirmed in block bh_n(100) at height 100 (txindex).
        mock.on(
            "getrawtransaction",
            json!([op.txid.to_string(), 1]),
            json!({
                "vout": [ {} ],
                "blockhash": bh_n(100).to_string(),
                "hex": hex_of(&ftx),
            }),
        );
        mock.on(
            "getblockheader",
            json!([bh_n(100).to_string()]),
            json!({ "height": 100, "confirmations": 6 }),
        );
        mock.on_method("getblockcount", json!(105));
        for h in 100u8..=103 {
            mock.on("getblockhash", json!([u32::from(h)]), json!(bh_n(h).to_string()));
        }
        for h in 100u8..=102 {
            mock.on("getblock", json!([bh_n(h).to_string(), 2]), json!({ "tx": [] }));
        }
        mock.on(
            "getblock",
            json!([bh_n(103).to_string(), 2]),
            json!({ "tx": [ spender_json(&sp, op) ] }),
        );
        // Cache revalidation for later polls.
        mock.on(
            "getblockheader",
            json!([bh_n(103).to_string()]),
            json!({ "height": 103, "confirmations": 3 }),
        );
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.spend_status(op), SpendStatus::Confirmed(103));
        assert_eq!(view.spend_txid(op), Some(sp_txid));
        assert_eq!(view.spending_witness_sig(op), Some(sig));
        // Served from cache afterwards (header check only — programmed above).
        assert_eq!(view.spend_status(op), SpendStatus::Confirmed(103));
    }

    /// Reorg: a cached CONFIRMED spend whose block leaves the main chain is
    /// dropped and re-resolved — here the output is unspent again.
    #[test]
    fn reorged_spend_cache_is_dropped_and_rereads() {
        let op = op0(9);
        let sp = spender_of(op, &[0x11u8; 64]);
        let ftx = funding_tx(50_000, p2tr_spk(9));
        let mock = MockTransport::new();
        // First resolve: confirmed spend in block 101 (scan 100..=101).
        mock.on("gettxout", json!([op.txid.to_string(), 0, true]), Value::Null);
        mock.on("gettxout", json!([op.txid.to_string(), 0, false]), Value::Null);
        mock.on(
            "getrawtransaction",
            json!([op.txid.to_string(), 1]),
            json!({ "vout": [ {} ], "blockhash": bh_n(100).to_string(), "hex": hex_of(&ftx) }),
        );
        mock.on(
            "getblockheader",
            json!([bh_n(100).to_string()]),
            json!({ "height": 100, "confirmations": 2 }),
        );
        mock.on_method("getblockcount", json!(101));
        mock.on("getblockhash", json!([100]), json!(bh_n(100).to_string()));
        mock.on("getblockhash", json!([101]), json!(bh_n(101).to_string()));
        mock.on("getblock", json!([bh_n(100).to_string(), 2]), json!({ "tx": [] }));
        mock.on(
            "getblock",
            json!([bh_n(101).to_string(), 2]),
            json!({ "tx": [ spender_json(&sp, op) ] }),
        );
        // Revalidation: the spend block got REORGED OUT (confirmations -1)...
        mock.on(
            "getblockheader",
            json!([bh_n(101).to_string()]),
            json!({ "height": 101, "confirmations": -1 }),
        );
        // ...and the fresh re-resolve now finds the output UNSPENT.
        mock.on("gettxout", json!([op.txid.to_string(), 0, true]), json!({ "confirmations": 0 }));
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.spend_status(op), SpendStatus::Confirmed(101));
        assert_eq!(
            view.spend_status(op),
            SpendStatus::Unspent,
            "a reorged-away spend must not be reported forever"
        );
    }

    #[test]
    fn witness_sig_takes_first_64_of_longer_element_and_none_when_short() {
        // 65-byte element (sig + sighash flag): first 64 returned — exactly
        // SimChain's `get(..64)` semantics the extraction path depends on.
        let op = op0(10);
        let mut sig65 = vec![0xABu8; 64];
        sig65.push(0x01);
        let sp = spender_of(op, &sig65);
        let sp_txid = sp.compute_txid();
        let mock = MockTransport::new();
        mock.on("gettxout", json!([op.txid.to_string(), 0, true]), Value::Null);
        mock.on(
            "gettxout",
            json!([op.txid.to_string(), 0, false]),
            json!({ "bestblock": bh_n(0xBB).to_string(), "confirmations": 1 }),
        );
        mock.on_method("getrawmempool", json!([sp_txid.to_string()]));
        mock.on("getrawtransaction", json!([sp_txid.to_string(), 1]), spender_json(&sp, op));
        let view = BitcoinCoreChainView::new(mock);
        assert_eq!(view.spending_witness_sig(op), Some([0xABu8; 64]));

        // A short (script-path-ish) first element yields None.
        let op2 = op0(11);
        let sp2 = spender_of(op2, &[0x01, 0x02, 0x03]);
        let sp2_txid = sp2.compute_txid();
        let mock2 = MockTransport::new();
        mock2.on("gettxout", json!([op2.txid.to_string(), 0, true]), Value::Null);
        mock2.on(
            "gettxout",
            json!([op2.txid.to_string(), 0, false]),
            json!({ "bestblock": bh_n(0xBB).to_string(), "confirmations": 1 }),
        );
        mock2.on_method("getrawmempool", json!([sp2_txid.to_string()]));
        mock2.on("getrawtransaction", json!([sp2_txid.to_string(), 1]), spender_json(&sp2, op2));
        let view2 = BitcoinCoreChainView::new(mock2);
        assert_eq!(view2.spend_status(op2), SpendStatus::InMempool);
        assert_eq!(view2.spending_witness_sig(op2), None);
    }

    // ---- broadcast / package -------------------------------------------------

    #[test]
    fn broadcast_ok_and_idempotent_on_already_known() {
        let tx = funding_tx(1_000, p2tr_spk(1));
        let bytes = bitcoin::consensus::encode::serialize(&tx);
        let txid = tx.compute_txid();

        let mock = MockTransport::new();
        mock.on_method("sendrawtransaction", json!(txid.to_string()));
        assert_eq!(BitcoinCoreChainView::new(mock).broadcast(&bytes).unwrap(), txid);

        for (code, msg) in [
            (-27, "Transaction already in block chain"),
            (-27, "Transaction outputs already in utxo set"),
            (-26, "txn-already-in-mempool"),
            (-26, "txn-already-known"),
        ] {
            let mock = MockTransport::new();
            mock.on_method_err("sendrawtransaction", code, msg);
            assert_eq!(
                BitcoinCoreChainView::new(mock).broadcast(&bytes).unwrap(),
                txid,
                "already-known must be idempotent success ({msg})"
            );
        }
    }

    #[test]
    fn broadcast_errors_map_to_simchain_classes() {
        let tx = funding_tx(1_000, p2tr_spk(1));
        let bytes = bitcoin::consensus::encode::serialize(&tx);
        type Check = fn(&Error) -> bool;
        let cases: [(i64, &str, Check); 6] = [
            (-26, "min relay fee not met", |e| matches!(e, Error::Deadline(_))),
            (-26, "mempool min fee not met", |e| matches!(e, Error::Deadline(_))),
            (-26, "non-BIP68-final", |e| matches!(e, Error::Deadline(_))),
            (-26, "insufficient fee, rejecting replacement abc", |e| matches!(e, Error::Abort(_))),
            (-25, "bad-txns-inputs-missingorspent", |e| matches!(e, Error::Abort(_))),
            (-26, "dust", |e| matches!(e, Error::Validation(_))),
        ];
        for (code, msg, check) in cases {
            let mock = MockTransport::new();
            mock.on_method_err("sendrawtransaction", code, msg);
            let err = BitcoinCoreChainView::new(mock).broadcast(&bytes).unwrap_err();
            assert!(check(&err), "{msg} mapped to {err:?}");
        }
        // Unclassified rejections keep the node's words for the operator.
        let mock = MockTransport::new();
        mock.on_method_err("sendrawtransaction", -26, "scriptpubkey");
        match BitcoinCoreChainView::new(mock).broadcast(&bytes).unwrap_err() {
            Error::Rpc(m) => assert!(m.contains("scriptpubkey")),
            other => panic!("expected Rpc, got {other:?}"),
        }
    }

    #[test]
    fn submit_package_success_and_failures() {
        let parent = funding_tx(2_000, p2tr_spk(2));
        let child = funding_tx(1_000, p2tr_spk(3));
        let (pb, cb) = (
            bitcoin::consensus::encode::serialize(&parent),
            bitcoin::consensus::encode::serialize(&child),
        );
        let (pid, cid) = (parent.compute_txid(), child.compute_txid());

        let mock = MockTransport::new();
        mock.on_method("submitpackage", json!({ "package_msg": "success", "tx-results": {} }));
        assert_eq!(
            BitcoinCoreChainView::new(mock).submit_package(&pb, &cb).unwrap(),
            (pid, cid)
        );

        // Old node: no submitpackage — loud, not a silent parent broadcast.
        let mock = MockTransport::new();
        mock.on_method_err("submitpackage", -32601, "Method not found");
        assert!(matches!(
            BitcoinCoreChainView::new(mock).submit_package(&pb, &cb),
            Err(Error::Unimplemented(_))
        ));

        // Package fee failure classifies as the congestion Deadline.
        let mock = MockTransport::new();
        mock.on_method(
            "submitpackage",
            json!({
                "package_msg": "transaction failed",
                "tx-results": { "aa": { "error": "mempool min fee not met" } }
            }),
        );
        assert!(matches!(
            BitcoinCoreChainView::new(mock).submit_package(&pb, &cb),
            Err(Error::Deadline(_))
        ));

        // Package rejections with settlement semantics carry the SAME classes
        // as single-tx broadcasts (review finding — SimChain's package path
        // routes through the same physics): CSV immaturity ⇒ Deadline,
        // conflicting/spent inputs ⇒ Abort.
        type Check = fn(&Error) -> bool;
        let class_cases: [(&str, Check); 3] = [
            ("non-BIP68-final", |e| matches!(e, Error::Deadline(_))),
            ("txn-mempool-conflict", |e| matches!(e, Error::Abort(_))),
            ("bad-txns-inputs-missingorspent", |e| matches!(e, Error::Abort(_))),
        ];
        for (err, check) in class_cases {
            let mock = MockTransport::new();
            mock.on_method(
                "submitpackage",
                json!({
                    "package_msg": "transaction failed",
                    "tx-results": { "aa": { "error": err } }
                }),
            );
            let e = BitcoinCoreChainView::new(mock).submit_package(&pb, &cb).unwrap_err();
            assert!(check(&e), "package error {err} mapped to {e:?}");
        }

        // Other package failures surface the node's words.
        let mock = MockTransport::new();
        mock.on_method(
            "submitpackage",
            json!({
                "package_msg": "transaction failed",
                "tx-results": { "aa": { "error": "package-not-child-with-parents" } }
            }),
        );
        assert!(matches!(
            BitcoinCoreChainView::new(mock).submit_package(&pb, &cb),
            Err(Error::Rpc(_))
        ));
    }

    // ---- type-level: markers + dual-source composition ------------------------

    #[test]
    fn usable_as_authoritative_self_verifying_and_in_dual_source() {
        fn takes_authoritative(_c: &impl AuthoritativeChainView) {}
        let view = BitcoinCoreChainView::new(MockTransport::new());
        takes_authoritative(&view);

        // The whole point of the markers: this composes as the SELF-VERIFYING
        // half of a dual view (an explorer client could not — compile error).
        let sv = super::super::Source::self_verifying(BitcoinCoreChainView::new(MockTransport::new()));
        let untrusted = super::super::Source::untrusted(super::super::SimChain::new(0));
        let dual = super::super::DualSourceChainView::new(sv, untrusted).unwrap();
        takes_authoritative(&dual);
    }

    // ---- live (manual) ---------------------------------------------------------

    /// Live smoke test against a LOCAL regtest node — run manually:
    /// ```text
    /// bitcoind -regtest -txindex=1 -rpcuser=swapkey -rpcpassword=swapkey
    /// bitcoin-cli -regtest -rpcuser=swapkey -rpcpassword=swapkey createwallet w1
    /// bitcoin-cli -regtest -rpcuser=swapkey -rpcpassword=swapkey -generate 101
    /// BITCOIND_RPC_URL=http://127.0.0.1:18443 \
    /// BITCOIND_RPC_USER=swapkey BITCOIND_RPC_PASS=swapkey \
    ///   cargo test --features bitcoind -- --ignored live_regtest_smoke
    /// ```
    /// (Cookie auth: set `BITCOIND_RPC_COOKIE=<datadir>/regtest/.cookie`
    /// instead of USER/PASS.) The full swap runbook lands in Task 10.
    #[test]
    #[ignore = "needs a local bitcoind -regtest (see doc comment for the runbook)"]
    fn live_regtest_smoke() {
        let url = std::env::var("BITCOIND_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:18443".to_string());
        let transport = match (std::env::var("BITCOIND_RPC_USER"), std::env::var("BITCOIND_RPC_PASS"))
        {
            (Ok(u), Ok(p)) => HttpTransport::new(url, &u, &p),
            _ => {
                let cookie = std::env::var("BITCOIND_RPC_COOKIE")
                    .expect("set BITCOIND_RPC_USER/BITCOIND_RPC_PASS or BITCOIND_RPC_COOKIE");
                HttpTransport::from_cookie_file(url, std::path::Path::new(&cookie))
                    .expect("readable cookie file")
            }
        };
        let view = BitcoinCoreChainView::new(transport);
        let tip = view.tip_height();
        assert!(tip > 0, "expected a regtest chain with mined blocks, got tip {tip} (mine 101 first)");
        assert!(view.last_rpc_error().is_none(), "clean run: {:?}", view.last_rpc_error());
    }
}
