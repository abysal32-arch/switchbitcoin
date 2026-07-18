//! Wallet configuration (Task 07): ONE validated config for the runnable
//! wallet — data dir, network, node RPC credentials, peer transport
//! addresses — loaded from `switchbitcoin.toml` plus `SWITCHBITCOIN_*`
//! environment overrides (env wins over file). The pre-rebrand names —
//! `swapkey.toml` and `SWAPKEY_*` — remain accepted as LEGACY fallbacks
//! (Task 31: the live testnet fleet predates the rename); when both
//! namespaces set the same key, `SWITCHBITCOIN_*` wins.
//!
//! FORMAT: a deliberately tiny TOML subset, hand-parsed so the config path
//! adds no dependency (the config file is the wallet's outermost input
//! surface — a full TOML grammar is far more parser than eight string keys
//! need):
//!   * `key = "value"` pairs — every value is a STRING, double-quoted
//!     (with `\\ \" \n \r \t` escapes) or single-quoted (literal, no
//!     escapes — the friendly form for Windows paths);
//!   * `[node]` / `[peer]` section headers;
//!   * `#` comments (whole-line or after a value); blank lines ignored;
//!     a leading UTF-8 BOM is tolerated (PowerShell writes one);
//!   * unknown keys/sections and duplicate keys are ERRORS (typo safety —
//!     a silently ignored `rpc_passwrod` would strand the node offline).
//!     [`WalletConfig::load`] applies the same strictness to the env side:
//!     unknown `SWITCHBITCOIN_*` variables are refused — and so are unknown
//!     `SWAPKEY_*` variables, because the legacy namespace is still consulted
//!     (a silently ignored legacy typo would strand the node exactly the way
//!     a file typo would). A set-but-EMPTY variable counts as unset (shells
//!     "clear" variables that way), so an empty override can never shadow a
//!     valid file value.
//!
//! SECRET HYGIENE: the RPC password lives in a [`Secret`] — redacted
//! `Debug`, no `Display`, zeroized on drop; the raw file text and parsed
//! values are scrubbed after loading too. Parse and validation errors name
//! keys and line numbers, NEVER values, and `rpc_url` may not embed
//! userinfo credentials (they would sit outside the `Secret` wrapper).
//! Prefer `SWITCHBITCOIN_RPC_PASSWORD` (or bitcoind cookie auth) over
//! writing the password into the file at all. Residual (documented, pre-alpha threat
//! model): the process environment block itself, and OS paging, are not
//! scrubbable from here.
//!
//! PARAMS ARE NOT CONFIG: [`WalletConfig::params`] carries the compiled
//! provisional defaults and the file deliberately cannot override them —
//! settlement parameters arrive on the SIGNED MANIFEST trust path
//! (`wallet::manifest`), not as free-form wallet settings (see
//! `settlement::params`' header). After open, the manifest store is
//! authoritative: [`crate::wallet::runtime::Wallet::params`].

use crate::settlement::params::Params;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Conventional config file name. The file lives wherever the runner is
/// pointed (it CONTAINS `data_dir`); it need not be inside the data dir.
pub const CONFIG_FILE: &str = "switchbitcoin.toml";

/// The pre-rebrand config file name (Task 31). The binaries' default-path
/// resolution still falls back to it (with a deprecation log line) so the
/// live testnet fleet's existing configs keep working; loading it by
/// explicit `--config` path was never name-sensitive.
pub const LEGACY_CONFIG_FILE: &str = "swapkey.toml";

/// Config loading/validation error. Its own type (not [`crate::Error`])
/// because config diagnostics need dynamic context — key names and line
/// numbers; never values — and the crate error deliberately carries only
/// static strings.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config io: {0}")]
    Io(String),
    #[error("config parse: {0}")]
    Parse(String),
    #[error("config invalid: {0}")]
    Invalid(String),
}

/// Pre-alpha networks. Mainnet has NO variant — refusing real funds until
/// the external cryptographer review is structural, not a runtime check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Regtest,
    Testnet,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Regtest => "regtest",
            Network::Testnet => "testnet",
        }
    }

    /// bitcoind's default JSON-RPC port for this network.
    pub fn default_rpc_port(self) -> u16 {
        match self {
            Network::Regtest => 18443,
            Network::Testnet => 18332,
        }
    }

    pub fn to_bitcoin(self) -> bitcoin::Network {
        match self {
            Network::Regtest => bitcoin::Network::Regtest,
            Network::Testnet => bitcoin::Network::Testnet,
        }
    }

    fn parse(s: &str) -> Result<Network, ConfigError> {
        match s {
            "regtest" => Ok(Network::Regtest),
            "testnet" => Ok(Network::Testnet),
            "bitcoin" | "mainnet" | "main" => Err(ConfigError::Invalid(
                "network: mainnet is refused pre-alpha (no real funds until the external cryptographer review)"
                    .into(),
            )),
            _ => Err(ConfigError::Invalid(
                "network: unknown value (expected \"regtest\" or \"testnet\")".into(),
            )),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A secret string that can never reach a log line: `Debug` prints
/// `<redacted>`, there is no `Display`, and the contents are zeroized on
/// drop. Reading the value is an explicit, greppable [`Secret::expose`].
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(s.into())
    }
    /// Deliberately loud accessor — every use site is a review point.
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// How to authenticate to the node's JSON-RPC endpoint.
#[derive(Clone, Debug)]
pub enum RpcAuth {
    /// `rpcuser`/`rpcpassword` basic auth.
    UserPass { user: String, password: Secret },
    /// bitcoind cookie auth: the `<datadir>/<network>/.cookie` file (read at
    /// connection time, so a node restart's fresh cookie is picked up by a
    /// reconnect, not a config edit).
    CookieFile(PathBuf),
}

/// The Task-03 chain backend's connection config (feature `bitcoind`
/// consumes it; the fields parse and validate regardless so one config file
/// serves both build flavors).
#[derive(Clone, Debug)]
pub struct NodeRpcConfig {
    /// `http://127.0.0.1:18443`-style URL (LOCAL node — see
    /// `chain::bitcoind`'s plain-HTTP rationale).
    pub url: String,
    pub auth: RpcAuth,
}

#[cfg(feature = "bitcoind")]
impl NodeRpcConfig {
    /// Build the Task-03 chain backend from this config. The runner keeps the
    /// returned view for its whole poll loop (startup, `poll`, backstop).
    pub fn chain_view(
        &self,
    ) -> crate::Result<crate::chain::BitcoinCoreChainView<crate::chain::HttpTransport>> {
        use crate::chain::HttpTransport;
        let rpc = match &self.auth {
            RpcAuth::UserPass { user, password } => {
                HttpTransport::new(self.url.clone(), user, password.expose())
            }
            RpcAuth::CookieFile(path) => HttpTransport::from_cookie_file(self.url.clone(), path)
                .map_err(|e| crate::Error::Rpc(e.to_string()))?,
        };
        Ok(crate::chain::BitcoinCoreChainView::new(rpc))
    }
}

/// Task-04 peer transport addresses. Both optional: a wallet may only ever
/// dial out, only listen, or (offline reconcile/recover runs) neither.
#[derive(Clone, Debug, Default)]
pub struct PeerConfig {
    /// `host:port` to bind for inbound swap peers.
    pub listen: Option<String>,
    /// `host:port` of the counterparty to dial.
    pub connect: Option<String>,
}

/// The wallet's single validated configuration — everything
/// [`crate::wallet::runtime::Wallet::open`] and the Task-08 runner need.
#[derive(Clone, Debug)]
pub struct WalletConfig {
    /// The wallet data directory (stores, keystore, locks — layout documented
    /// in `wallet::runtime`).
    pub data_dir: PathBuf,
    pub network: Network,
    /// Chain backend connection; `None` = no node configured (the wallet
    /// still opens — step 1 of startup is deliberately chain-blind).
    pub node: Option<NodeRpcConfig>,
    pub peer: PeerConfig,
    /// The compiled provisional parameter table — the manifest BASELINE, not
    /// a user setting (see the module docs). Post-open, read params from the
    /// manifest store instead.
    pub params: Params,
}

impl WalletConfig {
    /// Minimal in-code construction (tests, embedding): provisional params,
    /// no node, no peers.
    pub fn new(data_dir: impl Into<PathBuf>, network: Network) -> WalletConfig {
        WalletConfig {
            data_dir: data_dir.into(),
            network,
            node: None,
            peer: PeerConfig::default(),
            params: Params::testnet_provisional(),
        }
    }

    /// Load `path` and apply `SWITCHBITCOIN_*` environment overrides (legacy
    /// `SWAPKEY_*` still consulted; the new namespace wins per key), then
    /// validate. See the module docs for the file format and key set.
    /// Both env namespaces get the same typo strictness as the file: an
    /// unknown `SWITCHBITCOIN_*` or `SWAPKEY_*` variable in the process
    /// environment is an error (a silently ignored
    /// `SWITCHBITCOIN_RPC_PASSWROD` would strand the node on a stale
    /// credential — the exact failure the file parser's strictness exists
    /// to prevent).
    pub fn load(path: &Path) -> Result<WalletConfig, ConfigError> {
        reject_unknown_namespace_vars(std::env::vars().map(|(name, _)| name))?;
        Self::load_with_env(path, &|key| std::env::var(key).ok())
    }

    /// [`WalletConfig::load`] with an injectable environment (tests use a
    /// closure over a map — no process-global env mutation races). A
    /// SET-BUT-EMPTY variable is treated as UNSET, not as an override: shells
    /// and CI commonly "clear" variables by exporting them empty, and an
    /// empty override could only ever shadow a valid file value into a
    /// misleading validation error.
    pub fn load_with_env(
        path: &Path,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<WalletConfig, ConfigError> {
        let mut text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(format!("{}: {e}", path.display())))?;
        // Tolerate a UTF-8 BOM (PowerShell 5.1's default `utf8` output
        // prepends one; trim() does NOT remove it, so without this the first
        // key fails as an inscrutable "bad key name").
        let parsed = parse_toml_subset(text.strip_prefix('\u{feff}').unwrap_or(&text));
        // The raw text may contain rpc_password: scrub it (and, via the
        // guard, every parsed value) once parsing is done — Secret's
        // zeroize-on-drop is worth little if plaintext intermediates outlive
        // it on the freed heap.
        text.zeroize();
        let file = ZeroizeValuesOnDrop(parsed?);
        // Per key: new-namespace env, else legacy-namespace env, else file.
        let get = |file_key: &str, env_suffix: &str| -> Option<String> {
            env(&format!("SWITCHBITCOIN_{env_suffix}"))
                .filter(|v| !v.is_empty())
                .or_else(|| env(&format!("SWAPKEY_{env_suffix}")).filter(|v| !v.is_empty()))
                .or_else(|| file.0.get(file_key).cloned())
        };

        let network = Network::parse(&get("network", "NETWORK").ok_or_else(|| {
            ConfigError::Invalid(
                "network is required (file key `network` or SWITCHBITCOIN_NETWORK)".into(),
            )
        })?)?;
        let data_dir = PathBuf::from(get("data_dir", "DATA_DIR").ok_or_else(|| {
            ConfigError::Invalid(
                "data_dir is required (file key `data_dir` or SWITCHBITCOIN_DATA_DIR)".into(),
            )
        })?);

        let url = get("node.rpc_url", "RPC_URL");
        let user = get("node.rpc_user", "RPC_USER");
        let password = get("node.rpc_password", "RPC_PASSWORD").map(Secret::new);
        let cookie = get("node.rpc_cookie_file", "RPC_COOKIE_FILE").map(PathBuf::from);
        let any_node_key =
            url.is_some() || user.is_some() || password.is_some() || cookie.is_some();
        let node = if !any_node_key {
            None
        } else {
            let url = url.ok_or_else(|| {
                ConfigError::Invalid("node.rpc_url is required when any [node] key is set".into())
            })?;
            let auth = match (user, password, cookie) {
                (Some(user), Some(password), None) => RpcAuth::UserPass { user, password },
                (None, None, Some(path)) => RpcAuth::CookieFile(path),
                (None, None, None) => {
                    return Err(ConfigError::Invalid(
                        "node auth is required: rpc_user + rpc_password, or rpc_cookie_file"
                            .into(),
                    ))
                }
                (_, _, Some(_)) => {
                    return Err(ConfigError::Invalid(
                        "rpc_cookie_file and rpc_user/rpc_password are mutually exclusive".into(),
                    ))
                }
                _ => {
                    return Err(ConfigError::Invalid(
                        "rpc_user and rpc_password must be set together".into(),
                    ))
                }
            };
            Some(NodeRpcConfig { url, auth })
        };

        let peer = PeerConfig {
            listen: get("peer.listen", "PEER_LISTEN"),
            connect: get("peer.connect", "PEER_CONNECT"),
        };

        let config = WalletConfig {
            data_dir,
            network,
            node,
            peer,
            params: Params::testnet_provisional(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Total validation: hostile input gets `Err`, never a panic, and error
    /// text never carries a value. `load` runs this; in-code constructions
    /// get it re-run by `Wallet::open`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("data_dir must be non-empty".into()));
        }
        self.params
            .validate()
            .map_err(|e| ConfigError::Invalid(format!("params: {e}")))?;
        if let Some(node) = &self.node {
            if !(node.url.starts_with("http://") || node.url.starts_with("https://")) {
                return Err(ConfigError::Invalid(
                    "node.rpc_url must start with http:// or https://".into(),
                ));
            }
            // Refuse curl-style userinfo (`http://user:pass@host`): the
            // transport never honors it, and the URL is a plain String that
            // derived Debug prints verbatim — a password there would bypass
            // the `Secret` wrapper entirely.
            let after_scheme = node.url.split_once("://").map(|(_, rest)| rest).unwrap_or("");
            let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
            if authority.contains('@') {
                return Err(ConfigError::Invalid(
                    "node.rpc_url must not embed credentials (user@host) — use rpc_user/rpc_password or rpc_cookie_file".into(),
                ));
            }
            match &node.auth {
                RpcAuth::UserPass { user, password } => {
                    if user.is_empty() || password.is_empty() {
                        return Err(ConfigError::Invalid(
                            "node rpc_user and rpc_password must be non-empty".into(),
                        ));
                    }
                }
                RpcAuth::CookieFile(path) => {
                    if path.as_os_str().is_empty() {
                        return Err(ConfigError::Invalid(
                            "node.rpc_cookie_file must be non-empty".into(),
                        ));
                    }
                }
            }
        }
        for (key, addr) in [
            ("peer.listen", &self.peer.listen),
            ("peer.connect", &self.peer.connect),
        ] {
            if let Some(a) = addr {
                if a.is_empty() || !a.contains(':') {
                    return Err(ConfigError::Invalid(format!(
                        "{key} must be a host:port address"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Every key the file may contain — anything else is a parse error.
const KNOWN_KEYS: [&str; 8] = [
    "network",
    "data_dir",
    "node.rpc_url",
    "node.rpc_user",
    "node.rpc_password",
    "node.rpc_cookie_file",
    "peer.listen",
    "peer.connect",
];

/// Every environment-variable SUFFIX `load` consults (1:1 with
/// `KNOWN_KEYS`); the full names are `SWITCHBITCOIN_<suffix>` and, legacy,
/// `SWAPKEY_<suffix>`.
const ENV_SUFFIXES: [&str; 8] = [
    "NETWORK",
    "DATA_DIR",
    "RPC_URL",
    "RPC_USER",
    "RPC_PASSWORD",
    "RPC_COOKIE_FILE",
    "PEER_LISTEN",
    "PEER_CONNECT",
];

/// The env-side twin of the file parser's unknown-key strictness: any
/// `SWITCHBITCOIN_`- or (legacy) `SWAPKEY_`-prefixed variable whose suffix
/// is outside [`ENV_SUFFIXES`] is refused — both prefixes are this wallet's
/// namespace, and a silently ignored typo in either would strand the node
/// on a stale credential. Takes NAMES only — values never enter error
/// text. Separated from `load` so tests can inject names without touching
/// the process environment.
fn reject_unknown_namespace_vars(
    names: impl Iterator<Item = String>,
) -> Result<(), ConfigError> {
    for name in names {
        let suffix = name
            .strip_prefix("SWITCHBITCOIN_")
            .or_else(|| name.strip_prefix("SWAPKEY_"));
        if let Some(suffix) = suffix {
            if !ENV_SUFFIXES.contains(&suffix) {
                return Err(ConfigError::Invalid(format!(
                    "unknown environment variable `{name}` (typo? known variables: SWITCHBITCOIN_{{{}}} — legacy SWAPKEY_* accepted too)",
                    ENV_SUFFIXES.join(", ")
                )));
            }
        }
    }
    Ok(())
}

/// Wraps the parsed key→value map so every value (one may be the RPC
/// password) is scrubbed when the map goes out of scope — on the error paths
/// too.
struct ZeroizeValuesOnDrop(BTreeMap<String, String>);

impl Drop for ZeroizeValuesOnDrop {
    fn drop(&mut self) {
        for v in self.0.values_mut() {
            v.zeroize();
        }
    }
}

/// Parse the TOML subset into `section.key -> value` (top-level keys are
/// bare). Strict: unknown keys/sections and duplicates are errors; errors
/// carry line numbers and key names, never values.
fn parse_toml_subset(text: &str) -> Result<BTreeMap<String, String>, ConfigError> {
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
                return Err(ConfigError::Parse(format!("line {n}: unterminated section header")));
            };
            section = match name.trim() {
                "node" => Some("node"),
                "peer" => Some("peer"),
                other => {
                    return Err(ConfigError::Parse(format!(
                        "line {n}: unknown section [{other}] (expected [node] or [peer])"
                    )))
                }
            };
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfigError::Parse(format!("line {n}: expected `key = \"value\"`")));
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(ConfigError::Parse(format!("line {n}: bad key name")));
        }
        let value = parse_string_value(value.trim(), n)?;
        let full = match section {
            Some(s) => format!("{s}.{key}"),
            None => key.to_string(),
        };
        if !KNOWN_KEYS.contains(&full.as_str()) {
            return Err(ConfigError::Parse(format!("line {n}: unknown key `{full}`")));
        }
        if out.insert(full.clone(), value).is_some() {
            return Err(ConfigError::Parse(format!("line {n}: duplicate key `{full}`")));
        }
    }
    Ok(out)
}

/// One quoted string value; the remainder of the line may only be a comment.
fn parse_string_value(v: &str, n: usize) -> Result<String, ConfigError> {
    let mut chars = v.chars();
    match chars.next() {
        Some('"') => {
            let mut out = String::new();
            loop {
                match chars.next() {
                    None => {
                        return Err(ConfigError::Parse(format!("line {n}: unterminated string")))
                    }
                    Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some('\\') => out.push('\\'),
                        Some('"') => out.push('"'),
                        Some('n') => out.push('\n'),
                        Some('r') => out.push('\r'),
                        Some('t') => out.push('\t'),
                        _ => {
                            return Err(ConfigError::Parse(format!(
                                "line {n}: unsupported escape (use single quotes for literal Windows paths)"
                            )))
                        }
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
                return Err(ConfigError::Parse(format!("line {n}: unterminated string")));
            };
            only_comment_after(&rest[end + 1..], n)?;
            Ok(rest[..end].to_string())
        }
        _ => Err(ConfigError::Parse(format!(
            "line {n}: values must be quoted strings"
        ))),
    }
}

fn only_comment_after(rest: &str, n: usize) -> Result<(), ConfigError> {
    let rest = rest.trim_start();
    if rest.is_empty() || rest.starts_with('#') {
        Ok(())
    } else {
        Err(ConfigError::Parse(format!(
            "line {n}: unexpected trailing characters after string value"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_cfg(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join(CONFIG_FILE);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    const FULL: &str = r#"
# switchbitcoin.toml — full example
network = "regtest"
data_dir = 'C:\wallet\data'   # literal string: backslashes untouched

[node]
rpc_url = "http://127.0.0.1:18443"
rpc_user = "switchbitcoin"
rpc_password = "hunter2-secret"

[peer]
listen = "127.0.0.1:9735"
connect = "10.0.0.7:9735"
"#;

    #[test]
    fn full_config_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(dir.path(), FULL);
        let cfg = WalletConfig::load_with_env(&path, &no_env).unwrap();

        assert_eq!(cfg.network, Network::Regtest);
        assert_eq!(cfg.data_dir, PathBuf::from(r"C:\wallet\data"));
        let node = cfg.node.as_ref().unwrap();
        assert_eq!(node.url, "http://127.0.0.1:18443");
        match &node.auth {
            RpcAuth::UserPass { user, password } => {
                assert_eq!(user, "switchbitcoin");
                assert_eq!(password.expose(), "hunter2-secret");
            }
            other => panic!("expected user/pass auth, got {other:?}"),
        }
        assert_eq!(cfg.peer.listen.as_deref(), Some("127.0.0.1:9735"));
        assert_eq!(cfg.peer.connect.as_deref(), Some("10.0.0.7:9735"));
        assert_eq!(cfg.params, Params::testnet_provisional());
    }

    #[test]
    fn env_overrides_beat_the_file_and_supply_missing_keys() {
        let dir = tempfile::tempdir().unwrap();
        // File has no password and no peer section: env supplies both, and
        // overrides the file's network.
        let path = write_cfg(
            dir.path(),
            "network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://x:1\"\nrpc_user = \"u\"\n",
        );
        let env = |key: &str| -> Option<String> {
            match key {
                "SWITCHBITCOIN_NETWORK" => Some("testnet".into()),
                "SWITCHBITCOIN_RPC_PASSWORD" => Some("from-env".into()),
                "SWITCHBITCOIN_PEER_CONNECT" => Some("peer.example:9735".into()),
                _ => None,
            }
        };
        let cfg = WalletConfig::load_with_env(&path, &env).unwrap();
        assert_eq!(cfg.network, Network::Testnet);
        match &cfg.node.as_ref().unwrap().auth {
            RpcAuth::UserPass { password, .. } => assert_eq!(password.expose(), "from-env"),
            other => panic!("expected user/pass auth, got {other:?}"),
        }
        assert_eq!(cfg.peer.connect.as_deref(), Some("peer.example:9735"));
        assert_eq!(cfg.peer.listen, None);
    }

    #[test]
    fn legacy_swapkey_env_vars_still_work_and_the_new_namespace_wins() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(
            dir.path(),
            "network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://x:1\"\nrpc_user = \"u\"\n",
        );
        // Legacy-only: the pre-rebrand namespace still supplies values.
        let legacy_only = |key: &str| -> Option<String> {
            match key {
                "SWAPKEY_NETWORK" => Some("testnet".into()),
                "SWAPKEY_RPC_PASSWORD" => Some("from-legacy".into()),
                _ => None,
            }
        };
        let cfg = WalletConfig::load_with_env(&path, &legacy_only).unwrap();
        assert_eq!(cfg.network, Network::Testnet);
        match &cfg.node.as_ref().unwrap().auth {
            RpcAuth::UserPass { password, .. } => assert_eq!(password.expose(), "from-legacy"),
            other => panic!("expected user/pass auth, got {other:?}"),
        }
        // Both set: SWITCHBITCOIN_* beats SWAPKEY_* per key.
        let both = |key: &str| -> Option<String> {
            match key {
                "SWITCHBITCOIN_RPC_PASSWORD" => Some("from-new".into()),
                "SWAPKEY_RPC_PASSWORD" => Some("from-legacy".into()),
                _ => None,
            }
        };
        let cfg = WalletConfig::load_with_env(&path, &both).unwrap();
        match &cfg.node.unwrap().auth {
            RpcAuth::UserPass { password, .. } => assert_eq!(password.expose(), "from-new"),
            other => panic!("expected user/pass auth, got {other:?}"),
        }
    }

    #[test]
    fn cookie_auth_is_accepted_and_exclusive_with_userpass() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(
            dir.path(),
            "network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://x:1\"\nrpc_cookie_file = \"/tmp/.cookie\"\n",
        );
        let cfg = WalletConfig::load_with_env(&path, &no_env).unwrap();
        assert!(matches!(
            cfg.node.unwrap().auth,
            RpcAuth::CookieFile(p) if p.as_path() == Path::new("/tmp/.cookie")
        ));

        let path = write_cfg(
            dir.path(),
            "network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://x:1\"\nrpc_cookie_file = \"c\"\nrpc_user = \"u\"\nrpc_password = \"p\"\n",
        );
        let err = WalletConfig::load_with_env(&path, &no_env).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn invalid_configs_are_rejected_with_key_names_not_values() {
        let dir = tempfile::tempdir().unwrap();
        let cases: &[(&str, &str)] = &[
            // (file text, expected error fragment)
            ("data_dir = \"d\"\n", "network is required"),
            ("network = \"regtest\"\n", "data_dir is required"),
            ("network = \"mainnet\"\ndata_dir = \"d\"\n", "mainnet is refused"),
            ("network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_user = \"u\"\nrpc_password = \"p\"\n", "rpc_url is required"),
            ("network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://x:1\"\n", "auth is required"),
            ("network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://x:1\"\nrpc_user = \"u\"\n", "set together"),
            ("network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"ftp://x\"\nrpc_user = \"u\"\nrpc_password = \"p\"\n", "http://"),
            ("network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://x:1\"\nrpc_user = \"\"\nrpc_password = \"p\"\n", "non-empty"),
            ("network = \"regtest\"\ndata_dir = \"d\"\n[peer]\nlisten = \"no-port\"\n", "host:port"),
            ("network = \"regtest\"\ndata_dir = \"d\"\nnetwork = \"regtest\"\n", "duplicate key"),
            ("network = \"regtest\"\ndata_dir = \"d\"\nrpc_passwrod = \"p\"\n", "unknown key"),
            ("network = \"regtest\"\ndata_dir = \"d\"\n[wat]\n", "unknown section"),
            ("network = regtest\ndata_dir = \"d\"\n", "quoted"),
            ("network = \"regtest\ndata_dir = \"d\"\n", "unterminated"),
            ("network = \"regtest\" trailing\ndata_dir = \"d\"\n", "trailing"),
        ];
        for (text, fragment) in cases {
            let path = write_cfg(dir.path(), text);
            let err = WalletConfig::load_with_env(&path, &no_env).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(fragment), "for {text:?}: expected {fragment:?} in {msg:?}");
        }
    }

    #[test]
    fn hostile_params_fail_validate_totally() {
        let mut cfg = WalletConfig::new("d", Network::Regtest);
        cfg.params.margin = 0; // breaks THE ordering invariant
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("params:"), "{err}");
    }

    #[test]
    fn secrets_never_appear_in_debug_or_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(dir.path(), FULL);
        let cfg = WalletConfig::load_with_env(&path, &no_env).unwrap();
        let dump = format!("{cfg:?}");
        assert!(!dump.contains("hunter2-secret"), "password leaked into Debug: {dump}");
        assert!(dump.contains("<redacted>"));

        // A validation failure on the node block names the key, not the value.
        let path = write_cfg(
            dir.path(),
            "network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://x:1\"\nrpc_user = \"u\"\nrpc_password = \"\"\n",
        );
        let err = WalletConfig::load_with_env(&path, &no_env).unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }

    #[test]
    fn escapes_and_comments_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(
            dir.path(),
            "network = \"regtest\"  # inline comment\ndata_dir = \"C:\\\\a\\\\b\"\n\n# whole-line comment\n[peer]\nlisten = '0.0.0.0:9735' # after literal\n",
        );
        let cfg = WalletConfig::load_with_env(&path, &no_env).unwrap();
        assert_eq!(cfg.data_dir, PathBuf::from(r"C:\a\b"));
        assert_eq!(cfg.peer.listen.as_deref(), Some("0.0.0.0:9735"));
    }

    #[test]
    fn empty_env_vars_count_as_unset() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(dir.path(), FULL);
        // A shell that "cleared" the password by exporting it empty must not
        // shadow the file's valid value, and an empty stray var must not
        // conjure a [node] requirement.
        let env = |key: &str| -> Option<String> {
            matches!(
                key,
                "SWITCHBITCOIN_RPC_PASSWORD"
                    | "SWITCHBITCOIN_RPC_COOKIE_FILE"
                    | "SWAPKEY_RPC_PASSWORD"
                    | "SWAPKEY_RPC_COOKIE_FILE"
            )
            .then(String::new)
        };
        let cfg = WalletConfig::load_with_env(&path, &env).unwrap();
        match &cfg.node.unwrap().auth {
            RpcAuth::UserPass { password, .. } => assert_eq!(password.expose(), "hunter2-secret"),
            other => panic!("expected user/pass auth, got {other:?}"),
        }
    }

    #[test]
    fn a_utf8_bom_is_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(dir.path(), &format!("\u{feff}{FULL}"));
        let cfg = WalletConfig::load_with_env(&path, &no_env).unwrap();
        assert_eq!(cfg.network, Network::Regtest);
    }

    #[test]
    fn rpc_url_userinfo_is_refused_without_echoing_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_cfg(
            dir.path(),
            "network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://alice:hunter2@127.0.0.1:18443\"\nrpc_user = \"u\"\nrpc_password = \"p\"\n",
        );
        let err = WalletConfig::load_with_env(&path, &no_env).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("must not embed credentials"), "{msg}");
        assert!(!msg.contains("hunter2"), "leaked the URL userinfo: {msg}");
        // An '@' PAST the authority (e.g. in a path) stays legal.
        let path = write_cfg(
            dir.path(),
            "network = \"regtest\"\ndata_dir = \"d\"\n[node]\nrpc_url = \"http://127.0.0.1:18443/wallet/a@b\"\nrpc_user = \"u\"\nrpc_password = \"p\"\n",
        );
        assert!(WalletConfig::load_with_env(&path, &no_env).is_ok());
    }

    #[test]
    fn unknown_namespace_env_vars_are_refused_by_name() {
        // The recommended path for the password is the env var — it gets the
        // same typo safety as the file, in BOTH namespaces.
        let err = reject_unknown_namespace_vars(
            ["PATH", "SWITCHBITCOIN_RPC_PASSWROD", "HOME"].map(String::from).into_iter(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("SWITCHBITCOIN_RPC_PASSWROD"), "{err}");
        let err = reject_unknown_namespace_vars(
            ["PATH", "SWAPKEY_RPC_PASSWROD", "HOME"].map(String::from).into_iter(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("SWAPKEY_RPC_PASSWROD"), "{err}");
        assert!(reject_unknown_namespace_vars(
            ["PATH", "SWITCHBITCOIN_RPC_PASSWORD", "SWAPKEY_RPC_PASSWORD"]
                .map(String::from)
                .into_iter()
        )
        .is_ok());
    }

    #[test]
    fn missing_file_is_a_clean_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            WalletConfig::load_with_env(&dir.path().join("nope.toml"), &no_env).unwrap_err();
        assert!(matches!(err, ConfigError::Io(_)), "{err}");
    }
}
