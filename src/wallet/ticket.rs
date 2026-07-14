//! Swap ticket (Task 15): a paste-able, checksummed offer blob carrying the
//! PUBLIC pre-swap facts two testers need to rendezvous — network, the signed
//! params digest, a listen endpoint, and a random offer nonce — so a maker
//! hands the taker ONE string ("here's my swap ticket") instead of
//! coordinating host:port AND network/params out-of-band. Discovery is
//! deliberately STUBBED (v3.16 Requirement 5); this is the minimal usability
//! layer over the manual-rendezvous model, NOT a discovery network.
//!
//! # Why a forged ticket cannot steal
//! A ticket carries no key material and no funds — only the same class of
//! public facts [`runner::negotiate_swap`](crate::wallet::runner::negotiate_swap)'s
//! hello frame already exchanges. The actual swap still runs the full Task-05
//! sealed negotiation, whose hello RE-CHECKS network + params digest, so a
//! forged/replayed/garbage ticket can at most route a taker to a peer that
//! then REFUSES the handshake — never a theft. The ticket is a convenience,
//! not a trust anchor; the nonce rendezvous ([`taker_rendezvous`] /
//! [`maker_rendezvous`]) is a liveness / anti-confusion echo, not
//! authentication.
//!
//! # Parsing discipline
//! [`Ticket::decode`] mirrors `wire::open_message` / `runner::decode_hello`:
//! TOTAL parsing, every branch length-checked, the accepted string capped
//! BEFORE decoding, and hostile/truncated/oversize/garbage input maps to
//! `Err(Error::Validation(..))` — never a panic, never an unbounded
//! allocation. The negative tests (`tests/ticket.rs`) are the contract.
//!
//! # Encoding
//! bech32m (via the `bitcoin`-re-exported `bech32` crate — no new dependency)
//! with HRP `skt`, distinct from the segwit address HRPs (bc/tb/bcrt) so a
//! ticket can never be mistaken for an address. The checksum catches transcription
//! errors; bech32 itself rejects a MIXED-CASE string (all-lower and all-upper
//! decode identically), which is the case policy we accept.
//!
//! Payload (big-endian port; every field length-checked on decode):
//! `ver(1)=0x01 | net(1) | params_digest(32) | nonce(16) | port(2) | host_len(1) | host(ASCII, 1..=64)`

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::{self, Bech32m, Hrp};
use rand::TryRngCore;

use crate::settlement::params::Params;
use crate::settlement::state_machine::Transport;
use crate::wallet::config::Network;
use crate::wallet::runner::params_digest;
use crate::{Error, Result};

/// Human-readable prefix of the bech32m ticket. Deliberately NOT a segwit HRP.
const TICKET_HRP: &str = "skt";

/// Ticket payload version. Bumped on any change to the byte layout; an unknown
/// version is a clean refusal (a newer maker cannot silently mis-seat an older
/// taker on a re-interpreted payload).
const TICKET_VERSION: u8 = 0x01;

/// Max host label length (bytes). Hostnames / IPv4 literals fit well under
/// this; the cap bounds the whole payload so a hostile ticket cannot force a
/// large host allocation.
const MAX_HOST: usize = 64;

/// Hard cap on an accepted ticket STRING, applied BEFORE bech32 decoding so a
/// hostile/oversize blob is refused without doing base32 work over it. A
/// max-host ticket encodes to under ~200 chars; 256 is generous headroom.
const MAX_TICKET_STR: usize = 256;

/// Fixed payload prefix: ver(1) net(1) digest(32) nonce(16) port(2) host_len(1).
const PAYLOAD_FIXED: usize = 1 + 1 + 32 + 16 + 2 + 1;

// --- rendezvous frames (ride the already-connected transport, ABOVE
// negotiate_swap; NOT part of the ticket blob) --------------------------------

/// Rendezvous frame version — independent of [`TICKET_VERSION`].
const RV_VERSION: u8 = 0x01;
/// Taker → maker: "I hold ticket with this nonce."
const KIND_TAKE: u8 = 0x51;
/// Maker → taker: "I minted that nonce" (the liveness echo).
const KIND_ECHO: u8 = 0x52;
/// ver(1) kind(1) nonce(16).
const RV_FRAME_LEN: usize = 1 + 1 + 16;

/// Network ⇄ payload byte. Exhaustive so a new `Network` variant forces a
/// decision here (kept in step with `runner::params_digest`'s own mapping).
fn network_byte(network: Network) -> u8 {
    match network {
        Network::Regtest => 0,
        Network::Testnet => 1,
    }
}

fn network_from_byte(b: u8) -> Result<Network> {
    match b {
        0 => Ok(Network::Regtest),
        1 => Ok(Network::Testnet),
        _ => Err(Error::Validation("ticket names an unknown network byte")),
    }
}

/// Host shape gate: ASCII alnum + `.` + `-`, length 1..=[`MAX_HOST`].
/// Hostnames and IPv4 literals qualify; IPv6 (which needs `:` and `[]`) is OUT
/// OF SCOPE pre-alpha and is rejected here by the charset — a clean refusal,
/// not a mis-parse. Applied at BOTH mint and decode so no path admits a host
/// that would later break `addr()` or an unbracketed dial.
fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() || host.len() > MAX_HOST {
        return Err(Error::Validation("ticket host is empty or longer than 64 bytes"));
    }
    if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return Err(Error::Validation(
            "ticket host has a non-hostname character (only a-z0-9.- ; IPv6 is out of scope pre-alpha)",
        ));
    }
    Ok(())
}

/// The `skt` HRP as a parsed [`Hrp`] (case-insensitive on compare). `expect`
/// is sound: [`TICKET_HRP`] is a compile-time-valid lowercase HRP.
fn ticket_hrp() -> Hrp {
    Hrp::parse(TICKET_HRP).expect("`skt` is a valid bech32 HRP")
}

/// A decoded/minted swap ticket. `params_digest` is intentionally NOT public:
/// callers compare it via [`Ticket::validate`], never by hand (re-deriving the
/// digest elsewhere is the drift the runner recon warned against).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub network: Network,
    params_digest: [u8; 32],
    pub nonce: [u8; 16],
    pub host: String,
    pub port: u16,
}

impl Ticket {
    /// Mint a fresh ticket for `host:port` on `network` under this wallet's
    /// signed `params`. A fresh random 16-byte nonce makes the rendezvous echo
    /// unguessable per offer. Refuses a mis-shaped host or a zero port up
    /// front (the ticket must carry a peer-DIALABLE endpoint).
    pub fn mint(network: Network, params: &Params, host: &str, port: u16) -> Result<Ticket> {
        validate_host(host)?;
        if port == 0 {
            return Err(Error::Validation("ticket port must be non-zero"));
        }
        let mut nonce = [0u8; 16];
        // A predictable nonce would weaken the anti-confusion echo, so a failed
        // draw is a hard error (unlike the privacy-delay sampler, which may
        // safely degrade) — the swap simply is not offered.
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Abort("could not generate a ticket nonce"))?;
        Ok(Ticket { network, params_digest: params_digest(network, params), nonce, host: host.to_string(), port })
    }

    /// Encode to the paste-able `skt1…` bech32m string.
    pub fn encode(&self) -> String {
        let mut payload = Vec::with_capacity(PAYLOAD_FIXED + self.host.len());
        payload.push(TICKET_VERSION);
        payload.push(network_byte(self.network));
        payload.extend_from_slice(&self.params_digest);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.port.to_be_bytes());
        // host_len fits u8: mint/decode both enforce host.len() <= MAX_HOST (64).
        payload.push(self.host.len() as u8);
        payload.extend_from_slice(self.host.as_bytes());
        // A bounded (<=117-byte) payload is always encodable; the only
        // EncodeError paths are fmt/oversize, neither reachable here.
        bech32::encode::<Bech32m>(ticket_hrp(), &payload)
            .expect("bech32m encoding of a bounded ticket payload cannot fail")
    }

    /// TOTAL decode of a pasted ticket string. Every failure is
    /// `Err(Error::Validation(..))`; nothing panics or allocates unbounded.
    pub fn decode(s: &str) -> Result<Ticket> {
        // Cap BEFORE bech32 work so an oversize blob is refused cheaply.
        if s.len() > MAX_TICKET_STR {
            return Err(Error::Validation("ticket string exceeds the length cap"));
        }
        // STRICT Bech32m: `bech32::decode` would also accept a plain-Bech32
        // checksum, silently widening the format beyond what `encode` emits —
        // the checked-HRP path pins the exact checksum this module writes.
        let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|_| {
            Error::Validation("ticket is not valid bech32m (bad checksum, mixed case, or garbage)")
        })?;
        if checked.hrp() != ticket_hrp() {
            return Err(Error::Validation("ticket has the wrong prefix — not a swap ticket (expected skt1…)"));
        }
        let payload: Vec<u8> = checked.byte_iter().collect();
        if payload.len() < PAYLOAD_FIXED {
            return Err(Error::Validation("ticket payload is truncated (shorter than the fixed header)"));
        }
        if payload[0] != TICKET_VERSION {
            return Err(Error::Validation("ticket is an unknown version"));
        }
        let network = network_from_byte(payload[1])?;
        let mut params_digest = [0u8; 32];
        params_digest.copy_from_slice(&payload[2..34]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&payload[34..50]);
        let port = u16::from_be_bytes([payload[50], payload[51]]);
        if port == 0 {
            return Err(Error::Validation("ticket port is zero"));
        }
        let host_len = payload[52] as usize;
        if host_len == 0 || host_len > MAX_HOST {
            return Err(Error::Validation("ticket host length is out of bounds"));
        }
        if payload.len() != PAYLOAD_FIXED + host_len {
            return Err(Error::Validation("ticket payload length does not match its declared host length"));
        }
        let host = std::str::from_utf8(&payload[PAYLOAD_FIXED..])
            .map_err(|_| Error::Validation("ticket host is not valid ASCII"))?
            .to_string();
        // Re-apply the charset allowlist on receipt: the length field alone
        // does not bound the CONTENT (a hostile ticket could carry control
        // bytes or an IPv6 literal within a valid length).
        validate_host(&host)?;
        Ok(Ticket { network, params_digest, nonce, host, port })
    }

    /// Refuse a ticket that does not match THIS wallet's network + signed
    /// params BEFORE dialing — a mismatch is a clean, greppable refusal, not a
    /// hung socket. The two failure modes carry distinct messages so a tester
    /// knows which knob to fix.
    pub fn validate(&self, network: Network, params: &Params) -> Result<()> {
        if self.network != network {
            return Err(Error::Validation(
                "ticket is for a different network than this wallet (regtest vs testnet) — \
                 maker and taker must be on the same network",
            ));
        }
        if self.params_digest != params_digest(network, params) {
            return Err(Error::Validation(
                "ticket's signed params differ from this wallet's manifest — update one side \
                 so both run the same signed parameters",
            ));
        }
        Ok(())
    }

    /// The dialable `host:port` the taker connects to.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// ---------------------------------------------------------------------------
// Nonce rendezvous — ONE round-trip over the already-connected transport,
// strictly ABOVE the unchanged `negotiate_swap`.
// ---------------------------------------------------------------------------

/// Taker half: send TAKE(nonce), expect ECHO(nonce). A missing/garbage/
/// wrong-nonce echo is a refusal (the maker is not the one who minted this
/// ticket, or the wires crossed) — surfaced BEFORE any lease.
pub fn taker_rendezvous(peer: &mut dyn Transport, nonce: &[u8; 16]) -> Result<()> {
    peer.send(&encode_rv(KIND_TAKE, nonce))?;
    let echoed = decode_rv(&peer.recv()?, KIND_ECHO)?;
    if &echoed != nonce {
        return Err(Error::Validation(
            "swap ticket rendezvous: the maker echoed a different nonce (wrong peer or crossed wires)",
        ));
    }
    Ok(())
}

/// Maker half: recv TAKE, require the nonce equals the one THIS offer minted,
/// then reply ECHO. A nonce that does not match is a port scan or a stale/
/// wrong ticket — the caller drops the connection and keeps accepting.
pub fn maker_rendezvous(peer: &mut dyn Transport, expected: &[u8; 16]) -> Result<()> {
    let got = decode_rv(&peer.recv()?, KIND_TAKE)?;
    if &got != expected {
        return Err(Error::Validation(
            "swap ticket rendezvous: the taker presented a nonce this offer did not mint (wrong ticket or a port scan)",
        ));
    }
    peer.send(&encode_rv(KIND_ECHO, expected))?;
    Ok(())
}

fn encode_rv(kind: u8, nonce: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(RV_FRAME_LEN);
    v.push(RV_VERSION);
    v.push(kind);
    v.extend_from_slice(nonce);
    v
}

/// TOTAL parse of a rendezvous frame: exact length, version, and kind checked
/// before the nonce is read (a truncated/oversize/garbage frame → `Err`).
fn decode_rv(bytes: &[u8], expect_kind: u8) -> Result<[u8; 16]> {
    if bytes.len() != RV_FRAME_LEN {
        return Err(Error::Validation("swap ticket rendezvous: frame has the wrong length"));
    }
    if bytes[0] != RV_VERSION {
        return Err(Error::Validation("swap ticket rendezvous: peer speaks a different rendezvous version"));
    }
    if bytes[1] != expect_kind {
        return Err(Error::Validation("swap ticket rendezvous: unexpected frame kind"));
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&bytes[2..RV_FRAME_LEN]);
    Ok(nonce)
}
