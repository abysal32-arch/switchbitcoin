//! Swap ticket (Task 15) — the encode/decode/validate contract and the nonce
//! rendezvous, default-feature (no node, no sockets). The NEGATIVE tests come
//! first (Task-14's lesson: hostile/garbage input must `Err`, never panic or
//! hang); the happy paths follow.

use std::sync::mpsc;
use std::time::Duration;

use bitcoin::bech32::{self, Bech32m, Hrp};
use swapkey::settlement::params::Params;
use swapkey::settlement::state_machine::Transport;
use swapkey::wallet::config::Network;
use swapkey::wallet::ticket::{maker_rendezvous, taker_rendezvous, Ticket};
use swapkey::{Error, Result};

// ---------- helpers ----------

fn params() -> Params {
    Params::testnet_provisional()
}

/// Encode arbitrary payload bytes under the real `skt` HRP + bech32m checksum —
/// the tool the negative tests use to craft otherwise-valid strings with ONE
/// hostile field.
fn skt_encode(payload: &[u8]) -> String {
    bech32::encode::<Bech32m>(Hrp::parse("skt").unwrap(), payload).unwrap()
}

/// A well-formed payload with the given overridable fields (zeroed digest +
/// nonce — decode does not inspect those, `validate` does).
fn payload(ver: u8, net: u8, port: u16, host_len: u8, host: &[u8]) -> Vec<u8> {
    let mut v = vec![ver, net];
    v.extend_from_slice(&[0u8; 32]); // digest
    v.extend_from_slice(&[0u8; 16]); // nonce
    v.extend_from_slice(&port.to_be_bytes());
    v.push(host_len);
    v.extend_from_slice(host);
    v
}

struct ChannelTransport {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}
impl Transport for ChannelTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.tx.send(bytes.to_vec()).map_err(|_| Error::Abort("peer hung up"))
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        self.rx.recv_timeout(Duration::from_secs(60)).map_err(|_| Error::Abort("peer hung up"))
    }
}
fn duplex() -> (ChannelTransport, ChannelTransport) {
    let (tx_a, rx_b) = mpsc::channel();
    let (tx_b, rx_a) = mpsc::channel();
    (ChannelTransport { tx: tx_a, rx: rx_a }, ChannelTransport { tx: tx_b, rx: rx_b })
}

fn is_validation(r: &Result<Ticket>) -> bool {
    matches!(r, Err(Error::Validation(_)))
}

// ============================================================================
// decode REFUSES hostile input — none panic.
// ============================================================================

#[test]
fn decode_refuses_empty_and_garbage_and_non_ascii() {
    assert!(is_validation(&Ticket::decode("")));
    assert!(is_validation(&Ticket::decode("not a ticket")));
    assert!(is_validation(&Ticket::decode("skt1"))); // HRP + separator, no data
    assert!(is_validation(&Ticket::decode("skt1\u{00e9}\u{00e9}\u{00e9}"))); // non-ASCII
    assert!(is_validation(&Ticket::decode("💥💥💥")));
}

#[test]
fn decode_refuses_wrong_hrp() {
    // A perfectly-checksummed bech32m string under a DIFFERENT prefix.
    let body = payload(0x01, 0, 9735, 3, b"a.b");
    let wrong = bech32::encode::<Bech32m>(Hrp::parse("bc").unwrap(), &body).unwrap();
    assert!(is_validation(&Ticket::decode(&wrong)));
    let wrong2 = bech32::encode::<Bech32m>(Hrp::parse("tkt").unwrap(), &body).unwrap();
    assert!(is_validation(&Ticket::decode(&wrong2)));
}

#[test]
fn decode_refuses_wrong_version() {
    let s = skt_encode(&payload(0x02, 0, 9735, 3, b"a.b"));
    match Ticket::decode(&s) {
        Err(Error::Validation(m)) => assert!(m.contains("version"), "{m}"),
        other => panic!("expected version refusal, got {other:?}"),
    }
}

#[test]
fn decode_refuses_unknown_network_byte() {
    let s = skt_encode(&payload(0x01, 9, 9735, 3, b"a.b"));
    match Ticket::decode(&s) {
        Err(Error::Validation(m)) => assert!(m.contains("network"), "{m}"),
        other => panic!("expected network-byte refusal, got {other:?}"),
    }
}

#[test]
fn decode_refuses_zero_port() {
    let s = skt_encode(&payload(0x01, 0, 0, 3, b"a.b"));
    match Ticket::decode(&s) {
        Err(Error::Validation(m)) => assert!(m.contains("port"), "{m}"),
        other => panic!("expected zero-port refusal, got {other:?}"),
    }
}

#[test]
fn decode_refuses_bad_host_charset() {
    for host in [b"a/b".as_slice(), b"a_b", b"a b", b"a:b"] {
        let s = skt_encode(&payload(0x01, 0, 9735, host.len() as u8, host));
        assert!(is_validation(&Ticket::decode(&s)), "host {host:?} must be refused");
    }
}

#[test]
fn decode_refuses_oversize_host_and_length_mismatch() {
    // host_len byte says 65 (> MAX_HOST 64) with 65 real bytes.
    let big = vec![b'a'; 65];
    let s = skt_encode(&payload(0x01, 0, 9735, 65, &big));
    assert!(is_validation(&Ticket::decode(&s)));

    // Declared host_len disagrees with the trailing bytes present.
    let s2 = skt_encode(&payload(0x01, 0, 9735, 10, b"abc"));
    assert!(is_validation(&Ticket::decode(&s2)));

    // Truncated below the fixed header entirely.
    let s3 = skt_encode(&[0x01, 0x00, 0x00]);
    assert!(is_validation(&Ticket::decode(&s3)));
}

#[test]
fn decode_refuses_a_plain_bech32_checksum() {
    // Same payload, same HRP, but checksummed with plain Bech32 instead of
    // Bech32m: decode must pin the EXACT checksum encode emits, not silently
    // accept the wider family.
    use bitcoin::bech32::Bech32;
    let body = payload(0x01, 0, 9735, 3, b"a.b");
    let s = bech32::encode::<Bech32>(Hrp::parse("skt").unwrap(), &body).unwrap();
    assert!(is_validation(&Ticket::decode(&s)), "a plain-bech32 checksum must be refused");
}

#[test]
fn decode_refuses_corrupted_checksum() {
    let good = Ticket::mint(Network::Regtest, &params(), "127.0.0.1", 9735).unwrap().encode();
    // Flip the LAST character to a different valid bech32 symbol → checksum breaks.
    let mut chars: Vec<char> = good.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
    let corrupted: String = chars.into_iter().collect();
    assert_ne!(corrupted, good);
    assert!(is_validation(&Ticket::decode(&corrupted)));
}

#[test]
fn decode_refuses_every_truncated_prefix_without_panicking() {
    let good = Ticket::mint(Network::Testnet, &params(), "node.example", 18333).unwrap().encode();
    // Every PROPER prefix must refuse (checksum/length) — and, above all, none
    // may panic. (The string is pure ASCII, so byte slices are char-safe.)
    for i in 0..good.len() {
        assert!(
            is_validation(&Ticket::decode(&good[..i])),
            "prefix of length {i} unexpectedly decoded"
        );
    }
    // The full string still decodes.
    assert!(Ticket::decode(&good).is_ok());
}

#[test]
fn decode_refuses_oversize_string_before_bech32_work() {
    let huge = "skt1".to_string() + &"q".repeat(400);
    assert!(huge.len() > 256);
    match Ticket::decode(&huge) {
        Err(Error::Validation(m)) => assert!(m.contains("length cap"), "{m}"),
        other => panic!("expected the length-cap refusal, got {other:?}"),
    }
}

#[test]
fn decode_rejects_mixed_case_but_accepts_all_upper() {
    let good = Ticket::mint(Network::Regtest, &params(), "127.0.0.1", 9735).unwrap();
    let s = good.encode();

    // All-uppercase is the SAME ticket (bech32 is case-insensitive; our HRP
    // compare is too).
    let upper = Ticket::decode(&s.to_uppercase()).expect("all-uppercase decodes");
    assert_eq!(upper, good);

    // Mixed case (one data char flipped to upper) is rejected by bech32.
    let mut chars: Vec<char> = s.chars().collect();
    // Find a lowercase letter in the DATA part (after the '1' separator) to flip.
    let sep = s.find('1').unwrap();
    let flip = (sep + 1..chars.len()).find(|&i| chars[i].is_ascii_lowercase()).unwrap();
    chars[flip] = chars[flip].to_ascii_uppercase();
    let mixed: String = chars.into_iter().collect();
    assert!(is_validation(&Ticket::decode(&mixed)), "mixed case must be refused");
}

// ============================================================================
// validate REFUSES a network / params mismatch, with distinct messages.
// ============================================================================

#[test]
fn validate_refuses_network_mismatch() {
    let t = Ticket::mint(Network::Regtest, &params(), "127.0.0.1", 9735).unwrap();
    match t.validate(Network::Testnet, &params()) {
        Err(Error::Validation(m)) => assert!(m.contains("network"), "{m}"),
        other => panic!("expected a network-mismatch refusal, got {other:?}"),
    }
    // Same network validates.
    assert!(t.validate(Network::Regtest, &params()).is_ok());
}

#[test]
fn validate_refuses_params_mismatch() {
    let base = params();
    let tweaked = Params { tier_d_sats: base.tier_d_sats + 1, ..base.clone() };
    let t = Ticket::mint(Network::Regtest, &tweaked, "127.0.0.1", 9735).unwrap();
    // Network matches, so this reaches the params-digest check specifically.
    match t.validate(Network::Regtest, &base) {
        Err(Error::Validation(m)) => {
            assert!(m.contains("params") || m.contains("manifest"), "{m}");
            assert!(!m.contains("network"), "params mismatch must not report a network error: {m}");
        }
        other => panic!("expected a params-mismatch refusal, got {other:?}"),
    }
}

// ============================================================================
// mint REFUSES a mis-shaped endpoint.
// ============================================================================

#[test]
fn mint_refuses_bad_host_and_zero_port() {
    let p = params();
    assert!(Ticket::mint(Network::Regtest, &p, "", 9735).is_err());
    assert!(Ticket::mint(Network::Regtest, &p, "has space", 9735).is_err());
    assert!(Ticket::mint(Network::Regtest, &p, "[::1]", 9735).is_err()); // IPv6 out of scope
    assert!(Ticket::mint(Network::Regtest, &p, &"a".repeat(65), 9735).is_err());
    assert!(Ticket::mint(Network::Regtest, &p, "127.0.0.1", 0).is_err());
}

// ============================================================================
// encode → decode round-trips, incl. min/max host and high port.
// ============================================================================

#[test]
fn encode_decode_round_trips() {
    let p = params();
    for (net, host, port) in [
        (Network::Regtest, "127.0.0.1", 9735u16),
        (Network::Testnet, "a", 1),                 // min host, min nonzero port
        (Network::Testnet, &*"h".repeat(64), 65535), // max host, high port
        (Network::Regtest, "node-1.example.com", 18333),
    ] {
        let t = Ticket::mint(net, &p, host, port).unwrap();
        let s = t.encode();
        assert!(s.starts_with("skt1"), "ticket must be skt1-prefixed: {s}");
        let back = Ticket::decode(&s).expect("round-trip decode");
        assert_eq!(back, t);
        assert_eq!(back.addr(), format!("{host}:{port}"));
        // A round-tripped ticket still validates against the same wallet facts.
        assert!(back.validate(net, &p).is_ok());
    }
}

#[test]
fn typical_regtest_ticket_length_is_modest() {
    let t = Ticket::mint(Network::Regtest, &params(), "127.0.0.1", 9735).unwrap();
    let s = t.encode();
    println!("regtest 127.0.0.1:9735 ticket = {} chars: {s}", s.len());
    assert!(s.len() < 256, "a typical ticket must sit well under the 256 cap");
}

// ============================================================================
// rendezvous over the duplex ChannelTransport.
// ============================================================================

#[test]
fn rendezvous_happy_path_echoes_the_nonce() {
    let (mut a, mut b) = duplex();
    let nonce = [0x5Au8; 16];
    let h = std::thread::spawn(move || maker_rendezvous(&mut b, &nonce));
    taker_rendezvous(&mut a, &nonce).expect("taker rendezvous");
    h.join().unwrap().expect("maker rendezvous");
}

#[test]
fn maker_refuses_a_wrong_nonce() {
    let (mut a, mut b) = duplex();
    let taker_nonce = [1u8; 16];
    let maker_expected = [2u8; 16];
    let h = std::thread::spawn(move || {
        // Taker offers a nonce the maker never minted; its own recv will then
        // error once the maker drops without echoing — that is fine.
        let _ = taker_rendezvous(&mut a, &taker_nonce);
    });
    let r = maker_rendezvous(&mut b, &maker_expected);
    assert!(matches!(r, Err(Error::Validation(_))), "wrong nonce must refuse, got {r:?}");
    drop(b); // unblock the taker thread's pending recv promptly
    h.join().unwrap();
}

#[test]
fn taker_refuses_a_non_echoing_or_wrong_nonce_maker() {
    // (a) garbage (wrong-length) reply.
    {
        let (mut a, mut b) = duplex();
        let nonce = [9u8; 16];
        let h = std::thread::spawn(move || {
            let _ = b.recv().unwrap(); // consume TAKE
            b.send(&[0xFFu8; 4]).unwrap(); // garbage echo
        });
        assert!(matches!(taker_rendezvous(&mut a, &nonce), Err(Error::Validation(_))));
        h.join().unwrap();
    }
    // (b) well-formed ECHO carrying a DIFFERENT nonce.
    {
        let (mut a, mut b) = duplex();
        let nonce = [9u8; 16];
        let h = std::thread::spawn(move || {
            let _ = b.recv().unwrap();
            let mut echo = vec![0x01u8, 0x52];
            echo.extend_from_slice(&[0xAAu8; 16]); // wrong nonce
            b.send(&echo).unwrap();
        });
        match taker_rendezvous(&mut a, &nonce) {
            Err(Error::Validation(m)) => assert!(m.contains("nonce"), "{m}"),
            other => panic!("wrong-nonce echo must refuse, got {other:?}"),
        }
        h.join().unwrap();
    }
}

#[test]
fn maker_refuses_truncated_or_oversized_take_frames() {
    let expected = [3u8; 16];
    // Truncated TAKE (3 bytes).
    {
        let (mut a, mut b) = duplex();
        a.send(&[0x01u8, 0x51, 0x00]).unwrap();
        assert!(matches!(maker_rendezvous(&mut b, &expected), Err(Error::Validation(_))));
    }
    // Oversized TAKE (2 + 64 bytes).
    {
        let (mut a, mut b) = duplex();
        let mut frame = vec![0x01u8, 0x51];
        frame.extend_from_slice(&[0u8; 64]);
        a.send(&frame).unwrap();
        assert!(matches!(maker_rendezvous(&mut b, &expected), Err(Error::Validation(_))));
    }
    // Wrong kind (an ECHO where a TAKE is expected).
    {
        let (mut a, mut b) = duplex();
        let mut frame = vec![0x01u8, 0x52];
        frame.extend_from_slice(&expected);
        a.send(&frame).unwrap();
        assert!(matches!(maker_rendezvous(&mut b, &expected), Err(Error::Validation(_))));
    }
}
