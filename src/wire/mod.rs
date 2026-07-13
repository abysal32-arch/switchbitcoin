//! Wire format + parser — the FUZZ TARGET (v3.16 Requirement 4) and the front
//! line of the validation gate (Requirement 2).
//!
//! HARD RULE: `parse_message` and `open_message` must NEVER panic on ANY
//! input — only ever return `Ok(Message)` (fully validated) or `Err`. Every
//! field that is a point/scalar/nonce/partial is parsed THROUGH the
//! `crypto::validate` newtypes, so a parsed `Message` is validated by
//! construction. The fuzzer throws arbitrary bytes at both entry points.
//!
//! Two layers (Task 05):
//! - BARE message (`serialize_message`/`parse_message`): one tag byte, then
//!   fixed-size fields, EXACT length (trailing bytes are an error — a message
//!   is not a prefix).
//! - ENVELOPE (`seal_message`/`open_message`) — what actually crosses a peer
//!   transport: `[version:1][tag:1][len: u32 BE][session_id:32][fields]`.
//!   `len` counts everything after itself (session id + fields) and must
//!   match the remaining bytes EXACTLY. The session id is the DERIVED
//!   `swap_session_id` (settlement layer), so a frame captured from — or
//!   forged for — another swap session fails to open: cross-session splices
//!   are rejected at the byte gate, mirroring the store's filename↔identity
//!   checks. A version byte other than [`WIRE_VERSION`] is rejected before
//!   anything else is parsed. NOTE: the envelope BINDS, it does not
//!   AUTHENTICATE — the sid is public and a MITM can re-seal; equivocation
//!   and substitution are caught by the protocol's crypto interlocks
//!   (commit-reveal, partial verification, G1), not by this header.
//!
//! Transport-facing code MUST use the envelope layer; the bare layer stays
//! public as the fuzz surface and for the envelope's own body encoding.
//!
//! No indexing, no unwrap/expect, no unchecked slicing: `split_at` only after
//! an explicit length check, and array conversion through fallible `try_into`.

use crate::crypto::adaptor::AdaptorPoint;
use crate::crypto::{ValidatedPartial, ValidatedPoint, ValidatedPubNonce};
use crate::{Error, Result};

const TAG_NONCE_COMMIT: u8 = 0x00;
const TAG_NONCES: u8 = 0x01;
const TAG_ADAPTOR_POINT: u8 = 0x02;
const TAG_SH_PARTIALS: u8 = 0x03;
const TAG_SL_ENABLING: u8 = 0x04;
const TAG_DESTINATION: u8 = 0x05;

/// Envelope wire-format version. Bump on ANY layout change; a peer speaking a
/// different version is rejected before a single field is parsed.
pub const WIRE_VERSION: u8 = 0x01;

/// Ceiling on the envelope's declared payload length (session id + fields).
/// Same order as the transport's 1 MiB `MAX_FRAME` (the 6-byte envelope
/// header means a max-length payload would not actually transit — both sides
/// Err); every current message is under 200 bytes, so anything near this
/// bound is hostile. The parse itself never allocates from the declared
/// length — the cap is pure defense in depth.
pub const MAX_ENVELOPE_PAYLOAD: u32 = 1_048_576;

/// The Phase-5 messages, in the exact order the possession gate requires
/// (v3.13 Phase 5 adaptor exchange). Discovery/matching messages are STUBBED
/// out of this build (Requirement 5).
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// (0) Concurrent-session interlock: a 32-byte hash commitment to BOTH of
    /// this party's public nonces (Comp->SH and Comp->SL), sent and matched on
    /// BOTH sides BEFORE either party reveals its nonces. This is what makes
    /// "commit-to-both-before-revealing-either" real on the wire and closes the
    /// concurrent-session (Wagner/Drijvers) adaptive-nonce surface.
    NonceCommitment([u8; 32]),
    /// (1) public nonces for BOTH completions — the REVEAL, checked against the
    /// counterparty's prior commitment before it is trusted.
    Nonces { comp_sh: ValidatedPubNonce, comp_sl: ValidatedPubNonce },
    /// (2) SH publishes T = t*G.
    AdaptorPointMsg(AdaptorPoint),
    /// (3) SH's partials on BOTH completions.
    ShPartials { comp_sh: ValidatedPartial, comp_sl: ValidatedPartial },
    /// (5) SL's single enabling partial on Comp->SH.
    SlEnablingPartial(ValidatedPartial),
    /// Fresh destination pubkey exchange (Phase 5 step 12).
    Destination(ValidatedPoint),
}

/// Take exactly N bytes off the front, or Err. Never panics: length is checked
/// before `split_at`, and the array conversion is fallible by construction.
fn take<const N: usize>(b: &[u8]) -> Result<([u8; N], &[u8])> {
    if b.len() < N {
        return Err(Error::Validation("truncated message"));
    }
    let (head, rest) = b.split_at(N);
    let arr: [u8; N] = head
        .try_into()
        .map_err(|_| Error::Validation("internal length mismatch"))?;
    Ok((arr, rest))
}

/// Reject trailing bytes: every message has exactly one fixed size.
fn finish<T>(value: T, rest: &[u8]) -> Result<T> {
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(Error::Validation("trailing bytes after message"))
    }
}

/// Decode the fixed-size fields for `tag`. Shared by the bare parser and the
/// envelope opener; enforces exact length via `finish`.
fn parse_body(tag: u8, rest: &[u8]) -> Result<Message> {
    match tag {
        TAG_NONCE_COMMIT => {
            let (h, rest) = take::<32>(rest)?;
            finish(Message::NonceCommitment(h), rest)
        }
        TAG_NONCES => {
            let (a, rest) = take::<66>(rest)?;
            let (b, rest) = take::<66>(rest)?;
            let comp_sh = ValidatedPubNonce::from_bytes(&a)?; // <-- gate
            let comp_sl = ValidatedPubNonce::from_bytes(&b)?; // <-- gate
            finish(Message::Nonces { comp_sh, comp_sl }, rest)
        }
        TAG_ADAPTOR_POINT => {
            let (p, rest) = take::<33>(rest)?;
            let t = ValidatedPoint::from_bytes(&p)?; // <-- gate
            finish(Message::AdaptorPointMsg(AdaptorPoint::new(t)), rest)
        }
        TAG_SH_PARTIALS => {
            let (a, rest) = take::<32>(rest)?;
            let (b, rest) = take::<32>(rest)?;
            let comp_sh = ValidatedPartial::from_bytes(&a)?; // <-- gate
            let comp_sl = ValidatedPartial::from_bytes(&b)?; // <-- gate
            finish(Message::ShPartials { comp_sh, comp_sl }, rest)
        }
        TAG_SL_ENABLING => {
            let (a, rest) = take::<32>(rest)?;
            let p = ValidatedPartial::from_bytes(&a)?; // <-- gate
            finish(Message::SlEnablingPartial(p), rest)
        }
        TAG_DESTINATION => {
            let (p, rest) = take::<33>(rest)?;
            let d = ValidatedPoint::from_bytes(&p)?; // <-- gate
            finish(Message::Destination(d), rest)
        }
        _ => Err(Error::Validation("unknown message tag")),
    }
}

/// THE fuzz entry point (bare layer). Must be total: every byte string maps to
/// Ok|Err, never panic.
pub fn parse_message(bytes: &[u8]) -> Result<Message> {
    let (tag, rest) = match bytes.split_first() {
        Some((t, r)) => (*t, r),
        None => return Err(Error::Validation("empty message")),
    };
    parse_body(tag, rest)
}

/// Encode `m`'s tag and fixed-size fields (fields WITHOUT the tag byte).
fn encode_body(m: &Message) -> (u8, Vec<u8>) {
    match m {
        Message::NonceCommitment(h) => (TAG_NONCE_COMMIT, h.to_vec()),
        Message::Nonces { comp_sh, comp_sl } => {
            let mut v = Vec::with_capacity(66 + 66);
            v.extend_from_slice(&comp_sh.to_bytes());
            v.extend_from_slice(&comp_sl.to_bytes());
            (TAG_NONCES, v)
        }
        Message::AdaptorPointMsg(t) => (TAG_ADAPTOR_POINT, t.to_bytes().to_vec()),
        Message::ShPartials { comp_sh, comp_sl } => {
            let mut v = Vec::with_capacity(32 + 32);
            v.extend_from_slice(&comp_sh.to_bytes());
            v.extend_from_slice(&comp_sl.to_bytes());
            (TAG_SH_PARTIALS, v)
        }
        Message::SlEnablingPartial(p) => (TAG_SL_ENABLING, p.to_bytes().to_vec()),
        Message::Destination(d) => (TAG_DESTINATION, d.to_bytes().to_vec()),
    }
}

/// Serialize is the easy direction; still fixed-size and total.
pub fn serialize_message(m: &Message) -> Vec<u8> {
    let (tag, body) = encode_body(m);
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(tag);
    v.extend_from_slice(&body);
    v
}

/// Seal `m` for the peer channel, bound to `session_id` (the DERIVED
/// swap_session_id): `[version:1][tag:1][len: u32 BE][session_id:32][fields]`.
pub fn seal_message(session_id: &[u8; 32], m: &Message) -> Vec<u8> {
    let (tag, body) = encode_body(m);
    // Fits u32 by construction: every body is a fixed size under 200 bytes.
    let len = (32 + body.len()) as u32;
    let mut v = Vec::with_capacity(1 + 1 + 4 + 32 + body.len());
    v.push(WIRE_VERSION);
    v.push(tag);
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(session_id);
    v.extend_from_slice(&body);
    v
}

/// The envelope fuzz entry point. Must be total: every byte string maps to
/// Ok|Err, never panic. Rejects, in order: wrong version, truncated header,
/// absurd declared length, any length/byte-count mismatch (covers BOTH
/// truncation and trailing bytes), a session id other than `session_id`,
/// then everything the bare-body gate rejects.
pub fn open_message(session_id: &[u8; 32], bytes: &[u8]) -> Result<Message> {
    let (version, rest) = match bytes.split_first() {
        Some((v, r)) => (*v, r),
        None => return Err(Error::Validation("empty envelope")),
    };
    if version != WIRE_VERSION {
        return Err(Error::Validation("unsupported wire version"));
    }
    let (tag, rest) = match rest.split_first() {
        Some((t, r)) => (*t, r),
        None => return Err(Error::Validation("truncated envelope")),
    };
    let (len_bytes, rest) = take::<4>(rest)?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_ENVELOPE_PAYLOAD {
        return Err(Error::Validation("absurd envelope length"));
    }
    if len as usize != rest.len() {
        return Err(Error::Validation("envelope length mismatch"));
    }
    let (sid, body) = take::<32>(rest)?;
    if &sid != session_id {
        return Err(Error::Validation("wire message for a different session"));
    }
    parse_body(tag, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp::{Scalar, G};

    fn scalar_from_u32(k: u32) -> Scalar {
        let mut b = [0u8; 32];
        b[28..].copy_from_slice(&k.to_be_bytes());
        Scalar::from_slice(&b).expect("nonzero test scalar")
    }

    fn test_point(k: u32) -> ValidatedPoint {
        ValidatedPoint::from_bytes(&(scalar_from_u32(k) * G).serialize()).expect("valid point")
    }

    fn test_nonce() -> ValidatedPubNonce {
        let mut b = [0u8; 66];
        b[..33].copy_from_slice(&(scalar_from_u32(1) * G).serialize());
        b[33..].copy_from_slice(&(scalar_from_u32(2) * G).serialize());
        ValidatedPubNonce::from_bytes(&b).expect("valid nonce")
    }

    fn test_partial(fill: u8) -> ValidatedPartial {
        let mut b = [0u8; 32];
        b[31] = fill;
        ValidatedPartial::from_bytes(&b).expect("valid partial")
    }

    /// One of each Message variant — every totality/round-trip test sweeps this.
    fn all_variants() -> Vec<Message> {
        vec![
            Message::NonceCommitment([0x5au8; 32]),
            Message::Nonces { comp_sh: test_nonce(), comp_sl: test_nonce() },
            Message::AdaptorPointMsg(AdaptorPoint::new(test_point(7))),
            Message::ShPartials { comp_sh: test_partial(1), comp_sl: test_partial(0) },
            Message::SlEnablingPartial(test_partial(9)),
            Message::Destination(test_point(11)),
        ]
    }

    const SID: [u8; 32] = [0xC1u8; 32];

    #[test]
    fn round_trips_every_variant() {
        for m in all_variants() {
            let bytes = serialize_message(&m);
            let back = parse_message(&bytes).expect("round trip");
            assert_eq!(serialize_message(&back), bytes);
        }
    }

    #[test]
    fn rejects_empty_unknown_truncated_and_trailing() {
        assert!(parse_message(&[]).is_err());
        assert!(parse_message(&[0x00]).is_err());
        assert!(parse_message(&[0xff, 1, 2, 3]).is_err());
        // Truncated nonce message.
        assert!(parse_message(&[TAG_NONCES, 0x02]).is_err());
        // Valid message + trailing byte must be rejected.
        let mut bytes = serialize_message(&Message::SlEnablingPartial(test_partial(1)));
        bytes.push(0);
        assert!(parse_message(&bytes).is_err());
    }

    #[test]
    fn rejects_off_curve_point_in_valid_frame() {
        let mut frame = vec![TAG_DESTINATION];
        let mut bad = [0xffu8; 33];
        bad[0] = 0x02;
        frame.extend_from_slice(&bad);
        assert!(parse_message(&frame).is_err());
    }

    #[test]
    fn every_bare_truncation_errs() {
        for m in all_variants() {
            let bytes = serialize_message(&m);
            for i in 0..bytes.len() {
                assert!(
                    parse_message(&bytes[..i]).is_err(),
                    "truncation to {i} of {m:?} must Err"
                );
            }
        }
    }

    #[test]
    fn sealed_round_trips_every_variant() {
        for m in all_variants() {
            let bytes = seal_message(&SID, &m);
            let back = open_message(&SID, &bytes).expect("sealed round trip");
            assert_eq!(back, m);
            assert_eq!(seal_message(&SID, &back), bytes, "re-seal must be canonical");
        }
    }

    #[test]
    fn every_sealed_truncation_errs() {
        for m in all_variants() {
            let bytes = seal_message(&SID, &m);
            for i in 0..bytes.len() {
                assert!(
                    open_message(&SID, &bytes[..i]).is_err(),
                    "sealed truncation to {i} of {m:?} must Err"
                );
            }
        }
    }

    #[test]
    fn sealed_rejects_wrong_session() {
        for m in all_variants() {
            let bytes = seal_message(&SID, &m);
            let other = [0xC2u8; 32];
            assert!(open_message(&other, &bytes).is_err(), "cross-session splice must Err");
        }
    }

    #[test]
    fn sealed_rejects_wrong_version() {
        for m in all_variants() {
            for bad in [0x00u8, WIRE_VERSION + 1, 0xff] {
                let mut bytes = seal_message(&SID, &m);
                bytes[0] = bad;
                assert!(open_message(&SID, &bytes).is_err(), "version {bad:#x} must Err");
            }
        }
    }

    #[test]
    fn sealed_rejects_length_field_tampering() {
        for m in all_variants() {
            let good = seal_message(&SID, &m);
            let true_len = (good.len() - 6) as u32;
            for bad_len in [true_len - 1, true_len + 1, 0, u32::MAX] {
                let mut bytes = good.clone();
                bytes[2..6].copy_from_slice(&bad_len.to_be_bytes());
                assert!(
                    open_message(&SID, &bytes).is_err(),
                    "declared len {bad_len} (true {true_len}) must Err"
                );
            }
        }
    }

    #[test]
    fn sealed_rejects_trailing_bytes() {
        for m in all_variants() {
            let mut bytes = seal_message(&SID, &m);
            bytes.push(0);
            assert!(open_message(&SID, &bytes).is_err(), "trailing byte must Err");
        }
    }

    #[test]
    fn sealed_rejects_absurd_declared_length() {
        // A frame whose declared length is over the cap AND whose byte count
        // backs it up: the cap must fire (not just the length mismatch).
        let over = MAX_ENVELOPE_PAYLOAD as usize + 1;
        let mut bytes = Vec::with_capacity(6 + over);
        bytes.push(WIRE_VERSION);
        bytes.push(TAG_NONCE_COMMIT);
        bytes.extend_from_slice(&(over as u32).to_be_bytes());
        bytes.resize(6 + over, 0xEE);
        assert!(open_message(&SID, &bytes).is_err());
    }

    #[test]
    fn sealed_rejects_short_declared_length_under_session_id() {
        // len < 32: not even room for the session id — must Err, not panic.
        let mut bytes = vec![WIRE_VERSION, TAG_NONCE_COMMIT];
        bytes.extend_from_slice(&31u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 31]);
        assert!(open_message(&SID, &bytes).is_err());
    }
}
