//! Wire format + parser — the FUZZ TARGET (v3.16 Requirement 4) and the front
//! line of the validation gate (Requirement 2).
//!
//! HARD RULE: `parse_message` must NEVER panic on ANY input — only ever return
//! `Ok(Message)` (fully validated) or `Err`. Every field that is a point/scalar/
//! nonce/partial is parsed THROUGH the `crypto::validate` newtypes, so a parsed
//! `Message` is validated by construction. The fuzzer throws arbitrary bytes here.
//!
//! Encoding: one tag byte, then fixed-size fields, EXACT length (trailing bytes
//! are an error — a message is not a prefix). No indexing, no unwrap/expect, no
//! unchecked slicing: `split_at` only after an explicit length check, and array
//! conversion through fallible `try_into`.

use crate::crypto::adaptor::AdaptorPoint;
use crate::crypto::{ValidatedPartial, ValidatedPoint, ValidatedPubNonce};
use crate::{Error, Result};

const TAG_NONCES: u8 = 0x01;
const TAG_ADAPTOR_POINT: u8 = 0x02;
const TAG_SH_PARTIALS: u8 = 0x03;
const TAG_SL_ENABLING: u8 = 0x04;
const TAG_DESTINATION: u8 = 0x05;

/// The Phase-5 messages, in the exact order the possession gate requires.
/// (Discovery/matching messages are STUBBED out of this build — Requirement 5.)
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// (1) public nonces for BOTH completions (commit-then-reveal happens above this).
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

/// THE fuzz entry point. Must be total: every byte string maps to Ok|Err, never panic.
pub fn parse_message(bytes: &[u8]) -> Result<Message> {
    let (tag, rest) = match bytes.split_first() {
        Some((t, r)) => (*t, r),
        None => return Err(Error::Validation("empty message")),
    };
    match tag {
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

/// Serialize is the easy direction; still fixed-size and total.
pub fn serialize_message(m: &Message) -> Vec<u8> {
    match m {
        Message::Nonces { comp_sh, comp_sl } => {
            let mut v = Vec::with_capacity(1 + 66 + 66);
            v.push(TAG_NONCES);
            v.extend_from_slice(&comp_sh.to_bytes());
            v.extend_from_slice(&comp_sl.to_bytes());
            v
        }
        Message::AdaptorPointMsg(t) => {
            let mut v = Vec::with_capacity(1 + 33);
            v.push(TAG_ADAPTOR_POINT);
            v.extend_from_slice(&t.to_bytes());
            v
        }
        Message::ShPartials { comp_sh, comp_sl } => {
            let mut v = Vec::with_capacity(1 + 32 + 32);
            v.push(TAG_SH_PARTIALS);
            v.extend_from_slice(&comp_sh.to_bytes());
            v.extend_from_slice(&comp_sl.to_bytes());
            v
        }
        Message::SlEnablingPartial(p) => {
            let mut v = Vec::with_capacity(1 + 32);
            v.push(TAG_SL_ENABLING);
            v.extend_from_slice(&p.to_bytes());
            v
        }
        Message::Destination(d) => {
            let mut v = Vec::with_capacity(1 + 33);
            v.push(TAG_DESTINATION);
            v.extend_from_slice(&d.to_bytes());
            v
        }
    }
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

    #[test]
    fn round_trips_every_variant() {
        let msgs = vec![
            Message::Nonces { comp_sh: test_nonce(), comp_sl: test_nonce() },
            Message::AdaptorPointMsg(AdaptorPoint::new(test_point(7))),
            Message::ShPartials { comp_sh: test_partial(1), comp_sl: test_partial(0) },
            Message::SlEnablingPartial(test_partial(9)),
            Message::Destination(test_point(11)),
        ];
        for m in msgs {
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
}
