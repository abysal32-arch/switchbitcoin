//! Requirement 4 interim harness: property-based totality testing of the wire
//! parser on stable Rust/Windows, until the real libFuzzer+ASan job runs (WSL2
//! or Linux CI — see fuzz/). Contract under test: `parse_message` AND the
//! Task 05 envelope opener `open_message` are TOTAL — every byte string maps
//! to Ok|Err, never a panic. Any panic fails these tests.
//!
//! Raise PROPTEST_CASES in CI to hammer harder (e.g. PROPTEST_CASES=1000000).

use swapkey::wire::{open_message, parse_message, seal_message, serialize_message, Message};
use swapkey::crypto::{ValidatedPartial, ValidatedPoint, ValidatedPubNonce};
use swapkey::crypto::adaptor::AdaptorPoint;
use proptest::prelude::*;
use secp::{Scalar, G};

fn scalar_from_u32(k: u32) -> Scalar {
    let mut b = [0u8; 32];
    b[28..].copy_from_slice(&k.to_be_bytes());
    Scalar::from_slice(&b).expect("nonzero scalar")
}

fn valid_point(k: u32) -> ValidatedPoint {
    ValidatedPoint::from_bytes(&(scalar_from_u32(k.max(1)) * G).serialize()).expect("point")
}

fn valid_nonce(k: u32) -> ValidatedPubNonce {
    let mut b = [0u8; 66];
    b[..33].copy_from_slice(&(scalar_from_u32(k.max(1)) * G).serialize());
    b[33..].copy_from_slice(&(scalar_from_u32(k.max(1) + 1) * G).serialize());
    ValidatedPubNonce::from_bytes(&b).expect("nonce")
}

fn valid_partial(k: u32) -> ValidatedPartial {
    let mut b = [0u8; 32];
    b[28..].copy_from_slice(&k.to_be_bytes());
    ValidatedPartial::from_bytes(&b).expect("partial")
}

fn arb_valid_message() -> impl Strategy<Value = Message> {
    (any::<u32>(), any::<u32>(), 0u8..6, any::<[u8; 32]>()).prop_map(|(a, b, which, h)| match which {
        0 => Message::Nonces { comp_sh: valid_nonce(a), comp_sl: valid_nonce(b) },
        1 => Message::AdaptorPointMsg(AdaptorPoint::new(valid_point(a))),
        2 => Message::ShPartials { comp_sh: valid_partial(a), comp_sl: valid_partial(b) },
        3 => Message::SlEnablingPartial(valid_partial(a)),
        4 => Message::Destination(valid_point(a)),
        _ => Message::NonceCommitment(h),
    })
}

proptest! {
    /// Arbitrary bytes: parser is total. (The fuzz target's exact contract.)
    #[test]
    fn parse_never_panics_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse_message(&data);
    }

    /// Valid messages round-trip bit-exactly.
    #[test]
    fn valid_messages_round_trip(m in arb_valid_message()) {
        let bytes = serialize_message(&m);
        let back = parse_message(&bytes).expect("valid message must parse");
        prop_assert_eq!(serialize_message(&back), bytes);
    }

    /// Mutations of valid messages: still total, and any accepted mutation
    /// re-serializes canonically (no malleable accepted encodings).
    #[test]
    fn mutated_valid_messages_stay_total(
        m in arb_valid_message(),
        cut in 0usize..200,
        extend in proptest::collection::vec(any::<u8>(), 0..8),
        flip_at in any::<usize>(),
        flip_bit in 0u8..8,
    ) {
        let mut bytes = serialize_message(&m);
        bytes.truncate(bytes.len().saturating_sub(cut));
        bytes.extend_from_slice(&extend);
        if !bytes.is_empty() {
            let i = flip_at % bytes.len();
            bytes[i] ^= 1 << flip_bit;
        }
        if let Ok(parsed) = parse_message(&bytes) {
            // Accepted -> must be canonical: exact same bytes back.
            prop_assert_eq!(serialize_message(&parsed), bytes);
        }
    }

    /// Arbitrary bytes: the envelope opener is total (the second fuzz target).
    #[test]
    fn open_never_panics_on_arbitrary_bytes(
        sid in any::<[u8; 32]>(),
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let _ = open_message(&sid, &data);
    }

    /// Sealed messages round-trip under their session id, and re-seal
    /// canonically.
    #[test]
    fn sealed_messages_round_trip(m in arb_valid_message(), sid in any::<[u8; 32]>()) {
        let bytes = seal_message(&sid, &m);
        let back = open_message(&sid, &bytes).expect("sealed message must open");
        prop_assert_eq!(&back, &m);
        prop_assert_eq!(seal_message(&sid, &back), bytes);
    }

    /// A sealed frame NEVER opens under a different session id (cross-session
    /// splice rejection).
    #[test]
    fn sealed_messages_reject_other_sessions(
        m in arb_valid_message(),
        sid in any::<[u8; 32]>(),
        other in any::<[u8; 32]>(),
    ) {
        prop_assume!(sid != other);
        let bytes = seal_message(&sid, &m);
        prop_assert!(open_message(&other, &bytes).is_err());
    }

    /// Every proper truncation of a sealed frame must Err (a frame is not a
    /// prefix), never panic.
    #[test]
    fn truncated_sealed_messages_always_err(
        m in arb_valid_message(),
        sid in any::<[u8; 32]>(),
        cut in 1usize..200,
    ) {
        let bytes = seal_message(&sid, &m);
        let keep = bytes.len().saturating_sub(cut);
        prop_assert!(open_message(&sid, &bytes[..keep]).is_err());
    }

    /// Mutations of sealed frames: still total, and any accepted mutation
    /// re-seals canonically under the expected session id.
    #[test]
    fn mutated_sealed_messages_stay_total(
        m in arb_valid_message(),
        sid in any::<[u8; 32]>(),
        cut in 0usize..200,
        extend in proptest::collection::vec(any::<u8>(), 0..8),
        flip_at in any::<usize>(),
        flip_bit in 0u8..8,
    ) {
        let mut bytes = seal_message(&sid, &m);
        bytes.truncate(bytes.len().saturating_sub(cut));
        bytes.extend_from_slice(&extend);
        if !bytes.is_empty() {
            let i = flip_at % bytes.len();
            bytes[i] ^= 1 << flip_bit;
        }
        if let Ok(parsed) = open_message(&sid, &bytes) {
            prop_assert_eq!(seal_message(&sid, &parsed), bytes);
        }
    }
}
