//! The validation gate (v3.16 Requirement 2).
//!
//! Motivation: in Dec 2025 fuzzing found Bitcoin Core would deserialize MuSig2
//! PSBT pubkeys WITHOUT confirming they were valid secp256k1 points. Our
//! counterparty is Byzantine; every point/scalar on the wire is hostile input.
//!
//! Each newtype below can ONLY be constructed by passing validation. There is no
//! other constructor. `wire` parsing produces these types, so anything that type-
//! checks downstream has already been validated. Invalid input => `Error::Validation`,
//! which the caller turns into `Error::Abort` (never a panic, never a proceed).

use crate::{Error, Result};

// NOTE for the implementer: swap these stand-in inner types for the real ones,
// e.g. `secp256k1::PublicKey`, `musig2::PubNonce`, `secp256k1::Scalar`.
// Keep them PRIVATE so the only way in is the validating constructor.

/// A secp256k1 point confirmed on-curve and not the identity.
#[derive(Clone, Debug)]
pub struct ValidatedPoint(/* secp256k1::PublicKey */ [u8; 33]);

/// A scalar confirmed in range [1, n-1] (nonzero, < curve order).
#[derive(Clone, Debug)]
pub struct ValidatedScalar(/* secp256k1::Scalar */ [u8; 32]);

/// A MuSig2 public nonce (pair of points) confirmed well-formed.
#[derive(Clone, Debug)]
pub struct ValidatedPubNonce(/* musig2::PubNonce */ [u8; 66]);

/// A MuSig2 partial signature confirmed to be a valid scalar.
/// NOTE: BIP327 partials are verifiable for blame but are NOT unforgeable on
/// their own — see `adaptor`/`signing` for where PartialSigVerify is REQUIRED.
#[derive(Clone, Debug)]
pub struct ValidatedPartial(/* musig2::PartialSignature */ [u8; 32]);

impl ValidatedPoint {
    /// Validate 33 compressed bytes as an on-curve, non-identity point.
    pub fn from_bytes(_b: &[u8; 33]) -> Result<Self> {
        // IMPLEMENT: secp256k1::PublicKey::from_slice(b) — returns Err on
        // off-curve/malformed. Reject the point at infinity explicitly.
        // On success: Ok(ValidatedPoint(pk)). On any error: below.
        Err(Error::Unimplemented("ValidatedPoint::from_bytes: call secp256k1::PublicKey::from_slice + reject identity"))
    }
}

impl ValidatedScalar {
    /// Validate 32 bytes as a scalar in [1, n-1].
    pub fn from_bytes(_b: &[u8; 32]) -> Result<Self> {
        // IMPLEMENT: reject zero; reject >= curve order n. Use secp256k1::Scalar
        // parsing which enforces the range, then explicitly reject zero.
        Err(Error::Unimplemented("ValidatedScalar::from_bytes: enforce 1<=s<n"))
    }
}

impl ValidatedPubNonce {
    pub fn from_bytes(_b: &[u8; 66]) -> Result<Self> {
        // IMPLEMENT: parse both points via the pinned musig2 crate; each must be
        // on-curve. A malformed nonce here must NOT be silently coerced.
        Err(Error::Unimplemented("ValidatedPubNonce::from_bytes: validate both nonce points"))
    }
}

impl ValidatedPartial {
    pub fn from_bytes(_b: &[u8; 32]) -> Result<Self> {
        // IMPLEMENT: range-check as a scalar. (Cryptographic verification that the
        // partial is CORRECT for a given session is separate — see signing.)
        Err(Error::Unimplemented("ValidatedPartial::from_bytes: scalar range-check"))
    }
}

// --- Fuzz entry point (Requirement 4) -------------------------------------
// The wire parser calls these. The fuzz target throws arbitrary bytes at
// `wire::parse_message`, which must NEVER panic — only ever return Err. See
// fuzz/fuzz_targets/wire_parse.rs.
