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
//!
//! Inner types are the `secp`/`musig2` type family (Req 1: these delegate all
//! curve math to libsecp256k1 — no pure-Rust backend). Fields stay PRIVATE; the
//! `pub(crate)` accessors hand the inner value to the crypto/signing modules
//! only. `to_bytes` is safe to expose: serializing is not a validation bypass.

use crate::{Error, Result};
use musig2::{LiftedSignature, PartialSignature, PubNonce};
use secp::{Point, Scalar};

/// A secp256k1 point confirmed on-curve and not the identity.
/// (`secp::Point` is non-infinity by construction; parsing rejects the rest.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPoint(Point);

/// A scalar confirmed in range [1, n-1] (nonzero, < curve order).
/// Used for secret keys and adaptor secrets — NOT for partial signatures,
/// which are allowed to be zero (see `ValidatedPartial`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedScalar(Scalar);

/// A MuSig2 public nonce (pair of points) confirmed well-formed:
/// both 33-byte encodings must parse as on-curve, non-infinity points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPubNonce(PubNonce);

/// A MuSig2 partial signature confirmed to be a scalar in [0, n).
///
/// NOTE (BIP327): zero IS a legal partial-signature value, so this deliberately
/// does NOT reuse `ValidatedScalar`'s reject-zero rule. Also: a range-valid
/// partial is verifiable for blame but NOT unforgeable on its own — see
/// `signing::verify_partial` for where PartialSigVerify is REQUIRED.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPartial(PartialSignature);

/// A finalized BIP340 signature (R, s) parsed from mempool/chain, confirmed
/// well-formed (R lifts to an on-curve even-Y point, s in [0, n)).
///
/// This is deliberately distinct from `ValidatedPartial`: extraction
/// (`crypto::adaptor::CompletePreSig::extract_secret`) needs the FULL final
/// signature, and a final signature is not a partial — the type distinction
/// prevents the two from ever being confused in the extraction path.
#[derive(Clone, Debug)]
pub struct ValidatedFinalSig(LiftedSignature);

impl ValidatedPoint {
    /// Validate 33 compressed bytes as an on-curve, non-identity point.
    pub fn from_bytes(b: &[u8; 33]) -> Result<Self> {
        Point::from_slice(b)
            .map(ValidatedPoint)
            .map_err(|_| Error::Validation("not a valid compressed secp256k1 point"))
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        self.0.serialize()
    }

    pub(crate) fn point(&self) -> Point {
        self.0
    }

    /// Crate-internal wrap of a point that is valid BY TYPE (already a
    /// `secp::Point`, e.g. freshly derived from a secret). Not a gate bypass:
    /// the type itself is the proof of validity.
    pub(crate) fn from_valid(p: Point) -> Self {
        ValidatedPoint(p)
    }
}

impl ValidatedScalar {
    /// Validate 32 bytes as a scalar in [1, n-1]. Rejects zero and >= n.
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self> {
        Scalar::from_slice(b)
            .map(ValidatedScalar)
            .map_err(|_| Error::Validation("scalar out of range [1, n-1]"))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.serialize()
    }

    // Used by the tx layer (key/tweak handling); not yet called in this build.
    #[allow(dead_code)]
    pub(crate) fn scalar(&self) -> Scalar {
        self.0
    }
}

impl ValidatedPubNonce {
    /// Validate 66 bytes as two on-curve, non-infinity nonce points.
    /// A malformed nonce is NOT silently coerced — it is an Err, full stop.
    pub fn from_bytes(b: &[u8; 66]) -> Result<Self> {
        PubNonce::from_bytes(b)
            .map(ValidatedPubNonce)
            .map_err(|_| Error::Validation("malformed MuSig2 public nonce"))
    }

    pub fn to_bytes(&self) -> [u8; 66] {
        self.0.serialize()
    }

    pub(crate) fn nonce(&self) -> &PubNonce {
        &self.0
    }

    pub(crate) fn from_valid(n: PubNonce) -> Self {
        ValidatedPubNonce(n)
    }
}

impl ValidatedPartial {
    /// Validate 32 bytes as a scalar in [0, n). Zero is allowed (BIP327).
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self> {
        PartialSignature::try_from(&b[..])
            .map(ValidatedPartial)
            .map_err(|_| Error::Validation("partial signature scalar >= n"))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.serialize()
    }

    pub(crate) fn partial(&self) -> PartialSignature {
        self.0
    }

    pub(crate) fn from_valid(p: PartialSignature) -> Self {
        ValidatedPartial(p)
    }
}

impl ValidatedFinalSig {
    /// Validate a 64-byte BIP340 signature read from mempool/chain.
    pub fn from_bytes(b: &[u8; 64]) -> Result<Self> {
        LiftedSignature::from_bytes(b)
            .map(ValidatedFinalSig)
            .map_err(|_| Error::Validation("malformed BIP340 signature"))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.serialize()
    }

    pub(crate) fn sig(&self) -> &LiftedSignature {
        &self.0
    }
}

// --- Fuzz entry point (Requirement 4) -------------------------------------
// The wire parser calls these. The fuzz target throws arbitrary bytes at
// `wire::parse_message`, which must NEVER panic — only ever return Err. See
// fuzz/fuzz_targets/wire_parse.rs.

#[cfg(test)]
mod tests {
    use super::*;
    use secp::G;

    #[test]
    fn point_gate_rejects_garbage_and_identity_encodings() {
        // All-zero: invalid prefix byte, must reject.
        assert!(ValidatedPoint::from_bytes(&[0u8; 33]).is_err());
        // Valid prefix, x-coordinate with no curve solution.
        let mut b = [0xffu8; 33];
        b[0] = 0x02;
        assert!(ValidatedPoint::from_bytes(&b).is_err());
        // The generator round-trips.
        let g = ValidatedPoint::from_valid(Scalar::one() * G);
        assert_eq!(ValidatedPoint::from_bytes(&g.to_bytes()).unwrap(), g);
    }

    #[test]
    fn scalar_gate_rejects_zero_and_overflow() {
        assert!(ValidatedScalar::from_bytes(&[0u8; 32]).is_err());
        assert!(ValidatedScalar::from_bytes(&[0xffu8; 32]).is_err()); // >= n
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(ValidatedScalar::from_bytes(&one).is_ok());
    }

    #[test]
    fn partial_gate_allows_zero_rejects_overflow() {
        // BIP327: zero is a legal partial signature.
        assert!(ValidatedPartial::from_bytes(&[0u8; 32]).is_ok());
        assert!(ValidatedPartial::from_bytes(&[0xffu8; 32]).is_err()); // >= n
    }

    #[test]
    fn pubnonce_gate_requires_two_valid_points() {
        let g = (Scalar::one() * G).serialize();
        let mut ok = [0u8; 66];
        ok[..33].copy_from_slice(&g);
        ok[33..].copy_from_slice(&g);
        assert!(ValidatedPubNonce::from_bytes(&ok).is_ok());
        // Second point corrupted -> whole nonce rejected.
        let mut bad = ok;
        bad[33] = 0x05;
        assert!(ValidatedPubNonce::from_bytes(&bad).is_err());
    }
}
