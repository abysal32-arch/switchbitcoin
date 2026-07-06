//! Signing sessions — nonce-lifecycle invariants INV-1..4 (v3.16 Requirement 3).
//!
//! This is the single most dangerous module in the codebase. Nonce reuse across
//! two sessions leaks the secret key ALGEBRAICALLY — silent, total, unrecoverable.
//! The invariants are encoded in the TYPES so the compiler helps enforce them:
//!
//!   INV-1  secret nonce never leaves volatile memory
//!          -> `SecretNonce` is `!Clone`, `!Serialize`, `#[zeroize]` on drop,
//!             and never returned by value from this module.
//!   INV-2  no session survives a process restart
//!          -> `SigningSession` holds `SecretNonce`; it is created ONLY in-memory
//!             at Phase 5 and has NO (de)serialization. A restart drops it, and
//!             `settlement` maps a missing/incomplete session to ABORT_REFUND.
//!   INV-3  two devices never sign one swap at once
//!          -> construction requires a `SingleSignerLease` (see below).
//!   INV-4  fresh nonce per session/retry/attempt; never reused
//!          -> the only constructor calls the pinned NonceGen with fresh OS
//!             randomness; there is no "reuse" or "resume" path to call.
//!
//! CRYPTOGRAPHER REVIEW ITEM #4 targets exactly this module: find any real-world
//! event sequence (crash, lease handoff, retry, watchtower) that reuses a nonce.

use crate::crypto::{ValidatedPubNonce, ValidatedPartial};
use crate::crypto::adaptor::{AdaptorPoint, CompletePreSig};
use crate::{Error, Result};
use zeroize::Zeroize;

/// Proof that THIS process holds the exclusive signing lease for a swap (INV-3).
/// Keyed to swap_session_id. Acquiring it must be atomic across devices (e.g. a
/// lease record the watchtower/second device also respects). Non-`Clone` on
/// purpose: you cannot duplicate the right to sign.
#[derive(Debug)]
pub struct SingleSignerLease {
    pub swap_session_id: [u8; 32],
    _noncopy: core::marker::PhantomData<*const ()>, // not Send/Sync by default: don't ship across threads casually
}

impl SingleSignerLease {
    /// IMPLEMENT: acquire the lease atomically; fail if another holder exists.
    pub fn acquire(_swap_session_id: [u8; 32]) -> Result<Self> {
        Err(Error::Unimplemented("SingleSignerLease::acquire: atomic cross-device lease"))
    }
}

/// A secret nonce. INV-1: volatile only. No Clone, no Serialize, zeroized on drop.
/// It is NEVER exposed outside this module by value.
struct SecretNonce {
    // IMPLEMENT: wrap `musig2::SecNonce`. Keep it PRIVATE.
    bytes: [u8; 64],
}

impl Drop for SecretNonce {
    fn drop(&mut self) {
        self.bytes.zeroize(); // scrub on drop (INV-1)
    }
}
// Intentionally NOT deriving/!implementing Clone, Copy, Serialize, Debug-with-secret.

/// One MuSig2 signing session. Holds the secret nonce; cannot be serialized,
/// cloned, or resumed. Dropping it (crash/restart) destroys the only signing
/// state — which is exactly INV-2.
pub struct SigningSession {
    lease: SingleSignerLease,
    secret_nonce: SecretNonce,
    pub public_nonce: ValidatedPubNonce,
    // IMPLEMENT: keep aggregate context handles (KeyAggContext, message, agg nonce
    // once known). None of this is persisted.
    committed_both_sessions: bool, // concurrent-session interlock (review item #3)
}

impl SigningSession {
    /// Begin a session. INV-4: generates a FRESH nonce from the pinned NonceGen
    /// with OS randomness. There is deliberately no `resume`, `from_bytes`, or
    /// `with_nonce` constructor anywhere.
    pub fn begin(lease: SingleSignerLease /*, keyagg ctx, msg */) -> Result<Self> {
        // IMPLEMENT: let (sec, pubn) = musig2 NonceGen(fresh OS rng, sk, msg, aux);
        // wrap sec in SecretNonce, validate pubn into ValidatedPubNonce.
        let _ = &lease;
        Err(Error::Unimplemented("SigningSession::begin: pinned NonceGen with fresh randomness"))
    }

    /// Concurrent-session interlock (review item #3): both Comp->SH and Comp->SL
    /// public nonces must be COMMITTED before EITHER is revealed. Call this on
    /// both sessions before revealing nonces; refuse to proceed otherwise.
    pub fn mark_both_committed(&mut self) {
        self.committed_both_sessions = true;
    }

    /// Produce this party's partial signature, adaptor-bound to T.
    /// Consuming `self` here is a design lever the implementer may use to make the
    /// session single-use at the type level (helps INV-4). At minimum, a session
    /// must refuse to sign twice.
    pub fn sign_partial(self, _t: &AdaptorPoint) -> Result<ValidatedPartial> {
        if !self.committed_both_sessions {
            return Err(Error::Ordering("nonce revealed before both sessions committed (concurrent-session interlock)"));
        }
        // IMPLEMENT: musig2 partial-sign with adaptor tweak T. `self` drops here,
        // zeroizing the secret nonce — it can never sign again.
        Err(Error::Unimplemented("SigningSession::sign_partial: adaptor-bound partial sign, then drop"))
    }
}

/// Verify a counterparty partial (BIP327 PartialSigVerify) — REQUIRED before it
/// is aggregated. A partial is verifiable for blame; do not skip this.
pub fn verify_partial(
    _partial: &ValidatedPartial,
    _their_pub_nonce: &ValidatedPubNonce,
    _t: &AdaptorPoint,
) -> Result<()> {
    Err(Error::Unimplemented("verify_partial: musig2 PartialSigVerify + adaptor check"))
}

/// Assemble a COMPLETE pre-signature from both verified partials over the agreed
/// aggregate nonce (Gate G1 material). Cannot be built from one partial.
pub fn assemble_complete_presig(
    _ours: &ValidatedPartial,
    _theirs: &ValidatedPartial,
    _t: &AdaptorPoint,
) -> Result<CompletePreSig> {
    Err(Error::Unimplemented("assemble_complete_presig: aggregate both partials, adaptor-bound"))
}
