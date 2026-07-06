//! Signing sessions — nonce-lifecycle invariants INV-1..4 (v3.16 Requirement 3).
//!
//! This is the single most dangerous module in the codebase. Nonce reuse across
//! two sessions leaks the secret key ALGEBRAICALLY — silent, total, unrecoverable.
//! The invariants are encoded in the TYPES so the compiler helps enforce them:
//!
//!   INV-1  secret nonce never leaves volatile memory
//!          -> `SecretNonce` is `!Clone`, `!Serialize`, private, and never
//!             returned by value from this module.
//!             SCRUBBING CAVEATS (cryptographer review item #4 — disclosed,
//!             not hidden; the real fix belongs upstream in musig2):
//!             (a) musig2 0.4.1's `SecNonce` implements no Zeroize, so the two
//!                 nonce scalars are dropped, not scrubbed.
//!             (b) The seed buffer WE own is `Zeroizing`, but the by-value
//!                 copies handed into `SecNonce::generate`/`NonceSeed` are
//!                 plain `[u8; 32]` copies that drop unscrubbed — and since
//!                 NonceGen is deterministic in its inputs, a residual seed
//!                 copy is equivalent to a residual nonce copy.
//!             (c) The session's `seckey: Scalar` is held unscrubbed for the
//!                 session lifetime (secp 0.7 scalars carry no Zeroize).
//!             Net: INV-1's *no-persistence* half is fully enforced; its
//!             *memory-scrubbing* half is best-effort pending upstream support.
//!   INV-2  no session survives a process restart
//!          -> `SigningSession` holds `SecretNonce`; it is created ONLY in-memory
//!             at Phase 5 and has NO (de)serialization. A restart drops it, and
//!             `settlement` maps a missing/incomplete session to ABORT_REFUND.
//!   INV-3  two devices never sign one swap at once
//!          -> construction requires a `SingleSignerLease` (exclusive-create on
//!             a shared lease record; the local-FS form here is the prototype of
//!             the cross-device store). A crashed process leaves the lease held:
//!             the failure mode is REFUSAL to sign, never a second signer.
//!   INV-4  fresh nonce per session/retry/attempt; never reused
//!          -> the only constructor calls the pinned NonceGen (BIP327
//!             `SecNonce::generate`) with fresh OS randomness; there is no
//!             "reuse" or "resume" path to call.
//!
//! CONCURRENT-SESSION INTERLOCK (review item #3): both completions' public
//! nonces must be COMMITTED before EITHER is revealed. The public nonce is a
//! PRIVATE field, and the only way to read it out is `commit_and_reveal`, which
//! requires BOTH live sessions of the pair — the evidence is in the signature,
//! not in a caller-settable flag.
//!
//! CRYPTOGRAPHER REVIEW ITEM #4 targets exactly this module: find any real-world
//! event sequence (crash, lease handoff, retry, watchtower) that reuses a nonce.

use crate::crypto::adaptor::{AdaptorPoint, CompletePreSig};
use crate::crypto::{ValidatedPartial, ValidatedPoint, ValidatedPubNonce};
use crate::{Error, Result};
use musig2::{AggNonce, KeyAggContext, SecNonce};
use rand::TryRngCore;
use secp::{Point, Scalar};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use zeroize::Zeroizing;

/// Proof that THIS process holds the exclusive signing lease for a swap (INV-3).
/// Keyed to swap_session_id. Acquired by atomic exclusive-create on a lease
/// record; the same primitive ports to the cross-device store (watchtower /
/// second device) — both must respect the same record.
///
/// Non-`Clone` on purpose: you cannot duplicate the right to sign. The two
/// per-completion sessions of ONE swap share the ONE lease via `Rc` (sharing is
/// not duplication — `Rc<SingleSignerLease>` is still one lease, and `Rc` keeps
/// the whole arrangement `!Send`: sessions cannot casually cross threads).
#[derive(Debug)]
pub struct SingleSignerLease {
    swap_session_id: [u8; 32],
    lease_file: PathBuf,
    _noncopy: core::marker::PhantomData<*const ()>, // !Send/!Sync: don't ship across threads
}

fn hex32(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use core::fmt::Write;
        // Infallible for String; ignore the Result rather than unwrap.
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl SingleSignerLease {
    /// Acquire the lease atomically; fail if another holder exists.
    /// Default lease directory (prototype): a fixed per-user location. In
    /// production this record lives in the cross-device store.
    pub fn acquire(swap_session_id: [u8; 32]) -> Result<Rc<Self>> {
        let dir = std::env::temp_dir().join("newkey-leases");
        Self::acquire_in(&dir, swap_session_id)
    }

    /// Acquire against an explicit lease directory (tests; alternate stores).
    pub fn acquire_in(dir: &Path, swap_session_id: [u8; 32]) -> Result<Rc<Self>> {
        std::fs::create_dir_all(dir)
            .map_err(|_| Error::Abort("cannot create lease directory"))?;
        let lease_file = dir.join(hex32(&swap_session_id));
        // create_new = atomic exclusive create: EEXIST means another holder.
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&lease_file) {
            Ok(_) => Ok(Rc::new(SingleSignerLease {
                swap_session_id,
                lease_file,
                _noncopy: core::marker::PhantomData,
            })),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::NonceInvariant(
                "signing lease already held for this swap (INV-3); refusing to sign",
            )),
            Err(_) => Err(Error::Abort("lease acquisition failed")),
        }
    }

    pub fn swap_session_id(&self) -> &[u8; 32] {
        &self.swap_session_id
    }
}

impl Drop for SingleSignerLease {
    fn drop(&mut self) {
        // Best-effort release. A crash skips this — the lease stays held and
        // the swap can only ABORT_REFUND, which is the conservative failure.
        let _ = std::fs::remove_file(&self.lease_file);
    }
}

/// A secret nonce. INV-1: volatile only. No Clone, no Serialize, no Debug,
/// private field, never exposed outside this module. See the module docs for
/// the musig2-0.4.1 zeroization caveat.
struct SecretNonce(SecNonce);

/// One MuSig2 signing session for ONE completion message. Holds the secret
/// nonce; cannot be serialized, cloned, or resumed. Dropping it (crash/restart)
/// destroys the only signing state — which is exactly INV-2.
pub struct SigningSession {
    lease: Rc<SingleSignerLease>,
    secret_nonce: SecretNonce,
    /// PRIVATE: the only read path is `commit_and_reveal`, which requires the
    /// sibling session too (concurrent-session interlock, review item #3).
    public_nonce: ValidatedPubNonce,
    key_agg_ctx: KeyAggContext,
    seckey: Scalar,
    message: [u8; 32],
    /// Set ONLY by `commit_and_reveal` on the session PAIR.
    committed_both_sessions: bool,
}

impl SigningSession {
    /// Begin a session. INV-4: generates a FRESH nonce via the pinned BIP327
    /// NonceGen with fresh OS randomness. There is deliberately no `resume`,
    /// `from_bytes`, or `with_nonce` constructor anywhere.
    ///
    /// `key_agg_ctx` must already carry any taproot tweak: BIP327 binds the
    /// nonce to the TWEAKED aggregate key, so the tweak decision happens at
    /// session construction, never at sign time.
    pub fn begin(
        lease: Rc<SingleSignerLease>,
        key_agg_ctx: KeyAggContext,
        seckey: Scalar,
        message: [u8; 32],
    ) -> Result<Self> {
        // Fresh OS randomness for the seed. Our buffer is scrubbed on drop;
        // the by-value copy `*seed` hands to musig2 is NOT (module-doc caveat b).
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| Error::Abort("OS randomness unavailable; refusing to generate nonce"))?;

        let agg_pubkey: Point = key_agg_ctx.aggregated_pubkey();
        let secnonce = SecNonce::generate(*seed, seckey, agg_pubkey, message, b"newkey-v3.16");
        let public_nonce = ValidatedPubNonce::from_valid(secnonce.public_nonce());

        Ok(SigningSession {
            lease,
            secret_nonce: SecretNonce(secnonce),
            public_nonce,
            key_agg_ctx,
            seckey,
            message,
            committed_both_sessions: false,
        })
    }

    pub fn message(&self) -> &[u8; 32] {
        &self.message
    }

    pub fn key_agg_ctx(&self) -> &KeyAggContext {
        &self.key_agg_ctx
    }

    /// Produce this party's partial signature, adaptor-bound to T, over the
    /// session-pair's agreed aggregate nonce. CONSUMES the session: the secret
    /// nonce is moved into the pinned signer and the session can never sign
    /// again (INV-4 single-use, enforced by the compiler).
    pub fn sign_partial(self, agg_nonce: &AggNonce, t: &AdaptorPoint) -> Result<ValidatedPartial> {
        if !self.committed_both_sessions {
            return Err(Error::Ordering(
                "nonce revealed / signing attempted before both sessions committed (interlock)",
            ));
        }
        let partial = musig2::adaptor::sign_partial(
            &self.key_agg_ctx,
            self.seckey,
            self.secret_nonce.0,
            agg_nonce,
            t.point(),
            self.message,
        )
        .map_err(|_| Error::Verification("partial signing failed"))?;
        Ok(ValidatedPartial::from_valid(partial))
        // `self` drops here; the secret nonce was consumed by the signer.
    }
}

/// The pair of public nonces released together by `commit_and_reveal`.
#[derive(Debug, Clone)]
pub struct RevealedNonces {
    pub comp_sh: ValidatedPubNonce,
    pub comp_sl: ValidatedPubNonce,
}

/// Concurrent-session interlock (review item #3): both Comp->SH and Comp->SL
/// nonces are committed and revealed as ONE atomic step that requires BOTH live
/// sessions of the SAME swap. There is no way to read a session's public nonce
/// without going through here, so "reveal one, then crash, then re-nonce the
/// other" cannot happen at the API level.
pub fn commit_and_reveal(
    comp_sh: &mut SigningSession,
    comp_sl: &mut SigningSession,
) -> Result<RevealedNonces> {
    if !Rc::ptr_eq(&comp_sh.lease, &comp_sl.lease) {
        return Err(Error::Ordering("sessions do not share one swap lease"));
    }
    if comp_sh.message == comp_sl.message {
        return Err(Error::Ordering("session pair must cover two distinct completions"));
    }
    if comp_sh.committed_both_sessions || comp_sl.committed_both_sessions {
        return Err(Error::Ordering("session pair already revealed"));
    }
    comp_sh.committed_both_sessions = true;
    comp_sl.committed_both_sessions = true;
    Ok(RevealedNonces {
        comp_sh: comp_sh.public_nonce.clone(),
        comp_sl: comp_sl.public_nonce.clone(),
    })
}

/// Aggregate the two parties' public nonces for one completion (BIP327 nonce
/// aggregation is order-independent point summation).
pub fn aggregate_nonces(ours: &ValidatedPubNonce, theirs: &ValidatedPubNonce) -> AggNonce {
    AggNonce::sum([ours.nonce().clone(), theirs.nonce().clone()])
}

/// Verify a counterparty partial (BIP327 PartialSigVerify, adaptor-aware) —
/// REQUIRED before it is aggregated. A partial is verifiable for blame; do not
/// skip this. All seven inputs the check needs are taken explicitly.
pub fn verify_partial(
    key_agg_ctx: &KeyAggContext,
    partial: &ValidatedPartial,
    agg_nonce: &AggNonce,
    t: &AdaptorPoint,
    their_pubkey: &ValidatedPoint,
    their_pubnonce: &ValidatedPubNonce,
    message: &[u8; 32],
) -> Result<()> {
    musig2::adaptor::verify_partial(
        key_agg_ctx,
        partial.partial(),
        agg_nonce,
        t.point(),
        their_pubkey.point(),
        their_pubnonce.nonce(),
        message,
    )
    .map_err(|_| Error::Verification("counterparty partial failed PartialSigVerify"))
}

/// Assemble a COMPLETE pre-signature from both verified partials over the agreed
/// aggregate nonce (Gate G1 material). Cannot be built from one partial, and the
/// aggregate is verified against (R + T, P, m) before the value exists at all —
/// `musig2::adaptor::aggregate_partial_signatures` verifies internally, and this
/// is the ONLY constructor of `CompletePreSig`.
pub fn assemble_complete_presig(
    key_agg_ctx: &KeyAggContext,
    agg_nonce: &AggNonce,
    t: &AdaptorPoint,
    ours: &ValidatedPartial,
    theirs: &ValidatedPartial,
    message: [u8; 32],
) -> Result<CompletePreSig> {
    let sig = musig2::adaptor::aggregate_partial_signatures(
        key_agg_ctx,
        agg_nonce,
        t.point(),
        [ours.partial(), theirs.partial()],
        message,
    )
    .map_err(|_| Error::Verification("aggregate pre-signature failed verification"))?;
    Ok(CompletePreSig::new(sig, key_agg_ctx.clone(), message, t.point()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> (KeyAggContext, Scalar, Scalar) {
        let mut rng = rand::rng();
        let sk_a = Scalar::random(&mut rng);
        let sk_b = Scalar::random(&mut rng);
        let (pk_a, pk_b) = (sk_a * secp::G, sk_b * secp::G);
        // Canonical pubkey ordering (BIP327 key agg is order-DEPENDENT).
        let mut keys = [pk_a, pk_b];
        keys.sort_by_key(|p| p.serialize());
        let ctx = KeyAggContext::new(keys).expect("valid key set");
        (ctx, sk_a, sk_b)
    }

    #[test]
    fn lease_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = [7u8; 32];
        let lease = SingleSignerLease::acquire_in(dir.path(), id).expect("first acquire");
        // Second acquire while held must refuse (INV-3).
        assert!(matches!(
            SingleSignerLease::acquire_in(dir.path(), id),
            Err(Error::NonceInvariant(_))
        ));
        drop(lease);
        // Released -> can acquire again.
        assert!(SingleSignerLease::acquire_in(dir.path(), id).is_ok());
    }

    #[test]
    fn interlock_blocks_lone_or_mismatched_sessions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ctx, sk_a, _) = test_ctx();
        let lease = SingleSignerLease::acquire_in(dir.path(), [1u8; 32]).expect("lease");
        let mut s1 = SigningSession::begin(lease.clone(), ctx.clone(), sk_a, [1u8; 32]).unwrap();
        let mut s2 = SigningSession::begin(lease.clone(), ctx.clone(), sk_a, [2u8; 32]).unwrap();

        // Same message pair is rejected.
        let mut s_dup = SigningSession::begin(lease.clone(), ctx.clone(), sk_a, [1u8; 32]).unwrap();
        assert!(commit_and_reveal(&mut s1, &mut s_dup).is_err());

        // Different lease is rejected.
        let other_lease =
            SingleSignerLease::acquire_in(dir.path(), [9u8; 32]).expect("other lease");
        let mut s_other =
            SigningSession::begin(other_lease, ctx.clone(), sk_a, [3u8; 32]).unwrap();
        assert!(commit_and_reveal(&mut s1, &mut s_other).is_err());

        // Proper pair works, and double-reveal is rejected.
        assert!(commit_and_reveal(&mut s1, &mut s2).is_ok());
        assert!(commit_and_reveal(&mut s1, &mut s2).is_err());
    }

    #[test]
    fn signing_before_interlock_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ctx, sk_a, _) = test_ctx();
        let lease = SingleSignerLease::acquire_in(dir.path(), [2u8; 32]).expect("lease");
        let s = SigningSession::begin(lease, ctx, sk_a, [1u8; 32]).unwrap();
        let (_t_sec, t_point) = crate::crypto::adaptor::AdaptorSecret::generate().unwrap();
        // A lone un-committed session cannot even learn the aggregate nonce
        // through the API; construct one directly to prove sign_partial refuses.
        let n = s.public_nonce.clone();
        let agg = aggregate_nonces(&n, &n);
        assert!(matches!(s.sign_partial(&agg, &t_point), Err(Error::Ordering(_))));
    }

    #[test]
    fn real_crash_leaves_lease_held_and_refuses_signing() {
        // A real crash SKIPS Drop (unlike a scope exit). Model it with
        // mem::forget so the lease file is NOT removed. INV-3's intended
        // failure mode is then REFUSAL to sign, never a second signer.
        let dir = tempfile::tempdir().expect("tempdir");
        let id = [0x5cu8; 32];
        {
            let lease = SingleSignerLease::acquire_in(dir.path(), id).expect("acquire");
            let (ctx, sk, _) = test_ctx();
            let s1 = SigningSession::begin(lease.clone(), ctx.clone(), sk, [1u8; 32]).unwrap();
            let s2 = SigningSession::begin(lease.clone(), ctx, sk, [2u8; 32]).unwrap();
            // "Crash": leak everything so no Drop runs.
            core::mem::forget(s1);
            core::mem::forget(s2);
            core::mem::forget(lease);
        }
        // Lease file survives the crash...
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_some(), "lease vanished on crash");
        // ...and a restart is REFUSED (conservative: abort-to-refund, no 2nd signer).
        assert!(matches!(
            SingleSignerLease::acquire_in(dir.path(), id),
            Err(Error::NonceInvariant(_))
        ));
    }

    #[test]
    fn fresh_nonce_every_session_even_same_inputs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ctx, sk_a, _) = test_ctx();
        let lease = SingleSignerLease::acquire_in(dir.path(), [3u8; 32]).expect("lease");
        let s1 = SigningSession::begin(lease.clone(), ctx.clone(), sk_a, [1u8; 32]).unwrap();
        let s2 = SigningSession::begin(lease.clone(), ctx.clone(), sk_a, [1u8; 32]).unwrap();
        // INV-4: identical (key, message) inputs still yield distinct nonces
        // because the seed is fresh OS randomness each time.
        assert_ne!(s1.public_nonce.to_bytes(), s2.public_nonce.to_bytes());
    }
}
