//! Adaptor signatures — the load-bearing settlement operation.
//!
//! CRYPTOGRAPHER REVIEW ITEMS #2 (extraction) and part of #1 (possession):
//! The whole atomicity claim depends on these two facts holding under MuSig2
//! aggregation:
//!
//!   * A *complete* pre-signature `s_hat` for a completion is the aggregate of
//!     BOTH parties' partials over the agreed aggregate nonce, adaptor-shifted by
//!     the single point T = t*G, verifying against (R + T, P, m).
//!   * The only valid on-chain signature is  s_final = s_hat + t (mod n),
//!     so any holder of `s_hat` recovers  t = s_final - s_hat (mod n).
//!
//! v3.11 GOT THIS WRONG by exchanging lone partials, leaving SL without the
//! COMPLETE pre-signature and unable to extract. The types here force the
//! distinction: extraction requires a `CompletePreSig`, whose ONLY constructor
//! is `signing::assemble_complete_presig` — which aggregates BOTH partials and
//! verifies the result before handing the value out.
//!
//! All scalar/point arithmetic is the pinned stack (musig2/secp over
//! libsecp256k1). `adapt` and `reveal_secret` are the crate's own s_hat + t /
//! s_final - s_hat operations; nothing is hand-rolled here (Req 1).

use crate::crypto::{ValidatedFinalSig, ValidatedPoint};
use crate::{Error, Result};
use musig2::{AdaptorSignature, KeyAggContext, LiftedSignature};
use rand::TryRngCore;
use secp::{MaybeScalar, Point, Scalar};
use zeroize::Zeroizing;

/// The adaptor point T = t*G. SH publishes this; t itself is NEVER sent.
///
/// Inner point is gate-validated but the BINDING of T to a session is protocol
/// state: `Funded::run_adaptor_exchange` is the single place a session's T is
/// accepted (message 2), and `CompletePreSig` records the T it was built for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorPoint(ValidatedPoint);

impl AdaptorPoint {
    pub fn new(p: ValidatedPoint) -> Self {
        AdaptorPoint(p)
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        self.0.to_bytes()
    }

    pub(crate) fn point(&self) -> Point {
        self.0.point()
    }
}

/// The adaptor secret t (a nonzero scalar). Held ONLY by SH until reveal;
/// recovered by any holder of the matching CompletePreSig once s_final is on
/// the wire/chain. Not `Clone`: there is never a reason to duplicate it.
#[derive(Debug)]
pub struct AdaptorSecret(Scalar);

impl AdaptorSecret {
    /// SH-side: draw a fresh t from OS randomness and derive T = t*G.
    /// FALLIBLE by design: RNG failure maps to `Error::Abort` (the crate-wide
    /// rule that every failure path is an Err, never a panic — `rand::rng()`
    /// would panic on first-use entropy failure).
    pub fn generate() -> Result<(AdaptorSecret, AdaptorPoint)> {
        // Rejection-sample a nonzero scalar (P(reject) ~ 2^-128 per draw).
        for _ in 0..8 {
            let mut buf = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng
                .try_fill_bytes(buf.as_mut())
                .map_err(|_| Error::Abort("OS randomness unavailable; cannot mint adaptor secret"))?;
            if let Ok(t) = Scalar::from_slice(&*buf) {
                let point = AdaptorPoint(ValidatedPoint::from_valid(t * secp::G));
                return Ok((AdaptorSecret(t), point));
            }
        }
        Err(Error::Abort("OS randomness returned out-of-range scalars repeatedly"))
    }

    /// The point this secret opens: T = t*G.
    pub fn point(&self) -> AdaptorPoint {
        AdaptorPoint(ValidatedPoint::from_valid(self.0 * secp::G))
    }

    pub(crate) fn scalar(&self) -> Scalar {
        self.0
    }
}

/// A COMPLETE adaptor pre-signature: both partials aggregated over the agreed
/// aggregate nonce, adaptor-bound to T, VERIFIED against (R + T, P, m) at
/// construction. Deliberately NOT constructible from one partial — the only
/// constructor is `signing::assemble_complete_presig` (crate-private `new`).
#[derive(Clone)]
pub struct CompletePreSig {
    /// (R', s_hat) — the adaptor-shifted nonce and aggregate pre-sig scalar.
    sig: AdaptorSignature,
    /// Aggregate-key context this pre-sig verifies under.
    key_agg_ctx: KeyAggContext,
    /// The exact 32-byte message (sighash) it signs.
    message: [u8; 32],
    /// The adaptor point it is bound to.
    t_point: Point,
}

impl core::fmt::Debug for CompletePreSig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A pre-signature is not a secret, but keep Debug terse and s_hat-free:
        // logs should never carry material a holder could extract with later.
        f.debug_struct("CompletePreSig")
            .field("message", &self.message)
            .field("t_point", &self.t_point)
            .finish_non_exhaustive()
    }
}

impl CompletePreSig {
    /// Crate-internal: called ONLY by `signing::assemble_complete_presig`, which
    /// has already aggregated both partials and verified the result.
    pub(crate) fn new(
        sig: AdaptorSignature,
        key_agg_ctx: KeyAggContext,
        message: [u8; 32],
        t_point: Point,
    ) -> Self {
        CompletePreSig { sig, key_agg_ctx, message, t_point }
    }

    pub fn message(&self) -> &[u8; 32] {
        &self.message
    }

    /// Verify this pre-signature is valid against (R + T, P, m) BEFORE relying on
    /// it. REQUIRED at the possession gate: SL must verify it holds a valid
    /// CompletePreSig for Comp->SH before releasing its final partial (Gate G1).
    pub fn verify_adaptor(&self, t_point: &AdaptorPoint) -> Result<()> {
        if self.t_point != t_point.point() {
            return Err(Error::Verification("pre-signature bound to a different adaptor point"));
        }
        let agg_pubkey: Point = self.key_agg_ctx.aggregated_pubkey();
        musig2::adaptor::verify_single(agg_pubkey, &self.sig, self.message, self.t_point)
            .map_err(|_| Error::Verification("complete pre-signature failed adaptor verification"))
    }

    /// EXTRACTION (review item #2): t = s_final - s_hat (mod n).
    /// `final_sig` is the finalized signature read from mempool/chain.
    ///
    /// The extracted secret is checked against the published T (t*G == T);
    /// on any mismatch this returns Err — never a wrong secret.
    pub fn extract_secret(&self, final_sig: &ValidatedFinalSig) -> Result<AdaptorSecret> {
        let t: MaybeScalar = self
            .sig
            .reveal_secret(final_sig.sig())
            .ok_or(Error::Verification("final signature unrelated to this pre-signature"))?;
        let t = match t {
            MaybeScalar::Zero => {
                return Err(Error::Verification("extracted adaptor secret is zero"))
            }
            MaybeScalar::Valid(s) => s,
        };
        if t * secp::G != self.t_point {
            return Err(Error::Abort("extracted secret does not open the published T; aborting"));
        }
        Ok(AdaptorSecret(t))
    }

    /// Serialize for the G1 possession record (crash-safety: SL MUST persist
    /// its complete pre-signatures BEFORE releasing the enabling partial —
    /// after release, ABORT_REFUND is no longer a safe sink and extraction is
    /// the only path, so the material extraction needs has to survive restart).
    ///
    /// SAFE TO PERSIST: contains the adaptor pre-signature, the two aggregate
    /// pubkeys, the message, and T — no secret nonces (INV-1/2 untouched), no
    /// secret keys. A stolen record only lets the holder complete the FIXED
    /// sighash it binds. Layout is fixed 197 bytes:
    /// `[1 version=1][65 adaptor sig][33 key0][33 key1][32 msg][33 T]`.
    /// key0/key1 are in the exact KeyAggContext order — BIP327 key aggregation
    /// is order-dependent. The version byte is reserved for future tweaked
    /// contexts.
    pub fn to_bytes(&self) -> Vec<u8> {
        let keys: Vec<Point> = self.key_agg_ctx.pubkeys().to_vec();
        let mut v = Vec::with_capacity(197);
        v.push(1u8);
        v.extend_from_slice(&self.sig.serialize());
        for k in &keys {
            v.extend_from_slice(&k.serialize());
        }
        v.extend_from_slice(&self.message);
        v.extend_from_slice(&self.t_point.serialize());
        v
    }

    /// Rebuild from a possession record. Everything is re-validated: points
    /// re-parsed through the curve checks, the context re-aggregated, and the
    /// pre-signature RE-VERIFIED against (R + T, P, m) before the value exists
    /// — a corrupt or tampered record yields Err, never a bogus pre-sig.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 197 {
            return Err(Error::Validation("possession record: wrong length"));
        }
        if b[0] != 1 {
            return Err(Error::Validation("possession record: unknown version"));
        }
        let sig_bytes: [u8; 65] = b[1..66]
            .try_into()
            .map_err(|_| Error::Validation("possession record: sig slice"))?;
        let sig = AdaptorSignature::from_bytes(&sig_bytes)
            .map_err(|_| Error::Validation("possession record: malformed adaptor signature"))?;
        let k0: [u8; 33] =
            b[66..99].try_into().map_err(|_| Error::Validation("possession record: key0"))?;
        let k1: [u8; 33] =
            b[99..132].try_into().map_err(|_| Error::Validation("possession record: key1"))?;
        let key0 = ValidatedPoint::from_bytes(&k0)?; // <-- gate
        let key1 = ValidatedPoint::from_bytes(&k1)?; // <-- gate
        let message: [u8; 32] =
            b[132..164].try_into().map_err(|_| Error::Validation("possession record: msg"))?;
        let t: [u8; 33] =
            b[164..197].try_into().map_err(|_| Error::Validation("possession record: T"))?;
        let t_point = ValidatedPoint::from_bytes(&t)?.point(); // <-- gate

        let key_agg_ctx = KeyAggContext::new([key0.point(), key1.point()])
            .map_err(|_| Error::Validation("possession record: key aggregation failed"))?;
        let presig = CompletePreSig { sig, key_agg_ctx, message, t_point };
        // Re-verify: a record that does not verify never becomes a value.
        presig.verify_adaptor(&AdaptorPoint(ValidatedPoint::from_valid(t_point)))?;
        Ok(presig)
    }

    /// Repair to the final signature using the known secret (SH completing, or SL
    /// completing its own leg after learning t). The result is verified as a
    /// plain BIP340 signature over (P, m) before it is handed out.
    pub fn complete_with(&self, t: &AdaptorSecret) -> Result<[u8; 64]> {
        if t.scalar() * secp::G != self.t_point {
            return Err(Error::Verification("adaptor secret does not match this pre-signature's T"));
        }
        let sig: LiftedSignature = self
            .sig
            .adapt(t.scalar())
            .ok_or(Error::Verification("adapting produced an invalid signature"))?;
        let agg_pubkey: Point = self.key_agg_ctx.aggregated_pubkey();
        musig2::verify_single(agg_pubkey, sig, self.message)
            .map_err(|_| Error::Verification("completed signature failed BIP340 verification"))?;
        Ok(sig.serialize())
    }
}
