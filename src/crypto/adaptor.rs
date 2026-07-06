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
use secp::{MaybeScalar, Point, Scalar};

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
    /// SH-side: draw a fresh t from OS-seeded randomness and derive T = t*G.
    pub fn generate() -> Result<(AdaptorSecret, AdaptorPoint)> {
        let mut rng = rand::rng();
        let t = Scalar::random(&mut rng);
        let point = AdaptorPoint(ValidatedPoint::from_valid(t * secp::G));
        Ok((AdaptorSecret(t), point))
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
