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
//! distinction: extraction requires a `CompletePreSig`, which cannot be built
//! from a single partial.

use crate::crypto::{ValidatedPartial, ValidatedPoint};
use crate::{Error, Result};

/// The adaptor point T = t*G. SH publishes this; t itself is NEVER sent.
#[derive(Clone, Debug)]
pub struct AdaptorPoint(pub ValidatedPoint);

/// A COMPLETE adaptor pre-signature: both partials aggregated over the agreed
/// aggregate nonce, adaptor-bound to T. Deliberately NOT constructible from one
/// partial — see `signing` for the gated assembly.
#[derive(Clone, Debug)]
pub struct CompletePreSig {
    // IMPLEMENT: hold the aggregated pre-sig scalar `s_hat`, the aggregate nonce R,
    // aggregate pubkey P, message m, and T so verify/extract are self-contained.
    _private: (),
}

/// The adaptor secret t (a scalar). Held ONLY by SH until reveal; recovered by
/// any holder of the matching CompletePreSig once s_final is on the wire/chain.
#[derive(Clone, Debug)]
pub struct AdaptorSecret {
    _private: (),
}

impl CompletePreSig {
    /// Verify this pre-signature is valid against (R + T, P, m) BEFORE relying on
    /// it. REQUIRED at the possession gate: SL must verify it holds a valid
    /// CompletePreSig for Comp->SH before releasing its final partial (Gate G1).
    pub fn verify_adaptor(&self, _t_point: &AdaptorPoint) -> Result<()> {
        // IMPLEMENT via pinned musig2 adaptor verify. Failure => Verification err.
        Err(Error::Unimplemented("CompletePreSig::verify_adaptor: musig2 adaptor pre-sig verify"))
    }

    /// EXTRACTION (review item #2): t = s_final - s_hat (mod n).
    /// `s_final` is the finalized signature scalar read from mempool/chain.
    pub fn extract_secret(&self, _s_final: &ValidatedPartial /* scalar */) -> Result<AdaptorSecret> {
        // IMPLEMENT: scalar subtraction via pinned lib. Assert the result R s.t.
        // result*G == T (i.e. the extracted t matches the published AdaptorPoint);
        // if it does not, ABORT — never return a wrong secret.
        Err(Error::Unimplemented("CompletePreSig::extract_secret: s_final - s_hat, then check t*G == T"))
    }

    /// Repair to the final signature using the known secret (SH completing, or SL
    /// completing its own leg after learning t).
    pub fn complete_with(&self, _t: &AdaptorSecret) -> Result<[u8; 64] /* BIP340 sig */> {
        Err(Error::Unimplemented("CompletePreSig::complete_with: s_hat + t, output BIP340 sig"))
    }
}
