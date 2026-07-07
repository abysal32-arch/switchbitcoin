//! Wallet layer — the durable, crash-safe shell around the settlement core.
//!
//! The settlement core (crypto/, signing/, settlement/, tx/) is deliberately
//! FROZEN for the external cryptographer review: nothing in this module adds
//! curve math, touches the adaptor+timelock composition, or weakens an
//! invariant. The wallet layer ORCHESTRATES the reviewed seams:
//!
//!   * `store`  — crash-safe persistence of swap lifecycle state (v3.16's
//!     residual critical risk: deadline discipline under crash-and-restore).
//!     Records are sealed at rest under the per-swap TEK (`crypto::storage`)
//!     and secret signing nonces are STRUCTURALLY excluded — no record field
//!     can hold one (INV-1 extends to disk by construction).
//!
//! Lifecycle law enforced here (v3.13/v3.16):
//!   - A crash during a live signing session is NON-RESUMABLE: restore routes
//!     the swap to ABORT_REFUND (INV-2); a retry is a brand-new session/swap.
//!   - After SL releases its enabling partial (G1 satisfied, possession record
//!     persisted), the safe path is restore-and-extract — NOT refund; those
//!     records survive restarts untouched.
//!   - A funded escrow is never persisted without its pre-armed refund (G2's
//!     crash half): the store refuses such a record.

//!   * `manifest` — signed, versioned parameter ingestion (v3.13 "signed
//!     manifest" trust path). BIP340-verified against the pinned trust root,
//!     strictly-monotonic version gate, ordering invariant asserted on every
//!     ingest regardless of signature, Δ_fee-version swap refusal. Uses the
//!     pinned libsecp256k1 for verification — no new curve math, and none of
//!     it lives in the settlement crypto modules.

pub mod manifest;
pub mod store;

pub use manifest::{
    ClaimDelayPosture, ManifestOpenReport, ManifestStore, ManifestTrustRoot, ModeledTrustRoot,
    SignedManifest,
};
pub use store::{EnclaveKeyProvider, ModeledEnclave, RecoveryAction, SwapPhase, SwapRecord, SwapStore};
