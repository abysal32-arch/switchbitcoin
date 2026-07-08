//! Swap Key Protocol — settlement-core reference scaffold.
//!
//! Corresponds to Swap Key Protocol Specification **v3.16**, build sequence step 1–2:
//! pinned crypto + validation gate + nonce-lifecycle invariants + settlement core,
//! with discovery STUBBED (peers fed to each other manually — Requirement 5).
//!
//! ============================ READ THIS FIRST ============================
//! This is a SCAFFOLD, not an implementation. Every `todo!()` / `unimplemented!()`
//! marks a spot to fill against the REAL libsecp256k1-zkp APIs. The value here is
//! that the dangerous decisions are already encoded in the TYPES and INVARIANTS:
//!
//!   * Requirement 1 — crypto is pinned in Cargo.toml; no hand-rolling.
//!   * Requirement 2 — every deserialized point/scalar is validated on receipt
//!     (see `wire` + `crypto::validate`). Invalid => Abort.
//!   * Requirement 3 — nonce-lifecycle invariants INV-1..4 are encoded as a
//!     non-resumable, non-clonable `SecretNonce` and a signing state machine
//!     that CANNOT survive a restart.
//!   * Requirement 4 — the wire parser is the fuzz target (see ./fuzz).
//!   * Requirement 6 — parameters are named constants in `settlement::params`.
//!   * Requirement 7 — the failure checklist is stubbed as named tests.
//!
//! The safety argument reduces to Schnorr/AOMDL + ECDLP + two POLICY gates the
//! code must enforce (and the external cryptographer must verify):
//!   (G1) POSSESSION GATE  — no party releases its final partial before it holds
//!        a verified complete pre-signature for the tx it must extract from.
//!   (G2) DEADLINE GATE    — the extract-and-race region is unreachable, incl.
//!        under crash/restart (pre-armed refund + Δ_buffer).
//! ========================================================================

pub mod chain;
pub mod crypto;
pub mod wire;
pub mod signing;
pub mod settlement;
pub mod tx;
pub mod wallet;

/// Crate-wide error type. `Abort` is the safe sink for EVERY failure path:
/// any validation failure, verification failure, crash, or timeout maps here,
/// and the settlement layer turns `Abort` into the refund subroutine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation failed: {0}")]
    Validation(&'static str),
    #[error("partial/adaptor verification failed: {0}")]
    Verification(&'static str),
    #[error("protocol ordering violated: {0}")]
    Ordering(&'static str),
    #[error("signing session invariant violated: {0}")]
    NonceInvariant(&'static str),
    #[error("timelock/deadline invariant violated: {0}")]
    Deadline(&'static str),
    #[error("abort to refund: {0}")]
    Abort(&'static str),
    #[error("not yet implemented in scaffold: {0}")]
    Unimplemented(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;
