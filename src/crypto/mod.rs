//! Crypto module — pinned primitives + the validation gate (Requirements 1 & 2).
//!
//! DESIGN RULE: a value of one of these newtypes EXISTS only if it already passed
//! validation. Construction is the gate. Downstream code that holds a
//! `ValidatedPoint` never has to re-check — the type is the proof. This is how
//! Requirement 2 ("validate before it touches any math") is enforced structurally
//! rather than by remembering to call a checker.

pub mod validate;
pub mod adaptor;
pub mod storage;

pub use validate::{
    ValidatedFinalSig, ValidatedPartial, ValidatedPoint, ValidatedPubNonce, ValidatedScalar,
};
