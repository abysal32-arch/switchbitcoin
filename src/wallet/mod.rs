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

//!   * `ledger` + `keys` — the coin ledger and onboarding pipeline (v3.13
//!     Phase 0–1): typed Phase-0 warning gate, auto-split to exactly
//!     D + Δ_fee pre-encumbrance UTXOs (single change output absorbs all
//!     rounding), CSPRNG 24–72h encumbrance delay persisted across
//!     restarts, class-pure non-mixing coin selection, enclave-seam key
//!     derivation (disk holds indices, never keys).

//!   * `orchestrator` — the wallet's funding + abort decision loop over the
//!     settlement core (rank 4). Canonical-order funding with deferred
//!     encumbrance verification, co-funding window + Block-X policy, and the
//!     re-enterable completion-supersedes refund driver. No new crypto.

//!   * `claim_scheduler` — the SL randomized claim-delay scheduler (rank 5):
//!     posture sampling from the manifest clamped to the hard settlement
//!     ceiling, mempool-first reveal detection, plus SH broadcast-vs-refund
//!     runway routing. The primary privacy-vs-liveness dial.

//!   * `abort_hygiene` — coordinator-free anti-griefing (v3.15): a
//!     UTXO-keyed cooldown/ban tracker for counterparties who match then
//!     abandon. Pure LIVENESS policy — it never affects an in-flight swap's
//!     fund safety (forward-or-refund holds regardless).

//!
//!   * `watchtower_driver` — own-device watchtower poll loop (dead-device
//!     refund fire) + the congestion fee-backstop routing (silent for
//!     refunds, consent-gated for completions), rank 6.

//!
//!   * `engine` — the swap engine (rank 7): the wallet's core loop that
//!     composes every rank into one driven, crash-recoverable swap lifecycle
//!     (funded → exchange → settle), persisting the SwapRecord through every
//!     phase and reconciling the ledger. The integration layer over the parts.

pub mod abort_hygiene;
pub mod backstop_driver;
pub mod claim_scheduler;
pub mod driver;
pub mod engine;
pub mod funding_driver;
pub mod keys;
pub mod watchtower_driver;
pub mod ledger;
pub mod manifest;
pub mod orchestrator;
pub mod recovery_driver;
pub mod store;

pub use backstop_driver::{
    run_cpfp_bump, BackstopDriver, BackstopTick, BumpOutcome, CpfpBumpRequest,
};
pub use driver::{DriveStatus, SwapDriver};
pub use funding_driver::{FundingDriver, FundingTick, HandoffError};
pub use recovery_driver::{RecoveryDriver, RecoveryTick};
pub use manifest::{
    ClaimDelayPosture, ManifestOpenReport, ManifestStore, ManifestTrustRoot, ModeledTrustRoot,
    SignedManifest,
};
pub use store::{EnclaveKeyProvider, ModeledEnclave, RecoveryAction, SwapPhase, SwapRecord, SwapStore};
