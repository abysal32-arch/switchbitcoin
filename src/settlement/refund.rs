//! Refund / abort subroutine — completion-supersedes (v3.14 §Operational State
//! Machine). The safe sink for EVERY failure path. Idempotent; safe to re-enter
//! after a crash.
//!
//! It is invoked whenever anything returns `Error::Abort` (or on deadline). The
//! golden rule: before broadcasting a refund, RE-CHECK whether the counterparty's
//! completion is winning; if it is, DON'T fight it — take the successful swap.
//! A needless refund wastes fees AND reveals the script leaf (privacy loss).

use crate::{Error, Result};

/// A refund transaction signed and stored BEFORE any completion is broadcast
/// (v3.13 pre-armed refunds). The watchtower can broadcast it even if this device
/// is dead — this is what makes gate G2 crash-safe. Pays the owner's own address.
#[derive(Clone, Debug)]
pub struct PreArmedRefund {
    // IMPLEMENT: fully-signed refund tx bytes (script-path spend of own escrow),
    // plus the CSV maturity height. Safe to hand (encrypted) to the watchtower.
    _private: (),
}

impl PreArmedRefund {
    /// Build and sign the refund NOW, before broadcasting any completion (G2).
    pub fn arm(/* escrow, own key, csv height, params */) -> Result<Self> {
        Err(Error::Unimplemented("PreArmedRefund::arm: sign script-path refund up front"))
    }
}

/// What the chain view told us about the counterparty's completion.
pub enum CompletionStatus {
    Confirmed,
    InMempool,
    Absent,
}

/// The completion-supersedes decision. Call BEFORE broadcasting any refund.
/// Returns Ok(()) meaning "refund broadcast is appropriate"; Err(Abort(..)) with
/// a "completion winning" reason meaning "do NOT refund, follow the swap path".
pub fn should_refund(status: CompletionStatus, refund_matured: bool) -> Result<()> {
    match status {
        CompletionStatus::Confirmed | CompletionStatus::InMempool => {
            // Do NOT fight a winning completion.
            Err(Error::Abort("counterparty completion is winning; take the swap, do not refund"))
        }
        CompletionStatus::Absent if refund_matured => Ok(()),
        CompletionStatus::Absent => Err(Error::Deadline("refund not yet matured")),
    }
}

/// Run the refund subroutine. Idempotent and crash-safe: re-checking status on
/// every entry means a crash mid-refund simply re-evaluates on restart.
pub fn run(_refund: &PreArmedRefund /*, chain view, watchtower */) -> Result<()> {
    // IMPLEMENT:
    //   loop-ish (event driven):
    //     let status = dual_source_completion_status();   // self-verifying
    //     should_refund(status, matured)?;                // may say "take the swap"
    //     broadcast pre-armed refund over dedicated Tor circuit;
    //     if it stalls -> escalate via anchor+reserve backstop (silent for refunds);
    //   if completion appears after we broadcast: CSV ordering decides; never
    //   double-spend against ourselves; reconcile to whichever confirms.
    Err(Error::Unimplemented("refund::run: completion-supersedes, Tor broadcast, deterministic reconciliation"))
}
