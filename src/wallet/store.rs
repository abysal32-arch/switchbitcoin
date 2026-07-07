//! Crash-safe SwapStore (wallet rank 1; v3.16 residual critical risk).
//!
//! One sealed file per swap: `<hex swap_session_id>.swap`, encrypted with
//! AES-256-GCM under the per-swap TEK (`crypto::storage::derive_tek`) — the
//! same spec formula the possession record uses, so one TEK covers all of a
//! swap's at-rest artifacts. A record from swap A cannot be opened as swap B.
//!
//! WHAT IS (and is NOT) IN A RECORD — the INV-1 boundary:
//!   * IN: lifecycle phase, params snapshot, escrow outpoints, deadline
//!     heights, the PRE-ARMED refund (a fully-SIGNED tx — public bytes), and
//!     the path of SL's possession record. Everything needed to meet deadlines
//!     after a crash.
//!   * STRUCTURALLY OUT: secret signing nonces and signing-session state.
//!     `SwapRecord` has no field that can hold them (no opaque blob field
//!     either — extension creep is how a nonce would sneak to disk), and the
//!     signing layer's `SecretNonce` is non-serializable by construction.
//!
//! LIFECYCLE LAW (INV-2/INV-4, enforced by `open` + the transition table):
//!   * `Signing` found on disk at startup == we died mid-session. The volatile
//!     nonces are gone; the session is NON-RESUMABLE. `open` atomically
//!     rewrites the record to `AbortRefund` and reports it.
//!   * There is NO `AbortRefund -> Signing` edge: an aborted swap can never be
//!     "retried" in place. A retry is a brand-new swap (fresh session keys,
//!     fresh swap_session_id, fresh nonces) — INV-4 at the wallet layer.
//!   * `Released` (SL, post-G1) survives restarts untouched: the safe path is
//!     restore-and-extract via the persisted possession record, never refund.
//!
//! G2's crash half: a record with a funded escrow but no pre-armed refund is
//! REFUSED — the wallet cannot even represent "money locked, no exit".

use crate::settlement::params::Params;
use crate::settlement::refund::PreArmedRefund;
use crate::settlement::state_machine::Role;
use crate::{Error, Result};
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use std::path::{Path, PathBuf};

// ----- Enclave seam ----------------------------------------------------------

/// The device-bound platform key seam. In production this is the Secure
/// Enclave / Keystore key: stable across restarts, never leaves the device.
/// The wallet layer only ever sees the 32 bytes it derives TEKs from.
pub trait EnclaveKeyProvider {
    fn platform_key(&self) -> [u8; 32];
}

/// Prototype provider wrapping the modeled constant in `crypto::storage`.
/// A real build supplies an OS-keystore-backed implementation instead; every
/// consumer is already coded against the trait, so nothing else changes.
pub struct ModeledEnclave;

impl EnclaveKeyProvider for ModeledEnclave {
    fn platform_key(&self) -> [u8; 32] {
        crate::crypto::storage::platform_secure_key()
    }
}

// ----- Record ----------------------------------------------------------------

/// Wallet-visible swap lifecycle phase. Coarser than the settlement
/// typestates on purpose: this is what must be KNOWN AFTER A CRASH, not the
/// in-memory protocol position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapPhase {
    /// Setups constructed/broadcast; awaiting co-funding confirmation.
    /// Crash-safe: funding is chain-observable, no volatile signing state.
    Funding,
    /// A LIVE Phase-5 signing session is in flight. Volatile nonces exist
    /// only in memory — a record found in this phase at startup means the
    /// session died with them. Non-resumable (INV-2).
    Signing,
    /// SL only: enabling partial released under G1, possession record
    /// persisted. Crash => restore-and-extract, NOT refund.
    Released,
    /// Our completion (SH) or claim (SL) is broadcast; babysitting it in.
    Completing,
    /// Terminal: our output confirmed.
    Completed,
    /// Refund path engaged. The refund driver (completion-supersedes first,
    /// then pre-armed refund at maturity) owns this record now.
    AbortRefund,
    /// Terminal: refund confirmed.
    Refunded,
}

impl SwapPhase {
    fn to_byte(self) -> u8 {
        match self {
            SwapPhase::Funding => 0,
            SwapPhase::Signing => 1,
            SwapPhase::Released => 2,
            SwapPhase::Completing => 3,
            SwapPhase::Completed => 4,
            SwapPhase::AbortRefund => 5,
            SwapPhase::Refunded => 6,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            0 => SwapPhase::Funding,
            1 => SwapPhase::Signing,
            2 => SwapPhase::Released,
            3 => SwapPhase::Completing,
            4 => SwapPhase::Completed,
            5 => SwapPhase::AbortRefund,
            6 => SwapPhase::Refunded,
            _ => return Err(Error::Validation("swap record: unknown phase")),
        })
    }

    fn is_terminal(self) -> bool {
        matches!(self, SwapPhase::Completed | SwapPhase::Refunded)
    }
}

/// The allowed phase graph. Everything not listed is an ordering violation.
/// Note the two load-bearing ABSENCES: no edge out of a terminal phase, and
/// no `AbortRefund -> Signing` (a dead session is never resumed — INV-4).
/// `AbortRefund -> Completed` is completion-supersedes: the refund driver
/// discovers the counterparty's completion winning and takes the swap.
fn transition_ok(from: SwapPhase, to: SwapPhase) -> bool {
    use SwapPhase::*;
    if from == to {
        // In-place updates (new outpoints, refund attached) are fine while
        // live; terminal records are frozen.
        return !from.is_terminal();
    }
    matches!(
        (from, to),
        (Funding, Signing)
            | (Funding, AbortRefund)
            | (Signing, Released)
            | (Signing, Completing)
            | (Signing, AbortRefund)
            | (Released, Completing)
            | (Released, Completed)
            | (Released, AbortRefund)
            | (Completing, Completed)
            | (Completing, AbortRefund)
            | (AbortRefund, Refunded)
            | (AbortRefund, Completed)
    )
}

/// Everything the wallet must remember about one swap to meet its deadlines
/// after a crash. See the module docs for what is structurally excluded.
#[derive(Clone, Debug)]
pub struct SwapRecord {
    pub swap_session_id: [u8; 32],
    pub role: Role,
    pub phase: SwapPhase,
    /// Params snapshot this swap was agreed under (a later manifest update
    /// must not silently change a live swap's deadlines). Re-validated on
    /// every put AND every load — the ordering invariant is checked at each
    /// trust boundary.
    pub params: Params,
    /// Co-funding baseline S (later of the two funding confirmations).
    /// 0 until known.
    pub s_height: u32,
    /// Confirmation height of the escrow WE sweep (claim-deadline anchor).
    /// 0 until known.
    pub sweep_escrow_height: u32,
    /// The escrow OUR funds sit in (what the pre-armed refund spends).
    pub our_escrow_outpoint: Option<OutPoint>,
    /// The counterparty's escrow (what our completion sweeps).
    pub their_escrow_outpoint: Option<OutPoint>,
    /// Pre-armed refund: fully-signed tx + CSV maturity height. MUST be
    /// present the moment `our_escrow_outpoint` is — the store refuses a
    /// record that represents "money locked, no exit" (G2 crash half).
    pub pre_armed_refund: Option<PreArmedRefund>,
    /// SL only: path of the sealed possession record (G1 artifact) that
    /// `Possessing::restore_secret_learner` rebuilds from.
    pub possession_record: Option<PathBuf>,
}

impl SwapRecord {
    /// Structural invariants that must hold for a record to be persistable.
    /// Total: hostile/buggy callers get Err, never a panic.
    fn check(&self) -> Result<()> {
        self.params.validate()?;
        // G2 crash half: funded escrow => pre-armed refund exists.
        if self.our_escrow_outpoint.is_some() && self.pre_armed_refund.is_none() {
            return Err(Error::Deadline(
                "swap record has a funded escrow but no pre-armed refund (G2)",
            ));
        }
        // The refund must be pre-armed BEFORE any signing session starts.
        if matches!(
            self.phase,
            SwapPhase::Signing | SwapPhase::Released | SwapPhase::Completing
        ) && self.pre_armed_refund.is_none()
        {
            return Err(Error::Deadline(
                "cannot enter a signing phase without the pre-armed refund (G2)",
            ));
        }
        // Released is G1's post-release window: SL only, possession record
        // persisted (persist-then-release).
        if self.phase == SwapPhase::Released {
            if self.role != Role::SecretLearner {
                return Err(Error::Ordering("Released is an SL-only phase"));
            }
            if self.possession_record.is_none() {
                return Err(Error::Ordering(
                    "Released requires a persisted possession record (G1 persist-then-release)",
                ));
            }
        }
        Ok(())
    }

    // ---- serialization (record format v1, all integers LE) ----
    //
    // [1 version=1][32 swap_session_id][1 role][1 phase]
    // [44 params: tier(8) fee(8) early(4) margin(4) buffer(4) allowance(4)
    //             cofund(4) onboard_lo(4) onboard_hi(4)]
    // [4 s_height][4 sweep_escrow_height][1 flags]
    // flags bit0: our_outpoint    -> [32 txid][4 vout]
    // flags bit1: their_outpoint  -> [32 txid][4 vout]
    // flags bit2: refund          -> [4 csv_maturity][4 len][len tx bytes]
    // flags bit3: possession path -> [4 len][len utf8]
    // Fixed field order, no extension/blob field: there is nowhere for
    // unforeseen (secret) material to hide.

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(256);
        v.push(1u8);
        v.extend_from_slice(&self.swap_session_id);
        v.push(match self.role {
            Role::SecretHolder => 0,
            Role::SecretLearner => 1,
        });
        v.push(self.phase.to_byte());
        v.extend_from_slice(&self.params.tier_d_sats.to_le_bytes());
        v.extend_from_slice(&self.params.delta_fee_sats.to_le_bytes());
        v.extend_from_slice(&self.params.delta_early.to_le_bytes());
        v.extend_from_slice(&self.params.margin.to_le_bytes());
        v.extend_from_slice(&self.params.delta_buffer.to_le_bytes());
        v.extend_from_slice(&self.params.claim_confirm_allowance.to_le_bytes());
        v.extend_from_slice(&self.params.cofunding_window.to_le_bytes());
        v.extend_from_slice(&self.params.onboarding_delay_hours.0.to_le_bytes());
        v.extend_from_slice(&self.params.onboarding_delay_hours.1.to_le_bytes());
        v.extend_from_slice(&self.s_height.to_le_bytes());
        v.extend_from_slice(&self.sweep_escrow_height.to_le_bytes());
        let mut flags = 0u8;
        if self.our_escrow_outpoint.is_some() {
            flags |= 1;
        }
        if self.their_escrow_outpoint.is_some() {
            flags |= 2;
        }
        if self.pre_armed_refund.is_some() {
            flags |= 4;
        }
        if self.possession_record.is_some() {
            flags |= 8;
        }
        v.push(flags);
        for op in [&self.our_escrow_outpoint, &self.their_escrow_outpoint]
            .into_iter()
            .flatten()
        {
            v.extend_from_slice(&op.txid.to_byte_array());
            v.extend_from_slice(&op.vout.to_le_bytes());
        }
        if let Some(r) = &self.pre_armed_refund {
            v.extend_from_slice(&r.csv_maturity_height().to_le_bytes());
            v.extend_from_slice(&(r.tx_bytes().len() as u32).to_le_bytes());
            v.extend_from_slice(r.tx_bytes());
        }
        if let Some(p) = &self.possession_record {
            let s = p.to_string_lossy();
            let b = s.as_bytes();
            v.extend_from_slice(&(b.len() as u32).to_le_bytes());
            v.extend_from_slice(b);
        }
        v
    }

    /// Total parser: any malformed input is Err, never a panic. Only ever
    /// called on plaintext that already passed GCM authentication — but total
    /// anyway (defense in depth; the parser must not be the trust boundary).
    fn from_bytes(b: &[u8]) -> Result<SwapRecord> {
        let mut at = 0usize;
        let version = take_arr::<1>(b, &mut at)?[0];
        if version != 1 {
            return Err(Error::Validation("swap record: unknown version"));
        }
        let swap_session_id = take_arr::<32>(b, &mut at)?;
        let role = match take_arr::<1>(b, &mut at)?[0] {
            0 => Role::SecretHolder,
            1 => Role::SecretLearner,
            _ => return Err(Error::Validation("swap record: unknown role")),
        };
        let phase = SwapPhase::from_byte(take_arr::<1>(b, &mut at)?[0])?;
        let params = Params {
            tier_d_sats: take_le_u64(b, &mut at)?,
            delta_fee_sats: take_le_u64(b, &mut at)?,
            delta_early: take_le_u32(b, &mut at)?,
            margin: take_le_u32(b, &mut at)?,
            delta_buffer: take_le_u32(b, &mut at)?,
            claim_confirm_allowance: take_le_u32(b, &mut at)?,
            cofunding_window: take_le_u32(b, &mut at)?,
            onboarding_delay_hours: (take_le_u32(b, &mut at)?, take_le_u32(b, &mut at)?),
        };
        let s_height = take_le_u32(b, &mut at)?;
        let sweep_escrow_height = take_le_u32(b, &mut at)?;
        let flags = take_arr::<1>(b, &mut at)?[0];
        if flags & !0x0f != 0 {
            return Err(Error::Validation("swap record: unknown flag bits"));
        }
        let mut outpoint = |set: bool| -> Result<Option<OutPoint>> {
            if !set {
                return Ok(None);
            }
            let txid = Txid::from_byte_array(take_arr::<32>(b, &mut at)?);
            let vout = take_le_u32(b, &mut at)?;
            Ok(Some(OutPoint::new(txid, vout)))
        };
        let our_escrow_outpoint = outpoint(flags & 1 != 0)?;
        let their_escrow_outpoint = outpoint(flags & 2 != 0)?;
        let pre_armed_refund = if flags & 4 != 0 {
            let maturity = take_le_u32(b, &mut at)?;
            let len = take_le_u32(b, &mut at)? as usize;
            let bytes = b
                .get(at..at.checked_add(len).ok_or(Error::Validation("swap record: refund length"))?)
                .ok_or(Error::Validation("swap record truncated (refund)"))?
                .to_vec();
            at += len;
            Some(PreArmedRefund::from_signed_tx(bytes, maturity)?)
        } else {
            None
        };
        let possession_record = if flags & 8 != 0 {
            let len = take_le_u32(b, &mut at)? as usize;
            let bytes = b
                .get(at..at.checked_add(len).ok_or(Error::Validation("swap record: path length"))?)
                .ok_or(Error::Validation("swap record truncated (path)"))?;
            at += len;
            let s = core::str::from_utf8(bytes)
                .map_err(|_| Error::Validation("swap record: path not utf-8"))?;
            Some(PathBuf::from(s))
        } else {
            None
        };
        if at != b.len() {
            return Err(Error::Validation("swap record: trailing bytes"));
        }
        let rec = SwapRecord {
            swap_session_id,
            role,
            phase,
            params,
            s_height,
            sweep_escrow_height,
            our_escrow_outpoint,
            their_escrow_outpoint,
            pre_armed_refund,
            possession_record,
        };
        // Loaded records must satisfy the same structural invariants as
        // persisted ones (the ordering invariant re-checked at every trust
        // boundary) — with one exception handled by the caller: a legacy
        // in-flight record being force-aborted.
        rec.check()?;
        Ok(rec)
    }
}

// ----- Store -----------------------------------------------------------------

/// What `open` had to do to bring the store to a safe state. Surface these to
/// the user — every one is a swap whose outcome changed while the wallet was
/// down.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// A live signing session died with the process. The swap was atomically
    /// routed to ABORT_REFUND (INV-2); the refund driver must pick it up.
    AbortedLiveSigning { swap_session_id: [u8; 32] },
    /// A record failed GCM authentication or parsing: tampered, corrupt, or
    /// sealed under a different platform key. Renamed aside (never deleted —
    /// the bytes may still matter forensically), swap no longer tracked.
    Quarantined { path: PathBuf },
    /// A file could not be read at all (I/O). Left in place; the swap is
    /// invisible until the I/O condition clears. NOT quarantined — transient
    /// I/O must not destroy tracking.
    Unreadable { path: PathBuf },
}

/// Crash-safe, sealed-at-rest swap store. One instance per wallet data dir.
pub struct SwapStore {
    dir: PathBuf,
    platform_key: [u8; 32],
}

impl SwapStore {
    /// Open (or create) the store and bring it to a SAFE state: any record
    /// found mid-signing-session is atomically routed to ABORT_REFUND
    /// (INV-2 — the volatile nonces died with the process; the session is
    /// non-resumable). Returns the recovery actions taken.
    pub fn open(
        dir: &Path,
        enclave: &dyn EnclaveKeyProvider,
    ) -> Result<(SwapStore, Vec<RecoveryAction>)> {
        std::fs::create_dir_all(dir).map_err(|_| Error::Abort("swap store dir unavailable"))?;
        let store = SwapStore { dir: dir.to_path_buf(), platform_key: enclave.platform_key() };
        let mut actions = Vec::new();
        let entries =
            std::fs::read_dir(dir).map_err(|_| Error::Abort("swap store dir unreadable"))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(sid) = sid_from_path(&path) else { continue };
            let sealed = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => {
                    actions.push(RecoveryAction::Unreadable { path });
                    continue;
                }
            };
            let tek = crate::crypto::storage::derive_tek(&store.platform_key, &sid);
            let rec = crate::crypto::storage::open(&tek, &sealed)
                .and_then(|pt| SwapRecord::from_bytes(&pt))
                // The filename must agree with the sealed identity. (Cross-swap
                // splices already fail the per-swap TEK; this catches same-key
                // renames.)
                .and_then(|r| {
                    if r.swap_session_id == sid {
                        Ok(r)
                    } else {
                        Err(Error::Validation("swap record: filename/identity mismatch"))
                    }
                });
            let mut rec = match rec {
                Ok(r) => r,
                Err(_) => {
                    match quarantine(&path) {
                        Ok(qpath) => actions.push(RecoveryAction::Quarantined { path: qpath }),
                        Err(_) => actions.push(RecoveryAction::Unreadable { path }),
                    }
                    continue;
                }
            };
            if rec.phase == SwapPhase::Signing {
                rec.phase = SwapPhase::AbortRefund;
                store.write_record(&rec)?;
                actions.push(RecoveryAction::AbortedLiveSigning { swap_session_id: sid });
            }
        }
        Ok((store, actions))
    }

    /// Persist a record. Enforces the structural invariants and the phase
    /// transition table against whatever is already on disk. First insert
    /// must be `Funding` — a swap cannot appear mid-flight from nowhere.
    pub fn put(&self, rec: &SwapRecord) -> Result<()> {
        rec.check()?;
        match self.get(&rec.swap_session_id)? {
            None => {
                if rec.phase != SwapPhase::Funding {
                    return Err(Error::Ordering(
                        "new swap records must start in Funding",
                    ));
                }
            }
            Some(existing) => {
                if !transition_ok(existing.phase, rec.phase) {
                    return Err(Error::Ordering("illegal swap phase transition"));
                }
            }
        }
        self.write_record(rec)
    }

    /// Load one record. `Ok(None)` if absent. A record that fails GCM/parse
    /// is an Err — `get` never guesses. (Startup-time cleanup is `open`'s job.)
    pub fn get(&self, swap_session_id: &[u8; 32]) -> Result<Option<SwapRecord>> {
        let path = self.record_path(swap_session_id);
        let sealed = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Abort("swap record unreadable")),
        };
        let tek = crate::crypto::storage::derive_tek(&self.platform_key, swap_session_id);
        let pt = crate::crypto::storage::open(&tek, &sealed)?;
        let rec = SwapRecord::from_bytes(&pt)?;
        if &rec.swap_session_id != swap_session_id {
            return Err(Error::Validation("swap record: filename/identity mismatch"));
        }
        Ok(Some(rec))
    }

    /// All live (non-quarantined) records.
    pub fn list(&self) -> Result<Vec<SwapRecord>> {
        let mut out = Vec::new();
        let entries =
            std::fs::read_dir(&self.dir).map_err(|_| Error::Abort("swap store dir unreadable"))?;
        for entry in entries.flatten() {
            if let Some(sid) = sid_from_path(&entry.path()) {
                if let Some(rec) = self.get(&sid)? {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }

    fn record_path(&self, sid: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.swap", hex32(sid)))
    }

    /// Seal + atomic tmp-and-rename. Unlike the possession record (append-only
    /// by design), swap records are UPDATED across phases — the transition
    /// table in `put` is what prevents a rewrite from going backwards.
    fn write_record(&self, rec: &SwapRecord) -> Result<()> {
        let tek = crate::crypto::storage::derive_tek(&self.platform_key, &rec.swap_session_id);
        let sealed = crate::crypto::storage::seal(&tek, &rec.to_bytes())?;
        let path = self.record_path(&rec.swap_session_id);
        let tmp = self.dir.join(format!("{}.swap.tmp", hex32(&rec.swap_session_id)));
        std::fs::write(&tmp, &sealed).map_err(|_| Error::Abort("swap record write failed"))?;
        std::fs::rename(&tmp, &path).map_err(|_| Error::Abort("swap record rename failed"))?;
        Ok(())
    }
}

/// `<64 hex>.swap` -> sid. Anything else (tmp files, quarantine, strangers)
/// is not a record.
fn sid_from_path(path: &Path) -> Option<[u8; 32]> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".swap")?;
    if stem.len() != 64 {
        return None;
    }
    let mut sid = [0u8; 32];
    for (i, chunk) in stem.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        sid[i] = (hi << 4) | lo;
    }
    Some(sid)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex32(id: &[u8; 32]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Move a bad record aside without destroying it. Bounded numbered suffixes so
/// repeated corruption cannot loop forever.
fn quarantine(path: &Path) -> Result<PathBuf> {
    for n in 0u32..1000 {
        let q = path.with_extension(format!("swap.quarantine{n}"));
        if !q.exists() {
            std::fs::rename(path, &q)
                .map_err(|_| Error::Abort("quarantine rename failed"))?;
            return Ok(q);
        }
    }
    Err(Error::Abort("quarantine namespace exhausted"))
}

fn take_arr<const N: usize>(b: &[u8], at: &mut usize) -> Result<[u8; N]> {
    let s = b
        .get(*at..*at + N)
        .ok_or(Error::Validation("swap record truncated"))?;
    *at += N;
    s.try_into().map_err(|_| Error::Validation("array slice"))
}

fn take_le_u32(b: &[u8], at: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take_arr::<4>(b, at)?))
}

fn take_le_u64(b: &[u8], at: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take_arr::<8>(b, at)?))
}

// ----- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn refund() -> PreArmedRefund {
        PreArmedRefund::from_signed_tx(vec![0xab; 64], 700_144).expect("refund")
    }

    fn outpoint(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(Txid::from_byte_array(b), 0)
    }

    fn base_record(seed: u8, phase: SwapPhase) -> SwapRecord {
        SwapRecord {
            swap_session_id: sid(seed),
            role: Role::SecretLearner,
            phase,
            params: Params::testnet_provisional(),
            s_height: 700_000,
            sweep_escrow_height: 699_995,
            our_escrow_outpoint: Some(outpoint(1)),
            their_escrow_outpoint: Some(outpoint(2)),
            pre_armed_refund: Some(refund()),
            possession_record: None,
        }
    }

    fn open_store(dir: &Path) -> (SwapStore, Vec<RecoveryAction>) {
        SwapStore::open(dir, &ModeledEnclave).expect("open store")
    }

    #[test]
    fn round_trips_a_full_record() {
        let dir = tempfile::tempdir().unwrap();
        let (store, actions) = open_store(dir.path());
        assert!(actions.is_empty());

        let mut rec = base_record(7, SwapPhase::Funding);
        rec.possession_record = Some(PathBuf::from("C:/somewhere/record.possession"));
        store.put(&rec).expect("put");

        let got = store.get(&sid(7)).expect("get").expect("present");
        assert_eq!(got.swap_session_id, rec.swap_session_id);
        assert_eq!(got.role, rec.role);
        assert_eq!(got.phase, rec.phase);
        assert_eq!(got.s_height, rec.s_height);
        assert_eq!(got.sweep_escrow_height, rec.sweep_escrow_height);
        assert_eq!(got.our_escrow_outpoint, rec.our_escrow_outpoint);
        assert_eq!(got.their_escrow_outpoint, rec.their_escrow_outpoint);
        assert_eq!(
            got.pre_armed_refund.as_ref().unwrap().tx_bytes(),
            rec.pre_armed_refund.as_ref().unwrap().tx_bytes()
        );
        assert_eq!(
            got.pre_armed_refund.as_ref().unwrap().csv_maturity_height(),
            rec.pre_armed_refund.as_ref().unwrap().csv_maturity_height()
        );
        assert_eq!(got.possession_record, rec.possession_record);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn record_is_sealed_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());
        let mut rec = base_record(9, SwapPhase::Funding);
        let marker = "SECRET-PATH-MARKER-must-not-appear-in-plaintext";
        rec.possession_record = Some(PathBuf::from(marker));
        store.put(&rec).unwrap();

        let raw = std::fs::read(store.record_path(&sid(9))).unwrap();
        // Neither the path string nor the 64-byte refund run may appear in
        // the on-disk bytes: the record is ciphertext, not plaintext.
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "possession path leaked to disk in plaintext"
        );
        assert!(
            !raw.windows(64).any(|w| w == [0xab; 64]),
            "refund tx bytes leaked to disk in plaintext"
        );
    }

    #[test]
    fn live_signing_is_aborted_on_open_and_not_resumable() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = open_store(dir.path());
            store.put(&base_record(3, SwapPhase::Funding)).unwrap();
            store.put(&base_record(3, SwapPhase::Signing)).unwrap();
            // process "crashes" here — the in-memory session is gone
        }
        // Fresh process: INV-2 — the dead session routes to ABORT_REFUND.
        let (store, actions) = open_store(dir.path());
        assert_eq!(
            actions,
            vec![RecoveryAction::AbortedLiveSigning { swap_session_id: sid(3) }]
        );
        let rec = store.get(&sid(3)).unwrap().unwrap();
        assert_eq!(rec.phase, SwapPhase::AbortRefund);

        // INV-4 at the wallet layer: the aborted swap is NON-RESUMABLE — there
        // is no AbortRefund -> Signing edge. A retry is a brand-new swap.
        let err = store.put(&base_record(3, SwapPhase::Signing)).unwrap_err();
        assert!(matches!(err, Error::Ordering(_)), "got {err:?}");
        // The refund path stays open, and completion-supersedes stays legal.
        store.put(&base_record(3, SwapPhase::Refunded)).unwrap();
    }

    #[test]
    fn released_records_survive_restart_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let mut rec = base_record(4, SwapPhase::Released);
        rec.possession_record = Some(PathBuf::from("possession/path"));
        {
            let (store, _) = open_store(dir.path());
            store.put(&base_record(4, SwapPhase::Funding)).unwrap();
            store.put(&base_record(4, SwapPhase::Signing)).unwrap();
            store.put(&rec).unwrap();
        }
        // Post-G1 crash: restore-and-extract, NOT abort — open leaves it be.
        let (store, actions) = open_store(dir.path());
        assert!(actions.is_empty(), "Released must not be force-aborted: {actions:?}");
        assert_eq!(store.get(&sid(4)).unwrap().unwrap().phase, SwapPhase::Released);
    }

    #[test]
    fn illegal_transitions_and_malformed_records_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_store(dir.path());

        // A swap cannot appear from nowhere mid-flight.
        let err = store.put(&base_record(5, SwapPhase::Signing)).unwrap_err();
        assert!(matches!(err, Error::Ordering(_)));

        // Terminal phases are frozen.
        store.put(&base_record(5, SwapPhase::Funding)).unwrap();
        store.put(&base_record(5, SwapPhase::AbortRefund)).unwrap();
        store.put(&base_record(5, SwapPhase::Refunded)).unwrap();
        for next in [SwapPhase::Funding, SwapPhase::Signing, SwapPhase::Refunded] {
            assert!(store.put(&base_record(5, next)).is_err(), "{next:?} after terminal");
        }

        // G2 crash half: funded escrow without a pre-armed refund is
        // unrepresentable.
        let mut noexit = base_record(6, SwapPhase::Funding);
        noexit.pre_armed_refund = None;
        let err = store.put(&noexit).unwrap_err();
        assert!(matches!(err, Error::Deadline(_)), "got {err:?}");

        // Signing without a refund is unrepresentable even with no escrow yet.
        let mut nofund = base_record(6, SwapPhase::Signing);
        nofund.our_escrow_outpoint = None;
        nofund.pre_armed_refund = None;
        assert!(store.put(&nofund).is_err());

        // Released demands SL + possession record.
        let mut sh_rel = base_record(6, SwapPhase::Released);
        sh_rel.role = Role::SecretHolder;
        sh_rel.possession_record = Some(PathBuf::from("x"));
        assert!(store.put(&sh_rel).is_err());
        let mut no_poss = base_record(6, SwapPhase::Released);
        no_poss.possession_record = None;
        assert!(store.put(&no_poss).is_err());

        // Hostile params snapshots are rejected on put (ordering invariant
        // re-checked at every trust boundary).
        let mut bad_params = base_record(6, SwapPhase::Funding);
        bad_params.params.margin = 0;
        assert!(store.put(&bad_params).is_err());
    }

    #[test]
    fn tampered_and_foreign_key_records_are_quarantined_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = open_store(dir.path());
            store.put(&base_record(8, SwapPhase::Funding)).unwrap();
            store.put(&base_record(10, SwapPhase::Funding)).unwrap();
            // Tamper with record 8 on disk.
            let p = store.record_path(&sid(8));
            let mut raw = std::fs::read(&p).unwrap();
            let last = raw.len() - 1;
            raw[last] ^= 0x01;
            std::fs::write(&p, &raw).unwrap();
        }
        // Reopen: the tampered record is quarantined (GCM fails), the healthy
        // one is untouched, and open() itself succeeds — one bad file must
        // not brick the wallet.
        let (store, actions) = open_store(dir.path());
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], RecoveryAction::Quarantined { .. }));
        assert!(store.get(&sid(8)).unwrap().is_none(), "tampered record still tracked");
        assert!(store.get(&sid(10)).unwrap().is_some(), "healthy record lost");

        // A store under a DIFFERENT platform key cannot read these records
        // (device-bound custody): they quarantine, they do not decrypt.
        struct OtherEnclave;
        impl EnclaveKeyProvider for OtherEnclave {
            fn platform_key(&self) -> [u8; 32] {
                [0x5e; 32]
            }
        }
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::copy(
            store.record_path(&sid(10)),
            dir2.path().join(format!("{}.swap", hex32(&sid(10)))),
        )
        .unwrap();
        let (store2, actions2) = SwapStore::open(dir2.path(), &OtherEnclave).expect("open");
        assert_eq!(actions2.len(), 1);
        assert!(matches!(actions2[0], RecoveryAction::Quarantined { .. }));
        assert!(store2.get(&sid(10)).unwrap().is_none());
    }

    #[test]
    fn crashed_lease_and_store_abort_compose() {
        // INV-2 + INV-3 together at the wallet layer: after a crash mid-signing,
        // (a) the store routes the swap to ABORT_REFUND, and (b) the signing
        // lease is still held on disk, so a zombie/second process CANNOT start
        // signing the same swap even if it ignores the store.
        let dir = tempfile::tempdir().unwrap();
        let lease_dir = tempfile::tempdir().unwrap();
        let swap_sid = sid(11);
        {
            let (store, _) = open_store(dir.path());
            store.put(&base_record(11, SwapPhase::Funding)).unwrap();
            let lease =
                crate::signing::SingleSignerLease::acquire_in(lease_dir.path(), swap_sid)
                    .expect("lease");
            store.put(&base_record(11, SwapPhase::Signing)).unwrap();
            // Crash: Drop never runs; the lease file stays held.
            std::mem::forget(lease);
        }
        let (store, actions) = open_store(dir.path());
        assert_eq!(
            actions,
            vec![RecoveryAction::AbortedLiveSigning { swap_session_id: swap_sid }]
        );
        assert_eq!(store.get(&swap_sid).unwrap().unwrap().phase, SwapPhase::AbortRefund);
        // The lease still refuses a second signer (INV-3 held conservatively).
        let err = crate::signing::SingleSignerLease::acquire_in(lease_dir.path(), swap_sid)
            .unwrap_err();
        assert!(matches!(err, Error::NonceInvariant(_)), "got {err:?}");
    }
}
