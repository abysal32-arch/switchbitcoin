//! Abort-hygiene: coordinator-free anti-griefing (v3.15 "abort hygiene with
//! UTXO-keyed bans"; the buildable-now slice of the anti-Sybil layer).
//!
//! WHAT THIS IS AND IS NOT. This is a LIVENESS defense, never a fund-safety
//! one — the forward-or-refund invariant holds regardless of what this does.
//! A malicious counterparty who proves encumbrance, matches, then ABANDONS
//! can never steal (the math + pre-armed refund forbid it), but it CAN lock
//! your capital for the co-funding window and waste your signing effort, and
//! it can repeat cheaply. This tracker raises the cost of REPEATING.
//!
//! THE COORDINATOR-FREE TRICK: reputation is keyed to the counterparty's
//! proof-of-encumbrance UTXO (the on-chain outpoint they present to prove a
//! real locked coin), NOT to a network identity. A network identity is free
//! to churn; a confirmed D+Δ_fee UTXO is not. To evade a cooldown the griefer
//! must burn a FRESH encumbered coin (real capital + the onboarding delay) —
//! so Sybil is only as cheap as minting new encumbered coins.
//!
//! ATTRIBUTION IS CONSERVATIVE. Only aborts genuinely ATTRIBUTABLE to the
//! counterparty count against them: they failed to fund after we committed,
//! or they abandoned mid-signing after we committed. A no-fault abort (our
//! side, or a symmetric window expiry before either committed) NEVER
//! penalizes the peer — we must not ban an honest peer for our own or a
//! shared failure. A completed swap REHABILITATES (decays the strike count),
//! so an occasional real-world failure does not accrete into a ban.
//!
//! HONEST LIMITS (documented; the strong version is the deferred discovery
//! layer): keying to the PRESENTED encumbrance UTXO catches no-show reuse and
//! rapid repeats, but a fund-then-abort griefer gets a fresh refund UTXO each
//! time; following that lineage forward needs the discovery proof-of-
//! encumbrance commitment scheme + burnable fidelity bonds (v3.14/v3.15,
//! rank 10, post-cryptographer-review). This module is local policy only —
//! no consensus, no crypto, no effect on the frozen review surface.

use crate::wallet::store::EnclaveKeyProvider;
use crate::{Error, Result};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{OutPoint, Txid};
use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The wall clock (bans are time-based). Tests inject a fixed clock.
pub trait Clock {
    fn now_unix(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// The outcome of a swap attempt with a given counterparty, from OUR side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The swap completed. Rehabilitates the peer (decays a strike).
    Completed,
    /// Attributable: the counterparty never funded after WE committed funds
    /// (fund-and-run / no-show), locking our capital until refund maturity.
    CounterpartyNoShow,
    /// Attributable: the counterparty abandoned mid-signing after WE
    /// committed (funded + entered Phase 5), wasting the co-funding window.
    CounterpartyAbortedInSigning,
    /// NOT attributable to the peer: our own abort, or a symmetric window
    /// expiry before either side committed. Never penalizes the peer.
    NoFaultAbort,
}

impl Outcome {
    fn is_attributable(self) -> bool {
        matches!(
            self,
            Outcome::CounterpartyNoShow | Outcome::CounterpartyAbortedInSigning
        )
    }
}

/// Escalation policy (all durations in seconds). Tunable; conservative
/// defaults. A strike is an attributable abort; the cooldown after `s`
/// strikes is `base << (s-1)` capped at `max_cooldown`, and after
/// `strikes_to_long_ban` strikes the peer is banned for `long_ban`.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub base_cooldown: u64,
    pub max_cooldown: u64,
    pub strikes_to_long_ban: u32,
    pub long_ban: u64,
    /// A completion decays this many strikes (rehabilitation).
    pub completion_decay: u32,
    /// Strike counters older than this since last activity are forgotten
    /// (an honest peer is not haunted forever by one old failure).
    pub record_ttl: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            base_cooldown: 3_600,           // 1 h after the first strike
            max_cooldown: 24 * 3_600,       // capped at 24 h
            strikes_to_long_ban: 5,         // 5 attributable aborts ⇒ long ban
            long_ban: 30 * 24 * 3_600,      // 30 days
            completion_decay: 1,            // one good swap forgives one strike
            record_ttl: 90 * 24 * 3_600,    // forget stale records after 90 days
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PeerRecord {
    strikes: u32,
    completions: u32,
    /// Unix time this peer is blocked until (0 = not blocked).
    blocked_until: u64,
    /// Last time we touched this record (for TTL expiry).
    last_seen: u64,
}

/// Sealed, coordinator-free griefing tracker keyed by encumbrance UTXO.
pub struct GriefingLedger {
    path: PathBuf,
    platform_key: [u8; 32],
    policy: Policy,
    records: HashMap<OutPoint, PeerRecord>,
    _lock: std::fs::File,
}

fn hygiene_salt() -> [u8; 32] {
    sha256::Hash::hash(b"newkey-abort-hygiene-v1").to_byte_array()
}

impl GriefingLedger {
    /// Open (or create) the tracker. FAIL-SAFE, not fail-closed: unlike the
    /// coin ledger, this holds no funds — a corrupt/unreadable file starts
    /// EMPTY (worst case we temporarily forget some bans; we never lose
    /// money and never wrongly ban). Single-instance via an OS lock.
    pub fn open(
        dir: &Path,
        enclave: &dyn EnclaveKeyProvider,
        policy: Policy,
    ) -> Result<GriefingLedger> {
        std::fs::create_dir_all(dir).map_err(|_| Error::Abort("hygiene dir unavailable"))?;
        let lock_path = dir.join(".hygiene.lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| Error::Abort("hygiene lock file unavailable"))?;
        if lock.try_lock().is_err() {
            return Err(Error::Abort("another process holds the hygiene tracker"));
        }
        let path = dir.join("hygiene.bin");
        let platform_key = enclave.platform_key();
        let records = match std::fs::read(&path) {
            Ok(sealed) => {
                let tek = crate::crypto::storage::derive_tek(&platform_key, &hygiene_salt());
                // Fail-SAFE: a bad/foreign-keyed file just starts empty (no
                // funds here) — we never wrongly ban, never lose money.
                crate::crypto::storage::open(&tek, &sealed)
                    .and_then(|pt| parse(&pt))
                    .unwrap_or_default()
            }
            Err(_) => HashMap::new(),
        };
        Ok(GriefingLedger { path, platform_key, policy, records, _lock: lock })
    }

    /// Is this counterparty (by their encumbrance UTXO) allowed to open a
    /// swap with us right now? A peer in cooldown/ban is refused — a pure
    /// LIVENESS/matching decision; it never touches an in-flight swap's
    /// fund safety. Unknown peers are allowed (innocent until attributable).
    pub fn is_allowed(&self, counterparty_utxo: OutPoint, now: u64) -> bool {
        match self.records.get(&counterparty_utxo) {
            None => true,
            Some(r) => now >= r.blocked_until,
        }
    }

    /// The unix time a blocked peer becomes allowed again (for surfacing to
    /// the user / retry scheduling). None if not currently blocked.
    pub fn blocked_until(&self, counterparty_utxo: OutPoint, now: u64) -> Option<u64> {
        self.records
            .get(&counterparty_utxo)
            .filter(|r| now < r.blocked_until)
            .map(|r| r.blocked_until)
    }

    /// Record the outcome of a swap attempt and persist. Attributable aborts
    /// add a strike and (re)compute the cooldown/ban; a completion decays
    /// strikes. No-fault aborts are recorded as activity but never penalize.
    pub fn record_outcome(
        &mut self,
        counterparty_utxo: OutPoint,
        outcome: Outcome,
        now: u64,
    ) -> Result<()> {
        // A no-fault outcome is a TRUE no-op (review fix): it must not penalize
        // the peer AND must not count as strike-aging "activity" — otherwise it
        // would refresh `last_seen` and keep a residual strike from ever aging
        // out under the TTL, silently disadvantaging an honest peer. So it
        // never touches the record (nor triggers a needless persist).
        if outcome == Outcome::NoFaultAbort {
            return Ok(());
        }
        // Snapshot for rollback-on-persist-failure (memory never diverges).
        let snapshot = self.records.get(&counterparty_utxo).cloned();
        {
            let rec = self.records.entry(counterparty_utxo).or_default();
            rec.last_seen = now;
            match outcome {
                Outcome::Completed => {
                    rec.completions = rec.completions.saturating_add(1);
                    rec.strikes = rec.strikes.saturating_sub(self.policy.completion_decay);
                    // A completion clears the cooldown ONLY when it fully
                    // rehabilitates the peer (strikes back to 0). It must NOT
                    // instantly wipe a multi-strike ban (review fix): a serial
                    // griefer at a 30-day ban cannot buy its way out with one
                    // real swap — the active ban stands and only the FUTURE
                    // escalation is reduced. An honest peer with a single strike
                    // still clears immediately (strikes → 0).
                    if rec.strikes == 0 {
                        rec.blocked_until = 0;
                    }
                }
                o if o.is_attributable() => {
                    rec.strikes = rec.strikes.saturating_add(1);
                    let block_secs = if rec.strikes >= self.policy.strikes_to_long_ban {
                        self.policy.long_ban
                    } else {
                        // base << (strikes-1), capped. strikes >= 1 here.
                        let shift = rec.strikes.saturating_sub(1).min(31);
                        self.policy
                            .base_cooldown
                            .saturating_mul(1u64 << shift)
                            .min(self.policy.max_cooldown)
                    };
                    rec.blocked_until = now.saturating_add(block_secs);
                }
                _ => {}
            }
        }
        // Drop a fully-rehabilitated, unblocked record to bound growth.
        if let Some(rec) = self.records.get(&counterparty_utxo) {
            if rec.strikes == 0 && now >= rec.blocked_until {
                self.records.remove(&counterparty_utxo);
            }
        }
        match self.persist() {
            Ok(()) => Ok(()),
            Err(e) => {
                // Roll back so memory matches disk.
                match snapshot {
                    Some(prev) => {
                        self.records.insert(counterparty_utxo, prev);
                    }
                    None => {
                        self.records.remove(&counterparty_utxo);
                    }
                }
                Err(e)
            }
        }
    }

    /// Forget stale records (last activity older than the TTL) while KEEPING
    /// any still-active ban. Call periodically; also bounds the on-disk size.
    /// Transactional (review fix): the in-memory drop is rolled back if the
    /// persist fails, so memory never diverges from disk — the same
    /// discipline `record_outcome` uses.
    pub fn prune(&mut self, now: u64) -> Result<()> {
        let ttl = self.policy.record_ttl;
        let removed: Vec<(OutPoint, PeerRecord)> = self
            .records
            .iter()
            .filter(|(_, r)| !(now < r.blocked_until || now.saturating_sub(r.last_seen) < ttl))
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        if removed.is_empty() {
            return Ok(());
        }
        for (k, _) in &removed {
            self.records.remove(k);
        }
        match self.persist() {
            Ok(()) => Ok(()),
            Err(e) => {
                for (k, v) in removed {
                    self.records.insert(k, v);
                }
                Err(e)
            }
        }
    }

    pub fn tracked_peers(&self) -> usize {
        self.records.len()
    }

    // ---- persistence (sealed; v1) ----
    // [1 ver=1][4 count] then per record:
    // [32 txid][4 vout][4 strikes][4 completions][8 blocked_until][8 last_seen]

    fn persist(&self) -> Result<()> {
        let mut v = Vec::with_capacity(8 + self.records.len() * 60);
        v.push(1u8);
        v.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for (op, r) in &self.records {
            v.extend_from_slice(&op.txid.to_byte_array());
            v.extend_from_slice(&op.vout.to_le_bytes());
            v.extend_from_slice(&r.strikes.to_le_bytes());
            v.extend_from_slice(&r.completions.to_le_bytes());
            v.extend_from_slice(&r.blocked_until.to_le_bytes());
            v.extend_from_slice(&r.last_seen.to_le_bytes());
        }
        let tek = crate::crypto::storage::derive_tek(&self.platform_key, &hygiene_salt());
        let sealed = crate::crypto::storage::seal(&tek, &v)?;
        let tmp = self.path.with_extension("bin.tmp");
        let mut f =
            std::fs::File::create(&tmp).map_err(|_| Error::Abort("hygiene tmp create failed"))?;
        f.write_all(&sealed)
            .and_then(|()| f.sync_all())
            .map_err(|_| Error::Abort("hygiene write/sync failed"))?;
        drop(f);
        std::fs::rename(&tmp, &self.path).map_err(|_| Error::Abort("hygiene rename failed"))?;
        Ok(())
    }
}

fn parse(b: &[u8]) -> Result<HashMap<OutPoint, PeerRecord>> {
    let mut at = 0usize;
    if take_arr::<1>(b, &mut at)?[0] != 1 {
        return Err(Error::Validation("hygiene: unknown version"));
    }
    let count = take_le_u32(b, &mut at)? as usize;
    let mut records = HashMap::with_capacity(count.min(1 << 16));
    for _ in 0..count {
        let txid = Txid::from_byte_array(take_arr::<32>(b, &mut at)?);
        let vout = take_le_u32(b, &mut at)?;
        let strikes = take_le_u32(b, &mut at)?;
        let completions = take_le_u32(b, &mut at)?;
        let blocked_until = take_le_u64(b, &mut at)?;
        let last_seen = take_le_u64(b, &mut at)?;
        records.insert(
            OutPoint::new(txid, vout),
            PeerRecord { strikes, completions, blocked_until, last_seen },
        );
    }
    if at != b.len() {
        return Err(Error::Validation("hygiene: trailing bytes"));
    }
    Ok(records)
}

fn take_arr<const N: usize>(b: &[u8], at: &mut usize) -> Result<[u8; N]> {
    let s = b.get(*at..*at + N).ok_or(Error::Validation("hygiene truncated"))?;
    *at += N;
    s.try_into().map_err(|_| Error::Validation("array slice"))
}
fn take_le_u32(b: &[u8], at: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take_arr::<4>(b, at)?))
}
fn take_le_u64(b: &[u8], at: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take_arr::<8>(b, at)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::store::ModeledEnclave;

    fn utxo(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(Txid::from_byte_array(b), 0)
    }

    fn open(dir: &Path) -> GriefingLedger {
        GriefingLedger::open(dir, &ModeledEnclave, Policy::default()).unwrap()
    }

    #[test]
    fn unknown_peer_is_allowed_and_attributable_abort_escalates() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = open(dir.path());
        let peer = utxo(1);
        let t0 = 1_000_000u64;

        assert!(g.is_allowed(peer, t0), "unknown peer allowed");

        // First attributable abort: 1 h cooldown.
        g.record_outcome(peer, Outcome::CounterpartyNoShow, t0).unwrap();
        assert!(!g.is_allowed(peer, t0));
        assert!(!g.is_allowed(peer, t0 + 3_599));
        assert!(g.is_allowed(peer, t0 + 3_600), "cooldown elapses");

        // Second strike: 2 h. Third: 4 h (base<<(s-1), capped at 24h).
        g.record_outcome(peer, Outcome::CounterpartyAbortedInSigning, t0 + 3_600).unwrap();
        assert_eq!(g.blocked_until(peer, t0 + 3_600), Some(t0 + 3_600 + 2 * 3_600));
        g.record_outcome(peer, Outcome::CounterpartyNoShow, t0 + 10_000).unwrap();
        assert_eq!(g.blocked_until(peer, t0 + 10_000), Some(t0 + 10_000 + 4 * 3_600));
    }

    #[test]
    fn no_fault_abort_never_penalizes_the_peer() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = open(dir.path());
        let peer = utxo(2);
        let t0 = 500u64;
        for _ in 0..10 {
            g.record_outcome(peer, Outcome::NoFaultAbort, t0).unwrap();
        }
        assert!(g.is_allowed(peer, t0), "our-fault/no-fault aborts must never ban the peer");
        assert_eq!(g.tracked_peers(), 0, "a peer with no strikes is not retained");
    }

    #[test]
    fn repeated_attributable_aborts_reach_a_long_ban() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = open(dir.path());
        let peer = utxo(3);
        let mut t = 0u64;
        for _ in 0..5 {
            g.record_outcome(peer, Outcome::CounterpartyNoShow, t).unwrap();
            t += 100; // rapid repeats (evading cooldown is the point of the ban)
        }
        // 5 strikes ⇒ 30-day ban.
        assert_eq!(g.blocked_until(peer, t), Some(t - 100 + 30 * 24 * 3_600));
        assert!(!g.is_allowed(peer, t + 29 * 24 * 3_600));
        assert!(g.is_allowed(peer, t - 100 + 30 * 24 * 3_600));
    }

    #[test]
    fn completion_fully_rehabilitates_a_single_strike_peer() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = open(dir.path());
        let peer = utxo(4);
        let t0 = 1_000u64;
        g.record_outcome(peer, Outcome::CounterpartyNoShow, t0).unwrap();
        assert!(!g.is_allowed(peer, t0));
        // A completed swap forgives the single strike (→ 0) AND clears the
        // cooldown — an honest peer with one blip is fully rehabilitated.
        g.record_outcome(peer, Outcome::Completed, t0 + 1).unwrap();
        assert!(g.is_allowed(peer, t0 + 1), "single-strike completion clears the cooldown");
        assert_eq!(g.tracked_peers(), 0, "rehabilitated peer is dropped");
    }

    /// Review fix (finding 3): a serial griefer at a long ban CANNOT buy its
    /// way out with one real swap. A completion decays a strike but does NOT
    /// wipe a multi-strike active ban — only future escalation is reduced.
    #[test]
    fn completion_does_not_wipe_a_multi_strike_ban() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = open(dir.path());
        let peer = utxo(5);
        let t0 = 1_000u64;
        for _ in 0..5 {
            g.record_outcome(peer, Outcome::CounterpartyNoShow, t0).unwrap();
        }
        // 5 strikes → 30-day ban.
        assert!(!g.is_allowed(peer, t0 + 100));
        // One completion: strike 5→4, but the ACTIVE ban still stands.
        g.record_outcome(peer, Outcome::Completed, t0 + 100).unwrap();
        assert!(
            !g.is_allowed(peer, t0 + 100),
            "one completion must not lift a multi-strike ban"
        );
        assert!(!g.is_allowed(peer, t0 + 29 * 24 * 3_600), "ban duration unchanged");
    }

    /// Review fix (finding 1): a NoFaultAbort is a true no-op — it must not
    /// refresh the strike-aging clock, so a residual strike on an otherwise-
    /// honest peer still ages out under the TTL despite ongoing no-fault
    /// activity.
    #[test]
    fn no_fault_activity_does_not_keep_a_residual_strike_alive() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = open(dir.path());
        let peer = utxo(6);
        let t0 = 1_000u64;
        // One old attributable strike (cooldown long past).
        g.record_outcome(peer, Outcome::CounterpartyNoShow, t0).unwrap();
        // Sustained no-fault activity across > TTL (our crashes / symmetric
        // expiries) — none of it may refresh the strike's aging clock.
        for k in 1..100u64 {
            g.record_outcome(peer, Outcome::NoFaultAbort, t0 + k * 24 * 3_600).unwrap();
        }
        // Past the TTL since the STRIKE (not since the last no-fault event):
        // the strike ages out on prune.
        g.prune(t0 + 91 * 24 * 3_600).unwrap();
        assert_eq!(g.tracked_peers(), 0, "residual strike must age out despite no-fault activity");
    }

    #[test]
    fn sybil_evasion_costs_a_fresh_utxo_bans_are_per_utxo() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = open(dir.path());
        let t0 = 42u64;
        // Peer A's coin is banned...
        for _ in 0..5 {
            g.record_outcome(utxo(10), Outcome::CounterpartyNoShow, t0).unwrap();
        }
        assert!(!g.is_allowed(utxo(10), t0));
        // ...but a DIFFERENT coin (a fresh encumbered UTXO — real capital +
        // onboarding delay to mint) is unaffected. That capital cost IS the
        // coordinator-free Sybil resistance.
        assert!(g.is_allowed(utxo(11), t0));
    }

    #[test]
    fn bans_survive_restart_and_bad_file_is_fail_safe_empty() {
        let dir = tempfile::tempdir().unwrap();
        let peer = utxo(7);
        let t0 = 2_000u64;
        {
            let mut g = open(dir.path());
            g.record_outcome(peer, Outcome::CounterpartyNoShow, t0).unwrap();
            // Single instance while open.
            assert!(GriefingLedger::open(dir.path(), &ModeledEnclave, Policy::default()).is_err());
        }
        // Reopen: the cooldown persisted (sealed).
        {
            let g = open(dir.path());
            assert!(!g.is_allowed(peer, t0 + 100));
        }
        // Corrupt the file: FAIL-SAFE — starts empty, never wrongly bans, no
        // funds at risk (this is not the coin ledger).
        let p = dir.path().join("hygiene.bin");
        let mut bad = std::fs::read(&p).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        std::fs::write(&p, &bad).unwrap();
        let g = open(dir.path());
        assert!(g.is_allowed(peer, t0 + 100), "corrupt hygiene file must fail SAFE (empty)");
    }

    #[test]
    fn prune_forgets_stale_records_but_keeps_active_bans() {
        let dir = tempfile::tempdir().unwrap();
        let mut g = open(dir.path());
        let stale = utxo(20);
        let active = utxo(21);
        let t0 = 1_000u64;
        // A single old strike that has long since cooled down.
        g.record_outcome(stale, Outcome::CounterpartyNoShow, t0).unwrap();
        // An active long ban.
        for _ in 0..5 {
            g.record_outcome(active, Outcome::CounterpartyNoShow, t0).unwrap();
        }
        let much_later = t0 + 91 * 24 * 3_600;
        g.prune(much_later).unwrap();
        // The active ban is 30 days, long expired by +91d, and `stale` cooled
        // down too — both past TTL with no recent activity ⇒ both pruned.
        assert_eq!(g.tracked_peers(), 0);
        drop(g); // release the single-instance lock before reopening
        // But a still-active ban is retained across a prune.
        let mut g2 = open(dir.path());
        for _ in 0..5 {
            g2.record_outcome(active, Outcome::CounterpartyNoShow, much_later).unwrap();
        }
        g2.prune(much_later + 3_600).unwrap();
        assert!(!g2.is_allowed(active, much_later + 3_600), "active ban survives prune");
    }
}
