//! Wallet ledger + onboarding pipeline (wallet rank 3; v3.13 Phase 0–1).
//!
//! THE ANONYMITY-SET FOUNDATION. v3.13: "Auto-split to D + Δ_fee. The wallet
//! splits the deposit client-side into pre-encumbrance UTXOs of exactly
//! D + Δ_fee each, so that every future Setup spends one whole with no
//! change. The remainder is placed in a separate unencumbered change output
//! that absorbs all rounding. This is the only change output in the user's
//! lifecycle, and it is unlinkable to any future swap." And v3.14 Phase 1:
//! "randomized 24–72 h delay" before encumbrance eligibility — severing the
//! withdrawal↔encumbrance timing correlation.
//!
//! COIN CLASSES AND NON-MIXING (enforced by construction — the ledger simply
//! has no API that co-spends classes):
//!   * `Deposit` — incoming receive; spendable ONLY by the split.
//!   * `PreEncumbrance` — exactly D + Δ_fee; spendable ONLY whole, by a
//!     Setup, and ONLY after its randomized delay.
//!   * `OnboardingChange` — the one change output; never touches a swap.
//!   * `Reserve` — CPFP backstop coins (congestion-only; opt-in WITH a
//!     typed linkage acknowledgement for completions, silent for refunds).
//!   * `Swapped` — exactly D at a fresh destination; carries a persisted
//!     `deposit_linked` taint flag when a deposit-provenance reserve ever
//!     bumped its completion (the linkage is recorded, not just consented).
//!
//! Completions structurally take no external input (single escrow input,
//! `tx::txbuild`), so "no external input ever touches a completion" holds at
//! the transaction-builder level, not by ledger discipline.
//!
//! DELAY ANCHORING (adversarial-review fix): the randomized delay is sampled
//! at split time but ANCHORED AT CONFIRMATION — a split that lingers in the
//! mempool must not consume its own decorrelation delay. Eligibility is
//! double-anchored: wall-clock (`eligible_at_unix = confirm_time + delay`)
//! AND chain height (`eligible_height = confirm_height + delay/600`), so an
//! attacker who can shift the system clock still cannot collapse the delay
//! without also mining the chain forward.
//!
//! SPLIT LIFECYCLE: `split_deposit` → broadcast → (`bump_split_fee` under
//! congestion, RBF, reusing the SAME child keys and delays)* →
//! `confirm_split`. Every attempt's children are tracked until one attempt
//! confirms (mutually exclusive by shared input); the winning attempt's
//! children activate, the losers are dropped, and the signed bytes are
//! RETAINED on the spent deposit for shallow-reorg recovery.
//!
//! LEASES carry the lessee's identity (swap_session_id) and are reconciled
//! at startup against the live swap set — a crash between lease and
//! swap-record creation cannot orphan a coin.
//!
//! KEYS: the ledger persists only `(purpose, index)`; single-sig signing
//! goes through `KeySource::sign_key_path` (enclave seam) — the ledger never
//! touches a raw secret. RESTORE CAVEAT: restoring an OLD ledger backup
//! rewinds `next_key_index`; restore tooling must call
//! `raise_key_index_floor` after a forward scan or new addresses will reuse
//! on-chain indices.
//!
//! PERSISTENCE: one sealed file (`ledger.bin`), fail-CLOSED on corruption
//! (the coin memory never silently resets), OS-file-lock single instance,
//! fsync'd atomic writes, transactional mutators (memory rolls back if the
//! persist fails — no divergence for a later write to flush).

use crate::settlement::params::Params;
use crate::wallet::keys::{KeyPurpose, KeySource};
use crate::wallet::store::EnclaveKeyProvider;
use crate::{Error, Result};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{OutPoint, ScriptBuf, Txid};
use rand::TryRngCore;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// v3.13 Phase 0 warning, verbatim. Full-screen, non-dismissable, shown once
/// at onboarding and again at first deposit; the UI's Confirm button passes
/// the displayed text to `acknowledge_phase0`.
pub const PHASE0_WARNING: &str = "Warning: Before you send Bitcoin to Swap Key, move it to a fresh address first. If it came from a KYC'd exchange or any service that knows your identity, send it to a brand-new self-custodied address you control before depositing here. Swap Key protects your history from the moment your Bitcoin arrives; it cannot erase provenance that already exists on-chain before you arrive. One clean transaction to a wallet you control, wait for confirmation, then deposit.";

/// The congestion-bump linkage warning (v3.13: "bumping via a reserve UTXO
/// reintroduces the link... explicit, user-visible consent"). Shown before a
/// reserve coin may bump a COMPLETION; refund bumps are silent by spec.
pub const LINKAGE_WARNING: &str = "Network congestion: paying extra fee from your reserve will publicly link this swap to your deposit history. This reduces the privacy of this one swap only. You can also wait for congestion to clear.";

/// Proof the Phase-0 warning was displayed and confirmed. Non-Clone,
/// non-constructible except via `acknowledge_phase0`.
#[derive(Debug)]
pub struct Phase0Ack {
    _private: (),
}

/// Mint the Phase-0 acknowledgement by echoing the exact displayed copy.
pub fn acknowledge_phase0(displayed_text: &str) -> Result<Phase0Ack> {
    if displayed_text != PHASE0_WARNING {
        return Err(Error::Validation(
            "phase-0 acknowledgement must echo the exact warning copy",
        ));
    }
    Ok(Phase0Ack { _private: () })
}

/// Proof the linkage warning was displayed and confirmed (per bump).
#[derive(Debug)]
pub struct LinkageAck {
    _private: (),
}

pub fn acknowledge_linkage(displayed_text: &str) -> Result<LinkageAck> {
    if displayed_text != LINKAGE_WARNING {
        return Err(Error::Validation(
            "linkage acknowledgement must echo the exact warning copy",
        ));
    }
    Ok(LinkageAck { _private: () })
}

/// What a reserve lease will bump. Refund bumps are silent (a refund has no
/// privacy left); completion bumps demand the typed linkage consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BumpTarget {
    Refund,
    Completion,
}

/// Wall-clock seam (the onboarding delay is specified in hours, not blocks).
pub trait WalletClock {
    fn now_unix(&self) -> u64;
}

pub struct SystemClock;

impl WalletClock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// P2TR dust threshold (sats): below this, change folds into the fee. 330
/// per Bitcoin Core's P2TR dust rule (546 is the LEGACY threshold — using it
/// would silently burn relayable 330–545-sat change).
const DUST_SATS: u64 = 330;
/// Sane wall-clock window for the confirmation-time eligibility anchor. A
/// reading outside it is a clock FAULT (dead-battery RTC pinned to an extreme
/// date, an NTP glitch, `SystemClock`'s `unwrap_or(0)` fallback). A faulted
/// reading is NOT trusted: it collapses to `SANE_CLOCK_MIN_UNIX`, degrading
/// the WALL half of the dual anchor to trivially-satisfied while the HEIGHT
/// anchor stays fully load-bearing (the onboarding delay is still enforced in
/// block time). Collapsing DOWN — never clamping an absurd-future reading to
/// the window ceiling — is deliberate: the anchor is written exactly once (no
/// code path re-anchors an `Unspent` coin, and the dual gate needs BOTH
/// anchors to pass), so an anchor written from an absurd-future reading would
/// freeze the coin until that date with no recovery API.
const SANE_CLOCK_MIN_UNIX: u64 = 1_600_000_000; // 2020-09-13
const SANE_CLOCK_MAX_UNIX: u64 = 7_258_118_400; // 2200-01-01
/// Standardness guard: cap pre-encumbrance outputs per split; the excess
/// stays in change (re-splittable later). 64 P2TR outputs ≈ 2.8 kvB.
const MAX_PRE_ENC_OUTPUTS: u64 = 64;
/// Absurd-fee ceiling for the split (defense against a buggy/hostile caller
/// burning the deposit as fee).
const MAX_SPLIT_FEE_SATS: u64 = 100_000;
/// RBF attempt cap per deposit (each attempt tracks its children).
const MAX_SPLIT_ATTEMPTS: usize = 16;
/// Expected seconds per block for the chain-height eligibility floor.
const SECS_PER_BLOCK: u64 = 600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinClass {
    Deposit,
    PreEncumbrance,
    OnboardingChange,
    Reserve,
    Swapped,
}

impl CoinClass {
    fn to_byte(self) -> u8 {
        match self {
            CoinClass::Deposit => 0,
            CoinClass::PreEncumbrance => 1,
            CoinClass::OnboardingChange => 2,
            CoinClass::Reserve => 3,
            CoinClass::Swapped => 4,
        }
    }
    fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            0 => CoinClass::Deposit,
            1 => CoinClass::PreEncumbrance,
            2 => CoinClass::OnboardingChange,
            3 => CoinClass::Reserve,
            4 => CoinClass::Swapped,
            _ => return Err(Error::Validation("ledger: unknown coin class")),
        })
    }
}

fn purpose_to_byte(p: KeyPurpose) -> u8 {
    match p {
        KeyPurpose::Deposit => 0,
        KeyPurpose::PreEncumbrance => 1,
        KeyPurpose::OnboardingChange => 2,
        KeyPurpose::Reserve => 3,
        KeyPurpose::SwapDestination => 4,
    }
}

fn purpose_from_byte(b: u8) -> Result<KeyPurpose> {
    Ok(match b {
        0 => KeyPurpose::Deposit,
        1 => KeyPurpose::PreEncumbrance,
        2 => KeyPurpose::OnboardingChange,
        3 => KeyPurpose::Reserve,
        4 => KeyPurpose::SwapDestination,
        _ => return Err(Error::Validation("ledger: unknown key purpose")),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinState {
    /// Confirmed and spendable (subject to class rules + eligibility).
    Unspent,
    /// Created by a broadcast-but-unconfirmed split attempt.
    PendingConfirm,
    /// A deposit whose split tx is signed (and possibly broadcast/bumped)
    /// but not yet confirmed. Exits: `confirm_split` or `bump_split_fee`.
    SplitPending,
    /// Reserved by a live swap/backstop; `lessee` says which.
    Leased,
    /// Gone.
    Spent,
}

impl CoinState {
    fn to_byte(self) -> u8 {
        match self {
            CoinState::Unspent => 0,
            CoinState::PendingConfirm => 1,
            CoinState::SplitPending => 2,
            CoinState::Leased => 3,
            CoinState::Spent => 4,
        }
    }
    fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            0 => CoinState::Unspent,
            1 => CoinState::PendingConfirm,
            2 => CoinState::SplitPending,
            3 => CoinState::Leased,
            4 => CoinState::Spent,
            _ => return Err(Error::Validation("ledger: unknown coin state")),
        })
    }
}

/// One signed split ATTEMPT (deposit only): the attempt's txid PAIRED with its
/// full signed bytes. Keeping the bytes per attempt (not just the latest) is
/// what lets `confirm_split` retain the WINNING attempt's tx for shallow-reorg
/// rebroadcast: `bump_split_fee` overwrites `split_tx` with the newest attempt,
/// but a LOWER-fee earlier attempt can still be the one that confirms (a real
/// mempool/RBF propagation race), and rebroadcasting the latest — losing,
/// mutually exclusive — tx after a reorg would strand the confirmed children
/// as phantoms while minting untracked outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitAttempt {
    pub txid: Txid,
    pub tx_bytes: Vec<u8>,
}

/// One tracked coin. Key material is NOT here — only `(key_purpose, key_index)`.
#[derive(Clone, Debug)]
pub struct CoinRecord {
    pub outpoint: OutPoint,
    pub amount_sats: u64,
    pub class: CoinClass,
    pub state: CoinState,
    /// The key-derivation domain this coin's key was ISSUED under. Fixed at
    /// issuance and survives class changes (change promoted to reserve still
    /// signs under `OnboardingChange`) — always derive with
    /// `(key_purpose, key_index)` from the record, never from the class.
    pub key_purpose: KeyPurpose,
    pub key_index: u32,
    pub created_height: u32,
    /// STATE-SCOPED (use `eligibility_unix()`, not this field directly):
    /// while `PendingConfirm` this is the sampled delay DURATION (seconds);
    /// once confirmed it is the ABSOLUTE eligibility time (confirm + delay).
    /// 0 for classes with no delay.
    pub delay_or_eligible_unix: u64,
    /// Chain-height eligibility floor, set at confirmation
    /// (confirm_height + delay/600). Second anchor against clock shift.
    pub eligible_height: u32,
    /// True when this coin's history is publicly linked to the deposit
    /// cluster (a reserve coin bumped its completion). Persisted taint.
    pub deposit_linked: bool,
    /// For split children: the deposit that produced them.
    pub parent: Option<OutPoint>,
    /// For Leased coins: who holds the lease (swap_session_id or backstop id).
    pub lessee: Option<[u8; 32]>,
    /// Deposit only: the signed split tx to (re)broadcast — the LATEST attempt
    /// while the split is pending, and the CONFIRMED (winning) attempt after
    /// `confirm_split` (retained for shallow-reorg rebroadcast; installing the
    /// winner is what makes that retention truthful when a non-latest attempt
    /// confirms).
    pub split_tx: Option<Vec<u8>>,
    /// Deposit only: every split attempt — txid + signed bytes, paired
    /// (mutually exclusive txs; at most one ever confirms).
    pub split_attempts: Vec<SplitAttempt>,
}

impl CoinRecord {
    /// Absolute eligibility time, once known (None while the split attempt
    /// is unconfirmed — the delay anchors at CONFIRMATION).
    pub fn eligibility_unix(&self) -> Option<u64> {
        match self.state {
            CoinState::PendingConfirm => None,
            _ => Some(self.delay_or_eligible_unix),
        }
    }
}

/// The outcome of `split_deposit` / `bump_split_fee`, ready to broadcast.
/// (All-public chain data — Debug is safe.)
#[derive(Debug)]
pub struct SplitPlan {
    pub tx_bytes: Vec<u8>,
    pub txid: Txid,
    pub pre_encumbrance_count: u32,
    pub change_sats: u64,
    /// Which output index carries the change (shuffled position — a fixed
    /// change position would fingerprint the tx shape). None if no change.
    pub change_vout: Option<u32>,
    /// Sampled per-child delay DURATIONS (seconds); the absolute eligibility
    /// is fixed at confirmation time.
    pub delay_secs: Vec<u64>,
}

/// The outcome of a chain-aware lease reconciliation
/// ([`Ledger::reconcile_leases_with_chain`]): the outpoints marked `Spent`
/// because the chain confirms them gone (the phantom heal), and the orphaned
/// leases released back to `Unspent`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LeaseReconcile {
    /// Leased-or-unspent coins the chain confirms spent → now `Spent`.
    pub swept: Vec<OutPoint>,
    /// Still-leased coins whose lessee is not in the live set → now `Unspent`.
    pub released: Vec<OutPoint>,
}

/// Sealed, fail-closed, single-instance wallet coin ledger.
pub struct Ledger {
    path: PathBuf,
    platform_key: [u8; 32],
    coins: Vec<CoinRecord>,
    /// Monotonic key-index counter: a (purpose, index) pair is never reused.
    next_key_index: u32,
    first_deposit_acked: bool,
    _lock: std::fs::File,
}

/// Domain-separated wallet-ledger TEK salt.
fn ledger_salt() -> [u8; 32] {
    sha256::Hash::hash(b"newkey-ledger-v1").to_byte_array()
}

impl Ledger {
    /// Onboarding: create a fresh ledger. Demands the Phase-0 acknowledgement
    /// (shown once at onboarding). Refuses to clobber an existing ledger.
    pub fn create(
        dir: &Path,
        enclave: &dyn EnclaveKeyProvider,
        _onboarding_ack: Phase0Ack,
    ) -> Result<Ledger> {
        std::fs::create_dir_all(dir).map_err(|_| Error::Abort("ledger dir unavailable"))?;
        let path = dir.join("ledger.bin");
        if path.exists() {
            return Err(Error::Abort("ledger already exists (refusing to clobber)"));
        }
        let lock = Self::acquire_lock(dir)?;
        let ledger = Ledger {
            path,
            platform_key: enclave.platform_key(),
            coins: Vec::new(),
            next_key_index: 0,
            first_deposit_acked: false,
            _lock: lock,
        };
        ledger.persist()?;
        Ok(ledger)
    }

    /// Reopen an existing ledger. FAIL-CLOSED: a missing or corrupt ledger is
    /// an error (the coin memory must never silently reset).
    pub fn open(dir: &Path, enclave: &dyn EnclaveKeyProvider) -> Result<Ledger> {
        let path = dir.join("ledger.bin");
        let lock = Self::acquire_lock(dir)?;
        let sealed = std::fs::read(&path)
            .map_err(|_| Error::Abort("ledger missing/unreadable (restore from backup)"))?;
        let platform_key = enclave.platform_key();
        let tek = crate::crypto::storage::derive_tek(&platform_key, &ledger_salt());
        let pt = crate::crypto::storage::open(&tek, &sealed)
            .map_err(|_| Error::Abort("ledger corrupt or foreign-keyed (restore from backup)"))?;
        let (coins, next_key_index, first_deposit_acked) = parse_ledger(&pt)?;
        Ok(Ledger { path, platform_key, coins, next_key_index, first_deposit_acked, _lock: lock })
    }

    fn acquire_lock(dir: &Path) -> Result<std::fs::File> {
        let lock_path = dir.join(".ledger.lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| Error::Abort("ledger lock file unavailable"))?;
        if lock.try_lock().is_err() {
            return Err(Error::Abort("another process holds this ledger (single-instance)"));
        }
        Ok(lock)
    }

    /// Transactional mutation: apply `f`, persist, and ROLL BACK the
    /// in-memory state if the persist fails — memory and disk never diverge
    /// (a later unrelated persist can't flush a half-applied change).
    fn transact<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let snap_coins = self.coins.clone();
        let snap_idx = self.next_key_index;
        let snap_ack = self.first_deposit_acked;
        let result = f(self).and_then(|t| self.persist().map(|()| t));
        if result.is_err() {
            self.coins = snap_coins;
            self.next_key_index = snap_idx;
            self.first_deposit_acked = snap_ack;
        }
        result
    }

    // ---- key issuance --------------------------------------------------

    fn issue_key(
        &mut self,
        purpose: KeyPurpose,
        keys: &dyn KeySource,
    ) -> Result<(u32, ScriptBuf)> {
        let index = self.next_key_index;
        self.next_key_index = self
            .next_key_index
            .checked_add(1)
            .ok_or(Error::Abort("ledger key index space exhausted"))?;
        let xonly = keys.derive_xonly(purpose, index)?;
        let spk = crate::tx::setup::pre_encumbrance_spk(xonly)?;
        Ok((index, spk))
    }

    /// A fresh deposit address. Persists the index bump immediately.
    pub fn next_deposit_address(&mut self, keys: &dyn KeySource) -> Result<(u32, ScriptBuf)> {
        self.transact(|l| l.issue_key(KeyPurpose::Deposit, keys))
    }

    /// A fresh per-swap destination (v3.13: fresh, never reused).
    pub fn next_swap_destination(&mut self, keys: &dyn KeySource) -> Result<(u32, ScriptBuf)> {
        self.transact(|l| l.issue_key(KeyPurpose::SwapDestination, keys))
    }

    /// A fresh Reserve key for a CPFP bump child's change output — the
    /// executor derives the change spk from this index and registers the
    /// change as a new Reserve coin (the pool replenishes itself). Persists
    /// the index bump immediately; an index issued for a bump that then falls
    /// through (NoBump) is simply skipped, never reused.
    pub fn next_reserve_key(&mut self, keys: &dyn KeySource) -> Result<(u32, ScriptBuf)> {
        self.transact(|l| l.issue_key(KeyPurpose::Reserve, keys))
    }

    /// RESTORE TOOLING ONLY: after restoring an older ledger backup, the key
    /// counter has rewound; scan forward on-chain and raise the floor past
    /// every index observed in use, or new issuance will REUSE addresses.
    pub fn raise_key_index_floor(&mut self, floor: u32) -> Result<()> {
        self.transact(|l| {
            if floor > l.next_key_index {
                l.next_key_index = floor;
            }
            Ok(())
        })
    }

    // ---- onboarding ----------------------------------------------------

    /// Register a detected incoming deposit. THE FIRST deposit re-demands
    /// the Phase-0 acknowledgement. The claimed `(key_index → spk)` binding
    /// is VERIFIED against the derivation before anything persists — a wrong
    /// index would otherwise strand the deposit at signing time. The ack is
    /// only consumed if registration succeeds.
    #[allow(clippy::too_many_arguments)]
    pub fn register_deposit(
        &mut self,
        outpoint: OutPoint,
        amount_sats: u64,
        confirmed_height: u32,
        key_index: u32,
        deposit_spk: &ScriptBuf,
        keys: &dyn KeySource,
        first_deposit_ack: Option<Phase0Ack>,
    ) -> Result<()> {
        // Validate EVERYTHING before consuming the ack (a failed attempt
        // must not eat the Phase-0 gate).
        if self.find(&outpoint).is_some() {
            return Err(Error::Validation("ledger: outpoint already tracked"));
        }
        if amount_sats == 0 {
            return Err(Error::Validation("ledger: zero-value deposit"));
        }
        let derived = keys.derive_xonly(KeyPurpose::Deposit, key_index)?;
        if &crate::tx::setup::pre_encumbrance_spk(derived)? != deposit_spk {
            return Err(Error::Validation(
                "ledger: deposit spk does not match the claimed key index",
            ));
        }
        if !self.first_deposit_acked && first_deposit_ack.is_none() {
            return Err(Error::Ordering(
                "first deposit requires the Phase-0 acknowledgement again",
            ));
        }
        self.transact(|l| {
            l.first_deposit_acked = true;
            // A caller-supplied index must also RAISE the issuance floor:
            // recording a coin at an index the counter has not passed yet
            // (e.g. after a partial restore) must never let a later
            // `issue_key` re-issue that same (purpose, index) on-chain.
            l.next_key_index = l.next_key_index.max(key_index.saturating_add(1));
            l.coins.push(CoinRecord {
                outpoint,
                amount_sats,
                class: CoinClass::Deposit,
                state: CoinState::Unspent,
                key_purpose: KeyPurpose::Deposit,
                key_index,
                created_height: confirmed_height,
                delay_or_eligible_unix: 0,
                eligible_height: 0,
                deposit_linked: false,
                parent: None,
                lessee: None,
                split_tx: None,
                split_attempts: Vec::new(),
            });
            Ok(())
        })
    }

    /// Phase 1 auto-split: build + sign the split of one deposit into k
    /// (≤ 64) pre-encumbrance outputs of EXACTLY D + Δ_fee each plus at most
    /// one change output at a SHUFFLED position; sub-dust change folds into
    /// the fee; fee capped against absurdity. Per-child delays are sampled
    /// now but ANCHOR AT CONFIRMATION. Everything persists atomically before
    /// return (crash ⇒ rebroadcastable from the ledger alone).
    pub fn split_deposit(
        &mut self,
        deposit: OutPoint,
        params: &Params,
        fee_sats: u64,
        keys: &dyn KeySource,
    ) -> Result<SplitPlan> {
        let dep = self
            .find(&deposit)
            .ok_or(Error::Validation("ledger: unknown deposit"))?;
        if dep.class != CoinClass::Deposit || dep.state != CoinState::Unspent {
            return Err(Error::Ordering("ledger: split source must be an unspent deposit"));
        }
        let dep_amount = dep.amount_sats;
        let dep_key_index = dep.key_index;
        let dep_key_purpose = dep.key_purpose;
        params.validate()?;
        if fee_sats == 0 || fee_sats > MAX_SPLIT_FEE_SATS {
            return Err(Error::Validation("ledger: split fee out of sane range"));
        }
        let unit = params
            .tier_d_sats
            .checked_add(params.delta_fee_sats)
            .ok_or(Error::Validation("ledger: tier overflow"))?;
        let spendable = dep_amount
            .checked_sub(fee_sats)
            .ok_or(Error::Validation("ledger: fee exceeds deposit"))?;
        let k = (spendable / unit).min(MAX_PRE_ENC_OUTPUTS);
        if k == 0 {
            return Err(Error::Validation(
                "ledger: deposit too small for one pre-encumbrance unit",
            ));
        }
        let mut change = spendable - k * unit;
        let mut effective_fee = fee_sats;
        if change > 0 && change < DUST_SATS {
            effective_fee += change;
            change = 0;
        }

        // Sample per-child delay DURATIONS + the shuffled change position.
        let (lo_h, hi_h) = params.onboarding_delay_hours;
        let mut delay_secs = Vec::with_capacity(k as usize);
        for _ in 0..k {
            let hours = sample_range_u64(lo_h as u64, hi_h as u64)?;
            let jitter = sample_range_u64(0, 3599)?;
            delay_secs.push(hours * 3600 + jitter);
        }
        let change_vout = if change > 0 {
            Some(sample_range_u64(0, k)? as u32) // position among k+1 outputs
        } else {
            None
        };

        self.transact(|l| {
            // Fresh keys + output list with the change at its shuffled slot.
            let n_outputs = k + change_vout.map_or(0, |_| 1);
            let mut outputs: Vec<(ScriptBuf, u64)> = Vec::with_capacity(n_outputs as usize);
            let mut child_meta: Vec<(u32, u32, u64)> = Vec::new(); // (vout, key_index, delay)
            let mut change_meta: Option<(u32, u32)> = None; // (vout, key_index)
            let mut pre_i = 0usize;
            for vout in 0..n_outputs as u32 {
                if Some(vout) == change_vout {
                    let (idx, spk) = l.issue_key(KeyPurpose::OnboardingChange, keys)?;
                    change_meta = Some((vout, idx));
                    outputs.push((spk, change));
                } else {
                    let (idx, spk) = l.issue_key(KeyPurpose::PreEncumbrance, keys)?;
                    child_meta.push((vout, idx, delay_secs[pre_i]));
                    pre_i += 1;
                    outputs.push((spk, unit));
                }
            }

            // Build unsigned, sign through the enclave seam, finalize.
            let dep_xonly = keys.derive_xonly(dep_key_purpose, dep_key_index)?;
            let spend = crate::tx::setup::unsigned_onboarding_split(
                deposit,
                dep_amount,
                dep_xonly,
                &outputs,
                effective_fee,
            )?;
            let sig = keys.sign_key_path(dep_key_purpose, dep_key_index, spend.sighash)?;
            let tx_bytes = crate::tx::txbuild::finalize_key_spend(spend, sig);
            let parsed: bitcoin::Transaction =
                bitcoin::consensus::encode::deserialize(&tx_bytes)
                    .map_err(|_| Error::Abort("split re-decode"))?;
            let txid = parsed.compute_txid();

            for (vout, key_index, delay) in &child_meta {
                l.coins.push(CoinRecord {
                    outpoint: OutPoint::new(txid, *vout),
                    amount_sats: unit,
                    class: CoinClass::PreEncumbrance,
                    state: CoinState::PendingConfirm,
                    key_purpose: KeyPurpose::PreEncumbrance,
                    key_index: *key_index,
                    created_height: 0,
                    delay_or_eligible_unix: *delay,
                    eligible_height: 0,
                    deposit_linked: false,
                    parent: Some(deposit),
                    lessee: None,
                    split_tx: None,
                    split_attempts: Vec::new(),
                });
            }
            if let Some((vout, idx)) = change_meta {
                l.coins.push(CoinRecord {
                    outpoint: OutPoint::new(txid, vout),
                    amount_sats: change,
                    class: CoinClass::OnboardingChange,
                    state: CoinState::PendingConfirm,
                    key_purpose: KeyPurpose::OnboardingChange,
                    key_index: idx,
                    created_height: 0,
                    delay_or_eligible_unix: 0,
                    eligible_height: 0,
                    deposit_linked: false,
                    parent: Some(deposit),
                    lessee: None,
                    split_tx: None,
                    split_attempts: Vec::new(),
                });
            }
            {
                let dep = l.find_mut(&deposit).expect("checked above");
                dep.state = CoinState::SplitPending;
                dep.split_tx = Some(tx_bytes.clone());
                dep.split_attempts.push(SplitAttempt { txid, tx_bytes: tx_bytes.clone() });
            }
            Ok(SplitPlan {
                tx_bytes,
                txid,
                pre_encumbrance_count: k as u32,
                change_sats: change,
                change_vout,
                delay_secs,
            })
        })
    }

    /// RBF fee bump for a stuck split (the review's SplitPending-dead-end
    /// fix). Rebuilds the split spending the SAME deposit input (mutually
    /// exclusive with every earlier attempt) at a strictly higher fee,
    /// REUSING the same child keys and delay durations — k may shrink if the
    /// fee eats into the last unit's change. All attempts stay tracked until
    /// one confirms.
    pub fn bump_split_fee(
        &mut self,
        deposit: OutPoint,
        new_fee_sats: u64,
        params: &Params,
        keys: &dyn KeySource,
    ) -> Result<SplitPlan> {
        let dep = self
            .find(&deposit)
            .ok_or(Error::Validation("ledger: unknown deposit"))?;
        if dep.class != CoinClass::Deposit || dep.state != CoinState::SplitPending {
            return Err(Error::Ordering("ledger: fee bump requires a pending split"));
        }
        if dep.split_attempts.len() >= MAX_SPLIT_ATTEMPTS {
            return Err(Error::Abort("ledger: split attempt cap reached"));
        }
        let dep_amount = dep.amount_sats;
        let dep_key_index = dep.key_index;
        let dep_key_purpose = dep.key_purpose;
        let last_txid = dep.split_attempts.last().expect("SplitPending has attempts").txid;
        // Old fee from the cached bytes; RBF demands strictly more.
        let old_tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(
            dep.split_tx.as_ref().expect("SplitPending caches its tx"),
        )
        .map_err(|_| Error::Abort("ledger: cached split undecodable"))?;
        let old_out: u64 = old_tx.output.iter().map(|o| o.value.to_sat()).sum();
        let old_fee = dep_amount - old_out;
        if new_fee_sats <= old_fee || new_fee_sats > MAX_SPLIT_FEE_SATS {
            return Err(Error::Validation(
                "ledger: bump fee must be strictly higher (and sane)",
            ));
        }
        params.validate()?;
        let unit = params
            .tier_d_sats
            .checked_add(params.delta_fee_sats)
            .ok_or(Error::Validation("ledger: tier overflow"))?;
        let spendable = dep_amount
            .checked_sub(new_fee_sats)
            .ok_or(Error::Validation("ledger: fee exceeds deposit"))?;
        let k = (spendable / unit).min(MAX_PRE_ENC_OUTPUTS);
        if k == 0 {
            return Err(Error::Validation(
                "ledger: bump would consume the last pre-encumbrance unit",
            ));
        }
        let mut change = spendable - k * unit;
        let mut effective_fee = new_fee_sats;
        if change > 0 && change < DUST_SATS {
            effective_fee += change;
            change = 0;
        }

        // Reuse the LATEST attempt's child keys + delays (sorted by vout).
        let mut prev_children: Vec<(u32, u32, u64)> = self
            .coins
            .iter()
            .filter(|c| {
                c.parent == Some(deposit)
                    && c.outpoint.txid == last_txid
                    && c.class == CoinClass::PreEncumbrance
            })
            .map(|c| (c.outpoint.vout, c.key_index, c.delay_or_eligible_unix))
            .collect();
        prev_children.sort_by_key(|(v, _, _)| *v);
        if (k as usize) > prev_children.len() {
            return Err(Error::Abort("ledger: bump grew k (impossible with higher fee)"));
        }
        let prev_change_key: Option<u32> = self
            .coins
            .iter()
            .find(|c| {
                c.parent == Some(deposit)
                    && c.outpoint.txid == last_txid
                    && c.class == CoinClass::OnboardingChange
            })
            .map(|c| c.key_index);
        let change_vout = if change > 0 {
            Some(sample_range_u64(0, k)? as u32)
        } else {
            None
        };

        self.transact(|l| {
            let n_outputs = k + change_vout.map_or(0, |_| 1);
            let mut outputs: Vec<(ScriptBuf, u64)> = Vec::with_capacity(n_outputs as usize);
            let mut child_meta: Vec<(u32, u32, u64)> = Vec::new();
            let mut change_meta: Option<(u32, u32)> = None;
            let mut pre_i = 0usize;
            for vout in 0..n_outputs as u32 {
                if Some(vout) == change_vout {
                    let idx = match prev_change_key {
                        Some(idx) => idx,
                        None => l.issue_key(KeyPurpose::OnboardingChange, keys)?.0,
                    };
                    let spk = crate::tx::setup::pre_encumbrance_spk(
                        keys.derive_xonly(KeyPurpose::OnboardingChange, idx)?,
                    )?;
                    change_meta = Some((vout, idx));
                    outputs.push((spk, change));
                } else {
                    let (_, key_index, delay) = prev_children[pre_i];
                    let spk = crate::tx::setup::pre_encumbrance_spk(
                        keys.derive_xonly(KeyPurpose::PreEncumbrance, key_index)?,
                    )?;
                    child_meta.push((vout, key_index, delay));
                    pre_i += 1;
                    outputs.push((spk, unit));
                }
            }

            let dep_xonly = keys.derive_xonly(dep_key_purpose, dep_key_index)?;
            let spend = crate::tx::setup::unsigned_onboarding_split(
                deposit, dep_amount, dep_xonly, &outputs, effective_fee,
            )?;
            let sig = keys.sign_key_path(dep_key_purpose, dep_key_index, spend.sighash)?;
            let tx_bytes = crate::tx::txbuild::finalize_key_spend(spend, sig);
            let parsed: bitcoin::Transaction =
                bitcoin::consensus::encode::deserialize(&tx_bytes)
                    .map_err(|_| Error::Abort("split re-decode"))?;
            let txid = parsed.compute_txid();

            let delay_secs: Vec<u64> = child_meta.iter().map(|(_, _, d)| *d).collect();
            for (vout, key_index, delay) in &child_meta {
                l.coins.push(CoinRecord {
                    outpoint: OutPoint::new(txid, *vout),
                    amount_sats: unit,
                    class: CoinClass::PreEncumbrance,
                    state: CoinState::PendingConfirm,
                    key_purpose: KeyPurpose::PreEncumbrance,
                    key_index: *key_index,
                    created_height: 0,
                    delay_or_eligible_unix: *delay,
                    eligible_height: 0,
                    deposit_linked: false,
                    parent: Some(deposit),
                    lessee: None,
                    split_tx: None,
                    split_attempts: Vec::new(),
                });
            }
            if let Some((vout, idx)) = change_meta {
                l.coins.push(CoinRecord {
                    outpoint: OutPoint::new(txid, vout),
                    amount_sats: change,
                    class: CoinClass::OnboardingChange,
                    state: CoinState::PendingConfirm,
                    key_purpose: KeyPurpose::OnboardingChange,
                    key_index: idx,
                    created_height: 0,
                    delay_or_eligible_unix: 0,
                    eligible_height: 0,
                    deposit_linked: false,
                    parent: Some(deposit),
                    lessee: None,
                    split_tx: None,
                    split_attempts: Vec::new(),
                });
            }
            {
                let dep = l.find_mut(&deposit).expect("checked above");
                dep.split_tx = Some(tx_bytes.clone());
                dep.split_attempts.push(SplitAttempt { txid, tx_bytes: tx_bytes.clone() });
            }
            Ok(SplitPlan {
                tx_bytes,
                txid,
                pre_encumbrance_count: k as u32,
                change_sats: change,
                change_vout,
                delay_secs,
            })
        })
    }

    /// One split attempt confirmed at `height`: its children activate with
    /// their eligibility ANCHORED NOW (wall clock + chain height), losing
    /// attempts' children are dropped (mutually exclusive txs), the deposit
    /// becomes Spent. The CONFIRMED (winning) attempt's signed bytes are
    /// installed as `split_tx` for shallow-reorg rebroadcast — NOT left as the
    /// latest attempt's, which after an RBF race can be a losing, mutually
    /// exclusive tx whose rebroadcast would strand the confirmed children.
    ///
    /// The wall-clock anchor is FAULT-CHECKED against the sane window (see
    /// `SANE_CLOCK_MIN/MAX_UNIX`): an out-of-window reading collapses to the
    /// window floor, so a faulted clock at this instant can neither freeze the
    /// coin until an absurd future date nor inject a garbage anchor; the
    /// height anchor stays load-bearing regardless.
    ///
    /// Known nuance (documented, not fund-loss): a reorg that unconfirms and
    /// later re-confirms the same attempt keeps the FIRST confirmation's
    /// anchors (children are already `Unspent`, so the anchor-writing branch is
    /// skipped) — the effective delay is measured from the first confirmation,
    /// a bounded privacy nuance only.
    pub fn confirm_split(
        &mut self,
        split_txid: Txid,
        height: u32,
        clock: &dyn WalletClock,
    ) -> Result<()> {
        let deposit_op = self
            .coins
            .iter()
            .find(|c| {
                c.class == CoinClass::Deposit
                    && c.split_attempts.iter().any(|a| a.txid == split_txid)
            })
            .map(|c| c.outpoint)
            .ok_or(Error::Validation("ledger: unknown split txid"))?;
        // Fault-collapse, not trust: an out-of-window reading degrades the wall
        // anchor to SANE_MIN (trivially satisfied) — the height anchor still
        // enforces the delay — instead of freezing the coin until an absurd
        // future date. See the SANE_CLOCK_* doc.
        let raw_now = clock.now_unix();
        let now = if (SANE_CLOCK_MIN_UNIX..=SANE_CLOCK_MAX_UNIX).contains(&raw_now) {
            raw_now
        } else {
            SANE_CLOCK_MIN_UNIX
        };
        self.transact(|l| {
            for coin in &mut l.coins {
                if coin.parent == Some(deposit_op) && coin.state == CoinState::PendingConfirm {
                    if coin.outpoint.txid == split_txid {
                        coin.state = CoinState::Unspent;
                        coin.created_height = height;
                        if coin.class == CoinClass::PreEncumbrance {
                            let delay = coin.delay_or_eligible_unix;
                            coin.delay_or_eligible_unix = now.saturating_add(delay);
                            coin.eligible_height = height
                                .saturating_add((delay / SECS_PER_BLOCK) as u32);
                        }
                    } else {
                        coin.state = CoinState::Spent; // superseded attempt
                    }
                }
            }
            l.coins.retain(|c| {
                !(c.parent == Some(deposit_op)
                    && c.state == CoinState::Spent
                    && c.created_height == 0)
            });
            let dep = l.find_mut(&deposit_op).expect("found above");
            // Install the WINNING attempt's bytes (the confirming txid's own
            // signed tx) as the retained-for-rebroadcast artifact.
            let winning = dep
                .split_attempts
                .iter()
                .find(|a| a.txid == split_txid)
                .map(|a| a.tx_bytes.clone());
            dep.split_tx = winning;
            dep.state = CoinState::Spent;
            Ok(())
        })
    }

    // ---- selection (class-pure, non-mixing) ------------------------------

    /// Select ONE eligible pre-encumbrance coin of exactly `unit_sats` and
    /// LEASE it to `lessee` (the swap_session_id). Eligibility is
    /// DOUBLE-ANCHORED: wall clock AND chain height must both have passed —
    /// shifting the system clock alone cannot collapse the delay.
    pub fn lease_pre_encumbrance(
        &mut self,
        unit_sats: u64,
        clock: &dyn WalletClock,
        tip_height: u32,
        lessee: [u8; 32],
    ) -> Result<Option<CoinRecord>> {
        let now = clock.now_unix();
        let mut immature = false;
        let mut chosen: Option<usize> = None;
        for (i, c) in self.coins.iter().enumerate() {
            if c.class == CoinClass::PreEncumbrance
                && c.state == CoinState::Unspent
                && c.amount_sats == unit_sats
            {
                if c.delay_or_eligible_unix <= now && c.eligible_height <= tip_height {
                    chosen = Some(i);
                    break;
                }
                immature = true;
            }
        }
        match chosen {
            Some(i) => self.transact(|l| {
                l.coins[i].state = CoinState::Leased;
                l.coins[i].lessee = Some(lessee);
                Ok(Some(l.coins[i].clone()))
            }),
            None if immature => Err(Error::Deadline(
                "pre-encumbrance coins exist but are still in their onboarding delay",
            )),
            None => Ok(None),
        }
    }

    /// Lease a reserve coin for the CPFP backstop. Refund bumps are silent
    /// (spec); COMPLETION bumps demand the typed linkage acknowledgement —
    /// and the caller must then record the taint on the swapped output via
    /// `record_swapped_output(.., deposit_linked = true)`.
    pub fn lease_reserve(
        &mut self,
        target: BumpTarget,
        min_sats: u64,
        linkage_ack: Option<LinkageAck>,
        lessee: [u8; 32],
    ) -> Result<Option<CoinRecord>> {
        if target == BumpTarget::Completion && linkage_ack.is_none() {
            return Err(Error::Ordering(
                "bumping a completion from reserve requires the linkage acknowledgement",
            ));
        }
        // Size-aware, matching `has_leasable_reserve(min_sats)`: pick the LARGEST
        // unspent reserve that covers `min_sats`, so the gate and the lease can
        // never disagree (a true gate followed by a too-small lease that the
        // build then rejects). `min_sats` is the caller's `required_child_fee`.
        let idx = self
            .coins
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                c.class == CoinClass::Reserve
                    && c.state == CoinState::Unspent
                    && c.amount_sats >= min_sats
            })
            .max_by_key(|(_, c)| c.amount_sats)
            .map(|(i, _)| i);
        match idx {
            Some(i) => self.transact(|l| {
                l.coins[i].state = CoinState::Leased;
                l.coins[i].lessee = Some(lessee);
                Ok(Some(l.coins[i].clone()))
            }),
            None => Ok(None),
        }
    }

    /// Chain-aware reserve reconciliation (review finding): mark Spent any
    /// Reserve coin the ledger still counts as spendable (Unspent or Leased)
    /// but whose outpoint is CONFIRMED spent on chain. This is the phantom a
    /// crash in [`run_cpfp_bump`](crate::wallet::backstop_driver::run_cpfp_bump)'s
    /// submit→persist window creates: the CPFP child is on chain, the ledger
    /// persist never ran, and a later [`reconcile_leases`] re-exposes the coin
    /// as Unspent — where its deterministic `max_by_key` lease selection then
    /// wins forever and fails every bump at submit, silently disabling the
    /// backstop pool. Sweeping it here (the caller runs this at startup with
    /// the authoritative chain) removes the phantom before it is ever selected;
    /// `run_cpfp_bump` additionally self-heals one on a submit failure. Only
    /// CONFIRMED spends are swept — an `InMempool` spend may be our own
    /// still-confirming legitimate bump. Returns the swept outpoints.
    pub fn sweep_spent_reserves(
        &mut self,
        chain: &dyn crate::chain::AuthoritativeChainView,
    ) -> Result<Vec<OutPoint>> {
        let targets: Vec<OutPoint> = self
            .coins
            .iter()
            .filter(|c| {
                c.class == CoinClass::Reserve
                    && matches!(c.state, CoinState::Unspent | CoinState::Leased)
                    && matches!(
                        chain.spend_status(c.outpoint),
                        crate::chain::SpendStatus::Confirmed(_)
                    )
            })
            .map(|c| c.outpoint)
            .collect();
        if targets.is_empty() {
            return Ok(targets);
        }
        self.transact(|l| {
            for op in &targets {
                if let Some(c) = l.find_mut(op) {
                    c.state = CoinState::Spent;
                    c.lessee = None;
                }
            }
            Ok(())
        })?;
        Ok(targets)
    }

    /// Startup reconciliation (the orphaned-lease fix): release every lease
    /// whose lessee is not in the live set (crash between lease and swap-
    /// record creation). Returns the released outpoints.
    pub fn reconcile_leases(&mut self, live_lessees: &[[u8; 32]]) -> Result<Vec<OutPoint>> {
        self.transact(|l| {
            let mut released = Vec::new();
            for c in &mut l.coins {
                if c.state == CoinState::Leased {
                    let live = c.lessee.map(|who| live_lessees.contains(&who)).unwrap_or(false);
                    if !live {
                        c.state = CoinState::Unspent;
                        c.lessee = None;
                        released.push(c.outpoint);
                    }
                }
            }
            Ok(released)
        })
    }

    /// Chain-aware lease reconciliation (the LEASE analogue of
    /// [`sweep_spent_reserves`](Self::sweep_spent_reserves)): run at startup,
    /// after `open`, with the authoritative chain. Two effects in one persist:
    ///
    ///   1. SWEEP — any coin the ledger still counts spendable (`Leased` OR
    ///      `Unspent`) whose outpoint is CONFIRMED spent on chain is marked
    ///      `Spent` (never re-leasable), REGARDLESS of lease liveness. This is
    ///      the phantom a terminal swap's funding coin becomes: a pre-funding
    ///      abort spent the pre-encumbrance coin into its escrow on chain, but
    ///      `run_exchange` (which marks the funding coin `Spent`) never ran, so
    ///      the coin stayed `Leased`; when the swap reaches a terminal, `open`'s
    ///      chain-BLIND [`reconcile_leases`](Self::reconcile_leases) releases the
    ///      lease back to `Unspent` — a phantom that a later `lease_*` would
    ///      re-select and `submit_package` would reject forever. Considering both
    ///      `Leased` and `Unspent` catches the coin whether or not `open` already
    ///      released it, so running this post-open is idempotent and complete.
    ///
    ///   2. RELEASE — any coin STILL `Leased` whose lessee is not in the live set
    ///      is released to `Unspent`, exactly as [`reconcile_leases`] does (the
    ///      orphaned-lease crash between lease and swap-record creation).
    ///
    /// Only CONFIRMED spends are swept — an `InMempool` spend may be our own
    /// still-confirming legitimate Setup/bump. (A reorg that reverts a swept
    /// spend leaves the coin `Spent` until a rescan re-derives it — the same
    /// bounded, non-fund-loss caveat [`sweep_spent_reserves`] carries.)
    ///
    /// The sweep is SCOPED to the LEASABLE classes (`PreEncumbrance`, `Reserve`)
    /// — the only coins a lease can strand as a phantom. It deliberately does NOT
    /// touch `Deposit`/`OnboardingChange`/`SwapDestination`, whose spent-ness is
    /// owned by their own lifecycles (the deposit→split state machine, a normal
    /// send), so this reconcile can never race those. Returns swept + released.
    pub fn reconcile_leases_with_chain(
        &mut self,
        live_lessees: &[[u8; 32]],
        chain: &dyn crate::chain::AuthoritativeChainView,
    ) -> Result<LeaseReconcile> {
        self.transact(|l| {
            let mut out = LeaseReconcile::default();
            for c in &mut l.coins {
                let leasable = matches!(c.class, CoinClass::PreEncumbrance | CoinClass::Reserve);
                let confirmed_spent = leasable
                    && matches!(c.state, CoinState::Leased | CoinState::Unspent)
                    && matches!(
                        chain.spend_status(c.outpoint),
                        crate::chain::SpendStatus::Confirmed(_)
                    );
                if confirmed_spent {
                    c.state = CoinState::Spent;
                    c.lessee = None;
                    out.swept.push(c.outpoint);
                    continue;
                }
                if c.state == CoinState::Leased {
                    let live = c.lessee.map(|who| live_lessees.contains(&who)).unwrap_or(false);
                    if !live {
                        c.state = CoinState::Unspent;
                        c.lessee = None;
                        out.released.push(c.outpoint);
                    }
                }
            }
            Ok(out)
        })
    }

    /// A leased coin's swap/backstop was aborted before it was spent.
    pub fn release_lease(&mut self, outpoint: OutPoint) -> Result<()> {
        self.transact(|l| {
            let c = l
                .find_mut(&outpoint)
                .ok_or(Error::Validation("ledger: unknown outpoint"))?;
            if c.state != CoinState::Leased {
                return Err(Error::Ordering("ledger: coin is not leased"));
            }
            c.state = CoinState::Unspent;
            c.lessee = None;
            Ok(())
        })
    }

    /// A leased (or unspent) coin was consumed on-chain.
    pub fn mark_spent(&mut self, outpoint: OutPoint) -> Result<()> {
        self.transact(|l| {
            let c = l
                .find_mut(&outpoint)
                .ok_or(Error::Validation("ledger: unknown outpoint"))?;
            if !matches!(c.state, CoinState::Leased | CoinState::Unspent) {
                return Err(Error::Ordering("ledger: coin is not spendable"));
            }
            c.state = CoinState::Spent;
            c.lessee = None;
            Ok(())
        })
    }

    /// Spend a leased reserve into its CPFP child and register the child's
    /// change output as a NEW Reserve coin — in ONE persist, so the reserve
    /// accounting and the pool replenishment can never straddle a crash. The
    /// change inherits the source reserve's deposit provenance (never launders
    /// it). Called by `run_cpfp_bump` only after `submit_package` accepted.
    #[allow(clippy::too_many_arguments)]
    pub fn spend_reserve_into_change(
        &mut self,
        reserve_outpoint: OutPoint,
        change_outpoint: OutPoint,
        change_amount_sats: u64,
        change_key_index: u32,
        height: u32,
        deposit_linked: bool,
    ) -> Result<()> {
        if self.find(&change_outpoint).is_some() {
            return Err(Error::Validation("ledger: change outpoint already tracked"));
        }
        self.transact(|l| {
            let c = l
                .find_mut(&reserve_outpoint)
                .ok_or(Error::Validation("ledger: unknown reserve outpoint"))?;
            if !matches!(c.state, CoinState::Leased | CoinState::Unspent) {
                return Err(Error::Ordering("ledger: reserve is not spendable"));
            }
            c.state = CoinState::Spent;
            c.lessee = None;
            // Caller-supplied index also raises the issuance floor (see
            // `register_deposit`).
            l.next_key_index = l.next_key_index.max(change_key_index.saturating_add(1));
            l.coins.push(CoinRecord {
                outpoint: change_outpoint,
                amount_sats: change_amount_sats,
                class: CoinClass::Reserve,
                state: CoinState::Unspent,
                key_purpose: KeyPurpose::Reserve,
                key_index: change_key_index,
                created_height: height,
                delay_or_eligible_unix: 0,
                eligible_height: 0,
                deposit_linked,
                parent: None,
                lessee: None,
                split_tx: None,
                split_attempts: Vec::new(),
            });
            Ok(())
        })
    }

    /// Record a completed swap's output: exactly D at a fresh destination.
    /// `deposit_linked` must be true when a deposit-provenance reserve coin
    /// bumped this swap's completion — the taint persists with the coin.
    #[allow(clippy::too_many_arguments)]
    pub fn record_swapped_output(
        &mut self,
        outpoint: OutPoint,
        amount_sats: u64,
        key_index: u32,
        height: u32,
        deposit_linked: bool,
    ) -> Result<()> {
        if self.find(&outpoint).is_some() {
            return Err(Error::Validation("ledger: outpoint already tracked"));
        }
        self.transact(|l| {
            // Caller-supplied index also raises the issuance floor (see
            // `register_deposit`): a recorded on-chain index must never be
            // re-issued by a later `issue_key`.
            l.next_key_index = l.next_key_index.max(key_index.saturating_add(1));
            l.coins.push(CoinRecord {
                outpoint,
                amount_sats,
                class: CoinClass::Swapped,
                state: CoinState::Unspent,
                key_purpose: KeyPurpose::SwapDestination,
                key_index,
                created_height: height,
                delay_or_eligible_unix: 0,
                eligible_height: 0,
                deposit_linked,
                parent: None,
                lessee: None,
                split_tx: None,
                split_attempts: Vec::new(),
            });
            Ok(())
        })
    }

    /// Promote the onboarding change output to the reserve pool. Explicit
    /// and persisted; the coin keeps its `OnboardingChange` key purpose, so
    /// its deposit provenance remains readable forever.
    pub fn promote_change_to_reserve(&mut self, outpoint: OutPoint) -> Result<()> {
        self.transact(|l| {
            let c = l
                .find_mut(&outpoint)
                .ok_or(Error::Validation("ledger: unknown outpoint"))?;
            if c.class != CoinClass::OnboardingChange || c.state != CoinState::Unspent {
                return Err(Error::Ordering(
                    "ledger: only unspent onboarding change can become reserve",
                ));
            }
            c.class = CoinClass::Reserve;
            Ok(())
        })
    }

    // ---- queries ---------------------------------------------------------

    pub fn coins(&self) -> &[CoinRecord] {
        &self.coins
    }

    /// Is there a leasable reserve coin — unspent, class `Reserve` — holding at
    /// least `min_sats`? This is the production `reserve_available` gate the
    /// congestion backstop consults before deciding to CPFP-bump; `min_sats`
    /// is the caller's (conservative) `required_child_fee` estimate. The exact
    /// sizing is re-checked when the child is built, so an optimistic answer
    /// here never mints an under-funded bump — it degrades to the safe
    /// fallback. `lease_reserve` picks the same class/state, so a `true` here
    /// means a lease will succeed (modulo a concurrent lease).
    pub fn has_leasable_reserve(&self, min_sats: u64) -> bool {
        self.coins.iter().any(|c| {
            c.class == CoinClass::Reserve
                && c.state == CoinState::Unspent
                && c.amount_sats >= min_sats
        })
    }

    pub fn find(&self, outpoint: &OutPoint) -> Option<&CoinRecord> {
        self.coins.iter().find(|c| &c.outpoint == outpoint)
    }

    fn find_mut(&mut self, outpoint: &OutPoint) -> Option<&mut CoinRecord> {
        self.coins.iter_mut().find(|c| &c.outpoint == outpoint)
    }

    // ---- persistence -----------------------------------------------------
    //
    // v3 layout (sealed): [1 ver=3][1 first_deposit_acked][4 next_key_index]
    // [4 count] then per coin:
    // [32 txid][4 vout][8 amount][1 class][1 state][1 key_purpose]
    // [4 key_index][4 created_height][8 delay_or_eligible][4 eligible_height]
    // [1 flags: b0 deposit_linked, b1 parent, b2 lessee, b3 split_tx,
    //  b4 attempts]
    // [36 parent]? [32 lessee]? [4 len + bytes split_tx]?
    // [1 n + n x (32 txid + 4 len + bytes) attempts]?
    // (v3 made each split attempt carry its SIGNED BYTES, so confirm_split can
    // retain the WINNING attempt's tx for reorg rebroadcast; v2 records are
    // rejected — no deployed data predates this, same precedent as the swap
    // store's version bumps.)

    fn persist(&self) -> Result<()> {
        let mut v = Vec::with_capacity(64 + self.coins.len() * 96);
        v.push(3u8);
        v.push(self.first_deposit_acked as u8);
        v.extend_from_slice(&self.next_key_index.to_le_bytes());
        v.extend_from_slice(&(self.coins.len() as u32).to_le_bytes());
        for c in &self.coins {
            v.extend_from_slice(&c.outpoint.txid.to_byte_array());
            v.extend_from_slice(&c.outpoint.vout.to_le_bytes());
            v.extend_from_slice(&c.amount_sats.to_le_bytes());
            v.push(c.class.to_byte());
            v.push(c.state.to_byte());
            v.push(purpose_to_byte(c.key_purpose));
            v.extend_from_slice(&c.key_index.to_le_bytes());
            v.extend_from_slice(&c.created_height.to_le_bytes());
            v.extend_from_slice(&c.delay_or_eligible_unix.to_le_bytes());
            v.extend_from_slice(&c.eligible_height.to_le_bytes());
            let mut flags = 0u8;
            if c.deposit_linked {
                flags |= 1;
            }
            if c.parent.is_some() {
                flags |= 2;
            }
            if c.lessee.is_some() {
                flags |= 4;
            }
            if c.split_tx.is_some() {
                flags |= 8;
            }
            if !c.split_attempts.is_empty() {
                flags |= 16;
            }
            v.push(flags);
            if let Some(p) = &c.parent {
                v.extend_from_slice(&p.txid.to_byte_array());
                v.extend_from_slice(&p.vout.to_le_bytes());
            }
            if let Some(who) = &c.lessee {
                v.extend_from_slice(who);
            }
            if let Some(tx) = &c.split_tx {
                v.extend_from_slice(&(tx.len() as u32).to_le_bytes());
                v.extend_from_slice(tx);
            }
            if !c.split_attempts.is_empty() {
                v.push(c.split_attempts.len() as u8);
                for a in &c.split_attempts {
                    v.extend_from_slice(&a.txid.to_byte_array());
                    v.extend_from_slice(&(a.tx_bytes.len() as u32).to_le_bytes());
                    v.extend_from_slice(&a.tx_bytes);
                }
            }
        }
        let tek = crate::crypto::storage::derive_tek(&self.platform_key, &ledger_salt());
        let sealed = crate::crypto::storage::seal(&tek, &v)?;
        let tmp = self.path.with_extension("bin.tmp");
        let mut f =
            std::fs::File::create(&tmp).map_err(|_| Error::Abort("ledger tmp create failed"))?;
        f.write_all(&sealed)
            .and_then(|()| f.sync_all())
            .map_err(|_| Error::Abort("ledger write/sync failed"))?;
        drop(f);
        std::fs::rename(&tmp, &self.path).map_err(|_| Error::Abort("ledger rename failed"))?;
        // Directory-entry durability: on unix, fsync the dir so the rename
        // itself survives power loss; NTFS journals metadata (documented).
        #[cfg(unix)]
        {
            if let Ok(d) = std::fs::File::open(self.path.parent().unwrap_or(Path::new("."))) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

fn parse_ledger(b: &[u8]) -> Result<(Vec<CoinRecord>, u32, bool)> {
    let mut at = 0usize;
    if take_arr::<1>(b, &mut at)?[0] != 3 {
        return Err(Error::Validation("ledger: unknown version"));
    }
    let acked = match take_arr::<1>(b, &mut at)?[0] {
        0 => false,
        1 => true,
        _ => return Err(Error::Validation("ledger: malformed flag")),
    };
    let next_key_index = take_le_u32(b, &mut at)?;
    let count = take_le_u32(b, &mut at)? as usize;
    let mut coins = Vec::with_capacity(count.min(1 << 16));
    for _ in 0..count {
        let txid = Txid::from_byte_array(take_arr::<32>(b, &mut at)?);
        let vout = take_le_u32(b, &mut at)?;
        let amount_sats = take_le_u64(b, &mut at)?;
        let class = CoinClass::from_byte(take_arr::<1>(b, &mut at)?[0])?;
        let state = CoinState::from_byte(take_arr::<1>(b, &mut at)?[0])?;
        let key_purpose = purpose_from_byte(take_arr::<1>(b, &mut at)?[0])?;
        let key_index = take_le_u32(b, &mut at)?;
        let created_height = take_le_u32(b, &mut at)?;
        let delay_or_eligible_unix = take_le_u64(b, &mut at)?;
        let eligible_height = take_le_u32(b, &mut at)?;
        let flags = take_arr::<1>(b, &mut at)?[0];
        if flags & !0x1f != 0 {
            return Err(Error::Validation("ledger: unknown flag bits"));
        }
        let parent = if flags & 2 != 0 {
            let ptxid = Txid::from_byte_array(take_arr::<32>(b, &mut at)?);
            let pvout = take_le_u32(b, &mut at)?;
            Some(OutPoint::new(ptxid, pvout))
        } else {
            None
        };
        let lessee = if flags & 4 != 0 {
            Some(take_arr::<32>(b, &mut at)?)
        } else {
            None
        };
        let split_tx = if flags & 8 != 0 {
            let len = take_le_u32(b, &mut at)? as usize;
            let end = at
                .checked_add(len)
                .ok_or(Error::Validation("ledger: split length overflow"))?;
            let s = b
                .get(at..end)
                .ok_or(Error::Validation("ledger truncated (split tx)"))?;
            at = end;
            Some(s.to_vec())
        } else {
            None
        };
        let split_attempts = if flags & 16 != 0 {
            let n = take_arr::<1>(b, &mut at)?[0] as usize;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let atxid = Txid::from_byte_array(take_arr::<32>(b, &mut at)?);
                let len = take_le_u32(b, &mut at)? as usize;
                let end = at
                    .checked_add(len)
                    .ok_or(Error::Validation("ledger: attempt length overflow"))?;
                let s = b
                    .get(at..end)
                    .ok_or(Error::Validation("ledger truncated (attempt tx)"))?;
                at = end;
                v.push(SplitAttempt { txid: atxid, tx_bytes: s.to_vec() });
            }
            v
        } else {
            Vec::new()
        };
        coins.push(CoinRecord {
            outpoint: OutPoint::new(txid, vout),
            amount_sats,
            class,
            state,
            key_purpose,
            key_index,
            created_height,
            delay_or_eligible_unix,
            eligible_height,
            deposit_linked: flags & 1 != 0,
            parent,
            lessee,
            split_tx,
            split_attempts,
        });
    }
    if at != b.len() {
        return Err(Error::Validation("ledger: trailing bytes"));
    }
    Ok((coins, next_key_index, acked))
}

/// Uniform-ish sample in [lo, hi] from the OS CSPRNG. (Modulo bias over a
/// u64 for ranges this small is < 2^-50 — irrelevant for a decorrelation
/// delay; noted for honesty.)
fn sample_range_u64(lo: u64, hi: u64) -> Result<u64> {
    if lo > hi {
        return Err(Error::Validation("sample range inverted"));
    }
    let span = hi - lo + 1;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| Error::Abort("OS randomness unavailable for onboarding delay"))?;
    Ok(lo + (u64::from_le_bytes(buf) % span))
}

fn take_arr<const N: usize>(b: &[u8], at: &mut usize) -> Result<[u8; N]> {
    let s = b.get(*at..*at + N).ok_or(Error::Validation("ledger truncated"))?;
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
    use crate::wallet::keys::ModeledKeySource;
    use crate::wallet::store::ModeledEnclave;

    struct FixedClock(u64);
    impl WalletClock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    fn ack() -> Phase0Ack {
        acknowledge_phase0(PHASE0_WARNING).unwrap()
    }

    fn outpoint(seed: u8) -> OutPoint {
        let mut b = [0u8; 32];
        b[0] = seed;
        OutPoint::new(Txid::from_byte_array(b), 0)
    }

    fn fresh(dir: &Path) -> (Ledger, ModeledKeySource) {
        let ledger = Ledger::create(dir, &ModeledEnclave, ack()).unwrap();
        (ledger, ModeledKeySource::new(&ModeledEnclave))
    }

    /// Register a deposit at a freshly-issued address (valid spk binding).
    fn add_deposit(
        ledger: &mut Ledger,
        keys: &ModeledKeySource,
        op: OutPoint,
        amount: u64,
        first: bool,
    ) {
        let (idx, spk) = ledger.next_deposit_address(keys).unwrap();
        ledger
            .register_deposit(op, amount, 100, idx, &spk, keys, first.then(ack))
            .unwrap();
    }

    const LESSEE: [u8; 32] = [0xEE; 32];

    #[test]
    fn phase0_gate_is_typed_textual_and_not_consumed_by_failure() {
        assert!(acknowledge_phase0("I agree").is_err());
        assert!(acknowledge_phase0(&PHASE0_WARNING[..40]).is_err());
        acknowledge_phase0(PHASE0_WARNING).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();

        // Without the re-ack: refused.
        let err = ledger
            .register_deposit(outpoint(1), 5_000_000, 100, idx, &spk, &keys, None)
            .unwrap_err();
        assert!(matches!(err, Error::Ordering(_)));

        // A FAILED registration (bad spk binding) must not consume the gate:
        let wrong_spk = crate::tx::setup::pre_encumbrance_spk([7u8; 32]).unwrap();
        assert!(ledger
            .register_deposit(outpoint(1), 5_000_000, 100, idx, &wrong_spk, &keys, Some(ack()))
            .is_err());
        // ...so the NEXT registration still demands (and gets) the ack.
        let err = ledger
            .register_deposit(outpoint(1), 5_000_000, 100, idx, &spk, &keys, None)
            .unwrap_err();
        assert!(matches!(err, Error::Ordering(_)), "gate consumed by a failed attempt");
        ledger
            .register_deposit(outpoint(1), 5_000_000, 100, idx, &spk, &keys, Some(ack()))
            .unwrap();
        // Second deposit: no re-ack needed.
        let (idx2, spk2) = ledger.next_deposit_address(&keys).unwrap();
        ledger
            .register_deposit(outpoint(2), 3_000_000, 101, idx2, &spk2, &keys, None)
            .unwrap();
    }

    #[test]
    fn split_arithmetic_units_shuffled_change_dust_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;

        // 3 units + healthy change.
        let dep_amount = 3 * unit + 50_000 + 1_000;
        add_deposit(&mut ledger, &keys, outpoint(1), dep_amount, true);
        let plan = ledger.split_deposit(outpoint(1), &params, 1_000, &keys).unwrap();
        assert_eq!(plan.pre_encumbrance_count, 3);
        assert_eq!(plan.change_sats, 50_000);
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&plan.tx_bytes).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 4);
        let cv = plan.change_vout.expect("change present") as usize;
        assert_eq!(tx.output[cv].value.to_sat(), 50_000);
        for (i, out) in tx.output.iter().enumerate() {
            if i != cv {
                assert_eq!(out.value.to_sat(), unit);
            }
        }
        let out_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(dep_amount - out_total, 1_000);
        let spks: std::collections::HashSet<_> =
            tx.output.iter().map(|o| o.script_pubkey.clone()).collect();
        assert_eq!(spks.len(), 4, "no address reuse across split outputs");

        // Sub-dust change folds into the fee (P2TR dust = 330).
        add_deposit(&mut ledger, &keys, outpoint(2), 2 * unit + 300 + 1_000, false);
        let plan2 = ledger.split_deposit(outpoint(2), &params, 1_000, &keys).unwrap();
        assert_eq!(plan2.change_sats, 0);
        assert!(plan2.change_vout.is_none());
        let tx2: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&plan2.tx_bytes).unwrap();
        assert_eq!(tx2.output.len(), 2);
        // 330-sat change is RELAYABLE and kept (not burned).
        add_deposit(&mut ledger, &keys, outpoint(3), unit + 330 + 1_000, false);
        let plan3 = ledger.split_deposit(outpoint(3), &params, 1_000, &keys).unwrap();
        assert_eq!(plan3.change_sats, 330);

        // Too small; absurd fee; double-split: refused.
        add_deposit(&mut ledger, &keys, outpoint(4), unit / 2, false);
        assert!(ledger.split_deposit(outpoint(4), &params, 1_000, &keys).is_err());
        add_deposit(&mut ledger, &keys, outpoint(5), 3 * unit, false);
        assert!(ledger.split_deposit(outpoint(5), &params, 200_000, &keys).is_err());
        assert!(ledger.split_deposit(outpoint(1), &params, 1_000, &keys).is_err());

        // k cap: a whale deposit yields at most 64 units, excess in change.
        add_deposit(&mut ledger, &keys, outpoint(6), 100 * unit + 1_000, false);
        let plan6 = ledger.split_deposit(outpoint(6), &params, 1_000, &keys).unwrap();
        assert_eq!(plan6.pre_encumbrance_count, 64);
        assert_eq!(plan6.change_sats, 36 * unit);
    }

    #[test]
    fn delay_anchors_at_confirmation_with_dual_anchor_gate() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        add_deposit(&mut ledger, &keys, outpoint(1), 2 * unit + 2_000, true);
        let plan = ledger.split_deposit(outpoint(1), &params, 2_000, &keys).unwrap();

        // Delays are DURATIONS in [24h, 72h + 1h); nothing eligible yet.
        for &d in &plan.delay_secs {
            assert!((24 * 3600..73 * 3600).contains(&d));
        }
        for c in ledger.coins().iter().filter(|c| c.class == CoinClass::PreEncumbrance) {
            assert_eq!(c.eligibility_unix(), None, "no absolute time before confirm");
        }

        // The split lingers; confirmation happens MUCH later — the delay
        // must anchor from HERE, not from signing.
        let confirm_time = 2_000_000_000u64;
        let confirm_height = 900_000u32;
        ledger.confirm_split(plan.txid, confirm_height, &FixedClock(confirm_time)).unwrap();
        for c in ledger.coins().iter().filter(|c| c.class == CoinClass::PreEncumbrance) {
            let e = c.eligibility_unix().unwrap();
            assert!(e >= confirm_time + 24 * 3600, "delay must restart at confirmation");
            assert!(c.eligible_height > confirm_height, "height anchor set");
        }

        // Dual anchor: clock passed but chain NOT → still gated (an
        // NTP-shifted clock alone cannot collapse the delay).
        let clock_ok = FixedClock(confirm_time + 74 * 3600);
        assert!(matches!(
            ledger.lease_pre_encumbrance(unit, &clock_ok, confirm_height + 1, LESSEE),
            Err(Error::Deadline(_))
        ));
        // Chain passed but clock NOT → still gated.
        assert!(matches!(
            ledger.lease_pre_encumbrance(unit, &FixedClock(confirm_time + 1), 2_000_000, LESSEE),
            Err(Error::Deadline(_))
        ));
        // Both passed → leases, and carries the lessee.
        let coin = ledger
            .lease_pre_encumbrance(unit, &clock_ok, 2_000_000, LESSEE)
            .unwrap()
            .expect("eligible");
        assert_eq!(coin.lessee, Some(LESSEE));
    }

    #[test]
    fn bump_split_fee_rbf_reuses_keys_and_all_attempts_tracked() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        add_deposit(&mut ledger, &keys, outpoint(1), 2 * unit + 50_000, true);

        let plan1 = ledger.split_deposit(outpoint(1), &params, 1_000, &keys).unwrap();
        // Bump must be strictly higher.
        assert!(ledger.bump_split_fee(outpoint(1), 1_000, &params, &keys).is_err());
        let plan2 = ledger.bump_split_fee(outpoint(1), 5_000, &params, &keys).unwrap();
        assert_ne!(plan1.txid, plan2.txid);
        assert_eq!(plan2.pre_encumbrance_count, 2);

        // Same child KEYS reused across attempts (same spks, new txid).
        let tx1: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&plan1.tx_bytes).unwrap();
        let tx2: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&plan2.tx_bytes).unwrap();
        let spks1: std::collections::HashSet<_> =
            tx1.output.iter().map(|o| o.script_pubkey.clone()).collect();
        let spks2: std::collections::HashSet<_> =
            tx2.output.iter().map(|o| o.script_pubkey.clone()).collect();
        assert_eq!(spks1, spks2, "attempts must reuse the same child keys");

        // Both attempts' children tracked while pending.
        let pending: Vec<_> = ledger
            .coins()
            .iter()
            .filter(|c| c.state == CoinState::PendingConfirm)
            .collect();
        assert_eq!(pending.len(), 6, "2 attempts x (2 pre-enc + 1 change)");

        // Attempt 2 confirms: its children activate; attempt 1's vanish.
        ledger.confirm_split(plan2.txid, 500, &FixedClock(1_000)).unwrap();
        assert!(ledger
            .coins()
            .iter()
            .all(|c| c.outpoint.txid != plan1.txid), "losing attempt dropped");
        let active: Vec<_> = ledger
            .coins()
            .iter()
            .filter(|c| c.outpoint.txid == plan2.txid && c.state == CoinState::Unspent)
            .collect();
        assert_eq!(active.len(), 3);
        // The deposit retains the signed bytes for reorg recovery.
        let dep = ledger.find(&outpoint(1)).unwrap();
        assert_eq!(dep.state, CoinState::Spent);
        assert!(dep.split_tx.is_some(), "bytes retained for shallow-reorg rebroadcast");
    }

    /// Audit B2: when a NON-latest (lower-fee) RBF attempt is the one that
    /// confirms — a real mempool-propagation race — the deposit must retain the
    /// WINNING attempt's bytes, not the latest's. Rebroadcasting the latest
    /// (losing, mutually exclusive) tx after a shallow reorg would strand the
    /// confirmed children as phantoms while minting untracked outputs.
    #[test]
    fn confirming_a_non_latest_attempt_retains_the_winning_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        add_deposit(&mut ledger, &keys, outpoint(1), 2 * unit + 50_000, true);

        let plan1 = ledger.split_deposit(outpoint(1), &params, 1_000, &keys).unwrap();
        let plan2 = ledger.bump_split_fee(outpoint(1), 5_000, &params, &keys).unwrap();
        assert_ne!(plan1.txid, plan2.txid);

        // The LOWER-fee attempt 1 wins the race and confirms.
        ledger.confirm_split(plan1.txid, 500, &FixedClock(1_700_000_000)).unwrap();

        let dep = ledger.find(&outpoint(1)).unwrap();
        assert_eq!(dep.state, CoinState::Spent);
        let retained: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(dep.split_tx.as_ref().unwrap()).unwrap();
        assert_eq!(
            retained.compute_txid(),
            plan1.txid,
            "the retained rebroadcast artifact must be the CONFIRMED attempt, not the latest"
        );
        // The winner's children are live at the winner's outpoints...
        let active: Vec<_> = ledger
            .coins()
            .iter()
            .filter(|c| c.outpoint.txid == plan1.txid && c.state == CoinState::Unspent)
            .collect();
        assert_eq!(active.len(), 3, "2 pre-enc + 1 change from the confirmed attempt");
        // ...and the losing (latest) attempt's children are gone.
        assert!(ledger.coins().iter().all(|c| c.outpoint.txid != plan2.txid));
    }

    /// Audit B1+B4: a faulted wall clock AT CONFIRMATION (absurd-future,
    /// absurd-past, or SystemClock's unwrap_or(0)) must not be trusted into the
    /// once-written eligibility anchor. An out-of-window reading collapses to
    /// the sane floor: the coin is NOT frozen until an absurd date (B1), and
    /// the HEIGHT anchor still enforces the delay in block time (B4).
    #[test]
    fn clock_faults_at_confirmation_are_collapsed_not_trusted() {
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;

        // --- absurd-FUTURE clock at confirmation: coin must not freeze. ---
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        add_deposit(&mut ledger, &keys, outpoint(1), unit + 2_000, true);
        let plan = ledger.split_deposit(outpoint(1), &params, 2_000, &keys).unwrap();
        ledger.confirm_split(plan.txid, 105, &FixedClock(u64::MAX)).unwrap();
        let coin = ledger
            .coins()
            .iter()
            .find(|c| c.class == CoinClass::PreEncumbrance)
            .unwrap()
            .clone();
        let e = coin.eligibility_unix().unwrap();
        assert!(
            e <= SANE_CLOCK_MIN_UNIX + 73 * 3600,
            "a faulted future clock must collapse to the sane floor, got {e}"
        );
        // Leasable with a REALISTIC clock once both anchors pass — not frozen.
        let realistic = FixedClock(1_700_000_000);
        let leased = ledger
            .lease_pre_encumbrance(unit, &realistic, coin.eligible_height, LESSEE)
            .unwrap();
        assert!(leased.is_some(), "the coin must be recoverable under a corrected clock");

        // --- absurd-PAST clock (SystemClock's unwrap_or(0) shape): the wall
        // half degrades, but the HEIGHT anchor still enforces the delay. ---
        let dir2 = tempfile::tempdir().unwrap();
        let (mut ledger2, keys2) = fresh(dir2.path());
        add_deposit(&mut ledger2, &keys2, outpoint(2), unit + 2_000, true);
        let plan2 = ledger2.split_deposit(outpoint(2), &params, 2_000, &keys2).unwrap();
        ledger2.confirm_split(plan2.txid, 105, &FixedClock(0)).unwrap();
        let coin2 = ledger2
            .coins()
            .iter()
            .find(|c| c.class == CoinClass::PreEncumbrance)
            .unwrap()
            .clone();
        assert!(coin2.eligible_height > 105, "height anchor set from confirmation");
        // Wall passed (huge clock) but chain NOT: still gated — the height
        // anchor is the load-bearing half under a faulted clock.
        assert!(matches!(
            ledger2.lease_pre_encumbrance(
                unit,
                &FixedClock(u64::MAX),
                coin2.eligible_height - 1,
                LESSEE
            ),
            Err(Error::Deadline(_))
        ));
        // Both passed: leases.
        assert!(ledger2
            .lease_pre_encumbrance(unit, &FixedClock(u64::MAX), coin2.eligible_height, LESSEE)
            .unwrap()
            .is_some());
    }

    /// Audit G1+G7: a fee bump that COLLAPSES k (the higher fee eats a whole
    /// unit) mints a change output where the previous attempt had none — with a
    /// FRESH OnboardingChange key — and both attempts conserve value exactly
    /// (deposit = outputs + effective fee; no sat created or destroyed).
    #[test]
    fn bump_that_collapses_k_mints_fresh_change_and_conserves_value() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        let deposit_amt = 2 * unit + 1_000;
        add_deposit(&mut ledger, &keys, outpoint(1), deposit_amt, true);

        // Attempt 1: fee 1_000 -> spendable = 2*unit exactly -> k=2, NO change.
        let plan1 = ledger.split_deposit(outpoint(1), &params, 1_000, &keys).unwrap();
        assert_eq!(plan1.pre_encumbrance_count, 2);
        assert_eq!(plan1.change_sats, 0);
        let tx1: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&plan1.tx_bytes).unwrap();
        let out1: u64 = tx1.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(out1 + 1_000, deposit_amt, "attempt 1 conserves value");
        assert_eq!(tx1.output.len(), 2, "no change output on attempt 1");

        // Attempt 2: fee 5_000 -> spendable = 2*unit - 4_000 -> k COLLAPSES to 1
        // and a large change output appears, under a FRESH change key.
        let plan2 = ledger.bump_split_fee(outpoint(1), 5_000, &params, &keys).unwrap();
        assert_eq!(plan2.pre_encumbrance_count, 1, "the higher fee ate a unit");
        assert_eq!(plan2.change_sats, unit - 4_000);
        let tx2: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&plan2.tx_bytes).unwrap();
        let out2: u64 = tx2.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(out2 + 5_000, deposit_amt, "attempt 2 conserves value");
        // The minted change spk is FRESH — not any spk attempt 1 used.
        let spks1: std::collections::HashSet<_> =
            tx1.output.iter().map(|o| o.script_pubkey.clone()).collect();
        let change_out = tx2
            .output
            .iter()
            .find(|o| o.value.to_sat() == unit - 4_000)
            .expect("change output present");
        assert!(
            !spks1.contains(&change_out.script_pubkey),
            "collapsed-k bump must mint a FRESH change key"
        );
        // Confirming the collapsed attempt activates exactly its 2 outputs.
        ledger.confirm_split(plan2.txid, 500, &FixedClock(1_700_000_000)).unwrap();
        let active: Vec<_> = ledger
            .coins()
            .iter()
            .filter(|c| c.state == CoinState::Unspent && c.outpoint.txid == plan2.txid)
            .collect();
        assert_eq!(active.len(), 2, "1 pre-enc + 1 change");
    }

    /// Audit B3: hostile Params whose tier + delta_fee overflows u64 can pass
    /// `Params::validate` (which bounds the tier only from below), so the unit
    /// computation must be CHECKED in BOTH split paths — an unchecked add
    /// would wrap in release (minting absurd outputs) or panic under
    /// overflow-checks.
    #[test]
    fn hostile_tier_overflow_params_are_rejected_not_wrapped() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        let mut hostile = params.clone();
        hostile.tier_d_sats = u64::MAX;
        // Precondition: validate() admits the max-tier params — the checked
        // unit computation is the only line of defense.
        assert!(hostile.validate().is_ok(), "precondition: validate admits max-tier params");

        // split_deposit arm.
        add_deposit(&mut ledger, &keys, outpoint(1), 2 * unit + 50_000, true);
        let err = ledger.split_deposit(outpoint(1), &hostile, 1_000, &keys).unwrap_err();
        assert!(
            matches!(err, Error::Validation(m) if m.contains("tier overflow")),
            "got {err:?}"
        );

        // bump_split_fee arm: a legitimate pending split, then a hostile bump.
        ledger.split_deposit(outpoint(1), &params, 1_000, &keys).unwrap();
        let err = ledger.bump_split_fee(outpoint(1), 5_000, &hostile, &keys).unwrap_err();
        assert!(
            matches!(err, Error::Validation(m) if m.contains("tier overflow")),
            "got {err:?}"
        );
    }

    /// Audit G2+G5: promote_change_to_reserve's guards (only UNSPENT
    /// ONBOARDING-CHANGE is promotable — promoting a delayed pre-encumbrance
    /// coin would BYPASS its onboarding delay, since reserve leasing has no
    /// eligibility gate), and the promoted coin's class/purpose divergence
    /// (class Reserve, purpose OnboardingChange) survives a reopen.
    #[test]
    fn promote_guards_hold_and_promoted_reserve_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        let change_op;
        {
            let (mut ledger, keys) = fresh(dir.path());
            add_deposit(&mut ledger, &keys, outpoint(1), unit + 10_000, true);
            let plan = ledger.split_deposit(outpoint(1), &params, 1_000, &keys).unwrap();
            assert_eq!(plan.change_sats, 9_000);
            ledger.confirm_split(plan.txid, 105, &FixedClock(1_700_000_000)).unwrap();
            let pre_op = ledger
                .coins()
                .iter()
                .find(|c| c.class == CoinClass::PreEncumbrance)
                .unwrap()
                .outpoint;
            change_op = ledger
                .coins()
                .iter()
                .find(|c| c.class == CoinClass::OnboardingChange)
                .unwrap()
                .outpoint;

            // G5 negatives: a pre-encumbrance coin (delay-carrying) must not be
            // promotable — that would bypass its onboarding delay entirely.
            assert!(matches!(
                ledger.promote_change_to_reserve(pre_op).unwrap_err(),
                Error::Ordering(_)
            ));
            // Unknown outpoint refused.
            assert!(matches!(
                ledger.promote_change_to_reserve(outpoint(99)).unwrap_err(),
                Error::Validation(_)
            ));

            // The legal promotion: class flips, key purpose is RETAINED.
            ledger.promote_change_to_reserve(change_op).unwrap();
            let c = ledger.find(&change_op).unwrap();
            assert_eq!(c.class, CoinClass::Reserve);
            assert_eq!(c.key_purpose, KeyPurpose::OnboardingChange);
            // Double-promotion refused (no longer OnboardingChange class).
            assert!(ledger.promote_change_to_reserve(change_op).is_err());
        } // drop = restart

        // G2: the divergence survives persist/open — the coin still signs under
        // its ORIGINAL purpose, and it counts as leasable reserve.
        let mut ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
        let c = ledger.find(&change_op).unwrap();
        assert_eq!(c.class, CoinClass::Reserve, "promotion survives reopen");
        assert_eq!(
            c.key_purpose,
            KeyPurpose::OnboardingChange,
            "the promoted coin must keep signing under its issuance purpose"
        );
        assert!(ledger.has_leasable_reserve(9_000));
        let leased = ledger
            .lease_reserve(BumpTarget::Refund, 9_000, None, LESSEE)
            .unwrap()
            .expect("promoted reserve leases");
        assert_eq!(leased.outpoint, change_op);
    }

    /// Audit G9+G11: the eligibility gate is INCLUSIVE at both exact anchors
    /// (one second / one block earlier is gated), and lease selection is a
    /// trichotomy — no coin of the size at all is Ok(None), an existing but
    /// immature coin is Err(Deadline), a mature one leases.
    #[test]
    fn eligibility_boundaries_are_exact_and_selection_trichotomy_holds() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        add_deposit(&mut ledger, &keys, outpoint(1), unit + 2_000, true);
        let plan = ledger.split_deposit(outpoint(1), &params, 2_000, &keys).unwrap();
        ledger.confirm_split(plan.txid, 105, &FixedClock(1_700_000_000)).unwrap();
        let coin = ledger
            .coins()
            .iter()
            .find(|c| c.class == CoinClass::PreEncumbrance)
            .unwrap()
            .clone();
        let e = coin.eligibility_unix().unwrap();
        let eh = coin.eligible_height;

        // G11 trichotomy arm 1: no coin of THAT size exists -> Ok(None).
        assert!(ledger
            .lease_pre_encumbrance(unit + 1, &FixedClock(u64::MAX), u32::MAX, LESSEE)
            .unwrap()
            .is_none());
        // Arm 2: exists but immature -> Err(Deadline), on EITHER anchor.
        assert!(matches!(
            ledger.lease_pre_encumbrance(unit, &FixedClock(e - 1), eh, LESSEE),
            Err(Error::Deadline(_))
        ));
        assert!(matches!(
            ledger.lease_pre_encumbrance(unit, &FixedClock(e), eh - 1, LESSEE),
            Err(Error::Deadline(_))
        ));
        // Arm 3 + G9 boundary: EXACTLY at both anchors -> leases (inclusive).
        assert!(ledger
            .lease_pre_encumbrance(unit, &FixedClock(e), eh, LESSEE)
            .unwrap()
            .is_some());
    }

    /// Audit G3: the transact() rollback — a mutation whose PERSIST fails must
    /// leave the in-memory state exactly as before (memory and disk never
    /// diverge), and the same mutation must succeed once persistence recovers.
    #[test]
    fn transact_rolls_back_in_memory_state_when_persist_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        add_deposit(&mut ledger, &keys, outpoint(1), 5_000_000, true);
        assert_eq!(ledger.find(&outpoint(1)).unwrap().state, CoinState::Unspent);

        // Block persistence: a DIRECTORY at the tmp path makes File::create fail.
        let tmp_block = dir.path().join("ledger.bin.tmp");
        std::fs::create_dir(&tmp_block).unwrap();
        let err = ledger.mark_spent(outpoint(1)).unwrap_err();
        assert!(matches!(err, Error::Abort(_)), "persist failure surfaces, got {err:?}");
        assert_eq!(
            ledger.find(&outpoint(1)).unwrap().state,
            CoinState::Unspent,
            "the failed transact must roll the in-memory state back"
        );

        // Persistence recovers: the same mutation now lands, and survives reopen.
        std::fs::remove_dir(&tmp_block).unwrap();
        ledger.mark_spent(outpoint(1)).unwrap();
        assert_eq!(ledger.find(&outpoint(1)).unwrap().state, CoinState::Spent);
        drop(ledger);
        let ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
        assert_eq!(ledger.find(&outpoint(1)).unwrap().state, CoinState::Spent);
    }

    /// Audit G12: parse_ledger is TOTAL — malformed (but correctly SEALED)
    /// plaintext must fail closed with Err, never panic, for truncations,
    /// wrong versions, bad enums, absurd counts, and trailing bytes.
    #[test]
    fn parse_ledger_is_total_on_malformed_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.bin");
        let tek = crate::crypto::storage::derive_tek(
            &ModeledEnclave.platform_key(),
            &ledger_salt(),
        );
        let cases: Vec<Vec<u8>> = vec![
            vec![],                            // empty
            vec![3],                           // header truncated
            vec![2, 1, 0, 0, 0, 0, 0, 0, 0, 0], // old version (v2) rejected
            vec![3, 7, 0, 0, 0, 0, 0, 0, 0, 0], // malformed ack flag
            {
                // count says 5 coins, none present.
                let mut v = vec![3, 1];
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&5u32.to_le_bytes());
                v
            },
            {
                // one coin with an unknown class byte.
                let mut v = vec![3, 1];
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&1u32.to_le_bytes());
                v.extend_from_slice(&[0u8; 36]); // outpoint
                v.extend_from_slice(&1_000u64.to_le_bytes());
                v.push(0xFF); // class: invalid
                v
            },
            {
                // valid empty ledger, then trailing junk.
                let mut v = vec![3, 1];
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&0u32.to_le_bytes());
                v.push(0xAA);
                v
            },
            {
                // v3 attempt with an absurd length prefix — the attempt-bytes
                // parser must Err on truncation/overflow, never panic.
                let mut v = vec![3, 1];
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&1u32.to_le_bytes());
                v.extend_from_slice(&[0u8; 36]); // outpoint
                v.extend_from_slice(&1_000u64.to_le_bytes());
                v.push(0); // class: Deposit
                v.push(0); // state: Unspent
                v.push(0); // purpose: Deposit
                v.extend_from_slice(&0u32.to_le_bytes()); // key_index
                v.extend_from_slice(&0u32.to_le_bytes()); // created_height
                v.extend_from_slice(&0u64.to_le_bytes()); // delay
                v.extend_from_slice(&0u32.to_le_bytes()); // eligible_height
                v.push(16); // flags: attempts present
                v.push(1); // one attempt
                v.extend_from_slice(&[0u8; 32]); // attempt txid
                v.extend_from_slice(&u32::MAX.to_le_bytes()); // absurd length
                v
            },
        ];
        for (i, pt) in cases.iter().enumerate() {
            let sealed = crate::crypto::storage::seal(&tek, pt).unwrap();
            std::fs::write(&path, &sealed).unwrap();
            match Ledger::open(dir.path(), &ModeledEnclave) {
                Err(Error::Abort(_)) | Err(Error::Validation(_)) => {}
                Err(e) => panic!("case {i}: wrong error class {e:?}"),
                Ok(_) => panic!("case {i}: malformed ledger must fail closed"),
            }
        }
    }

    /// Audit G8+G13: recording a coin at a CALLER-SUPPLIED key index must raise
    /// the monotonic issuance floor past it — otherwise a later issue_key would
    /// re-issue the same (purpose, index) on-chain (address/key reuse). The
    /// raised floor survives reopen.
    #[test]
    fn caller_supplied_key_indices_raise_the_issuance_floor() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let (i1, _) = ledger.next_deposit_address(&keys).unwrap();

        // record_swapped_output at a far-ahead index.
        ledger
            .record_swapped_output(outpoint(9), 1_000, i1 + 50, 42, false)
            .unwrap();
        let (i2, _) = ledger.next_swap_destination(&keys).unwrap();
        assert!(i2 > i1 + 50, "issuance floor must clear the recorded index, got {i2}");

        // register_deposit at a far-ahead (but correctly bound) index.
        let far = i2 + 100;
        let derived = keys.derive_xonly(KeyPurpose::Deposit, far).unwrap();
        let spk = crate::tx::setup::pre_encumbrance_spk(derived).unwrap();
        ledger
            .register_deposit(outpoint(10), 2_000, 100, far, &spk, &keys, Some(ack()))
            .unwrap();
        let (i3, _) = ledger.next_deposit_address(&keys).unwrap();
        assert!(i3 > far, "deposit registration must raise the floor, got {i3}");

        // The floor survives restart.
        drop(ledger);
        let mut ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
        let (i4, _) = ledger.next_deposit_address(&keys).unwrap();
        assert!(i4 > i3, "the raised floor must persist across reopen");
    }

    #[test]
    fn linkage_ack_gates_completion_bumps_and_taint_persists() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        add_deposit(&mut ledger, &keys, outpoint(1), unit + 60_000 + 1_000, true);
        let plan = ledger.split_deposit(outpoint(1), &params, 1_000, &keys).unwrap();
        ledger.confirm_split(plan.txid, 105, &FixedClock(1_000)).unwrap();
        let change_op = OutPoint::new(plan.txid, plan.change_vout.unwrap());

        ledger.promote_change_to_reserve(change_op).unwrap();
        // The promoted coin keeps its provenance-readable key purpose.
        assert_eq!(
            ledger.find(&change_op).unwrap().key_purpose,
            KeyPurpose::OnboardingChange
        );

        // Refund bump: silent (no ack needed).
        let r = ledger.lease_reserve(BumpTarget::Refund, 1, None, LESSEE).unwrap().unwrap();
        ledger.release_lease(r.outpoint).unwrap();

        // Completion bump: refused without the typed linkage ack.
        assert!(matches!(
            ledger.lease_reserve(BumpTarget::Completion, 1, None, LESSEE),
            Err(Error::Ordering(_))
        ));
        assert!(acknowledge_linkage("ok").is_err());
        let ack = acknowledge_linkage(LINKAGE_WARNING).unwrap();
        let r = ledger
            .lease_reserve(BumpTarget::Completion, 1, Some(ack), LESSEE)
            .unwrap()
            .expect("reserve leased");
        assert_eq!(r.outpoint, change_op);

        // Size gate: no reserve is large enough → no lease (the gate and the
        // lease agree).
        let ack2 = acknowledge_linkage(LINKAGE_WARNING).unwrap();
        ledger.release_lease(r.outpoint).unwrap();
        assert!(
            ledger
                .lease_reserve(BumpTarget::Completion, u64::MAX, Some(ack2), LESSEE)
                .unwrap()
                .is_none(),
            "an oversized min must find no leasable reserve"
        );

        // The bumped swap's output carries the persisted taint.
        ledger
            .record_swapped_output(outpoint(9), params.tier_d_sats, 42, 200, true)
            .unwrap();
        drop(ledger);
        let ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
        assert!(ledger.find(&outpoint(9)).unwrap().deposit_linked, "taint must persist");
    }

    #[test]
    fn lease_reconciliation_releases_orphans_only() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        add_deposit(&mut ledger, &keys, outpoint(1), 2 * unit + 2_000, true);
        let plan = ledger.split_deposit(outpoint(1), &params, 2_000, &keys).unwrap();
        ledger.confirm_split(plan.txid, 105, &FixedClock(1_000)).unwrap();

        let late = FixedClock(u64::MAX);
        let live = [0xAA; 32];
        let dead = [0xBB; 32];
        let c1 = ledger.lease_pre_encumbrance(unit, &late, u32::MAX, live).unwrap().unwrap();
        let c2 = ledger.lease_pre_encumbrance(unit, &late, u32::MAX, dead).unwrap().unwrap();

        // Crash: the `dead` swap never wrote a SwapRecord. Reconcile against
        // the live set.
        let released = ledger.reconcile_leases(&[live]).unwrap();
        assert_eq!(released, vec![c2.outpoint], "only the orphan released");
        assert_eq!(ledger.find(&c1.outpoint).unwrap().state, CoinState::Leased);
        assert_eq!(ledger.find(&c2.outpoint).unwrap().state, CoinState::Unspent);
    }

    /// A minimal v3 spend of `outpoint` paying `out` sats to a standard P2TR, so
    /// a leased coin's outpoint can be marked confirmed-spent on the sim.
    fn spend_std(outpoint: OutPoint, out: u64) -> Vec<u8> {
        use bitcoin::{
            absolute, transaction::Version, Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
            Witness,
        };
        let mut spk = vec![0x51u8, 0x20];
        spk.extend_from_slice(&[0x77u8; 32]);
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(out), script_pubkey: ScriptBuf::from_bytes(spk) }],
        };
        bitcoin::consensus::encode::serialize(&tx)
    }

    /// Task 3: the chain-aware lease reconcile marks a `Leased` coin the chain
    /// confirms SPENT as `Spent` (never re-exposed as a phantom), independent of
    /// lease liveness, while still releasing orphaned leases and leaving a
    /// live+unspent lease untouched. This is the funding-coin phantom: a
    /// pre-funding abort spent the pre-encumbrance coin into its escrow on chain,
    /// but `run_exchange` never marked it spent, so the chain-blind reconcile
    /// would re-expose it as `Unspent`.
    #[test]
    fn reconcile_leases_with_chain_sweeps_a_confirmed_spent_lease() {
        use crate::chain::{ChainView, SimChain};
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        add_deposit(&mut ledger, &keys, outpoint(1), 3 * unit + 2_000, true);
        let plan = ledger.split_deposit(outpoint(1), &params, 2_000, &keys).unwrap();
        ledger.confirm_split(plan.txid, 105, &FixedClock(1_000)).unwrap();

        // A NON-LEASABLE coin: a bare Deposit (Unspent, class Deposit), left
        // unsplit. It exercises the class-scoping guard — even confirmed-spent on
        // chain it must NEVER be swept (its spent-ness is owned by the
        // deposit→split lifecycle, not this reconcile). Marking a real deposit
        // Spent here would strand a genuine coin.
        add_deposit(&mut ledger, &keys, outpoint(2), 5_000_000, false);
        assert_eq!(ledger.find(&outpoint(2)).unwrap().state, CoinState::Unspent);
        assert_eq!(ledger.find(&outpoint(2)).unwrap().class, CoinClass::Deposit);

        let late = FixedClock(u64::MAX);
        let live = [0xAA; 32];
        let dead = [0xBB; 32];
        // Three leased pre-encumbrance coins: live+unspent, live+spent (the
        // phantom this fix heals), and an orphan (dead lessee) + unspent.
        let c_live = ledger.lease_pre_encumbrance(unit, &late, u32::MAX, live).unwrap().unwrap();
        let c_spent = ledger.lease_pre_encumbrance(unit, &late, u32::MAX, live).unwrap().unwrap();
        let c_orphan = ledger.lease_pre_encumbrance(unit, &late, u32::MAX, dead).unwrap().unwrap();

        // The chain confirms c_spent's outpoint SPENT (its Setup confirmed) AND
        // the bare Deposit's outpoint spent (a normal on-chain send of it);
        // c_live and c_orphan are never touched on chain.
        let chain = SimChain::new(200);
        chain.fund_with_amount(c_spent.outpoint, 200, unit);
        chain.broadcast(&spend_std(c_spent.outpoint, unit - 500)).unwrap();
        chain.fund_with_amount(outpoint(2), 200, 5_000_000);
        chain.broadcast(&spend_std(outpoint(2), 4_999_500)).unwrap();
        chain.mine();
        assert!(matches!(chain.spend_status(c_spent.outpoint), crate::chain::SpendStatus::Confirmed(_)));
        assert!(matches!(chain.spend_status(outpoint(2)), crate::chain::SpendStatus::Confirmed(_)));

        let out = ledger.reconcile_leases_with_chain(&[live], &chain).unwrap();
        assert_eq!(out.swept, vec![c_spent.outpoint], "ONLY the leasable confirmed-spent lease is swept");
        assert_eq!(out.released, vec![c_orphan.outpoint], "the orphan lease is released");
        // The phantom is permanently Spent — never a lease candidate again.
        assert_eq!(ledger.find(&c_spent.outpoint).unwrap().state, CoinState::Spent);
        // The orphan is Unspent (re-leasable, unchanged from the chain-blind rule).
        assert_eq!(ledger.find(&c_orphan.outpoint).unwrap().state, CoinState::Unspent);
        // The live+unspent lease is untouched.
        assert_eq!(ledger.find(&c_live.outpoint).unwrap().state, CoinState::Leased);
        // THE GUARD: the non-leasable Deposit is left Unspent despite the chain
        // confirming it spent — this reconcile must never touch it.
        assert_eq!(
            ledger.find(&outpoint(2)).unwrap().state,
            CoinState::Unspent,
            "a non-leasable coin must never be swept by the lease reconcile"
        );

        // Idempotent: a second run over the healed ledger sweeps/releases nothing
        // new (c_spent is now Spent so not a sweep target; c_orphan is Unspent+
        // not-on-chain so not swept, and it is now leaseable, not leased).
        let again = ledger.reconcile_leases_with_chain(&[live], &chain).unwrap();
        assert!(again.swept.is_empty() && again.released.is_empty(), "reconcile is idempotent");
    }

    #[test]
    fn ledger_is_sealed_fail_closed_and_single_instance() {
        let dir = tempfile::tempdir().unwrap();
        let marker_amount = 0x00AB_CDEF_1234_5678u64;
        {
            let (mut ledger, keys) = fresh(dir.path());
            add_deposit(&mut ledger, &keys, outpoint(1), marker_amount, true);
            match Ledger::open(dir.path(), &ModeledEnclave) {
                Err(Error::Abort(_)) => {}
                Err(e) => panic!("wrong error: {e:?}"),
                Ok(_) => panic!("second instance must be refused"),
            }
        }
        let raw = std::fs::read(dir.path().join("ledger.bin")).unwrap();
        assert!(
            !raw.windows(8).any(|w| w == marker_amount.to_le_bytes()),
            "coin amounts leaked to disk in plaintext"
        );
        let p = dir.path().join("ledger.bin");
        let mut bad = std::fs::read(&p).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        std::fs::write(&p, &bad).unwrap();
        match Ledger::open(dir.path(), &ModeledEnclave) {
            Err(Error::Abort(msg)) => assert!(msg.contains("corrupt"), "got {msg}"),
            Err(e) => panic!("wrong error: {e:?}"),
            Ok(_) => panic!("corrupt ledger must fail closed"),
        }
    }

    #[test]
    fn split_tx_is_persisted_for_crash_rebroadcast_and_keys_never_reused() {
        let dir = tempfile::tempdir().unwrap();
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        let tx_bytes;
        let i1;
        {
            let (mut ledger, keys) = fresh(dir.path());
            add_deposit(&mut ledger, &keys, outpoint(1), unit + 1_000, true);
            let plan = ledger.split_deposit(outpoint(1), &params, 1_000, &keys).unwrap();
            tx_bytes = plan.tx_bytes;
            i1 = ledger.next_deposit_address(&keys).unwrap().0;
            // ===== crash before broadcast/confirm =====
        }
        let mut ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
        let dep = ledger.find(&outpoint(1)).unwrap();
        assert_eq!(dep.state, CoinState::SplitPending);
        assert_eq!(dep.split_tx.as_deref(), Some(tx_bytes.as_slice()));
        // Key counter survived (no on-chain reuse), and the restore floor
        // can only raise it.
        let keys = ModeledKeySource::new(&ModeledEnclave);
        let i2 = ledger.next_deposit_address(&keys).unwrap().0;
        assert!(i2 > i1);
        ledger.raise_key_index_floor(i2 + 100).unwrap();
        let i3 = ledger.next_deposit_address(&keys).unwrap().0;
        assert!(i3 >= i2 + 100, "floor must raise the counter");
    }
}
