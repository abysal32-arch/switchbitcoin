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
//!   * `Reserve` — CPFP backstop coins (congestion-only, opt-in for
//!     completions, silent for refunds — rank 6).
//!   * `Swapped` — exactly D at a fresh destination.
//!
//! Completions structurally take no external input (single escrow input,
//! `tx::txbuild`), so "no external input ever touches a completion" holds at
//! the transaction-builder level, not by ledger discipline.
//!
//! KEYS: the ledger persists only `(purpose, index)` — key material lives
//! behind the `KeySource` seam (enclave model; see `wallet::keys`).
//!
//! PERSISTENCE: one sealed file (`ledger.bin`), AES-256-GCM under a
//! domain-separated wallet TEK, fsync'd atomic writes, OS-file-lock single
//! instance. FAIL-CLOSED on corruption: unlike swap records (per-swap blast
//! radius, quarantine-able), the ledger is the wallet's ENTIRE coin memory —
//! silently resetting it would orphan every coin. A corrupt ledger is an
//! error the user must resolve (restore from backup), never a fresh start.
//!
//! PHASE 0: the v3.13 warning is a typed gate. `Ledger::create` (onboarding)
//! and the first `register_deposit` each demand a `Phase0Ack`, which can
//! only be minted by echoing the exact warning copy back — proof the UI
//! displayed THAT text, in the spirit of the WatchtowerReceipt gate.

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
pub const PHASE0_WARNING: &str = "Warning: Before you send Bitcoin to New Key, move it to a fresh address first. If it came from a KYC'd exchange or any service that knows your identity, send it to a brand-new self-custodied address you control before depositing here. New Key protects your history from the moment your Bitcoin arrives; it cannot erase provenance that already exists on-chain before you arrive. One clean transaction to a wallet you control, wait for confirmation, then deposit.";

/// Proof the Phase-0 warning was displayed and confirmed. Non-Clone,
/// non-constructible except via `acknowledge_phase0` — a caller cannot
/// conjure one by passing `true` somewhere.
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

/// Wall-clock seam (the onboarding delay is specified in hours, not blocks).
/// Tests inject a fixed clock; production uses the system clock.
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

/// Bitcoin dust threshold (sats) for the change-folding rule.
const DUST_SATS: u64 = 546;

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
    /// Created by a broadcast-but-unconfirmed split.
    PendingConfirm,
    /// A deposit whose split tx is signed/broadcast but not yet confirmed.
    SplitPending,
    /// Reserved by a live swap (or backstop); no other consumer may take it.
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

/// One tracked coin. Key material is NOT here — only `(class→purpose, key_index)`.
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
    /// Pre-encumbrance only: unix time at which this coin may be encumbered
    /// (the randomized 24–72h + sub-hour-jitter delay). 0 for other classes.
    pub eligible_at_unix: u64,
    /// Deposit only: the signed split transaction, persisted BEFORE
    /// broadcast so a crash cannot orphan the split (rebroadcastable from
    /// the ledger alone).
    pub split_tx: Option<Vec<u8>>,
}

/// The outcome of `split_deposit`, ready to broadcast.
pub struct SplitPlan {
    pub tx_bytes: Vec<u8>,
    pub txid: Txid,
    pub pre_encumbrance_count: u32,
    pub change_sats: u64,
    /// Sampled per-output encumbrance-eligibility times (unix).
    pub eligible_at_unix: Vec<u64>,
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

/// Domain-separated wallet-ledger TEK salt (vs the per-swap records, whose
/// salt is the swap_session_id).
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
    /// an error (the coin memory must never silently reset) — restore from
    /// backup rather than starting empty.
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

    // ---- key issuance --------------------------------------------------

    /// Issue a fresh (never-reused) key index and return the Taproot
    /// single-sig receive script for it.
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

    /// A fresh deposit address (ordinary Taproot receive). Persists the
    /// index bump immediately so a crash cannot reuse it.
    pub fn next_deposit_address(&mut self, keys: &dyn KeySource) -> Result<(u32, ScriptBuf)> {
        let out = self.issue_key(KeyPurpose::Deposit, keys)?;
        self.persist()?;
        Ok(out)
    }

    /// A fresh per-swap destination (v3.13: fresh, never reused). Rank 4
    /// exchanges this over the authenticated peer channel.
    pub fn next_swap_destination(&mut self, keys: &dyn KeySource) -> Result<(u32, ScriptBuf)> {
        let out = self.issue_key(KeyPurpose::SwapDestination, keys)?;
        self.persist()?;
        Ok(out)
    }

    // ---- onboarding ----------------------------------------------------

    /// Register a detected incoming deposit (the chain watcher's callback).
    /// THE FIRST deposit re-demands the Phase-0 acknowledgement (v3.13:
    /// "shown once at onboarding and again at first deposit").
    pub fn register_deposit(
        &mut self,
        outpoint: OutPoint,
        amount_sats: u64,
        confirmed_height: u32,
        key_index: u32,
        first_deposit_ack: Option<Phase0Ack>,
    ) -> Result<()> {
        if !self.first_deposit_acked {
            if first_deposit_ack.is_none() {
                return Err(Error::Ordering(
                    "first deposit requires the Phase-0 acknowledgement again",
                ));
            }
            self.first_deposit_acked = true;
        }
        if self.find(&outpoint).is_some() {
            return Err(Error::Validation("ledger: outpoint already tracked"));
        }
        if amount_sats == 0 {
            return Err(Error::Validation("ledger: zero-value deposit"));
        }
        self.coins.push(CoinRecord {
            outpoint,
            amount_sats,
            class: CoinClass::Deposit,
            key_purpose: KeyPurpose::Deposit,
            state: CoinState::Unspent,
            key_index,
            created_height: confirmed_height,
            eligible_at_unix: 0,
            split_tx: None,
        });
        self.persist()
    }

    /// Phase 1 auto-split: build + sign the split of one deposit into k
    /// pre-encumbrance outputs of EXACTLY D + Δ_fee each plus (at most) one
    /// change output absorbing all rounding; sub-dust change folds into the
    /// fee. Each pre-encumbrance child gets an independent CSPRNG-sampled
    /// 24–72h (+ sub-hour jitter) eligibility delay from `params`. The plan
    /// (children + signed tx) is PERSISTED before this returns, so a crash
    /// between broadcast and confirmation cannot orphan the split.
    pub fn split_deposit(
        &mut self,
        deposit: OutPoint,
        params: &Params,
        fee_sats: u64,
        keys: &dyn KeySource,
        clock: &dyn WalletClock,
    ) -> Result<SplitPlan> {
        let dep = self
            .find(&deposit)
            .ok_or(Error::Validation("ledger: unknown deposit"))?;
        if dep.class != CoinClass::Deposit || dep.state != CoinState::Unspent {
            return Err(Error::Ordering("ledger: split source must be an unspent deposit"));
        }
        let dep_amount = dep.amount_sats;
        let dep_key_index = dep.key_index;
        params.validate()?;
        if fee_sats == 0 {
            return Err(Error::Validation("ledger: split fee must be positive"));
        }
        let unit = params
            .tier_d_sats
            .checked_add(params.delta_fee_sats)
            .ok_or(Error::Validation("ledger: tier overflow"))?;
        let spendable = dep_amount
            .checked_sub(fee_sats)
            .ok_or(Error::Validation("ledger: fee exceeds deposit"))?;
        let k = spendable / unit;
        if k == 0 {
            return Err(Error::Validation(
                "ledger: deposit too small for one pre-encumbrance unit",
            ));
        }
        let mut change = spendable - k * unit;
        let mut effective_fee = fee_sats;
        if change > 0 && change < DUST_SATS {
            // Sub-dust remainder folds into the fee (v3.13: change absorbs
            // rounding; dust never rides on a swap coin).
            effective_fee += change;
            change = 0;
        }

        // Fresh keys: k pre-encumbrance + optional change.
        let mut outputs: Vec<(ScriptBuf, u64)> = Vec::with_capacity(k as usize + 1);
        let mut child_keys: Vec<u32> = Vec::with_capacity(k as usize + 1);
        for _ in 0..k {
            let (idx, spk) = self.issue_key(KeyPurpose::PreEncumbrance, keys)?;
            child_keys.push(idx);
            outputs.push((spk, unit));
        }
        let mut change_key = None;
        if change > 0 {
            let (idx, spk) = self.issue_key(KeyPurpose::OnboardingChange, keys)?;
            change_key = Some(idx);
            outputs.push((spk, change));
        }

        // Sign the split with the deposit key (enclave-derived on demand).
        let dep_seckey = keys.derive_seckey(KeyPurpose::Deposit, dep_key_index)?;
        let (tx_bytes, txid) = crate::tx::setup::build_onboarding_split(
            deposit,
            dep_amount,
            &dep_seckey,
            &outputs,
            effective_fee,
        )?;

        // Sample per-child eligibility delays (CSPRNG; hours in [lo, hi],
        // plus sub-hour jitter) so pre-encumbrance coins decorrelate from
        // the deposit AND from each other.
        let now = clock.now_unix();
        let (lo_h, hi_h) = params.onboarding_delay_hours;
        let mut eligible_at = Vec::with_capacity(k as usize);
        for _ in 0..k {
            let hours = sample_range_u64(lo_h as u64, hi_h as u64)?;
            let jitter = sample_range_u64(0, 3599)?;
            eligible_at.push(now.saturating_add(hours * 3600).saturating_add(jitter));
        }

        // Register children (PendingConfirm) + mark the deposit SplitPending
        // with the signed tx, ATOMICALLY (one persist).
        for (i, key_index) in child_keys.iter().enumerate() {
            self.coins.push(CoinRecord {
                outpoint: OutPoint::new(txid, i as u32),
                amount_sats: unit,
                class: CoinClass::PreEncumbrance,
                key_purpose: KeyPurpose::PreEncumbrance,
                state: CoinState::PendingConfirm,
                key_index: *key_index,
                created_height: 0,
                eligible_at_unix: eligible_at[i],
                split_tx: None,
            });
        }
        if let Some(idx) = change_key {
            self.coins.push(CoinRecord {
                outpoint: OutPoint::new(txid, k as u32),
                amount_sats: change,
                class: CoinClass::OnboardingChange,
                key_purpose: KeyPurpose::OnboardingChange,
                state: CoinState::PendingConfirm,
                key_index: idx,
                created_height: 0,
                eligible_at_unix: 0,
                split_tx: None,
            });
        }
        {
            let dep = self.find_mut(&deposit).expect("checked above");
            dep.state = CoinState::SplitPending;
            dep.split_tx = Some(tx_bytes.clone());
        }
        self.persist()?;

        Ok(SplitPlan {
            tx_bytes,
            txid,
            pre_encumbrance_count: k as u32,
            change_sats: change,
            eligible_at_unix: eligible_at,
        })
    }

    /// The split confirmed at `height`: children become Unspent, the deposit
    /// becomes Spent (and drops its cached tx bytes).
    pub fn confirm_split(&mut self, split_txid: Txid, height: u32) -> Result<()> {
        let mut confirmed_children = 0;
        for coin in &mut self.coins {
            if coin.outpoint.txid == split_txid && coin.state == CoinState::PendingConfirm {
                coin.state = CoinState::Unspent;
                coin.created_height = height;
                confirmed_children += 1;
            }
        }
        if confirmed_children == 0 {
            return Err(Error::Validation("ledger: unknown split txid"));
        }
        for coin in &mut self.coins {
            if coin.state == CoinState::SplitPending {
                if let Some(tx) = &coin.split_tx {
                    // Match the deposit whose cached split produced this txid.
                    let parsed: bitcoin::Transaction =
                        bitcoin::consensus::encode::deserialize(tx)
                            .map_err(|_| Error::Abort("ledger: cached split undecodable"))?;
                    if parsed.compute_txid() == split_txid {
                        coin.state = CoinState::Spent;
                        coin.split_tx = None;
                    }
                }
            }
        }
        self.persist()
    }

    // ---- selection (class-pure, non-mixing) ------------------------------

    /// Select ONE eligible pre-encumbrance coin of exactly `unit_sats`
    /// (= D + Δ_fee for the tier) and LEASE it to the caller (a live swap).
    /// Eligibility = confirmed + randomized delay elapsed. Distinguishes
    /// "none exist" (Ok(None)) from "exist but still maturing" (Err) so the
    /// UX can say when.
    pub fn lease_pre_encumbrance(
        &mut self,
        unit_sats: u64,
        clock: &dyn WalletClock,
    ) -> Result<Option<CoinRecord>> {
        let now = clock.now_unix();
        let mut immature = false;
        let mut chosen: Option<usize> = None;
        for (i, c) in self.coins.iter().enumerate() {
            if c.class == CoinClass::PreEncumbrance
                && c.state == CoinState::Unspent
                && c.amount_sats == unit_sats
            {
                if c.eligible_at_unix <= now {
                    chosen = Some(i);
                    break;
                }
                immature = true;
            }
        }
        match chosen {
            Some(i) => {
                self.coins[i].state = CoinState::Leased;
                let rec = self.coins[i].clone();
                self.persist()?;
                Ok(Some(rec))
            }
            None if immature => Err(Error::Deadline(
                "pre-encumbrance coins exist but are still in their onboarding delay",
            )),
            None => Ok(None),
        }
    }

    /// Lease a reserve coin for the CPFP backstop (rank 6). Reserve class
    /// ONLY — the backstop can never accidentally reach a swap-path coin.
    pub fn lease_reserve(&mut self) -> Result<Option<CoinRecord>> {
        let idx = self
            .coins
            .iter()
            .position(|c| c.class == CoinClass::Reserve && c.state == CoinState::Unspent);
        match idx {
            Some(i) => {
                self.coins[i].state = CoinState::Leased;
                let rec = self.coins[i].clone();
                self.persist()?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    /// A leased coin's swap/backstop was aborted before it was spent.
    pub fn release_lease(&mut self, outpoint: OutPoint) -> Result<()> {
        let c = self
            .find_mut(&outpoint)
            .ok_or(Error::Validation("ledger: unknown outpoint"))?;
        if c.state != CoinState::Leased {
            return Err(Error::Ordering("ledger: coin is not leased"));
        }
        c.state = CoinState::Unspent;
        self.persist()
    }

    /// A leased (or unspent) coin was consumed on-chain.
    pub fn mark_spent(&mut self, outpoint: OutPoint) -> Result<()> {
        let c = self
            .find_mut(&outpoint)
            .ok_or(Error::Validation("ledger: unknown outpoint"))?;
        if !matches!(c.state, CoinState::Leased | CoinState::Unspent) {
            return Err(Error::Ordering("ledger: coin is not spendable"));
        }
        c.state = CoinState::Spent;
        self.persist()
    }

    /// Record a completed swap's output: exactly D at a fresh destination.
    pub fn record_swapped_output(
        &mut self,
        outpoint: OutPoint,
        amount_sats: u64,
        key_index: u32,
        height: u32,
    ) -> Result<()> {
        if self.find(&outpoint).is_some() {
            return Err(Error::Validation("ledger: outpoint already tracked"));
        }
        self.coins.push(CoinRecord {
            outpoint,
            amount_sats,
            class: CoinClass::Swapped,
            key_purpose: KeyPurpose::SwapDestination,
            state: CoinState::Unspent,
            key_index,
            created_height: height,
            eligible_at_unix: 0,
            split_tx: None,
        });
        self.persist()
    }

    /// Promote the onboarding change output to the reserve pool. Reserve
    /// coins share provenance with the DEPOSIT (not with any swap escrow),
    /// which is what the backstop's linkage rule requires — but promoting is
    /// still an explicit, logged act, never automatic.
    pub fn promote_change_to_reserve(&mut self, outpoint: OutPoint) -> Result<()> {
        let c = self
            .find_mut(&outpoint)
            .ok_or(Error::Validation("ledger: unknown outpoint"))?;
        if c.class != CoinClass::OnboardingChange || c.state != CoinState::Unspent {
            return Err(Error::Ordering(
                "ledger: only unspent onboarding change can become reserve",
            ));
        }
        c.class = CoinClass::Reserve;
        self.persist()
    }

    // ---- queries ---------------------------------------------------------

    pub fn coins(&self) -> &[CoinRecord] {
        &self.coins
    }

    pub fn find(&self, outpoint: &OutPoint) -> Option<&CoinRecord> {
        self.coins.iter().find(|c| &c.outpoint == outpoint)
    }

    fn find_mut(&mut self, outpoint: &OutPoint) -> Option<&mut CoinRecord> {
        self.coins.iter_mut().find(|c| &c.outpoint == outpoint)
    }

    // ---- persistence -------------------------------------------------------
    //
    // v1 layout (sealed): [1 ver=1][1 first_deposit_acked][4 next_key_index]
    // [4 count] then per coin: [32 txid][4 vout][8 amount][1 class][1 state]
    // [4 key_index][4 created_height][8 eligible_at][1 has_split_tx]
    // ([4 len][bytes] if set).

    fn persist(&self) -> Result<()> {
        let mut v = Vec::with_capacity(64 + self.coins.len() * 64);
        v.push(1u8);
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
            v.extend_from_slice(&c.eligible_at_unix.to_le_bytes());
            match &c.split_tx {
                Some(tx) => {
                    v.push(1);
                    v.extend_from_slice(&(tx.len() as u32).to_le_bytes());
                    v.extend_from_slice(tx);
                }
                None => v.push(0),
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
        Ok(())
    }
}

fn parse_ledger(b: &[u8]) -> Result<(Vec<CoinRecord>, u32, bool)> {
    let mut at = 0usize;
    if take_arr::<1>(b, &mut at)?[0] != 1 {
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
        let eligible_at_unix = take_le_u64(b, &mut at)?;
        let split_tx = match take_arr::<1>(b, &mut at)?[0] {
            0 => None,
            1 => {
                let len = take_le_u32(b, &mut at)? as usize;
                let end = at
                    .checked_add(len)
                    .ok_or(Error::Validation("ledger: split length overflow"))?;
                let s = b
                    .get(at..end)
                    .ok_or(Error::Validation("ledger truncated (split tx)"))?;
                at = end;
                Some(s.to_vec())
            }
            _ => return Err(Error::Validation("ledger: malformed split flag")),
        };
        coins.push(CoinRecord {
            outpoint: OutPoint::new(txid, vout),
            amount_sats,
            class,
            state,
            key_purpose,
            key_index,
            created_height,
            eligible_at_unix,
            split_tx,
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

    #[test]
    fn phase0_gate_is_typed_and_textual() {
        // Wrong copy: no token.
        assert!(acknowledge_phase0("I agree").is_err());
        assert!(acknowledge_phase0(&PHASE0_WARNING[..40]).is_err());
        // Exact copy: token.
        acknowledge_phase0(PHASE0_WARNING).unwrap();

        // First deposit demands the second showing.
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let (dep_idx, _spk) = ledger.next_deposit_address(&keys).unwrap();
        let err = ledger
            .register_deposit(outpoint(1), 5_000_000, 100, dep_idx, None)
            .unwrap_err();
        assert!(matches!(err, Error::Ordering(_)));
        ledger
            .register_deposit(outpoint(1), 5_000_000, 100, dep_idx, Some(ack()))
            .unwrap();
        // Second deposit: no re-ack needed.
        ledger
            .register_deposit(outpoint(2), 3_000_000, 101, dep_idx, None)
            .unwrap();
    }

    #[test]
    fn split_arithmetic_exact_units_single_change_and_dust_folding() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ledger, keys) = fresh(dir.path());
        let params = Params::testnet_provisional(); // unit = 1_005_000
        let unit = params.tier_d_sats + params.delta_fee_sats;
        let clock = FixedClock(1_000_000);

        // 3 units + healthy change.
        let (idx, _) = ledger.next_deposit_address(&keys).unwrap();
        let dep_amount = 3 * unit + 50_000 + 1_000; // 3 units + change + fee
        ledger
            .register_deposit(outpoint(1), dep_amount, 100, idx, Some(ack()))
            .unwrap();
        let plan = ledger
            .split_deposit(outpoint(1), &params, 1_000, &keys, &clock)
            .unwrap();
        assert_eq!(plan.pre_encumbrance_count, 3);
        assert_eq!(plan.change_sats, 50_000);
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&plan.tx_bytes).unwrap();
        assert_eq!(tx.input.len(), 1, "single deposit input");
        assert_eq!(tx.output.len(), 4, "3 pre-encumbrance + 1 change");
        for out in &tx.output[..3] {
            assert_eq!(out.value.to_sat(), unit, "every pre-encumbrance output exactly D+fee");
        }
        assert_eq!(tx.output[3].value.to_sat(), 50_000);
        // Fee conservation.
        let out_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(dep_amount - out_total, 1_000);
        // Every output key is fresh and distinct.
        let spks: std::collections::HashSet<_> =
            tx.output.iter().map(|o| o.script_pubkey.clone()).collect();
        assert_eq!(spks.len(), 4, "no address reuse across split outputs");

        // Sub-dust change folds into the fee.
        let (idx2, _) = ledger.next_deposit_address(&keys).unwrap();
        let dep2 = 2 * unit + 300 + 1_000; // change would be 300 < dust
        ledger
            .register_deposit(outpoint(2), dep2, 100, idx2, None)
            .unwrap();
        let plan2 = ledger
            .split_deposit(outpoint(2), &params, 1_000, &keys, &clock)
            .unwrap();
        assert_eq!(plan2.pre_encumbrance_count, 2);
        assert_eq!(plan2.change_sats, 0);
        let tx2: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&plan2.tx_bytes).unwrap();
        assert_eq!(tx2.output.len(), 2, "no dust change output");
        let out2: u64 = tx2.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(dep2 - out2, 1_300, "dust folded into fee");

        // Too small for one unit: refused.
        let (idx3, _) = ledger.next_deposit_address(&keys).unwrap();
        ledger.register_deposit(outpoint(3), unit / 2, 100, idx3, None).unwrap();
        assert!(ledger.split_deposit(outpoint(3), &params, 1_000, &keys, &clock).is_err());

        // A deposit cannot be split twice (state moved to SplitPending).
        assert!(ledger.split_deposit(outpoint(1), &params, 1_000, &keys, &clock).is_err());
    }

    #[test]
    fn eligibility_delay_gates_leasing_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        let t0 = 1_700_000_000u64;
        let plan;
        {
            let (mut ledger, keys) = fresh(dir.path());
            let (idx, _) = ledger.next_deposit_address(&keys).unwrap();
            ledger
                .register_deposit(outpoint(1), 2 * unit + 2_000, 100, idx, Some(ack()))
                .unwrap();
            plan = ledger
                .split_deposit(outpoint(1), &params, 2_000, &keys, &FixedClock(t0))
                .unwrap();
            ledger.confirm_split(plan.txid, 105).unwrap();

            // Delays are in [24h, 72h + 1h) from t0.
            for &e in &plan.eligible_at_unix {
                assert!(e >= t0 + 24 * 3600, "delay below the 24h floor");
                assert!(e < t0 + 72 * 3600 + 3600, "delay above 72h + jitter");
            }

            // Before eligibility: coins exist but are immature => Err.
            assert!(matches!(
                ledger.lease_pre_encumbrance(unit, &FixedClock(t0 + 3600)),
                Err(Error::Deadline(_))
            ));
            // ===== crash =====
        }
        // Fresh process: eligibility persisted, still gated.
        let mut ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
        assert!(matches!(
            ledger.lease_pre_encumbrance(unit, &FixedClock(t0 + 3600)),
            Err(Error::Deadline(_))
        ));
        // After the max possible delay: leasable.
        let late = FixedClock(t0 + 73 * 3600 + 1);
        let coin = ledger.lease_pre_encumbrance(unit, &late).unwrap().expect("eligible");
        assert_eq!(coin.class, CoinClass::PreEncumbrance);
        assert_eq!(coin.amount_sats, unit);
        // Leased: a second lease gets the OTHER coin, then none.
        let coin2 = ledger.lease_pre_encumbrance(unit, &late).unwrap().expect("second");
        assert_ne!(coin.outpoint, coin2.outpoint, "leasing must not double-select");
        assert!(ledger.lease_pre_encumbrance(unit, &late).unwrap().is_none());
        // Release one: leasable again.
        ledger.release_lease(coin.outpoint).unwrap();
        assert!(ledger.lease_pre_encumbrance(unit, &late).unwrap().is_some());
    }

    #[test]
    fn non_mixing_selectors_are_class_pure() {
        let dir = tempfile::tempdir().unwrap();
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        let (mut ledger, keys) = fresh(dir.path());
        let (idx, _) = ledger.next_deposit_address(&keys).unwrap();
        ledger
            .register_deposit(outpoint(1), unit + 60_000 + 1_000, 100, idx, Some(ack()))
            .unwrap();
        let clock = FixedClock(1_000);
        let plan = ledger.split_deposit(outpoint(1), &params, 1_000, &keys, &clock).unwrap();
        ledger.confirm_split(plan.txid, 105).unwrap();
        let change_op = OutPoint::new(plan.txid, plan.pre_encumbrance_count);

        // Reserve selector sees nothing until change is explicitly promoted.
        assert!(ledger.lease_reserve().unwrap().is_none());
        ledger.promote_change_to_reserve(change_op).unwrap();
        let r = ledger.lease_reserve().unwrap().expect("reserve");
        assert_eq!(r.class, CoinClass::Reserve);
        assert_eq!(r.outpoint, change_op);

        // The pre-encumbrance selector can never return the change/reserve
        // coin even when amounts collide: class-pure by construction.
        assert!(matches!(
            ledger.lease_pre_encumbrance(unit, &FixedClock(2_000)),
            Err(Error::Deadline(_)),
        ));
        // A deposit can never be leased as pre-encumbrance, even at the
        // EXACT unit amount: class-pure selection, not amount matching.
        let (idx2, _) = ledger.next_deposit_address(&keys).unwrap();
        ledger.register_deposit(outpoint(9), unit, 100, idx2, None).unwrap();
        // Far future: the real pre-encumbrance coin is mature and leases...
        let leased = ledger
            .lease_pre_encumbrance(unit, &FixedClock(u64::MAX))
            .unwrap()
            .expect("mature pre-encumbrance coin");
        assert_eq!(leased.class, CoinClass::PreEncumbrance);
        assert_ne!(leased.outpoint, outpoint(9));
        // ...and once it is taken, the unit-amount DEPOSIT still never
        // matches: nothing left to lease.
        assert!(ledger.lease_pre_encumbrance(unit, &FixedClock(u64::MAX)).unwrap().is_none());
    }

    #[test]
    fn ledger_is_sealed_fail_closed_and_single_instance() {
        let dir = tempfile::tempdir().unwrap();
        let marker_amount = 0x00AB_CDEF_1234_5678u64;
        {
            let (mut ledger, keys) = fresh(dir.path());
            let (idx, _) = ledger.next_deposit_address(&keys).unwrap();
            ledger
                .register_deposit(outpoint(1), marker_amount, 100, idx, Some(ack()))
                .unwrap();

            // Single instance while open.
            match Ledger::open(dir.path(), &ModeledEnclave) {
                Err(Error::Abort(_)) => {}
                Err(e) => panic!("wrong error: {e:?}"),
                Ok(_) => panic!("second instance must be refused"),
            }
        }
        // Sealed at rest: the raw file must not contain the amount bytes.
        let raw = std::fs::read(dir.path().join("ledger.bin")).unwrap();
        assert!(
            !raw.windows(8).any(|w| w == marker_amount.to_le_bytes()),
            "coin amounts leaked to disk in plaintext"
        );

        // Tamper => FAIL CLOSED (no silent empty ledger).
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
    fn split_tx_is_persisted_until_confirmed_for_crash_rebroadcast() {
        let dir = tempfile::tempdir().unwrap();
        let params = Params::testnet_provisional();
        let unit = params.tier_d_sats + params.delta_fee_sats;
        let txid;
        let tx_bytes;
        {
            let (mut ledger, keys) = fresh(dir.path());
            let (idx, _) = ledger.next_deposit_address(&keys).unwrap();
            ledger
                .register_deposit(outpoint(1), unit + 1_000, 100, idx, Some(ack()))
                .unwrap();
            let plan = ledger
                .split_deposit(outpoint(1), &params, 1_000, &keys, &FixedClock(0))
                .unwrap();
            txid = plan.txid;
            tx_bytes = plan.tx_bytes;
            // ===== crash before broadcast/confirm =====
        }
        let mut ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
        let dep = ledger.find(&outpoint(1)).unwrap();
        assert_eq!(dep.state, CoinState::SplitPending);
        assert_eq!(
            dep.split_tx.as_deref(),
            Some(tx_bytes.as_slice()),
            "signed split must be rebroadcastable from the ledger alone"
        );
        // Confirm clears the cache and activates the children.
        ledger.confirm_split(txid, 200).unwrap();
        let dep = ledger.find(&outpoint(1)).unwrap();
        assert_eq!(dep.state, CoinState::Spent);
        assert!(dep.split_tx.is_none());
    }

    #[test]
    fn key_indices_are_never_reused_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let i1;
        {
            let (mut ledger, keys) = fresh(dir.path());
            i1 = ledger.next_deposit_address(&keys).unwrap().0;
            // ===== crash =====
        }
        let mut ledger = Ledger::open(dir.path(), &ModeledEnclave).unwrap();
        let keys = ModeledKeySource::new(&ModeledEnclave);
        let i2 = ledger.next_deposit_address(&keys).unwrap().0;
        assert!(i2 > i1, "key index must survive restart (no reuse)");
    }
}
