//! Wallet open + startup wiring (Task 07): ONE call from a validated
//! [`WalletConfig`] + passphrase to a running wallet handle, composing the
//! seams the tests otherwise wire ad hoc — [`SoftwareKeyStore`] (custody) →
//! [`SwapEngine::open`] (stores, chain-blind) → [`SwapApp::startup`] (chain
//! reconcile + crash-recovery scan). The Task-08 runner drives the returned
//! [`Wallet`].
//!
//! # Data-dir layout (ONE wallet per directory)
//!
//! Everything durable lives flat under [`WalletConfig::data_dir`]; every
//! sealed file is AES-256-GCM under a TEK derived from the keystore's
//! `platform_key`, so the whole dir restores onto a new device from
//! `keystore.bin` + passphrase (or the mnemonic):
//!
//! ```text
//! <data_dir>/
//!   keystore.bin        sealed BIP39 seed (the root secret; atomic create,
//!                       NEVER overwritten — wallet::keystore)
//!   ledger.bin          sealed coin ledger; `ledger.bin.tmp` transient
//!                       during atomic rewrite          lock: .ledger.lock
//!   manifest.current    accepted signed-params manifest
//!   manifest.floor      strictly-monotonic version floor
//!                       (both appear on the FIRST signed-manifest ingest;
//!                       until then the store serves the compiled baseline)
//!                                                      lock: .manifest.lock
//!   <sid>.swap          one sealed record per swap (sid = 64-hex session
//!                       id); `.swap.tmp` transient; `.swap.quarantineN` =
//!                       failed authentication, renamed aside — an ALARM,
//!                       surfaced via [`Wallet::open_actions`]
//!   <sid>.possession    SL possession records (G1 artifacts), written by
//!                       the settlement spine via
//!                       `ExchangeInputs.possession_store` — by convention
//!                       this same dir
//!   hygiene.bin         abort-hygiene cooldown tracker  lock: .hygiene.lock
//!   .store.lock         swap-store single-instance lock
//!   leases/<sid>        single-signer nonce-lease tombstones (INV-3, one
//!                       per live signing session; a crash leaves the file,
//!                       so that swap can only abort-refund — conservative)
//! ```
//!
//! `swapkey.toml` is NOT required to live here — the config file is wherever
//! the runner is pointed, and it *contains* `data_dir`.
//!
//! [`crate::wallet::backup`] snapshots this whole durable set (locks and
//! `.tmp` transients excluded) into ONE portable, integrity-hashed bundle and
//! restores it atomically into a fresh dir — see that module for the
//! backup-vs-running-wallet and encryption-posture decisions.
//!
//! # Single-instance locking
//!
//! Each store holds its own advisory OS file lock for the wallet's lifetime
//! (`.store.lock`, `.ledger.lock`, `.manifest.lock`); `SwapEngine::open`
//! acquires the swap store's first, so a second concurrent [`Wallet::open`]
//! on the same dir fails there with a clean "another process holds this swap
//! store". The OS releases the locks on process death — a crash never wedges
//! the wallet shut.
//!
//! # First-run flow (and its crash window)
//!
//! A fresh dir routes to [`OpenedWallet::FirstRun`]: the keystore is created
//! and the 24-word mnemonic is returned ONCE. [`FirstRun::complete`] demands
//! two proofs-of-display before any store exists — the mnemonic echoed back
//! (backup ack) and the Phase-0 warning copy echoed back
//! ([`acknowledge_phase0`]) — then creates the ledger and opens the engine.
//! A failed echo is [`FirstRunError::Refused`]: the SAME `FirstRun` comes
//! back, the mnemonic still displayable — a typo never burns the one-shot
//! words or waives the backup ack. A crash between keystore create and
//! `complete` leaves a valid keystore with no ledger: the next open resumes
//! as `FirstRun` with [`FirstRun::mnemonic`] `= None` (the words are
//! UNRECOVERABLE from the seed — if they were never backed up, start a
//! fresh data dir). A crash mid-keystore-create leaves a torn
//! `keystore.bin`: open refuses with explicit delete-to-recreate advice
//! instead of looping on a passphrase prompt.
//!
//! # Established-wallet guards (never re-onboard over wallet state)
//!
//! First-run routing is decided from the WHOLE dir, not one file. Artifacts
//! that only exist once the engine has run (`.store.lock`,
//! `.manifest.lock`, manifest files, `hygiene.bin`, any `<sid>.swap` /
//! `<sid>.possession` — quarantined ones included) prove onboarding
//! completed once, so with any of them present:
//! * missing `ledger.bin` is a fail-closed "restore ledger.bin from backup"
//!   (re-onboarding would silently reset the coin memory and rewind the key
//!   index into on-chain address reuse);
//! * missing `keystore.bin` refuses to mint a fresh seed (the old records
//!   would quarantine under the new `platform_key` and their pre-armed
//!   refunds would stop being driven) — restore the file, or
//!   [`SoftwareKeyStore::restore`] from the mnemonic;
//! * a format-invalid `keystore.bin` is reported as DAMAGE ("do NOT delete
//!   it"), never as an interrupted create.
//!
//! # Passphrase policy (binary-owned, per the Task-06 review)
//!
//! The keystore consumes raw bytes and deliberately enforces nothing. THIS
//! seam owns policy: empty passphrases are refused here; Unicode
//! normalization (NFC) of user-TYPED passphrases is the input boundary's job
//! (the Task-08 runner), so pass the normalized form in.

use crate::chain::AuthoritativeChainView;
use crate::settlement::params::Params;
use crate::wallet::app::SwapApp;
use crate::wallet::config::WalletConfig;
use crate::wallet::engine::{ChainReconcile, SwapEngine};
use crate::wallet::keystore::{probe_keystore_file, KeystoreFileState, SoftwareKeyStore};
use crate::wallet::ledger::{acknowledge_phase0, Ledger, LEDGER_FILE, PHASE0_WARNING};
use crate::wallet::manifest::ModeledTrustRoot;
use crate::wallet::recovery_driver::RecoveryScan;
use crate::wallet::store::RecoveryAction;
use crate::{Error, Result};
use zeroize::Zeroizing;

/// What [`Wallet::open`] found in the data dir.
pub enum OpenedWallet {
    /// An existing wallet: keystore opened, engine running.
    Ready(Box<Wallet>),
    /// First run (or an interrupted one): the keystore exists but onboarding
    /// is incomplete. Show the mnemonic + Phase-0 warning, then
    /// [`FirstRun::complete`].
    FirstRun(Box<FirstRun>),
}

/// Variant-name-only `Debug` (test/diagnostic ergonomics): both variants
/// hold the keystore, which deliberately has no `Debug` — nothing inside may
/// ever reach a log line.
impl std::fmt::Debug for OpenedWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OpenedWallet::Ready(_) => "OpenedWallet::Ready(..)",
            OpenedWallet::FirstRun(_) => "OpenedWallet::FirstRun(..)",
        })
    }
}

/// A running wallet: the engine plus the custody handle the runner needs for
/// seams the engine does not own (possession-store `platform_key`, the
/// abort-hygiene ledger).
pub struct Wallet {
    engine: SwapEngine,
    keystore: SoftwareKeyStore,
    config: WalletConfig,
    open_actions: Vec<RecoveryAction>,
}

/// First-run onboarding gate: holds the created keystore (and, on a truly
/// fresh run, the one-shot mnemonic) until both acknowledgements are given.
pub struct FirstRun {
    keystore: SoftwareKeyStore,
    config: WalletConfig,
    mnemonic: Option<Zeroizing<String>>,
}

impl Wallet {
    /// Open (or begin creating) the wallet under `config.data_dir`.
    ///
    /// Routing (see the module docs' established-wallet guards):
    /// * no `keystore.bin`, no wallet data at all → create the keystore,
    ///   return [`OpenedWallet::FirstRun`] carrying the one-shot mnemonic;
    /// * no `keystore.bin` but wallet data exists (ledger, ledger lock/tmp,
    ///   or any engine artifact) → `Err` — never mint a new seed over
    ///   existing state, whose sealed files would be unreadable under it;
    ///   restore the file or [`SoftwareKeyStore::restore`] from the mnemonic;
    /// * format-invalid `keystore.bin` + wallet data → `Err` reporting
    ///   DAMAGE (restore from backup, do NOT delete); with no wallet data →
    ///   an interrupted create, `Err` with delete-to-recreate advice — in
    ///   neither case re-prompt the passphrase;
    /// * valid keystore, no ledger, no engine artifacts (interrupted first
    ///   run) → [`OpenedWallet::FirstRun`] with no mnemonic (resume);
    /// * valid keystore, no ledger, but engine artifacts → `Err` (an
    ///   established wallet lost `ledger.bin`; restore it from backup);
    /// * valid keystore + ledger → open everything, [`OpenedWallet::Ready`].
    ///
    /// A wrong passphrase is a clean `Err` with no state change — safe to
    /// re-prompt in a loop. Uses the prototype [`ModeledTrustRoot`] as the
    /// manifest trust root; a real build pins the real operator key here.
    pub fn open(config: WalletConfig, passphrase: &str) -> Result<OpenedWallet> {
        config
            .validate()
            .map_err(|_| Error::Validation("wallet config failed validation"))?;
        // Binary-owned passphrase policy (see the module docs): the keystore
        // itself deliberately accepts anything, including empty.
        if passphrase.is_empty() {
            return Err(Error::Validation("empty wallet passphrase refused"));
        }
        let dir = config.data_dir.clone();
        match probe_keystore_file(&dir) {
            KeystoreFileState::Torn => {
                if dir.join(LEDGER_FILE).exists() || engine_artifacts_exist(&dir) {
                    // An ESTABLISHED wallet's keystore failed the format
                    // gates: external damage (the file is written once and
                    // never rewritten) — a mnemonic WAS issued and the seed
                    // guards this wallet's coins. Never advise deletion: a
                    // header-damaged file may still hold the intact sealed
                    // seed.
                    Err(Error::Validation(
                        "keystore.bin is damaged but wallet data exists — do NOT delete it; restore keystore.bin from backup, or SoftwareKeyStore::restore from the mnemonic into a fresh data dir",
                    ))
                } else {
                    Err(Error::Validation(
                        "torn keystore from an interrupted create — delete keystore.bin in the data dir to re-create (no mnemonic was ever issued for it)",
                    ))
                }
            }
            KeystoreFileState::Absent => {
                // The ledger lock/tmp join the guard here (unlike below):
                // they can only predate a MISSING keystore if one existed and
                // was removed — Ledger::create demands an open keystore.
                if dir.join(LEDGER_FILE).exists()
                    || dir.join(".ledger.lock").exists()
                    || dir.join("ledger.bin.tmp").exists()
                    || engine_artifacts_exist(&dir)
                {
                    return Err(Error::Validation(
                        "keystore missing but wallet data exists — restore keystore.bin from backup, or SoftwareKeyStore::restore from the mnemonic; a fresh seed cannot read the existing sealed stores",
                    ));
                }
                let (keystore, mnemonic) = SoftwareKeyStore::create(&dir, passphrase)?;
                Ok(OpenedWallet::FirstRun(Box::new(FirstRun {
                    keystore,
                    config,
                    mnemonic: Some(mnemonic),
                })))
            }
            KeystoreFileState::Plausible => {
                let keystore = SoftwareKeyStore::open(&dir, passphrase)?;
                if !dir.join(LEDGER_FILE).exists() {
                    if engine_artifacts_exist(&dir) {
                        // The engine ran before, so a ledger EXISTED:
                        // re-onboarding would silently reset the coin memory
                        // and rewind key issuance into address reuse — the
                        // exact fail-closed case Ledger::open exists for.
                        return Err(Error::Validation(
                            "ledger.bin missing but wallet data exists — an established wallet must not re-onboard; restore ledger.bin from backup",
                        ));
                    }
                    // Keystore created but first-run never completed (crash
                    // before Ledger::create). Resume onboarding; the mnemonic
                    // cannot be re-derived from the seed, so it is None.
                    return Ok(OpenedWallet::FirstRun(Box::new(FirstRun {
                        keystore,
                        config,
                        mnemonic: None,
                    })));
                }
                Ok(OpenedWallet::Ready(Box::new(Self::open_engine(keystore, config)?)))
            }
        }
    }

    /// STEP 1 of the canonical sequence, composed: the ONE keystore serves
    /// both engine key seams (enclave sealing root + signing source).
    fn open_engine(keystore: SoftwareKeyStore, config: WalletConfig) -> Result<Wallet> {
        let (engine, open_actions) = SwapEngine::open(
            &config.data_dir,
            &keystore,
            Box::new(keystore.clone()),
            &ModeledTrustRoot,
        )?;
        Ok(Wallet { engine, keystore, config, open_actions })
    }

    /// Steps 2+3 of the canonical startup sequence over an open wallet:
    /// delegates to [`SwapApp::startup`]. Per the Task-E contract the
    /// reconcile outcome comes back ALONGSIDE the scan (an inner `Result`),
    /// never ahead of it — a reconcile persist failure must not suppress the
    /// recovery ticks. CALLER CONTRACT (the runner): drive every
    /// [`RecoveryScan::ticks`] entry, surface `unreadable`/`failed` and a
    /// reconcile `Err` as operator alarms, and gate lease/bump actions on the
    /// reconcile being `Ok`.
    ///
    /// The chain comes from the caller (build it once from
    /// [`crate::wallet::config::NodeRpcConfig::chain_view`] under feature
    /// `bitcoind`, or any [`AuthoritativeChainView`] in tests) — a wallet
    /// with no node configured simply never calls this.
    pub fn startup(
        &mut self,
        chain: &impl AuthoritativeChainView,
    ) -> Result<(Result<ChainReconcile>, RecoveryScan)> {
        SwapApp::startup(&mut self.engine, chain)
    }

    pub fn engine(&self) -> &SwapEngine {
        &self.engine
    }
    pub fn engine_mut(&mut self) -> &mut SwapEngine {
        &mut self.engine
    }
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }
    /// The custody handle (both key seams). The runner needs it for
    /// possession-store wiring (`platform_key`) and the abort-hygiene ledger.
    pub fn keystore(&self) -> &SoftwareKeyStore {
        &self.keystore
    }
    /// Recovery actions surfaced by the store scan at open (INV-2 aborts,
    /// post-release restorations, quarantines). Quarantine/unreadable entries
    /// must reach the user as ALARMS, not log lines.
    pub fn open_actions(&self) -> &[RecoveryAction] {
        &self.open_actions
    }
    /// The AUTHORITATIVE params: the manifest store's current signed set —
    /// not [`WalletConfig::params`], which is only the compiled baseline the
    /// manifest falls back to.
    pub fn params(&self) -> &Params {
        self.engine.manifest().current().params()
    }
}

/// How [`FirstRun::complete`] failed — split so a refused acknowledgement
/// can be RETRIED with the mnemonic still displayable (one echo typo must
/// not burn the one-shot words and silently waive the backup ack; Fable
/// review finding).
pub enum FirstRunError {
    /// Refused before anything durable was created: a mismatched echo, or
    /// the ledger create itself failed cleanly (atomic — no partial ledger).
    /// The SAME `FirstRun` comes back; re-prompt and retry `complete`.
    Refused { first_run: Box<FirstRun>, error: Error },
    /// Failed PAST the point of no return: the ledger now exists but the
    /// engine open failed (lock contention, store I/O). The next
    /// [`Wallet::open`] routes `Ready` — do not expect `FirstRun` again.
    Fatal(Error),
}

impl FirstRunError {
    /// Collapse to the underlying error (dropping a `Refused`'s retry
    /// handle) for callers that only propagate.
    pub fn into_error(self) -> Error {
        match self {
            FirstRunError::Refused { error, .. } => error,
            FirstRunError::Fatal(error) => error,
        }
    }
}

/// Variant + error only: the retained `FirstRun` holds the keystore and the
/// mnemonic, which must never reach a log line.
impl std::fmt::Debug for FirstRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirstRunError::Refused { error, .. } => write!(f, "Refused({error:?})"),
            FirstRunError::Fatal(error) => write!(f, "Fatal({error:?})"),
        }
    }
}

impl FirstRun {
    /// The freshly minted 24-word mnemonic — the ONE chance to show it for
    /// backup; it is never persisted. `None` when resuming an interrupted
    /// first run (the words were returned by the interrupted attempt and
    /// cannot be re-derived).
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref().map(|s| s.as_str())
    }

    /// The Phase-0 warning copy the UI must display verbatim.
    pub fn phase0_warning(&self) -> &'static str {
        PHASE0_WARNING
    }

    /// Complete onboarding: prove both displays happened, then create the
    /// ledger and open the engine.
    ///
    /// * `phase0_echo` — the exact [`PHASE0_WARNING`] copy, passed back by
    ///   the UI's confirm action ([`acknowledge_phase0`]).
    /// * `mnemonic_backup_echo` — the displayed mnemonic passed back by the
    ///   UI's "I have backed it up" action. REQUIRED (and must match) when
    ///   [`FirstRun::mnemonic`] is `Some`; ignored on the resumed path.
    ///
    /// Failure routing is [`FirstRunError`]: `Refused` returns this
    /// `FirstRun` for a retry (nothing durable was created); `Fatal` means
    /// the ledger exists and re-open routes `Ready`.
    pub fn complete(
        self,
        phase0_echo: &str,
        mnemonic_backup_echo: Option<&str>,
    ) -> core::result::Result<Wallet, FirstRunError> {
        if let Some(words) = &self.mnemonic {
            match mnemonic_backup_echo {
                Some(echo) if echo == words.as_str() => {}
                _ => {
                    return Err(FirstRunError::Refused {
                        first_run: Box::new(self),
                        error: Error::Validation(
                            "mnemonic backup must be confirmed by echoing the displayed words",
                        ),
                    })
                }
            }
        }
        let ack = match acknowledge_phase0(phase0_echo) {
            Ok(ack) => ack,
            Err(error) => {
                return Err(FirstRunError::Refused { first_run: Box::new(self), error })
            }
        };
        // Create-then-drop: the returned Ledger HOLDS .ledger.lock, and
        // SwapEngine::open immediately reopens it. A create failure is
        // Refused (persist is tmp+rename-atomic: no ledger came to exist).
        match Ledger::create(&self.config.data_dir, &self.keystore, ack) {
            Ok(ledger) => drop(ledger),
            Err(error) => {
                return Err(FirstRunError::Refused { first_run: Box::new(self), error })
            }
        }
        Wallet::open_engine(self.keystore, self.config).map_err(FirstRunError::Fatal)
    }
}

/// TRUE iff `dir` holds artifacts that only exist once the ENGINE has run —
/// which requires onboarding to have completed (`Ledger::create` precedes
/// every `SwapEngine::open`): the swap-store/manifest locks, manifest files,
/// the hygiene tracker, or any swap/possession record (quarantined ones
/// included). The ledger lock and ledger tmp are deliberately EXCLUDED:
/// `Ledger::create` touches those BEFORE `ledger.bin` is durable, so they
/// also exist after a genuinely interrupted first run.
fn engine_artifacts_exist(dir: &std::path::Path) -> bool {
    for name in [".store.lock", ".manifest.lock", "manifest.current", "manifest.floor", "hygiene.bin"]
    {
        if dir.join(name).exists() {
            return true;
        }
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // A nonexistent dir is a fresh install (no artifacts). Any OTHER
        // read failure fails toward refusal — never mint wallet state over a
        // dir that cannot be inspected.
        Err(e) => return e.kind() != std::io::ErrorKind::NotFound,
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        name.ends_with(".swap")
            || name.ends_with(".possession")
            || name.contains(".swap.quarantine")
    })
}
