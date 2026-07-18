//! Wallet backup & restore (Task 17): ONE coherent, verified portability
//! operation over the data dir's durable files.
//!
//! # What a bundle is
//!
//! A single portable file: `newkey-backup-v1` magic, a count, then
//! length-prefixed `(name, bytes)` entries sorted by name, closed by a
//! SHA-256 integrity hash over everything preceding it. The members are the
//! data dir's DURABLE set (the `wallet::runtime` layout table): the sealed
//! `keystore.bin` / `ledger.bin` / `<sid>.swap` / `<sid>.possession` /
//! `hygiene.bin`, the signed `manifest.current` / `manifest.floor`, the
//! public `<sid>.artifacts` template sidecars, quarantined swap records
//! (damage evidence rides — a restore must not silently hide an alarm), and
//! the `leases/<sid>` single-signer tombstones (INV-3 burn evidence: a
//! crash-left lease means that swap may only abort-refund, and a restored
//! store must keep saying so). Locks and `.tmp` transients are excluded;
//! `switchbitcoin.toml` is excluded deliberately — it can hold a PLAINTEXT node
//! RPC password and is not wallet state (back it up separately if you care).
//!
//! # Encryption posture (decided, per the Task-17 charter)
//!
//! The bundle container adds NO encryption of its own. Every secret-bearing
//! member is already sealed at rest — the keystore under the passphrase KDF,
//! the ledger/swap/possession records under the seed-derived platform key —
//! so a stolen bundle cannot move funds and cannot expose the seed. The
//! remaining members (`<sid>.artifacts`, the manifest files, the lease
//! tombstones) are PUBLIC-BY-DESIGN (broadcast templates, signed params,
//! session-id file names). Treat a bundle as RESTORE-ONLY material all the
//! same: like the data dir itself, it reveals swap METADATA (session ids,
//! intended txids/amounts) a bit earlier than the chain would. No new secret
//! ever lands in plaintext.
//!
//! # Backup vs a RUNNING wallet
//!
//! A live wallet holds OS file locks (`.store.lock`, `.ledger.lock`,
//! `.manifest.lock`, `.hygiene.lock`) for its whole lifetime, and its stores
//! rewrite files via tmp+rename. Copying files out from under it could
//! capture a torn cross-file state, so [`backup_data_dir`] TRY-LOCKS every
//! lock file that exists and refuses when any is held ("stop the wallet
//! first"). It never CREATES a lock file: minting `.store.lock` in a dir
//! that only ever saw an interrupted first run would flip the
//! established-wallet routing in `wallet::runtime`. With the locks held, the
//! whole read is one consistent snapshot; each member file is additionally
//! internally consistent on its own (every store persists atomically), and a
//! restored snapshot re-enters through the same crash-recovery scan a reboot
//! uses — a backup is, by construction, a recoverable crash image.
//!
//! # Restore discipline
//!
//! [`restore_data_dir`] verifies the ENTIRE bundle in memory first (magic,
//! integrity hash, structure, a strict name allowlist that also blocks path
//! traversal, keystore/ledger completeness, a pre-KDF keystore format
//! probe), then stages every file into a sibling `<data_dir>.restore-tmp`
//! directory and RENAMES it into place — the same atomic-persist discipline
//! the stores use. A hostile, truncated, or corrupt bundle is a clean `Err`
//! with NOTHING created at the destination; a crash mid-restore leaves only
//! the staging dir, which the next attempt clears. The destination must be
//! fresh (absent or empty): restoring over an existing wallet is refused,
//! never merged.
//!
//! # The two restore scenarios (see the runbook)
//!
//! * FULL-BUNDLE restore: everything comes back — key index intact, records
//!   and their pre-armed refunds intact, the artifacts sidecars intact so a
//!   restored SL can rebuild its claim. `recover` then drives any in-flight
//!   swap to its terminal. A STALE bundle rewinds every point-in-time
//!   counter it carries: the key index (raise it with
//!   `Ledger::raise_key_index_floor`, CLI `--rescan <floor>`) and the
//!   manifest version floor (self-healing — the next newer signed manifest
//!   re-raises it; the window is an old-params replay until then).
//! * MNEMONIC-ONLY restore (`init --restore`): recovers the SEED alone. The
//!   coin ledger, swap records, and sidecars are GONE — issuance rewinds to
//!   index 0 (address reuse unless the floor is raised) and any in-flight
//!   swap can no longer be driven from this device. The mnemonic is the
//!   floor of recovery, not the backup story; keep bundles.

use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Bundle file magic. Version-bumps on any format change.
pub const BACKUP_MAGIC: &[u8; 17] = b"newkey-backup-v1\n";

/// Trailing SHA-256 integrity hash length.
const HASH_LEN: usize = 32;

/// Hard structural caps: a hostile bundle must not buy unbounded work. Real
/// member names are ≤ ~80 bytes and real wallets hold tens of files.
const MAX_NAME_LEN: usize = 255;
const MAX_FILES: u32 = 65_536;

/// The wallet's single-instance lock files (see `wallet::runtime`). Held by
/// any live store for its whole lifetime; probed (never created) by backup.
const LOCK_FILES: [&str; 4] = [".store.lock", ".ledger.lock", ".manifest.lock", ".hygiene.lock"];

/// What a backup or restore touched: `(member name, byte length)` per file,
/// in bundle (sorted-name) order.
pub struct BackupSummary {
    pub files: Vec<(String, u64)>,
}

impl BackupSummary {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|(_, n)| n).sum()
    }
}

/// TRUE iff `name` (bundle-relative, `/`-separated) is a member of the data
/// dir's durable set. This is the ONE allowlist both directions share:
/// backup selects by it, restore refuses anything outside it — which also
/// makes path traversal structurally impossible (the only separator a name
/// may contain is the literal `leases/` prefix before a 64-hex sid).
fn durable_backup_name(name: &str) -> bool {
    match name {
        "keystore.bin" | "ledger.bin" | "manifest.current" | "manifest.floor" | "hygiene.bin" => {
            return true
        }
        _ => {}
    }
    if let Some(rest) = name.strip_prefix("leases/") {
        return is_hex64(rest);
    }
    if let Some(stem) = name.strip_suffix(".swap") {
        return is_hex64(stem);
    }
    if let Some(stem) = name.strip_suffix(".possession") {
        return is_hex64(stem);
    }
    if let Some(stem) = name.strip_suffix(".artifacts") {
        return is_hex64(stem);
    }
    // Quarantined records (`<sid>.swap.quarantineN`): damage evidence rides.
    if let Some(at) = name.find(".swap.quarantine") {
        let (stem, tail) = name.split_at(at);
        let digits = &tail[".swap.quarantine".len()..];
        return is_hex64(stem) && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

/// Lowercase 64-hex (the `hex32` rendering every sid-named file uses).
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The on-disk path of a bundle member under `dir`. `name` has already
/// passed [`durable_backup_name`], so splitting on `/` is safe by
/// construction (at most the one `leases` component).
fn member_path(dir: &Path, name: &str) -> PathBuf {
    let mut path = dir.to_path_buf();
    for comp in name.split('/') {
        path.push(comp);
    }
    path
}

/// Try-lock every wallet lock file that EXISTS in `dir`, returning the held
/// handles (locks release on drop). A held lock means a wallet is running —
/// refuse, per the module docs. Lock files are never created here.
fn hold_wallet_locks(dir: &Path) -> Result<Vec<std::fs::File>> {
    let mut held = Vec::new();
    for name in LOCK_FILES {
        let file = match std::fs::OpenOptions::new().write(true).open(dir.join(name)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error::Abort("backup: could not open a wallet lock file")),
        };
        if file.try_lock().is_err() {
            return Err(Error::Validation(
                "backup: the wallet is running (a store lock is held) — stop it, then back up",
            ));
        }
        held.push(file);
    }
    Ok(held)
}

/// Enumerate the durable member names under `data_dir` (sorted). STRICT: an
/// entry that cannot be inspected is an error, never silently skipped — a
/// backup that quietly drops a swap record is worse than no backup.
fn durable_files(data_dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let entries =
        std::fs::read_dir(data_dir).map_err(|_| Error::Abort("backup: data dir unreadable"))?;
    for entry in entries {
        let entry = entry.map_err(|_| Error::Abort("backup: a data-dir entry was unreadable"))?;
        let ft = entry
            .file_type()
            .map_err(|_| Error::Abort("backup: a data-dir entry could not be inspected"))?;
        if !ft.is_file() {
            continue; // the `leases` dir is walked below; other dirs are foreign
        }
        // Non-UTF8 names cannot be wallet files (every store writes ASCII).
        let Ok(name) = entry.file_name().into_string() else { continue };
        if durable_backup_name(&name) {
            names.push(name);
        }
    }
    match std::fs::read_dir(data_dir.join("leases")) {
        Ok(entries) => {
            for entry in entries {
                let entry =
                    entry.map_err(|_| Error::Abort("backup: a lease entry was unreadable"))?;
                let Ok(name) = entry.file_name().into_string() else { continue };
                let name = format!("leases/{name}");
                if durable_backup_name(&name) {
                    names.push(name);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Abort("backup: leases dir unreadable")),
    }
    names.sort();
    Ok(names)
}

/// Write a backup bundle of `data_dir`'s durable files to `dest`.
///
/// Refuses while a wallet is running (see the module docs), refuses a dir
/// with no complete wallet (`keystore.bin` + `ledger.bin` are the minimum
/// restorable set — for a first run that never finished, the mnemonic is the
/// backup), and never overwrites an existing `dest`. A crash mid-write can
/// leave a torn file at `dest`; restore's integrity hash rejects it LOUDLY,
/// so a bundle that restores is a bundle that was written whole.
pub fn backup_data_dir(data_dir: &Path, dest: &Path) -> Result<BackupSummary> {
    if !data_dir.is_dir() {
        return Err(Error::Validation("backup: data dir does not exist"));
    }
    // A bundle written INTO the data dir would pollute the wallet's home
    // (and invite backing up backups). Canonicalize-compare where possible.
    if let (Ok(dd), Some(Ok(dp))) =
        (data_dir.canonicalize(), dest.parent().map(|p| p.canonicalize()))
    {
        if dd == dp {
            return Err(Error::Validation(
                "backup: destination must live OUTSIDE the data dir",
            ));
        }
    }
    let _locks = hold_wallet_locks(data_dir)?;

    let names = durable_files(data_dir)?;
    if !names.iter().any(|n| n == "keystore.bin") || !names.iter().any(|n| n == "ledger.bin") {
        return Err(Error::Validation(
            "backup: no complete wallet here (keystore.bin + ledger.bin required); an unfinished first run is covered by its mnemonic, not a bundle",
        ));
    }
    if names.len() as u64 > MAX_FILES as u64 {
        return Err(Error::Validation("backup: too many durable files for one bundle"));
    }

    let mut body = Vec::new();
    body.extend_from_slice(BACKUP_MAGIC);
    body.extend_from_slice(&(names.len() as u32).to_le_bytes());
    let mut summary = Vec::with_capacity(names.len());
    for name in &names {
        let data = std::fs::read(member_path(data_dir, name))
            .map_err(|_| Error::Abort("backup: a wallet file could not be read"))?;
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&(data.len() as u64).to_le_bytes());
        body.extend_from_slice(&data);
        summary.push((name.clone(), data.len() as u64));
    }
    let digest = Sha256::digest(&body);
    body.extend_from_slice(&digest);

    // ATOMIC claim of the destination (`create_new`, the keystore precedent):
    // an existing file is refused, never replaced — it may be the only good
    // backup the user has.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Validation("backup: destination file already exists — refusing to overwrite")
            } else {
                Error::Abort("backup: destination file could not be created")
            }
        })?;
    if let Err(_e) = file.write_all(&body).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(dest); // a half-written bundle must not look like a backup
        return Err(Error::Abort("backup: bundle write/sync failed"));
    }
    Ok(BackupSummary { files: summary })
}

/// Parse + fully verify a bundle: magic, trailing integrity hash, structure
/// (bounds-checked, capped), the name allowlist (no duplicates, no traversal
/// — [`durable_backup_name`] is the gate), and keystore/ledger completeness.
/// Returns `(name, payload)` slices into `bytes`; nothing is allocated per
/// payload and NOTHING has touched the filesystem yet.
fn parse_bundle(bytes: &[u8]) -> Result<Vec<(String, &[u8])>> {
    let header = BACKUP_MAGIC.len() + 4;
    if bytes.len() < header + HASH_LEN || &bytes[..BACKUP_MAGIC.len()] != BACKUP_MAGIC {
        return Err(Error::Validation(
            "restore: not a switchbitcoin backup bundle (bad magic/length)",
        ));
    }
    let body_end = bytes.len() - HASH_LEN;
    let digest = Sha256::digest(&bytes[..body_end]);
    if digest.as_slice() != &bytes[body_end..] {
        return Err(Error::Validation(
            "restore: bundle failed its integrity hash (corrupt or truncated)",
        ));
    }
    let count = u32::from_le_bytes(bytes[BACKUP_MAGIC.len()..header].try_into().expect("4 bytes"));
    if count == 0 || count > MAX_FILES {
        return Err(Error::Validation("restore: bundle file count out of range"));
    }
    let mut at = header;
    let mut files: Vec<(String, &[u8])> = Vec::with_capacity(count as usize);
    // Set-based duplicate detection: a linear scan per entry would hand a
    // hostile max-count bundle O(n²) work before the refusal.
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for _ in 0..count {
        if body_end - at < 2 {
            return Err(Error::Validation("restore: bundle structure malformed"));
        }
        let name_len =
            u16::from_le_bytes(bytes[at..at + 2].try_into().expect("2 bytes")) as usize;
        at += 2;
        if name_len == 0 || name_len > MAX_NAME_LEN || body_end - at < name_len {
            return Err(Error::Validation("restore: bundle structure malformed"));
        }
        let name = std::str::from_utf8(&bytes[at..at + name_len])
            .map_err(|_| Error::Validation("restore: bundle structure malformed"))?;
        at += name_len;
        if !durable_backup_name(name) {
            return Err(Error::Validation(
                "restore: bundle names a file outside the wallet's durable set",
            ));
        }
        if !seen.insert(name.to_string()) {
            return Err(Error::Validation("restore: bundle lists a file twice"));
        }
        if body_end - at < 8 {
            return Err(Error::Validation("restore: bundle structure malformed"));
        }
        let data_len = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        at += 8;
        if data_len > (body_end - at) as u64 {
            return Err(Error::Validation("restore: bundle structure malformed"));
        }
        let data_len = data_len as usize;
        files.push((name.to_string(), &bytes[at..at + data_len]));
        at += data_len;
    }
    if at != body_end {
        return Err(Error::Validation("restore: bundle structure malformed"));
    }
    if !files.iter().any(|(n, _)| n == "keystore.bin")
        || !files.iter().any(|(n, _)| n == "ledger.bin")
    {
        return Err(Error::Validation(
            "restore: bundle is missing keystore.bin or ledger.bin — not a restorable wallet",
        ));
    }
    Ok(files)
}

/// The staging directory for an atomic restore into `data_dir`: a sibling
/// named `<data_dir>.restore-tmp`. Deterministic so a crashed restore's
/// leftover is recognized (and cleared) by the next attempt.
fn staging_dir(data_dir: &Path) -> Result<PathBuf> {
    let mut name = data_dir
        .file_name()
        .ok_or(Error::Validation("restore: data dir path has no final component"))?
        .to_os_string();
    name.push(".restore-tmp");
    Ok(data_dir.with_file_name(name))
}

/// Restore a bundle written by [`backup_data_dir`] into a FRESH `data_dir`.
///
/// Verify-then-rename atomic (see the module docs): the bundle is fully
/// verified in memory, staged into `<data_dir>.restore-tmp`, and renamed
/// into place. Any failure leaves NO `data_dir` behind. The destination must
/// not exist (or must be empty) — an established wallet is never overwritten
/// or merged into.
///
/// Opening the restored wallet (and raising the key-index floor if the
/// bundle predates the last issued address) is the CALLER's next step — it
/// needs the passphrase, which restore itself deliberately does not.
pub fn restore_data_dir(bundle: &Path, data_dir: &Path) -> Result<BackupSummary> {
    let bytes =
        std::fs::read(bundle).map_err(|_| Error::Abort("restore: bundle file unreadable"))?;
    let files = parse_bundle(&bytes)?;

    match std::fs::read_dir(data_dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(Error::Validation(
                    "restore: target data dir exists and is not empty — restore only into a fresh dir",
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Abort("restore: target data dir unreadable")),
    }

    let tmp = staging_dir(data_dir)?;
    if tmp.exists() {
        // Ours by construction (a crashed earlier restore); incomplete, clear it.
        std::fs::remove_dir_all(&tmp)
            .map_err(|_| Error::Abort("restore: could not clear a stale staging dir"))?;
    }
    std::fs::create_dir_all(&tmp)
        .map_err(|_| Error::Abort("restore: could not create the staging dir"))?;

    let stage = || -> Result<()> {
        for (name, data) in &files {
            let path = member_path(&tmp, name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|_| Error::Abort("restore: could not stage a member dir"))?;
            }
            let mut f = std::fs::File::create(&path)
                .map_err(|_| Error::Abort("restore: could not stage a member file"))?;
            f.write_all(data)
                .and_then(|()| f.sync_all())
                .map_err(|_| Error::Abort("restore: staging write/sync failed"))?;
        }
        // Same pre-KDF gates `Wallet::open` will apply: a bundle whose
        // keystore member is torn should fail HERE, before a dir exists.
        match crate::wallet::keystore::probe_keystore_file(&tmp) {
            crate::wallet::keystore::KeystoreFileState::Plausible => Ok(()),
            _ => Err(Error::Validation(
                "restore: the bundle's keystore.bin is not a valid keystore file",
            )),
        }
    };
    if let Err(e) = stage() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }

    // Commit: clear an empty pre-existing destination, then rename. rename
    // REPLACES a file but not a non-empty dir on either OS; the emptiness
    // gate above plus this remove_dir (which only removes EMPTY dirs) keeps
    // "never overwrite a wallet" structural, not just checked.
    if data_dir.exists() {
        std::fs::remove_dir(data_dir)
            .map_err(|_| Error::Abort("restore: could not replace the empty target dir"))?;
    }
    if std::fs::rename(&tmp, data_dir).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(Error::Abort(
            "restore: could not move the staged wallet into place (did the target dir just appear?)",
        ));
    }
    // Directory-entry durability, same posture as the keystore: fsync the
    // parent on unix; NTFS journals metadata.
    #[cfg(unix)]
    {
        if let Some(parent) = data_dir.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
        }
    }
    Ok(BackupSummary {
        files: files.iter().map(|(n, d)| (n.clone(), d.len() as u64)).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowlist_admits_exactly_the_durable_set() {
        let sid = "ab".repeat(32);
        for good in [
            "keystore.bin".to_string(),
            "ledger.bin".into(),
            "manifest.current".into(),
            "manifest.floor".into(),
            "hygiene.bin".into(),
            format!("{sid}.swap"),
            format!("{sid}.possession"),
            format!("{sid}.artifacts"),
            format!("{sid}.swap.quarantine0"),
            format!("{sid}.swap.quarantine12"),
            format!("leases/{sid}"),
        ] {
            assert!(durable_backup_name(&good), "{good} must be durable");
        }
        for bad in [
            ".store.lock".to_string(),
            ".ledger.lock".into(),
            "ledger.bin.tmp".into(),
            "switchbitcoin.toml".into(),
            "swapkey.toml".into(), // legacy config name — equally non-durable
            format!("{sid}.swap.tmp"),
            format!("{sid}.swap.quarantine"),   // no index
            format!("{sid}.swap.quarantine1x"), // non-digit tail
            format!("{}.swap", "AB".repeat(32)), // uppercase hex is not ours
            format!("{}.swap", "ab".repeat(31)), // short sid
            format!("leases/{sid}x"),
            "leases/../keystore.bin".into(),
            format!("../{sid}.swap"),
            format!("..\\{sid}.swap"),
            format!("leases\\{sid}"),
            "leases/".into(),
            "".into(),
        ] {
            assert!(!durable_backup_name(&bad), "{bad} must be refused");
        }
    }

    #[test]
    fn parse_bundle_refuses_an_empty_or_oversized_count() {
        // Both with a VALID hash, so only the count gate can be what fires.
        for count in [0u32, MAX_FILES + 1] {
            let mut v = Vec::new();
            v.extend_from_slice(BACKUP_MAGIC);
            v.extend_from_slice(&count.to_le_bytes());
            let d = Sha256::digest(&v);
            v.extend_from_slice(&d);
            assert!(parse_bundle(&v).is_err(), "count {count} must be refused");
        }
    }
}
