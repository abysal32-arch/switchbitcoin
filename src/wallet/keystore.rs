//! Software key custody (Task 06): a real seed-backed key store, encrypted at
//! rest, replacing the `ModeledEnclave`/`ModeledKeySource` TEST doubles.
//!
//! ############################################################################
//! # SOFTWARE CUSTODY ONLY — NOT FOR REAL FUNDS.                              #
//! #                                                                          #
//! # This store keeps the wallet seed in ordinary process memory (zeroized on #
//! # drop, but with no enclave isolation) and on disk sealed under a          #
//! # passphrase-derived key. It is the PRE-ALPHA (regtest/testnet) custody    #
//! # tier. Explicitly OUT of scope until post-pre-alpha:                      #
//! #   * hardware-enclave / OS-keystore custody (keys never in app memory);   #
//! #   * an anti-rollback counter for the sealed files;                       #
//! #   * dead-device reserve-key custody — if the primary device (and its     #
//! #     keystore file + passphrase) is lost, only the BIP39 mnemonic backup  #
//! #     recovers funds; there is no second holder of the store.              #
//! ############################################################################
//!
//! Design:
//!   * Seed: BIP39 24-word mnemonic (256-bit CSPRNG entropy) -> 64-byte BIP39
//!     seed (empty BIP39 passphrase — the STORE passphrase below encrypts the
//!     seed at rest and deliberately does NOT alter derivation, so changing it
//!     never changes keys).
//!   * Signing keys: BIP32 hardened path m/3316'/purpose'/index' (3316 = the
//!     v3.16 spec nod; purpose branches FROZEN below). Derivation uses the
//!     pinned `bitcoin` crate's bip32; the child secret crosses into the
//!     settlement `secp` types by BYTE serialization only, per the crate
//!     version-pinning rule. Signing itself routes through the same
//!     `KeySource::sign_key_path` default the modeled source uses, so this
//!     store is structurally a drop-in.
//!   * `platform_key` (the `EnclaveKeyProvider` sealing root for the ledger /
//!     swap store / possession records): HKDF-SHA256 over the seed on a
//!     dedicated branch, independent of the BIP32 signing tree. Deterministic
//!     from the seed, so sealed files reopen across restarts and even across a
//!     mnemonic-only restore on a new device.
//!   * At rest: `keystore.bin` = magic || salt || pbkdf2-iters || sealed-seed,
//!     where the seed is AES-256-GCM sealed (`crypto::storage::seal`) under
//!     KEK = PBKDF2-HMAC-SHA256(passphrase, salt, iters). The plaintext seed
//!     and the mnemonic are NEVER written to disk. A wrong passphrase fails
//!     the GCM tag -> Err (fail closed, no partial plaintext).

use crate::wallet::keys::{KeyPurpose, KeySource};
use crate::wallet::store::EnclaveKeyProvider;
use crate::{Error, Result};
use bitcoin::bip32::{ChildNumber, Xpriv};
use hkdf::Hkdf;
use rand::TryRngCore;
use sha2::Sha256;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

/// Keystore file name inside the wallet data dir.
pub const KEYSTORE_FILE: &str = "keystore.bin";

/// File magic: version-bumps on any format change (no deployed data predates
/// v1, same precedent as the ledger/store version bytes).
const MAGIC: &[u8; 19] = b"newkey-keystore-v1\n";

const SALT_LEN: usize = 16;
const SEED_LEN: usize = 64; // BIP39 seed

/// Production PBKDF2-HMAC-SHA256 work factor (OWASP 2023+ recommendation).
/// Stored in the file header, so older/newer stores always reopen with the
/// iteration count they were created with.
pub const DEFAULT_PBKDF2_ITERS: u32 = 600_000;

// Compile-time floor: refuse a "temporarily lowered" production work factor.
const _: () = assert!(DEFAULT_PBKDF2_ITERS >= 600_000);

/// Hard ceiling on the ACCEPTED iteration count (100x the production default).
/// The header is outside the AES-GCM tag, so a tampered/corrupted `iters`
/// field is only detected AFTER the KDF burn — uncapped, `u32::MAX` turns
/// every `open` into an hours-long hang that presents as "wrong passphrase"
/// (Fable review finding). The cap bounds that to ~100x one legitimate open.
pub const MAX_PBKDF2_ITERS: u32 = 100 * DEFAULT_PBKDF2_ITERS;

/// Exact sealed-payload size for the v1 format: 12-byte GCM nonce + 64-byte
/// seed + 16-byte GCM tag (`crypto::storage::seal` layout). Checked BEFORE the
/// KDF so a truncated/padded file fails instantly instead of paying the full
/// PBKDF2 cost on a blob that can never authenticate.
const SEALED_SEED_LEN: usize = 12 + SEED_LEN + 16;

/// BIP32 root branch: m/3316'/... — a dedicated hardened purpose number so the
/// tree can never collide with standard wallet paths (BIP44/49/84/86).
const PURPOSE_ROOT: u32 = 3316;

/// FROZEN purpose->branch numbering. Renumbering silently re-keys every coin
/// class of every existing wallet — never change these, only append.
fn purpose_branch(purpose: KeyPurpose) -> u32 {
    match purpose {
        KeyPurpose::Deposit => 0,
        KeyPurpose::PreEncumbrance => 1,
        KeyPurpose::OnboardingChange => 2,
        KeyPurpose::Reserve => 3,
        KeyPurpose::SwapDestination => 4,
    }
}

/// Seed-backed software key store implementing BOTH wallet key seams:
/// `EnclaveKeyProvider` (the sealing root) and `KeySource` (signing keys).
///
/// The engine takes the two seams separately (`&dyn EnclaveKeyProvider` +
/// `Box<dyn KeySource>`); `Clone` exists so one opened store serves both:
///
/// ```ignore
/// let ks = SoftwareKeyStore::open(dir, passphrase)?;
/// let (engine, actions) =
///     SwapEngine::open(dir, &ks, Box::new(ks.clone()), &trust_root)?;
/// ```
///
/// No `Debug` impl, deliberately: nothing here may ever hit a log line.
#[derive(Clone)]
pub struct SoftwareKeyStore {
    /// The 64-byte BIP39 seed; scrubbed on drop. NOTE (documented limitation):
    /// the bip32 intermediates derived from it are `bitcoin` crate types
    /// without zeroize support, so in-memory scrubbing is best-effort — real
    /// isolation is the (post-pre-alpha) enclave implementation's job.
    seed: Zeroizing<[u8; SEED_LEN]>,
    platform_key: [u8; 32],
}

impl SoftwareKeyStore {
    /// Create a NEW keystore in `dir`: fresh 256-bit mnemonic, seed sealed to
    /// `dir/keystore.bin` under `passphrase` at the production work factor.
    /// Refuses to overwrite an existing keystore (atomically — `create_new`,
    /// not check-then-write). Returns the store plus the mnemonic words — the
    /// ONE chance to show them for backup; they are never persisted.
    ///
    /// The passphrase is consumed as RAW BYTES (no Unicode normalization):
    /// a frontend feeding user text must apply a stable encoding of its own,
    /// or a platform that switches NFC/NFD forms will present as
    /// wrong-passphrase (recoverable via the mnemonic).
    pub fn create(dir: &Path, passphrase: &str) -> Result<(SoftwareKeyStore, Zeroizing<String>)> {
        Self::create_with_iters(dir, passphrase, DEFAULT_PBKDF2_ITERS)
    }

    /// `create` with an explicit PBKDF2 iteration count. TEST/TUNING ONLY —
    /// production callers use [`SoftwareKeyStore::create`]; a low count makes
    /// the passphrase brute-forceable.
    pub fn create_with_iters(
        dir: &Path,
        passphrase: &str,
        iters: u32,
    ) -> Result<(SoftwareKeyStore, Zeroizing<String>)> {
        if iters == 0 || iters > MAX_PBKDF2_ITERS {
            return Err(Error::Validation("keystore: pbkdf2 iteration count out of range"));
        }
        let path = dir.join(KEYSTORE_FILE);
        std::fs::create_dir_all(dir).map_err(|_| Error::Abort("keystore dir create failed"))?;

        let mut entropy = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(entropy.as_mut())
            .map_err(|_| Error::Abort("OS randomness unavailable; cannot create keystore"))?;
        let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_ref())
            .map_err(|_| Error::Abort("keystore: mnemonic encoding failed"))?;
        // Empty BIP39 passphrase by design (see module docs): the store
        // passphrase seals the file; it must not change derivation.
        let seed = Zeroizing::new(mnemonic.to_seed(""));

        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| Error::Abort("OS randomness unavailable; cannot create keystore"))?;
        let kek = derive_kek(passphrase, &salt, iters);
        let sealed = crate::crypto::storage::seal(&kek, seed.as_ref())?;

        let mut buf = Vec::with_capacity(MAGIC.len() + SALT_LEN + 4 + sealed.len());
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&salt);
        buf.extend_from_slice(&iters.to_le_bytes());
        buf.extend_from_slice(&sealed);

        // ATOMIC claim of the final path: `create_new` is the overwrite guard
        // (an exists()-then-rename dance loses a two-process race — rename
        // REPLACES an existing destination on both Windows and unix, so the
        // loser would silently clobber the winner's live seed; Fable review
        // finding). NEVER overwrite a seed: the old one may still guard funds.
        // A crash mid-write leaves a torn file that fails `open`'s magic/
        // length gates LOUDLY and still refuses re-`create` — no seed existed
        // yet (none was returned), so deleting that file is safe and manual.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Validation("keystore already exists — refusing to overwrite")
                } else {
                    Error::Abort("keystore file create failed")
                }
            })?;
        f.write_all(&buf)
            .and_then(|()| f.sync_all())
            .map_err(|_| Error::Abort("keystore write/sync failed"))?;
        drop(f);
        // Directory-entry durability: on unix, fsync the dir so the new entry
        // survives power loss; NTFS journals metadata (documented).
        #[cfg(unix)]
        {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }

        let words = Zeroizing::new(mnemonic.to_string());
        Ok((Self::from_seed(seed), words))
    }

    /// Open an existing keystore. A wrong passphrase (or any file tampering)
    /// fails the AES-GCM tag and returns Err — never partial plaintext, never
    /// a panic; header tampering (magic, iteration count, length) is rejected
    /// BEFORE any KDF work is spent. Deterministic: the same dir + passphrase
    /// always yields identical keys, signatures, and `platform_key`. The
    /// passphrase is raw bytes — see [`SoftwareKeyStore::create`].
    pub fn open(dir: &Path, passphrase: &str) -> Result<SoftwareKeyStore> {
        let path = dir.join(KEYSTORE_FILE);
        let raw = std::fs::read(&path).map_err(|_| Error::Abort("keystore file unreadable"))?;
        if raw.len() < MAGIC.len() + SALT_LEN + 4 || &raw[..MAGIC.len()] != MAGIC {
            return Err(Error::Validation("keystore: not a keystore file (bad magic/length)"));
        }
        let mut off = MAGIC.len();
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[off..off + SALT_LEN]);
        off += SALT_LEN;
        let iters = u32::from_le_bytes(raw[off..off + 4].try_into().expect("4 bytes"));
        off += 4;
        // BOTH gates run BEFORE any KDF work. The header is outside the GCM
        // tag, so a tampered/corrupted iters field would otherwise buy an
        // hours-long PBKDF2 burn that then presents as "wrong passphrase";
        // and a wrong-length sealed blob can never authenticate, so paying
        // the KDF for it is pure loss (Fable review finding).
        if iters == 0 || iters > MAX_PBKDF2_ITERS {
            return Err(Error::Validation("keystore: iteration count out of range (corrupted header?)"));
        }
        if raw.len() - off != SEALED_SEED_LEN {
            return Err(Error::Validation("keystore: sealed payload has wrong length"));
        }

        let kek = derive_kek(passphrase, &salt, iters);
        let plain = Zeroizing::new(
            crate::crypto::storage::open(&kek, &raw[off..])
                .map_err(|_| Error::Validation("keystore: wrong passphrase or corrupted file"))?,
        );
        if plain.len() != SEED_LEN {
            return Err(Error::Validation("keystore: sealed payload has wrong seed length"));
        }
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        seed.copy_from_slice(&plain);
        Ok(Self::from_seed(seed))
    }

    fn from_seed(seed: Zeroizing<[u8; SEED_LEN]>) -> SoftwareKeyStore {
        // platform_key on its OWN derivation branch (HKDF over the seed, not a
        // BIP32 child): the sealing root is independent of the signing tree.
        let hk = Hkdf::<Sha256>::new(Some(b"newkey-keystore-v1"), seed.as_ref());
        let mut platform_key = [0u8; 32];
        hk.expand(b"platform-key", &mut platform_key)
            .expect("HKDF expand of 32 bytes is always in range");
        SoftwareKeyStore { seed, platform_key }
    }
}

/// KEK = PBKDF2-HMAC-SHA256(passphrase, salt, iters), 32 bytes.
fn derive_kek(passphrase: &str, salt: &[u8; SALT_LEN], iters: u32) -> Zeroizing<[u8; 32]> {
    let mut kek = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iters, kek.as_mut());
    kek
}

impl EnclaveKeyProvider for SoftwareKeyStore {
    fn platform_key(&self) -> [u8; 32] {
        self.platform_key
    }
}

impl KeySource for SoftwareKeyStore {
    fn derive_seckey(&self, purpose: KeyPurpose, index: u32) -> Result<secp::Scalar> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        // Network only flavors xpub/xpriv SERIALIZATION version bytes (which
        // never leave this function) — derivation is network-independent.
        let master = Xpriv::new_master(bitcoin::NetworkKind::Test, self.seed.as_ref())
            .map_err(|_| Error::Abort("keystore: bip32 master derivation failed"))?;
        let path = [
            ChildNumber::from_hardened_idx(PURPOSE_ROOT).expect("const branch in hardened range"),
            ChildNumber::from_hardened_idx(purpose_branch(purpose))
                .expect("const branch in hardened range"),
            ChildNumber::from_hardened_idx(index)
                .map_err(|_| Error::Validation("keystore: key index out of hardened range"))?,
        ];
        let child = master
            .derive_priv(&secp, &path)
            .map_err(|_| Error::Abort("keystore: bip32 child derivation failed"))?;
        // Cross bitcoin(0.32)/secp(0.31-family) crate versions by BYTES only.
        secp::Scalar::from_slice(&child.private_key.secret_bytes())
            .map_err(|_| Error::Abort("keystore: derived key outside scalar group"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keys::ModeledKeySource;
    use crate::wallet::store::ModeledEnclave;

    /// Low work factor so the suite stays fast; production is DEFAULT_PBKDF2_ITERS.
    const TEST_ITERS: u32 = 16;

    fn purposes() -> [KeyPurpose; 5] {
        [
            KeyPurpose::Deposit,
            KeyPurpose::PreEncumbrance,
            KeyPurpose::OnboardingChange,
            KeyPurpose::Reserve,
            KeyPurpose::SwapDestination,
        ]
    }

    #[test]
    fn create_then_reopen_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, _words) =
            SoftwareKeyStore::create_with_iters(dir.path(), "correct horse", TEST_ITERS).unwrap();

        // Snapshot everything observable, drop, reopen twice, compare.
        let mut xonlys = Vec::new();
        for p in purposes() {
            for i in [0u32, 1, 7] {
                xonlys.push(ks.derive_xonly(p, i).unwrap());
            }
        }
        let sig = ks.sign_key_path(KeyPurpose::Deposit, 3, [0x5a; 32]).unwrap();
        let pk = EnclaveKeyProvider::platform_key(&ks);
        drop(ks);

        for _ in 0..2 {
            let re = SoftwareKeyStore::open(dir.path(), "correct horse").unwrap();
            let mut re_xonlys = Vec::new();
            for p in purposes() {
                for i in [0u32, 1, 7] {
                    re_xonlys.push(re.derive_xonly(p, i).unwrap());
                }
            }
            assert_eq!(xonlys, re_xonlys, "reopen must re-derive identical pubkeys");
            assert_eq!(
                sig,
                re.sign_key_path(KeyPurpose::Deposit, 3, [0x5a; 32]).unwrap(),
                "BIP340 key-path signing must be deterministic across reopen"
            );
            assert_eq!(pk, EnclaveKeyProvider::platform_key(&re), "sealing root must be stable");
        }
    }

    #[test]
    fn derivation_is_domain_separated_and_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, _) = SoftwareKeyStore::create_with_iters(dir.path(), "pw", TEST_ITERS).unwrap();

        // Every (purpose, index) pair in a small grid yields a distinct key,
        // and the public half always matches the secret half.
        let mut seen = std::collections::HashSet::new();
        for p in purposes() {
            for i in 0u32..4 {
                let sk = ks.derive_seckey(p, i).unwrap();
                let x = ks.derive_xonly(p, i).unwrap();
                assert_eq!(x, (sk * secp::G).serialize_xonly());
                assert!(seen.insert(x), "duplicate key for {p:?}/{i}");
            }
        }
        // And it is NOT the modeled derivation (a real seed, not the constant).
        let modeled = ModeledKeySource::new(&ModeledEnclave);
        assert_ne!(
            ks.derive_xonly(KeyPurpose::Deposit, 0).unwrap(),
            modeled.derive_xonly(KeyPurpose::Deposit, 0).unwrap()
        );
        // Hardened-range guard: index >= 2^31 is a clean Err, not a panic.
        assert!(ks.derive_seckey(KeyPurpose::Deposit, 1 << 31).is_err());
    }

    #[test]
    fn sign_key_path_verifies_as_bip340_over_the_tweaked_key() {
        use bitcoin::key::TapTweak;
        let dir = tempfile::tempdir().unwrap();
        let (ks, _) = SoftwareKeyStore::create_with_iters(dir.path(), "pw", TEST_ITERS).unwrap();

        let sighash = [0xabu8; 32];
        let sig = ks.sign_key_path(KeyPurpose::Reserve, 2, sighash).unwrap();
        let xonly = ks.derive_xonly(KeyPurpose::Reserve, 2).unwrap();

        // Verify against the TWEAKED output key (key-path spend, empty root),
        // exactly what a Taproot spk commits to.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let internal = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&xonly).unwrap();
        let (tweaked, _parity) = internal.tap_tweak(&secp, None);
        let out_key =
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&tweaked.serialize()).unwrap();
        let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig).unwrap();
        let msg = bitcoin::secp256k1::Message::from_digest(sighash);
        secp.verify_schnorr(&schnorr_sig, &msg, &out_key)
            .expect("keystore key-path signature must verify under the tweaked output key");
    }

    #[test]
    fn wrong_passphrase_and_tampering_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _) = SoftwareKeyStore::create_with_iters(dir.path(), "right", TEST_ITERS).unwrap();

        assert!(SoftwareKeyStore::open(dir.path(), "wrong").is_err());
        assert!(SoftwareKeyStore::open(dir.path(), "").is_err());

        let path = dir.path().join(KEYSTORE_FILE);
        let good = std::fs::read(&path).unwrap();

        // Ciphertext bitflip -> GCM auth failure.
        let mut bad = good.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        std::fs::write(&path, &bad).unwrap();
        assert!(SoftwareKeyStore::open(dir.path(), "right").is_err());

        // Corrupted magic -> rejected before any KDF work.
        let mut bad = good.clone();
        bad[0] ^= 0xff;
        std::fs::write(&path, &bad).unwrap();
        assert!(SoftwareKeyStore::open(dir.path(), "right").is_err());

        // Truncation -> rejected.
        std::fs::write(&path, &good[..MAGIC.len() + 3]).unwrap();
        assert!(SoftwareKeyStore::open(dir.path(), "right").is_err());

        // Iters field tampered to u32::MAX -> rejected by the cap BEFORE any
        // KDF work (uncapped this was an hours-long hang, not an error).
        let mut bad = good.clone();
        bad[MAGIC.len() + SALT_LEN..MAGIC.len() + SALT_LEN + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &bad).unwrap();
        let t0 = std::time::Instant::now();
        assert!(SoftwareKeyStore::open(dir.path(), "right").is_err());
        assert!(t0.elapsed().as_secs() < 5, "iters cap must reject without a KDF burn");

        // Sealed payload padded by one byte -> rejected before the KDF too.
        let mut bad = good.clone();
        bad.push(0x00);
        std::fs::write(&path, &bad).unwrap();
        assert!(SoftwareKeyStore::open(dir.path(), "right").is_err());

        // Restore and confirm the original still opens (tests above didn't
        // depend on a stale handle).
        std::fs::write(&path, &good).unwrap();
        assert!(SoftwareKeyStore::open(dir.path(), "right").is_ok());
    }

    #[test]
    fn create_refuses_to_overwrite_and_never_writes_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, words) =
            SoftwareKeyStore::create_with_iters(dir.path(), "pw", TEST_ITERS).unwrap();

        // A second create on the same dir must refuse (a seed may guard funds).
        assert!(SoftwareKeyStore::create_with_iters(dir.path(), "pw", TEST_ITERS).is_err());
        assert!(SoftwareKeyStore::create(dir.path(), "pw").is_err());

        // The guard is `create_new` (atomic), not check-then-write: ANY
        // pre-existing file at the path — even a foreign/torn one — refuses.
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join(KEYSTORE_FILE), b"torn or foreign").unwrap();
        assert!(SoftwareKeyStore::create_with_iters(dir2.path(), "pw", TEST_ITERS).is_err());

        // The file contains neither the seed nor the platform key nor any
        // mnemonic word bytes in the clear.
        let raw = std::fs::read(dir.path().join(KEYSTORE_FILE)).unwrap();
        let mnemonic = bip39::Mnemonic::parse_normalized(&words).unwrap();
        let seed = mnemonic.to_seed("");
        assert!(
            !raw.windows(8).any(|w| seed.windows(8).any(|s| s == w)),
            "plaintext seed material found in keystore file"
        );
        let pk = EnclaveKeyProvider::platform_key(&ks);
        assert!(!raw.windows(8).any(|w| pk.windows(8).any(|s| s == w)));
        let first_word = words.split(' ').next().unwrap().as_bytes();
        assert!(!raw.windows(first_word.len()).any(|w| w == first_word));
    }

    #[test]
    fn returned_mnemonic_actually_restores_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let (ks, words) =
            SoftwareKeyStore::create_with_iters(dir.path(), "pw", TEST_ITERS).unwrap();

        // The backup words alone (BIP39, empty passphrase) rebuild the same
        // seed -> same platform key + same signing keys. This is the
        // dead-device recovery path documented in the module header.
        let mnemonic = bip39::Mnemonic::parse_normalized(&words).unwrap();
        let restored =
            SoftwareKeyStore::from_seed(Zeroizing::new(mnemonic.to_seed("")));
        assert_eq!(
            EnclaveKeyProvider::platform_key(&ks),
            EnclaveKeyProvider::platform_key(&restored)
        );
        assert_eq!(
            ks.derive_xonly(KeyPurpose::Deposit, 0).unwrap(),
            restored.derive_xonly(KeyPurpose::Deposit, 0).unwrap()
        );
    }

    #[test]
    fn out_of_range_iterations_are_rejected_at_create() {
        // (The production floor itself is a compile-time assert in the module.)
        let dir = tempfile::tempdir().unwrap();
        assert!(SoftwareKeyStore::create_with_iters(dir.path(), "pw", 0).is_err());
        assert!(
            SoftwareKeyStore::create_with_iters(dir.path(), "pw", MAX_PBKDF2_ITERS + 1).is_err()
        );
        // Neither refusal may leave a file behind.
        assert!(!dir.path().join(KEYSTORE_FILE).exists());
    }
}
