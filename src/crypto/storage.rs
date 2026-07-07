//! At-rest storage encryption (v3.13 Phase 3 / v3.16 custody).
//!
//! `TEK = HKDF-SHA256(platform_secure_key, swap_session_id, "newkey-txn-enc")`.
//! All persisted swap artifacts (the SL possession record) are AES-256-GCM
//! sealed under the TEK with a UNIQUE 96-bit random nonce per encryption.
//! Confidentiality (not just the integrity the re-verify-on-restore already
//! gave) is now covered.
//!
//! What is NOT here, by invariant: secret signing nonces are NEVER persisted
//! (INV-1), so they are never encrypted either — they simply do not exist on
//! disk. The possession record contains only public pre-signatures, params, T,
//! and the pre-armed refund — no secret keys — but at-rest confidentiality is
//! still the spec's mandate and is implemented here.
//!
//! ENCLAVE MODEL: `platform_secure_key` stands in for the Secure Enclave /
//! Keystore key that, in production, never leaves the device. Here it is a
//! fixed per-process modeled value; a real build injects the enclave key.

use crate::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::TryRngCore;
use sha2::Sha256;

const NONCE_LEN: usize = 12; // AES-GCM 96-bit nonce

/// Modeled platform (enclave/keystore) secret key. In production this lives in
/// the Secure Enclave and never leaves the device; here it is a fixed value so
/// artifacts written before a restart can be decrypted after it. A real build
/// replaces this with the injected enclave key.
pub fn platform_secure_key() -> [u8; 32] {
    // Domain-tagged constant stand-in (NOT a secret in this prototype).
    *b"newkey-modeled-platform-enclave!"
}

/// TEK = HKDF-SHA256(ikm = platform_secure_key, salt = swap_session_id,
/// info = "newkey-txn-enc"). Per-swap key: a different swap_session_id yields an
/// independent TEK.
pub fn derive_tek(platform_secure_key: &[u8; 32], swap_session_id: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(swap_session_id), platform_secure_key);
    let mut tek = [0u8; 32];
    // expand into 32 bytes never fails (well under the HKDF output limit).
    hk.expand(b"newkey-txn-enc", &mut tek)
        .expect("HKDF expand of 32 bytes is always in range");
    tek
}

/// Seal plaintext under the TEK: `[12-byte random nonce] || AES-256-GCM ct`.
/// A fresh nonce is drawn from the OS CSPRNG per call (unique-nonce invariant).
pub fn seal(tek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| Error::Abort("OS randomness unavailable; cannot seal at-rest record"))?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(tek));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Abort("AES-256-GCM seal failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed blob. Any tampering (or a wrong TEK) fails the GCM tag and
/// returns Err — never a silently-wrong plaintext.
pub fn open(tek: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Validation("sealed record too short"));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(tek));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| Error::Validation("sealed record failed authentication (tampered or wrong key)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_under_the_derived_tek() {
        let pk = platform_secure_key();
        let sid = [7u8; 32];
        let tek = derive_tek(&pk, &sid);
        let msg = b"possession record bytes".to_vec();
        let sealed = seal(&tek, &msg).unwrap();
        assert_eq!(open(&tek, &sealed).unwrap(), msg);
    }

    #[test]
    fn per_swap_tek_and_unique_nonce() {
        let pk = platform_secure_key();
        // Different swap_session_id => independent TEK.
        assert_ne!(derive_tek(&pk, &[1u8; 32]), derive_tek(&pk, &[2u8; 32]));
        // Same plaintext sealed twice => different ciphertext (unique nonce).
        let tek = derive_tek(&pk, &[3u8; 32]);
        let a = seal(&tek, b"x").unwrap();
        let b = seal(&tek, b"x").unwrap();
        assert_ne!(a, b, "nonce must be unique per encryption");
    }

    #[test]
    fn tampering_and_wrong_key_are_rejected() {
        let pk = platform_secure_key();
        let tek = derive_tek(&pk, &[9u8; 32]);
        let mut sealed = seal(&tek, b"secret artifact").unwrap();
        // Flip a ciphertext byte -> GCM auth fails.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&tek, &sealed).is_err());
        // Wrong TEK (different swap) -> auth fails.
        let sealed2 = seal(&tek, b"secret artifact").unwrap();
        let wrong = derive_tek(&pk, &[10u8; 32]);
        assert!(open(&wrong, &sealed2).is_err());
    }
}
