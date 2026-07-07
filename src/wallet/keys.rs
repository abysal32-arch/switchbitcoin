//! Wallet key derivation seam (v3.13/v3.14 custody: "Taproot single-sig in
//! the Secure Enclave / Keystore").
//!
//! In production every wallet key lives in (or is derived inside) the
//! platform enclave and NEVER leaves the device. The ledger persists only
//! `(purpose, index)` pairs — never key material — and re-derives on demand,
//! so the coin database contains nothing spendable (INV-1 discipline applied
//! to wallet keys: the disk holds indices, the enclave holds keys).
//!
//! `ModeledKeySource` is the prototype stand-in, deterministic from the
//! modeled platform key via HKDF-SHA256 with `(purpose, index)` domain
//! separation. This is key CUSTODY, not curve math: the scalar itself is
//! used only through the pinned libsecp256k1 stack, and nothing here touches
//! MuSig2/adaptor/nonce territory (Req 1 untouched).
//!
//! FRESHNESS RULE: a `(purpose, index)` pair is never reused — the ledger's
//! single monotonic index counter guarantees it. Fresh key per deposit
//! address, per pre-encumbrance output, per change output, per swap
//! destination (v3.13: fresh, never-reused destinations are what make
//! watchtower delegation and swap outputs unlinkable).

use crate::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;

/// What a derived key is FOR. Domain-separates the derivation so no two
/// purposes can ever collide on the same scalar, and gives the ledger's
/// non-mixing rules a key-level anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Ordinary Taproot receive address for an incoming deposit.
    Deposit,
    /// A pre-encumbrance output (exactly D + Δ_fee), future Setup input.
    PreEncumbrance,
    /// The single onboarding change output.
    OnboardingChange,
    /// Reserve coins for the congestion-only CPFP backstop.
    Reserve,
    /// Fresh per-swap destination (completion output).
    SwapDestination,
}

impl KeyPurpose {
    fn tag(self) -> &'static [u8] {
        match self {
            KeyPurpose::Deposit => b"deposit",
            KeyPurpose::PreEncumbrance => b"pre-encumbrance",
            KeyPurpose::OnboardingChange => b"onboarding-change",
            KeyPurpose::Reserve => b"reserve",
            KeyPurpose::SwapDestination => b"swap-destination",
        }
    }
}

/// The enclave-key-derivation seam. Production: an OS-keystore-backed
/// implementation whose keys never leave the device. Consumers hold only
/// `(purpose, index)`.
pub trait KeySource {
    /// Deterministically derive the secret key for `(purpose, index)`.
    /// The same pair always yields the same key (crash recovery re-derives);
    /// different pairs always yield independent keys.
    fn derive_seckey(&self, purpose: KeyPurpose, index: u32) -> Result<secp::Scalar>;

    /// The x-only public key for `(purpose, index)` (for building spks
    /// without handling the secret outside the signer).
    fn derive_xonly(&self, purpose: KeyPurpose, index: u32) -> Result<[u8; 32]> {
        Ok((self.derive_seckey(purpose, index)? * secp::G).serialize_xonly())
    }
}

/// Prototype key source: HKDF-SHA256 over the MODELED platform key with
/// `(purpose, index, attempt)` in the info string. The attempt counter makes
/// derivation total: the ~2^-128 chance of a candidate falling outside the
/// scalar group advances to the next candidate instead of failing.
pub struct ModeledKeySource {
    platform_key: [u8; 32],
}

impl ModeledKeySource {
    pub fn new(enclave: &dyn crate::wallet::store::EnclaveKeyProvider) -> Self {
        ModeledKeySource { platform_key: enclave.platform_key() }
    }
}

impl KeySource for ModeledKeySource {
    fn derive_seckey(&self, purpose: KeyPurpose, index: u32) -> Result<secp::Scalar> {
        let hk = Hkdf::<Sha256>::new(Some(b"newkey-wallet-keys-v1"), &self.platform_key);
        for attempt in 0u8..=255 {
            let mut info = Vec::with_capacity(32);
            info.extend_from_slice(purpose.tag());
            info.push(0x00); // unambiguous separator (tags are ASCII)
            info.extend_from_slice(&index.to_le_bytes());
            info.push(attempt);
            let mut candidate = [0u8; 32];
            hk.expand(&info, &mut candidate)
                .map_err(|_| Error::Abort("wallet key derivation failed"))?;
            if let Ok(s) = secp::Scalar::from_slice(&candidate) {
                return Ok(s);
            }
        }
        // 256 consecutive out-of-range candidates: probability ~2^-32768.
        Err(Error::Abort("wallet key derivation exhausted attempts"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::store::ModeledEnclave;

    #[test]
    fn derivation_is_deterministic_and_domain_separated() {
        let ks = ModeledKeySource::new(&ModeledEnclave);
        let a1 = ks.derive_seckey(KeyPurpose::Deposit, 0).unwrap();
        let a2 = ks.derive_seckey(KeyPurpose::Deposit, 0).unwrap();
        assert_eq!(a1.serialize(), a2.serialize(), "same pair must re-derive identically");

        // Different index, different purpose: independent keys.
        let b = ks.derive_seckey(KeyPurpose::Deposit, 1).unwrap();
        let c = ks.derive_seckey(KeyPurpose::PreEncumbrance, 0).unwrap();
        assert_ne!(a1.serialize(), b.serialize());
        assert_ne!(a1.serialize(), c.serialize());
        assert_ne!(b.serialize(), c.serialize());

        // Public half matches the secret half.
        let x = ks.derive_xonly(KeyPurpose::Deposit, 0).unwrap();
        assert_eq!(x, (a1 * secp::G).serialize_xonly());
    }
}
