// SPDX-License-Identifier: GPL-2.0-only
//! Verification of usign (OpenBSD signify) ed25519 signatures, as used
//! by the device agent. See docs/protocol.md section 2.
//!
//! Wire format (base64 blobs, no comment lines):
//! - public key, 42 bytes: pkalg[2]="Ed" + keynum[8] + pubkey[32]
//! - signature, 74 bytes:  pkalg[2]="Ed" + keynum[8] + sig[64]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

const PKALG: &[u8; 2] = b"Ed";
const PUBKEY_LEN: usize = 2 + 8 + 32;
const SIG_LEN: usize = 2 + 8 + 64;

#[derive(Debug, thiserror::Error)]
pub enum UsignError {
    #[error("invalid base64")]
    Base64,
    #[error("invalid blob length")]
    Length,
    #[error("unsupported algorithm")]
    Algorithm,
    #[error("key number mismatch")]
    KeyNum,
    #[error("invalid public key")]
    Key,
    #[error("signature verification failed")]
    Verification,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub keynum: [u8; 8],
    key: VerifyingKey,
}

impl PublicKey {
    pub fn from_base64(blob: &str) -> Result<Self, UsignError> {
        let raw = B64.decode(blob.trim()).map_err(|_| UsignError::Base64)?;

        if raw.len() != PUBKEY_LEN {
            return Err(UsignError::Length);
        }
        if &raw[0..2] != PKALG {
            return Err(UsignError::Algorithm);
        }

        let keynum = raw[2..10].try_into().unwrap();
        let key = VerifyingKey::from_bytes(raw[10..42].try_into().unwrap())
            .map_err(|_| UsignError::Key)?;

        Ok(PublicKey { keynum, key })
    }

    /// Verify a base64 usign signature blob over `msg`.
    pub fn verify(&self, sig_blob: &str, msg: &[u8]) -> Result<(), UsignError> {
        let raw = B64.decode(sig_blob.trim()).map_err(|_| UsignError::Base64)?;

        if raw.len() != SIG_LEN {
            return Err(UsignError::Length);
        }
        if &raw[0..2] != PKALG {
            return Err(UsignError::Algorithm);
        }
        if raw[2..10] != self.keynum {
            return Err(UsignError::KeyNum);
        }

        let sig = Signature::from_bytes(raw[10..74].try_into().unwrap());

        self.key
            .verify_strict(msg, &sig)
            .map_err(|_| UsignError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Build test blobs with a locally generated key; CI additionally
    // checks vectors produced by the real usign binary (see
    // tests/usign_vectors.rs, TODO).
    fn testkey() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let mut blob = Vec::new();
        blob.extend_from_slice(PKALG);
        blob.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        blob.extend_from_slice(sk.verifying_key().as_bytes());
        (sk, B64.encode(blob))
    }

    fn sign(sk: &SigningKey, msg: &[u8]) -> String {
        let sig = sk.sign(msg);
        let mut blob = Vec::new();
        blob.extend_from_slice(PKALG);
        blob.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        blob.extend_from_slice(&sig.to_bytes());
        B64.encode(blob)
    }

    #[test]
    fn roundtrip() {
        let (sk, pub_b64) = testkey();
        let pk = PublicKey::from_base64(&pub_b64).unwrap();
        let sig = sign(&sk, b"hello world");

        assert!(pk.verify(&sig, b"hello world").is_ok());
        assert!(matches!(
            pk.verify(&sig, b"hello worlD"),
            Err(UsignError::Verification)
        ));
    }

    // Vectors produced by the real usign binary (usign -G / -S):
    // message "The quick brown fox" (no trailing newline).
    #[test]
    fn real_usign_vectors() {
        let pub_b64 = "RWRP3pUo2MUv+3ovX1O4ICDzK1hUUSw9+uScuQT1XMmCBdyfibIk3Eo3";
        let sig_b64 = "RWRP3pUo2MUv+y9heOr9xKi3zsA2z9J/REuk2j5FcOOfuHlaLmzulNVNwXEznLkjjEAdiMcmx/c3v4sPXxR+ltxd7etA6vAB0A4=";

        let pk = PublicKey::from_base64(pub_b64).unwrap();
        assert!(pk.verify(sig_b64, b"The quick brown fox").is_ok());
        assert!(matches!(
            pk.verify(sig_b64, b"The quick brown foX"),
            Err(UsignError::Verification)
        ));
    }

    #[test]
    fn keynum_mismatch() {
        let (sk, pub_b64) = testkey();
        let pk = PublicKey::from_base64(&pub_b64).unwrap();

        let sig = sk.sign(b"msg");
        let mut blob = Vec::new();
        blob.extend_from_slice(PKALG);
        blob.extend_from_slice(&[9, 9, 9, 9, 9, 9, 9, 9]);
        blob.extend_from_slice(&sig.to_bytes());

        assert!(matches!(
            pk.verify(&B64.encode(blob), b"msg"),
            Err(UsignError::KeyNum)
        ));
    }
}
