use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::ApiError;

/// Simple symmetric encryption helper used to protect secrets at rest.
pub struct SecretCrypto {
    key: aes_gcm::Key<Aes256Gcm>,
}

impl SecretCrypto {
    /// Derive a 256-bit key from the provided master secret (auth secret by default).
    pub fn new(master_secret: &str) -> Result<Self, ApiError> {
        if master_secret.is_empty() {
            return Err(ApiError::Configuration(
                "Master secret for settings encryption is empty".to_string(),
            ));
        }

        let digest = Sha256::digest(master_secret.as_bytes());
        let mut key = aes_gcm::Key::<Aes256Gcm>::default();
        key.copy_from_slice(&digest);

        Ok(Self { key })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
        let cipher = Aes256Gcm::new(&self.key);

        let nonce = {
            let mut bytes = [0u8; 12];
            OsRng.fill_bytes(&mut bytes);
            Nonce::from(bytes)
        };

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| ApiError::Internal(format!("Failed to encrypt settings: {e}")))?;

        Ok((ciphertext, nonce.to_vec()))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ApiError> {
        if nonce.len() != 12 {
            return Err(ApiError::Internal(
                "Invalid nonce length for encrypted settings".to_string(),
            ));
        }

        let cipher = Aes256Gcm::new(&self.key);
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ApiError::Internal(format!("Failed to decrypt settings: {e}")))?;

        Ok(plaintext)
    }
}
