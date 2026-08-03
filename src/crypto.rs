use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use zeroize::Zeroize;

/// Sealed values carry a version prefix so the format can evolve, and are
/// bound to a caller-supplied context via AEAD associated data so a ciphertext
/// cannot be swapped into a different column and still decrypt.
const VERSION_PREFIX: &str = "v1.";

pub struct Vault {
    key: [u8; 32],
}

impl Clone for Vault {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Vault {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn seal(&self, context: &str, plaintext: &str) -> Result<String> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0_u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt secret"))?;
        let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(format!(
            "{VERSION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(sealed)
        ))
    }

    pub fn open(&self, context: &str, sealed: &str) -> Result<String> {
        let sealed = sealed
            .strip_prefix(VERSION_PREFIX)
            .context("encrypted secret has an unsupported format version")?;
        let sealed = URL_SAFE_NO_PAD
            .decode(sealed)
            .context("decode encrypted secret")?;
        if sealed.len() < 24 {
            anyhow::bail!("encrypted secret is truncated");
        }
        let (nonce, ciphertext) = sealed.split_at(24);
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("decrypt secret"))?;
        String::from_utf8(plaintext).context("decrypted secret is not UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_values_are_bound_to_their_context() {
        let vault = Vault::new([7_u8; 32]);
        let sealed = vault.seal("cloudflare.client_secret", "hunter2").unwrap();
        assert_eq!(
            vault.open("cloudflare.client_secret", &sealed).unwrap(),
            "hunter2"
        );
        assert!(
            vault.open("cloudflare.access_token", &sealed).is_err(),
            "a ciphertext must not decrypt under a different context"
        );
    }
}
