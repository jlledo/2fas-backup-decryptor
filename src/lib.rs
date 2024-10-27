use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::{DecodeError, Engine};
use itertools::Itertools;
use pbkdf2::pbkdf2_hmac_array;
use serde::Deserialize;
use sha2::Sha256;
use std::str::FromStr;

#[derive(Deserialize, Debug)]
pub struct Vault {
    #[serde(rename = "servicesEncrypted")]
    pub services_encrypted: String,
}

const NONCE_LENGTH_BYTES: usize = 12;
pub struct EncryptedServices {
    cipher_text: Vec<u8>,
    salt: Vec<u8>,
    nonce: [u8; NONCE_LENGTH_BYTES],
}

impl EncryptedServices {
    pub fn decrypt(&self, password: &str) -> anyhow::Result<String> {
        const KEY_LENGTH_BYTES: usize = 32;
        const ROUNDS: u32 = 10_000;
        let key =
            pbkdf2_hmac_array::<Sha256, KEY_LENGTH_BYTES>(password.as_bytes(), &self.salt, ROUNDS);
        let cipher = Aes256Gcm::new(&key.into());
        let plaintext = cipher.decrypt(&self.nonce.into(), self.cipher_text.as_ref())?;

        let string = std::str::from_utf8(&plaintext)?;
        Ok(string.into())
    }
}

impl FromStr for EncryptedServices {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((cipher_text, salt, nonce)) = s
            .split(':')
            .map(|component| base64::engine::general_purpose::STANDARD.decode(component))
            .collect::<Result<Vec<Vec<u8>>, DecodeError>>()?
            .into_iter()
            .collect_tuple()
        else {
            anyhow::bail!("Encrypted services data must contain exactly 3 fields");
        };

        Ok(EncryptedServices {
            cipher_text,
            salt,
            nonce: <[u8; NONCE_LENGTH_BYTES]>::try_from(nonce.as_slice())?,
        })
    }
}
