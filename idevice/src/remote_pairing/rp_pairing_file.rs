// Jackson Coxson

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use plist::Dictionary;
use plist_macro::plist_to_xml_bytes;
use rsa::rand_core::OsRng;
use serde::de::Error;
use tracing::warn;

use crate::IdeviceError;

#[derive(Clone)]
pub struct RpPairingFile {
    pub e_private_key: SigningKey,
    pub e_public_key: VerifyingKey,
    pub identifier: String,
    pub alt_irk: Option<Vec<u8>>,
    /// The device's long-term Ed25519 public key from pair-setup M6, which pair-verify checks the device's
    /// signature against. Records written before it was kept have none and must pair again.
    pub device_public_key: Option<[u8; 32]>,
}

impl RpPairingFile {
    /// Returns the Ed25519 public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.e_public_key.to_bytes().to_vec()
    }

    /// Returns the Ed25519 private key bytes (32 bytes).
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.e_private_key.to_bytes().to_vec()
    }

    /// Returns the identifier string.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Returns the `alt_irk` bytes (16 bytes).
    pub fn alt_irk(&self) -> Option<&[u8]> {
        self.alt_irk.as_deref()
    }

    pub fn generate(sending_host: &str) -> Self {
        // Ed25519 private key (persistent signing key)
        let ed25519_private_key = SigningKey::generate(&mut OsRng);
        let ed25519_public_key = VerifyingKey::from(&ed25519_private_key);

        let identifier =
            uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_DNS, sending_host.as_bytes()).to_string();

        Self {
            e_private_key: ed25519_private_key,
            e_public_key: ed25519_public_key,
            identifier,
            alt_irk: None,
            device_public_key: None,
        }
    }

    pub(crate) fn recreate_signing_keys(&mut self) {
        let ed25519_private_key = SigningKey::generate(&mut OsRng);
        let ed25519_public_key = VerifyingKey::from(&ed25519_private_key);
        self.e_public_key = ed25519_public_key;
        self.e_private_key = ed25519_private_key;
        self.alt_irk = None;
        self.device_public_key = None;
    }

    /// Serialize to XML plist bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "public_key".into(),
            plist::Value::Data(self.e_public_key.to_bytes().to_vec()),
        );
        dict.insert(
            "private_key".into(),
            plist::Value::Data(self.e_private_key.to_bytes().to_vec()),
        );
        dict.insert(
            "identifier".into(),
            plist::Value::String(self.identifier.clone()),
        );
        if let Some(irk) = &self.alt_irk {
            dict.insert("alt_irk".into(), plist::Value::Data(irk.clone()));
        }
        if let Some(key) = &self.device_public_key {
            dict.insert("device_public_key".into(), plist::Value::Data(key.to_vec()));
        }
        plist_to_xml_bytes(&dict)
    }

    /// Parse from plist bytes (XML or binary).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdeviceError> {
        let mut p: Dictionary = plist::from_bytes(bytes)?;

        let public_key = match p
            .remove("public_key")
            .and_then(|x| x.into_data())
            .filter(|x| x.len() == 32)
            .and_then(|x| VerifyingKey::from_bytes(&x[..32].try_into().unwrap()).ok())
        {
            Some(p) => p,
            None => {
                warn!("plist did not contain valid public key bytes");
                return Err(IdeviceError::Plist(plist::Error::missing_field(
                    "public_key",
                )));
            }
        };

        let private_key = match p
            .remove("private_key")
            .and_then(|x| x.into_data())
            .filter(|x| x.len() == 32)
        {
            Some(p) => SigningKey::from_bytes(&p.try_into().unwrap()),
            None => {
                warn!("plist did not contain valid private key bytes");
                return Err(IdeviceError::Plist(plist::Error::missing_field(
                    "private_key",
                )));
            }
        };

        let identifier = match p.remove("identifier").and_then(|x| x.into_string()) {
            Some(i) => i,
            None => {
                warn!("plist did not contain identifier");
                return Err(IdeviceError::Plist(plist::Error::missing_field(
                    "identifier",
                )));
            }
        };

        let alt_irk = match p.remove("alt_irk").and_then(|x| x.into_data()) {
            Some(irk) => Some(irk),
            None => {
                warn!("plist did not contain alt_irk");
                None
            }
        };

        let device_public_key = p
            .remove("device_public_key")
            .and_then(|x| x.into_data())
            .and_then(|x| <[u8; 32]>::try_from(x).ok());

        Ok(Self {
            e_private_key: private_key,
            e_public_key: public_key,
            identifier,
            alt_irk,
            device_public_key,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn write_to_file(&self, path: impl AsRef<Path>) -> Result<(), IdeviceError> {
        tokio::fs::write(path, self.to_bytes()).await?;
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn read_from_file(path: impl AsRef<Path>) -> Result<Self, IdeviceError> {
        let bytes = tokio::fs::read(path).await?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for RpPairingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpPairingFile")
            .field("e_public_key", &self.e_public_key)
            .field("identifier", &self.identifier)
            .field("alt_irk", &self.alt_irk)
            .field("device_public_key", &self.device_public_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_key_survives_a_round_trip_and_an_older_record_reads_without_it() {
        let mut record = RpPairingFile::generate("test-host");
        record.alt_irk = Some(vec![7; 16]);
        record.device_public_key = Some([9; 32]);
        let back = RpPairingFile::from_bytes(&record.to_bytes()).unwrap();
        assert_eq!(back.device_public_key, Some([9; 32]));
        assert_eq!(back.alt_irk(), Some(&[7u8; 16][..]));

        record.device_public_key = None;
        let older = RpPairingFile::from_bytes(&record.to_bytes()).unwrap();
        assert_eq!(older.device_public_key, None);
        assert_eq!(older.identifier(), record.identifier());
    }

    #[test]
    fn a_new_signing_key_forgets_the_device_it_paired_with() {
        let mut record = RpPairingFile::generate("test-host");
        record.device_public_key = Some([9; 32]);
        record.recreate_signing_keys();
        assert_eq!(record.device_public_key, None);
    }
}
