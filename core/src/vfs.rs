//! `forensic-vfs` [`CryptoLayer`] adapter for VeraCrypt / TrueCrypt, behind the
//! `vfs` feature.
//!
//! Wraps an encrypted VeraCrypt volume (a parent [`ImageSource`]) and, given a
//! password, presents the **decrypted** data area as a [`DynSource`] a normal
//! filesystem mounts unchanged. The decryption is veracrypt-core's own (audited
//! RustCrypto XTS, optional AES/Serpent/Twofish cascade); this module only wires
//! the contract.

use forensic_vfs::{CredentialSource, CryptoLayer, CryptoScheme, DynSource, VfsError, VfsResult};

/// A VeraCrypt-encrypted volume presented as a [`CryptoLayer`].
pub struct VeraCryptLayer {
    encrypted: DynSource,
    len: u64,
}

impl VeraCryptLayer {
    /// Wrap an encrypted VeraCrypt/TrueCrypt volume (the ciphertext byte source).
    pub fn new(encrypted: DynSource) -> Self {
        let len = encrypted.len();
        Self { encrypted, len }
    }
}

impl CryptoLayer for VeraCryptLayer {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::VeraCrypt
    }

    fn open(&self, _creds: &dyn CredentialSource) -> VfsResult<DynSource> {
        // RED: decryption not wired yet.
        Err(VfsError::NeedCredentials {
            scheme: "veracrypt",
            target: String::new(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::VeraCryptLayer;
    use forensic_vfs::adapters::FileSource;
    use forensic_vfs::{Credential, CredentialSource, CryptoLayer, CryptoScheme, DynSource};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    struct FixedCreds(Vec<Credential>);
    impl CredentialSource for FixedCreds {
        fn credentials_for(&self, _scheme: CryptoScheme, _target: &str) -> Vec<Credential> {
            self.0.clone()
        }
    }

    /// The real AES-Twofish cascade VeraCrypt container `vccasc.vc` (password
    /// `aaaaaaaaaaaa`), staged at /tmp (env `VC_CASCADE_ORACLE`, default path).
    /// Ground truth from the veracrypt binary + `cryptsetup --veracrypt`:
    /// decrypted data sector 0 has the SHA-256 below. Skips if absent.
    fn encrypted() -> Option<DynSource> {
        let path = std::env::var("VC_CASCADE_ORACLE")
            .unwrap_or_else(|_| "/tmp/vc-oracle/vccasc.vc".to_string());
        let src = FileSource::open(&path).ok()?;
        Some(Arc::new(src))
    }

    fn sha256_hex(data: &[u8]) -> String {
        use std::fmt::Write;
        Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn veracrypt_cryptolayer_decrypts_cascade() {
        let Some(enc) = encrypted() else {
            eprintln!("skip: no VeraCrypt image (set VC_CASCADE_ORACLE)");
            return;
        };
        let layer = VeraCryptLayer::new(enc);
        assert_eq!(layer.scheme(), CryptoScheme::VeraCrypt);

        let creds = FixedCreds(vec![Credential::Password("aaaaaaaaaaaa".to_string())]);
        let dec: DynSource = layer.open(&creds).expect("unlock vccasc.vc");

        // Decrypted data sector 0 — veracrypt/cryptsetup oracle SHA-256.
        let mut sector = [0u8; 512];
        assert_eq!(dec.read_at(0, &mut sector).expect("read decrypted"), 512);
        assert_eq!(
            sha256_hex(&sector),
            "da09622b78baeeb1fa8e6532f1eb23afc733a8449097d3a08d612286d4161492"
        );

        // No credentials offered → NeedCredentials, never a guess or panic.
        assert!(layer.open(&FixedCreds(vec![])).is_err());
    }
}
