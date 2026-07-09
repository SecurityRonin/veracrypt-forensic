//! # veracrypt-forensic — VeraCrypt/TrueCrypt volume anomaly auditor
//!
//! Observations over an unlocked volume's recovered facts: flavor (VeraCrypt vs
//! legacy TrueCrypt), the PRF/cipher in use, and whether the header advertises a
//! hidden volume. Findings are observations, never verdicts.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use veracrypt::{Flavor, VolumeInfo};

/// Severity of a VeraCrypt finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational context.
    Info,
    /// A weak or legacy configuration.
    Low,
    /// A materially notable configuration.
    Medium,
}

/// A classified observation with a stable code and note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity.
    pub severity: Severity,
    /// Stable, scheme-prefixed machine code.
    pub code: &'static str,
    /// Human-readable note including the offending value.
    pub note: String,
}

/// Audit an unlocked volume's [`VolumeInfo`] plus its declared hidden-volume size.
#[must_use]
pub fn audit(info: &VolumeInfo, hidden_size: u64) -> Vec<Anomaly> {
    let mut out = Vec::new();

    if info.flavor == Flavor::TrueCrypt {
        out.push(Anomaly {
            severity: Severity::Low,
            code: "VC-LEGACY-TRUECRYPT",
            note: "volume is a legacy TrueCrypt (not VeraCrypt) container".to_string(),
        });
    }

    if hidden_size != 0 {
        out.push(Anomaly {
            severity: Severity::Medium,
            code: "VC-HIDDEN-VOLUME-DECLARED",
            note: format!(
                "outer header declares a hidden volume of {hidden_size} bytes (deniable-encryption indicator)"
            ),
        });
    }

    out.push(Anomaly {
        severity: Severity::Info,
        code: "VC-CIPHER-INVENTORY",
        note: format!(
            "PRF {}, cipher {}, data area at byte {}",
            info.prf.name(),
            info.cipher.name(),
            info.encrypted_area_start
        ),
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use veracrypt::{Cipher, Prf};

    fn info(flavor: Flavor) -> VolumeInfo {
        VolumeInfo {
            flavor,
            prf: Prf::Sha512,
            cipher: Cipher::Aes,
            version: 5,
            encrypted_area_start: 131_072,
            encrypted_area_size: 36_864,
        }
    }

    #[test]
    fn veracrypt_clean_only_inventory() {
        let a = audit(&info(Flavor::VeraCrypt), 0);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].code, "VC-CIPHER-INVENTORY");
    }

    #[test]
    fn flags_truecrypt_and_hidden() {
        let a = audit(&info(Flavor::TrueCrypt), 4096);
        let codes: Vec<_> = a.iter().map(|x| x.code).collect();
        assert!(codes.contains(&"VC-LEGACY-TRUECRYPT"));
        assert!(codes.contains(&"VC-HIDDEN-VOLUME-DECLARED"));
    }
}
