//! # veracrypt-forensic — VeraCrypt/TrueCrypt volume anomaly auditor
//!
//! Emits severity-graded [`forensicnomicon::report::Finding`]s over an unlocked
//! volume's recovered facts: flavor (VeraCrypt vs legacy TrueCrypt), the
//! PRF/cipher in use, and whether the header advertises a hidden volume. Findings
//! are observations, never verdicts — the examiner draws conclusions.
//!
//! - `VC-LEGACY-TRUECRYPT` — a legacy TrueCrypt (not VeraCrypt) container (Low).
//! - `VC-HIDDEN-VOLUME-DECLARED` — the outer header declares a hidden volume (Medium).
//! - `VC-CIPHER-INVENTORY` — the PRF, cipher, and data offset in use (Info).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::{Category, Evidence, Finding, Observation, Severity, Source};
use veracrypt::{Flavor, VolumeInfo};

/// The producing analyzer name embedded in emitted findings' `Source`.
pub const ANALYZER: &str = "veracrypt-forensic";

/// A classified VeraCrypt observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// The volume is a legacy TrueCrypt container.
    LegacyTrueCrypt,
    /// The outer header declares a hidden volume (deniable-encryption indicator).
    HiddenVolumeDeclared {
        /// Declared hidden-volume size in bytes.
        size: u64,
    },
    /// The cipher/PRF inventory of the unlocked volume.
    CipherInventory {
        /// PRF name.
        prf: &'static str,
        /// Cipher name.
        cipher: &'static str,
        /// Byte offset of the encrypted data area.
        offset: u64,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::LegacyTrueCrypt => Severity::Low,
            AnomalyKind::HiddenVolumeDeclared { .. } => Severity::Medium,
            AnomalyKind::CipherInventory { .. } => Severity::Info,
        }
    }

    /// Stable, scheme-prefixed machine code (published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::LegacyTrueCrypt => "VC-LEGACY-TRUECRYPT",
            AnomalyKind::HiddenVolumeDeclared { .. } => "VC-HIDDEN-VOLUME-DECLARED",
            AnomalyKind::CipherInventory { .. } => "VC-CIPHER-INVENTORY",
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::LegacyTrueCrypt | AnomalyKind::CipherInventory { .. } => {
                Category::Provenance
            }
            AnomalyKind::HiddenVolumeDeclared { .. } => Category::Concealment,
        }
    }

    /// Human-readable note including the offending value.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::LegacyTrueCrypt => {
                "volume is a legacy TrueCrypt (not VeraCrypt) container".to_string()
            }
            AnomalyKind::HiddenVolumeDeclared { size } => format!(
                "outer header declares a hidden volume of {size} bytes (deniable-encryption indicator)"
            ),
            AnomalyKind::CipherInventory {
                prf,
                cipher,
                offset,
            } => format!("PRF {prf}, cipher {cipher}, data area at byte {offset}"),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::LegacyTrueCrypt => Vec::new(),
            AnomalyKind::HiddenVolumeDeclared { size } => {
                vec![evidence("hidden_size", size.to_string())]
            }
            AnomalyKind::CipherInventory {
                prf,
                cipher,
                offset,
            } => vec![
                evidence("prf", (*prf).to_string()),
                evidence("cipher", (*cipher).to_string()),
                evidence("encrypted_area_start", offset.to_string()),
            ],
        }
    }
}

fn evidence(field: &str, value: String) -> Evidence {
    Evidence {
        field: field.to_string(),
        value,
        location: None,
    }
}

/// A VeraCrypt forensic anomaly: an observation graded by severity, with a stable
/// code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

/// Audit an unlocked volume's [`VolumeInfo`] plus its declared hidden-volume size,
/// returning classified anomalies. Pure.
#[must_use]
pub fn audit(info: &VolumeInfo, hidden_size: u64) -> Vec<Anomaly> {
    let mut out = Vec::new();

    if info.flavor == Flavor::TrueCrypt {
        out.push(Anomaly::new(AnomalyKind::LegacyTrueCrypt));
    }

    if hidden_size != 0 {
        out.push(Anomaly::new(AnomalyKind::HiddenVolumeDeclared {
            size: hidden_size,
        }));
    }

    out.push(Anomaly::new(AnomalyKind::CipherInventory {
        prf: info.prf.name(),
        cipher: info.cipher.name(),
        offset: info.encrypted_area_start,
    }));

    out
}

/// Audit a volume and map each anomaly to a canonical [`Finding`], tagged with the
/// producing [`Source`] (`scope` names the evidence).
#[must_use]
pub fn audit_findings(
    info: &VolumeInfo,
    hidden_size: u64,
    scope: impl Into<String>,
) -> Vec<Finding> {
    let source = Source {
        analyzer: ANALYZER.to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    audit(info, hidden_size)
        .into_iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use veracrypt::{Cipher, Prf};

    fn info(flavor: Flavor) -> VolumeInfo {
        VolumeInfo {
            flavor,
            prf: Prf::Sha512,
            cipher: Cipher::Serpent,
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
        assert_eq!(a[0].severity, Severity::Info);
    }

    #[test]
    fn flags_truecrypt_and_hidden() {
        let a = audit(&info(Flavor::TrueCrypt), 4096);
        let codes: Vec<_> = a.iter().map(|x| x.code).collect();
        assert!(codes.contains(&"VC-LEGACY-TRUECRYPT"));
        assert!(codes.contains(&"VC-HIDDEN-VOLUME-DECLARED"));
    }

    #[test]
    fn findings_carry_source_category_and_evidence() {
        // TrueCrypt + hidden + inventory → exercises every Observation arm.
        let findings = audit_findings(&info(Flavor::TrueCrypt), 4096, "container.vc");
        assert_eq!(findings.len(), 3);
        for f in &findings {
            assert_eq!(f.source.analyzer, "veracrypt-forensic");
            assert_eq!(f.source.scope, "container.vc");
            assert!(f.source.version.is_some());
        }
        let hidden = findings
            .iter()
            .find(|f| f.code == "VC-HIDDEN-VOLUME-DECLARED")
            .unwrap();
        assert_eq!(hidden.category, Category::Concealment);
        assert_eq!(hidden.severity, Some(Severity::Medium));
        assert_eq!(hidden.evidence.len(), 1);
        let inv = findings
            .iter()
            .find(|f| f.code == "VC-CIPHER-INVENTORY")
            .unwrap();
        assert_eq!(inv.category, Category::Provenance);
        assert_eq!(inv.evidence.len(), 3);
        let legacy = findings
            .iter()
            .find(|f| f.code == "VC-LEGACY-TRUECRYPT")
            .unwrap();
        assert!(legacy.evidence.is_empty());
    }
}
