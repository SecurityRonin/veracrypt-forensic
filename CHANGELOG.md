# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1]

### Added

- `veracrypt-forensic`: findings now use the fleet-canonical
  `forensicnomicon::report` model — the analyzer keeps its typed `AnomalyKind`
  and emits `forensicnomicon::report::Finding` via `impl Observation`
  (`audit_findings(info, hidden_size, scope)`); `audit` still returns the typed
  `Anomaly`s. Codes/severities/categories unchanged.

## [0.1.0]

### Added

- `veracrypt-core`: from-scratch, pure-Rust VeraCrypt / TrueCrypt reader and
  decryptor.
  - Volume-header parsing: `salt[64]` + a 448-byte XTS-encrypted header, accepted
    only on a `VERA`/`TRUE` magic with both CRC-32 fields matching (dual-CRC gate
    ⇒ no false-positive unlock).
  - Header-key brute across **all five PRFs** (SHA-512, SHA-256, Whirlpool,
    Streebog-512, RIPEMD-160) × **both single ciphers** (AES-256-XTS,
    Twofish-256-XTS), with per-PRF default and PIM iteration counts.
  - Master-key recovery and data-area decryption as AES-256 or Twofish-256 XTS,
    tweak = `encrypted_area_start / 512 + LBA`.
  - `VeraVolume::unlock_with_password` / `unlock_with_pim` → plaintext
    `Read + Seek` view (`read_at`).
  - `VeraVolume::unlock_hidden_with_password` / `unlock_hidden_with_pim` for the
    hidden-volume header at 64 KiB (deniable-volume access / detection).
  - Tier-1 validated against a real VeraCrypt volume with a published password,
    where **VeraCrypt 1.26.20, `cryptsetup` 2.7.0, and this crate agree
    byte-for-byte** (normal and hidden volumes).
  - 256-bit Serpent and cipher cascades are deferred (no audited 256-bit Serpent
    Rust crate) — recognised as out of scope, never hand-rolled.
- `veracrypt-forensic`: anomaly auditor over the recovered volume facts, emitting
  `VC-LEGACY-TRUECRYPT`, `VC-HIDDEN-VOLUME-DECLARED`, and `VC-CIPHER-INVENTORY`
  observations.
