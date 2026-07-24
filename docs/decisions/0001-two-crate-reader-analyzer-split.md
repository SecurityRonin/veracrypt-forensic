# 1. Two-crate reader/analyzer split (`core/` + `forensic/`)

Date: 2026-07-24
Status: Accepted

## Context

The repo does two separable jobs: (a) turn a password + an encrypted container
into a plaintext `Read + Seek` view (a decryptor), and (b) grade the recovered
facts into severity-scored observations (an anomaly auditor). A Rust consumer
that only wants to decrypt a volume — a filesystem mounter, a carver — should not
have to compile the finding model (`forensicnomicon`) or an analyzer it never
calls. Conversely the analyzer's output must speak the fleet-wide reporting
vocabulary so ORCHESTRATION renders it uniformly.

## Decision

Split the workspace into two crates along the fleet reader/analyzer standard
(`~/src/ronin-issen/CLAUDE.md` → "Crate-structure standard — reader/analyzer
split"):

- **`veracrypt-core`** (`core/`, `Cargo.toml` `members = ["core", "forensic"]`) —
  the reader/decryptor. It parses the header, brutes the PRF+cipher, recovers the
  master key, and exposes `VeraVolume`/`DecryptedVolume` + a typed `VolumeInfo`.
  It emits **no findings** and depends only on audited crypto crates
  (`aes`/`serpent`/`twofish`/`xts-mode`/`pbkdf2`/`sha2`/…) plus `thiserror`.
- **`veracrypt-forensic`** (`forensic/`) — the analyzer. It consumes
  `veracrypt`'s `VolumeInfo`/`Flavor` and emits `forensicnomicon::report::Finding`
  values (`forensic/src/lib.rs`). Its `Cargo.toml` deps are exactly
  `veracrypt` + `forensicnomicon`.

The dependency direction is one-way and down: `forensic → core`, and both →
audited leaves. `core` never imports `forensic` or `forensicnomicon`.

## Consequences

A downstream decryptor pulls only `veracrypt-core` and its crypto graph, never
the reporting model. The analyzer stays a thin classification layer over already-
recovered facts, so it needs no lower-format knowledge (the recovered `VolumeInfo`
already exposes flavor, PRF, cipher chain, and the declared hidden-volume size).
The cost is a second published crate to version and release, handled by
release-plz across the workspace.
