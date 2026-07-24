# 7. Tier-1 validation against independent oracles, env-gated and uncommitted

Date: 2026-07-24
Status: Accepted

## Context

This crate is a decoder that emits a *value* (plaintext sectors) whose ground
truth is derivable and cross-checkable by an independent oracle — exactly the
"LZNT1 trap" zone where a self-authored round-trip test passes while both the
encoder and decoder are wrong the same way (`CLAUDE.core.md` → "Evidence-Based
Rigor"). A hermetic test where we mint a volume and decrypt it proves only self-
consistency. Correctness must be proven against implementations we did not write,
on volumes authored by third parties, with published passwords.

## Decision

Gate correctness on **Tier-1 agreement with two independent reference
implementations** on real VeraCrypt volumes (`docs/validation.md`,
`core/tests/oracle_veracrypt.rs`):

- Primary artifact `vc_1-sha512-xts-aes` from the **cryptsetup** test corpus
  (third-party author, published password `aaaaaaaaaaaa`); its decrypted-sector
  digests are produced identically by **VeraCrypt 1.26.20** (the format's own
  reference), **cryptsetup 2.7.0** (an independent reimplementation), and this
  crate — three code bases agreeing byte-for-byte.
- The hidden-volume companion, the Serpent-256 volume, and the AES-Twofish /
  AES-Twofish-Serpent cascades are each validated the same way (against cryptsetup
  and/or real VeraCrypt-1.26.20-minted volumes), pinning the hidden-header offset,
  the Serpent path, and the general *n*-cipher cascade offsets (ADR 0006).
- The oracle tests are **env-gated** (`VC_ORACLE`, `VC_HIDDEN_ORACLE`,
  `VC_SERPENT_ORACLE`, `VC_CASCADE_ORACLE`, `VC_CASCADE3_ORACLE`) and skip cleanly
  when unset; the volumes are **not committed** — provenance (source, md5,
  password, ground-truth digests) lives in `tests/data/README.md`.
- Beneath the oracles sit fast hermetic Tier-3 lib tests (PBKDF2 vector, header
  accept/reject paths, full unlock round-trip, cascade round-trip) as regression
  scaffolding — explicitly *not* the correctness proof.

## Consequences

Correctness rests on multi-implementation agreement on real artifacts, the
strongest tier available for a value-producing decoder; a wrong implementation and
a wrong fixture cannot both be wrong the same way across three code bases. Because
the volumes are large and licence-encumbered, CI cannot run the Tier-1 oracles
without them, so the committed line-coverage gate is carried by the hermetic
tests while the oracle tests document the real proof and run wherever the corpus
is present. The env-gating keeps `cargo test` green on a fresh clone.
