# 3. Header format: big-endian fields, dual-CRC32 acceptance gate, brute PRF×cipher

Date: 2026-07-24
Status: Accepted

## Context

A VeraCrypt/TrueCrypt volume header carries no plaintext type tag, no key ID, and
no cipher/PRF marker: the whole 448-byte header after the 64-byte salt is
XTS-encrypted under a key derived from the password (`core/src/header.rs`,
`docs/RESEARCH.md`). The reader is therefore given only a container and a
password and must discover *which* of five PRFs and *which* cipher/cascade
produced the volume, while never accepting a wrong-password decryption as valid.
Getting the field endianness or the acceptance test wrong silently yields either
false rejects or false accepts.

## Decision

Follow the authoritative VeraCrypt Volume Format Specification and the cryptsetup
reference exactly (`docs/RESEARCH.md`):

- The header is `salt[64] || header[448]`; the 448-byte region is one XTS
  data unit (unit 0) decrypted with the derived header key. Constants:
  `SALT_LEN = 64`, `HEADER_LEN = 448`, `NORMAL_HEADER_OFFSET = 0`,
  `HIDDEN_HEADER_OFFSET = 65_536` (`core/src/header.rs`).
- **All multi-byte header integers are big-endian** (`be_u32`/`be_u64` in
  `header.rs`) — distinct from the *little-endian* XTS data-unit numbering of the
  data area (ADR 0006).
- A candidate decryption is accepted **only** when the magic is `VERA` or `TRUE`
  **and both** CRC-32s match: `dec[8..12] == crc32(dec[192..448])` (master-key
  area) and `dec[188..192] == crc32(dec[0..188])` (header fields)
  (`VeraHeader::validate`).
- The reader **brutes PRF × cipher** in VeraCrypt's own try order
  (`Prf::all()`, `Cipher::all()` / `cipher_chains()`), stopping at the first
  combination that passes the dual-CRC gate.

## Consequences

The dual-CRC gate makes the brute sound: a wrong key decrypts to random bytes
whose two independent CRC-32s will not both match by chance, so PRF×cipher can be
tried exhaustively with no false positive. Fixing endianness at the spec ("big-
endian header, little-endian XTS tweak") prevents the classic inverted-field bug.
The cost is up to `5 PRFs × 8 chains` PBKDF2 derivations on a wrong password —
acceptable for a forensic unlock, and short-circuited on the first hit. The header
layout is pinned to the published spec, so a future format revision is a localized
change in `header.rs`/`RESEARCH.md`.
