# 6. Cipher-cascade XTS key layout and `plain64` data-unit numbering follow cryptsetup

Date: 2026-07-24
Status: Accepted

## Context

VeraCrypt supports single ciphers and five multi-cipher **cascades** (AES-Twofish,
AES-Twofish-Serpent, Serpent-AES, Serpent-Twofish-AES, Twofish-Serpent). A cascade
is not "encrypt then encrypt with any keys"; the 256-byte master-key area must be
split into per-cipher XTS sub-keys in an exact layout, and the layers applied in
an exact order, or the data decrypts to garbage that still *looks* random — a
silent-wrong-output failure the dual-CRC header gate (ADR 0003) cannot catch for
the data area. The VeraCrypt spec documents the format; cryptsetup's
`TCRYPT_decrypt_hdr` is the reference implementation that pins the numbering.

## Decision

Key and apply cascades exactly as cryptsetup does (`core/src/crypto.rs`,
`docs/RESEARCH.md`):

- **Key split:** for an *n*-cipher cascade in cryptsetup array order, the cipher
  at array index *j* uses XTS key `key[32j..32j+32]` (primary) ‖
  `key[32(n+j)..32(n+j)+32]` (secondary) — all *n* primaries first, then all *n*
  secondaries. `MAX_CHAIN_KEY_LEN = 3 * 64`.
- **Apply order:** layers are applied in **reverse** array order (`j = n-1 … 0`).
- **Single code path:** the same `crypto::xts_decrypt_chain` keys both the header
  brute and the data area, so the two can never diverge.
- **Data-unit numbering:** the data area is XTS with the tweak anchored to the
  physical start of the encrypted area — `tweak = encrypted_area_start/512 + LBA`
  (little-endian), i.e. `aes-xts-plain64` with the area offset folded in.
- `cipher_chains()` enumerates exactly the eight VeraCrypt chains in cryptsetup
  order; `VolumeInfo::cipher_display()` renders the chain in VeraCrypt's own
  naming (e.g. `aes-twofish-serpent`).

## Consequences

The cascade and data-unit logic is a faithful reimplementation of an independent
reference, so it is verifiable line-by-line against cryptsetup source and, more
importantly, byte-for-byte against real VeraCrypt output (ADR 0007 pins the
two- and three-cipher offsets against VeraCrypt 1.26.20 and cryptsetup 2.7.0).
Folding both header and data through one `xts_decrypt_chain` removes a whole class
of "header decrypts but data is garbage" bugs. The trade-off is that the key
layout is expressed in cryptsetup's array convention rather than VeraCrypt's
display convention, which the `cipher_display` mapping reconciles.
