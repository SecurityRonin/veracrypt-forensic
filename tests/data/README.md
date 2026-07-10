# Test data provenance

Large binary artifacts are **gitignored** and downloaded (or minted) manually.
Tests read them in place, env-gated, and skip cleanly when absent. This file is
the committed record so the corpus is reproducible. The single fleet-wide index is
`issen/docs/corpus-catalog.md` — cross-referenced here, not duplicated.

## Tier-1 oracle (REAL-ext, not committed)

#### vc_1-sha512-xts-aes

- **Source**: the **cryptsetup** project test suite
  ([`tests/tcrypt-images.tar.xz`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/tests/tcrypt-images.tar.xz)),
  a real VeraCrypt volume authored by a third party.
- **md5**: `70226872a0aae3864fe729bbd69f7a13`
- **Size**: 299 008 bytes
- **License / redistribution**: cryptsetup test corpus (GPL-2.0-or-later project);
  **not committed here** — documented for provenance only. Extract from
  `tcrypt-images.tar.xz` in the cryptsetup source tree.
- **Identity / contents**: SHA-512 PRF, AES-256, XTS (`aes-xts-plain64`, 512-byte
  sectors); encrypted data area starts at byte 131 072 (XTS data-unit base 256).
- **Published password**: `aaaaaaaaaaaa` (twelve `a`s), no PIM.
- **Used by**: `core/tests/oracle_veracrypt.rs` (env var `VC_ORACLE`). Ground-truth
  decrypted-sector SHA-256 digests were confirmed by **three independent
  implementations** — VeraCrypt 1.26.20, `cryptsetup` 2.7.0, and this crate — all
  byte-for-byte identical; see `docs/validation.md`.

#### vc_1-sha512-xts-aes-hidden

- **Source**: the hidden-volume companion from the same cryptsetup
  `tcrypt-images.tar.xz` corpus.
- **md5**: `2180518977e9634a127b6b0adeecc50a`
- **License / redistribution**: as above — **not committed**.
- **Identity / contents**: SHA-512 / AES-256 / XTS; hidden header at byte 65 536,
  hidden data area at byte 165 888 (XTS data-unit base 324).
- **Published password**: `bbbbbbbbbbbb` (the hidden volume's own password).
- **Used by**: `core/tests/oracle_veracrypt.rs::tier1_hidden_volume_matches_cryptsetup`
  (env var `VC_HIDDEN_ORACLE`). Ground truth from
  `cryptsetup open --veracrypt --tcrypt-hidden`; see `docs/validation.md`.

## Tier-1 oracle — Serpent-256 + cascades (REAL-ext, minted, not committed)

Minted by the **real VeraCrypt 1.26.20 binary** (Idrix) on the Ubuntu oracle VM,
published password `aaaaaaaaaaaa`, no PIM. The decrypted-sector ground truth is
whatever VeraCrypt itself produces; the two-cipher case is additionally confirmed
by `cryptsetup 2.7.0`. Not committed — regenerate with the `veracrypt --create`
lines in `/tmp/vc-oracle/GROUND-TRUTH.md`.

#### vcserp.vc

- **md5**: `2d3bf1bd1c4faae16709e28bb0796184` · **Size**: 2 097 152 bytes
- **Identity**: SHA-512 PRF, **Serpent-256**, XTS.
- **Used by**: `oracle_veracrypt.rs::tier1_serpent256_matches_cryptsetup`
  (`VC_SERPENT_ORACLE`). LBA 0 → `479ad715…be46693b`.

#### vccasc.vc

- **md5**: `bc0ddb81c37ed138d75a2d3fe547a59a` · **Size**: 2 097 152 bytes
- **Identity**: SHA-512 PRF, **AES-Twofish** cascade (stacked XTS).
- **Used by**: `oracle_veracrypt.rs::tier1_cascade_aes_twofish_matches_veracrypt`
  (`VC_CASCADE_ORACLE`). LBA 0 → `da09622b…d4161492`. Cross-checked vs cryptsetup.

#### vccasc3.vc

- **md5**: `0852e9379444891f02e00d0b869635e0` · **Size**: 3 145 728 bytes
- **Identity**: SHA-512 PRF, **AES-Twofish-Serpent** cascade (stacked XTS).
- **Used by**: `oracle_veracrypt.rs::tier1_cascade3_aes_twofish_serpent_matches_veracrypt`
  (`VC_CASCADE3_ORACLE`). LBA 0 → `9ae00053…d2c58142`.

To run the Tier-1 tests:

```bash
VC_ORACLE=/tmp/vc-oracle/vc_1-sha512-xts-aes \
VC_HIDDEN_ORACLE=/tmp/vc-oracle/vc_1-sha512-xts-aes-hidden \
VC_SERPENT_ORACLE=/tmp/vc-oracle/vcserp.vc \
VC_CASCADE_ORACLE=/tmp/vc-oracle/vccasc.vc \
VC_CASCADE3_ORACLE=/tmp/vc-oracle/vccasc3.vc \
  cargo test -p veracrypt-core --test oracle_veracrypt -- --nocapture
```

The cryptsetup corpus also carries `sha256` / `whirlpool` / `streebog` /
`ripemd160` PRF variants under the same published passwords. Full ground truth
(offsets, sector hashes, the mint commands, the triple-implementation cross-check)
is recorded in `/tmp/vc-oracle/GROUND-TRUTH.md`.
