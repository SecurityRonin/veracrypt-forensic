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

To run the Tier-1 tests:

```bash
VC_ORACLE=/tmp/vc-oracle/vc_1-sha512-xts-aes \
VC_HIDDEN_ORACLE=/tmp/vc-oracle/vc_1-sha512-xts-aes-hidden \
  cargo test -p veracrypt-core --test oracle_veracrypt -- --nocapture
```

The same corpus carries `sha256` / `whirlpool` / `streebog` / `ripemd160` PRF
variants and `twofish` / `serpent` / `cascades` cipher variants under the same
published passwords — the ready extension path as ciphers are added. Full ground
truth (offsets, sector hashes, the triple-implementation cross-check) is recorded
in `/tmp/vc-oracle/GROUND-TRUTH.md`.
