# Validation

Correctness is proven against **independent third-party reference
implementations on a real VeraCrypt volume with a published password** — never
against fixtures we authored (which would only prove self-consistency, the LZNT1
trap). The decryptor emits plaintext that an independent oracle can check
byte-for-byte, so a Tier-1 oracle is mandatory — and here there are two.

## Tier-1 (unimpeachable) — `vc_1-sha512-xts-aes` vs VeraCrypt *and* cryptsetup

- **Artifact**: `vc_1-sha512-xts-aes`, from the **cryptsetup** project test suite
  (`tests/tcrypt-images.tar.xz`) — a real VeraCrypt volume authored by a third
  party. 299 008 bytes, md5 `70226872a0aae3864fe729bbd69f7a13`. SHA-512 PRF,
  AES-256, XTS (`aes-xts-plain64`, 512-byte sectors). The encrypted data area
  begins at byte offset 131 072 (XTS data-unit base 256).
- **Published password**: `aaaaaaaaaaaa` (twelve `a`s), no PIM.
- **Answer key — three implementations agree byte-for-byte.** The decrypted-sector
  ground truth (LBA 0/1/2/16 →
  `76a9e841…de8ff8fa` / `076a27c7…55f36560` / `6242cb7c…f74247a5` /
  `00882984…ecee4b0f`) is produced identically by:
    1. **VeraCrypt 1.26.20** (Idrix — the format's own reference implementation),
       `veracrypt --text --mount --filesystem=none` → `/dev/mapper/veracrypt1`;
    2. **cryptsetup 2.7.0** (an independent reimplementation),
       `cryptsetup open --veracrypt`;
    3. **`veracrypt-core`** (this crate), `core/tests/oracle_veracrypt.rs`.

  The artifact was authored by a third party and the password is published, so
  this is genuine Tier-1; two independent reference oracles agree with this crate,
  so it is unimpeachable — a wrong implementation and a wrong fixture cannot both
  be wrong the same way across three code bases.

The env-gated test `core/tests/oracle_veracrypt.rs` (`VC_ORACLE`) unlocks the
image with the published password and asserts these decrypted-sector SHA-256
digests:

| Data-area LBA | Region | SHA-256 |
|---|---|---|
| 0 | volume start | `76a9e8419a1e688732c03236e01e564c6b3660c0bcdc4561eb05e1d1de8ff8fa` |
| 1 | all-zero plaintext (non-zero ciphertext ⇒ proves correct inversion) | `076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560` |
| 2 | data | `6242cb7cb043b219a77ffa2bd0aedab6735389bbbe8b3b2e88410cf5f74247a5` |
| 16 | data | `00882984fac5e7298c45bae80bad8debc4456d06d5189bb91f9f3901ecee4b0f` |

Run:

```bash
VC_ORACLE=/tmp/vc-oracle/vc_1-sha512-xts-aes \
  cargo test -p veracrypt-core --test oracle_veracrypt -- --nocapture
```

The image is **not** committed; the test skips cleanly when the env var is unset.
Provenance is recorded in `tests/data/README.md` (and `/tmp/vc-oracle/GROUND-TRUTH.md`).

## Tier-1 — hidden volume `vc_1-sha512-xts-aes-hidden` vs cryptsetup

- **Artifact**: `vc_1-sha512-xts-aes-hidden`, the hidden-volume companion from the
  same cryptsetup corpus. md5 `2180518977e9634a127b6b0adeecc50a`. SHA-512 / AES /
  XTS; the hidden header is at byte 65 536 and the hidden data area begins at byte
  165 888 (XTS data-unit base 324).
- **Published password**: `bbbbbbbbbbbb` (the hidden volume's own password).
- **Answer key**: `cryptsetup open --veracrypt --tcrypt-hidden`. The env-gated test
  `core/tests/oracle_veracrypt.rs::tier1_hidden_volume_matches_cryptsetup`
  (`VC_HIDDEN_ORACLE`) unlocks the hidden header and reproduces its decrypted
  sectors byte-for-byte (LBA 0 → `79a162bd…9bffed8e`, LBA 2 → `6242cb7c…f74247a5`).

```bash
VC_HIDDEN_ORACLE=/tmp/vc-oracle/vc_1-sha512-xts-aes-hidden \
  cargo test -p veracrypt-core --test oracle_veracrypt -- --nocapture
```

The same corpus also carries `sha256` / `whirlpool` / `streebog` / `ripemd160`
PRF variants under the same published passwords.

## Tier-1 — Serpent-256 and cipher cascades vs real VeraCrypt 1.26.20

Serpent-256 and the cipher cascades are validated against volumes **minted by the
real VeraCrypt 1.26.20 binary** (Idrix's own implementation) with a published
password (`aaaaaaaaaaaa`) — a third-party author and an independent oracle, so
genuine Tier-1. Each env-gated test in `core/tests/oracle_veracrypt.rs` unlocks the
volume and asserts the decrypted-sector SHA-256 digests VeraCrypt itself produced.

| Test / env var | Volume | Cipher chain | LBA 0 SHA-256 |
|---|---|---|---|
| `tier1_serpent256_matches_cryptsetup` / `VC_SERPENT_ORACLE` | `vcserp.vc` | `serpent` | `479ad71598de182171230acbe3322cdac3b9bb9f70894a7cc3e7b526be46693b` |
| `tier1_cascade_aes_twofish_matches_veracrypt` / `VC_CASCADE_ORACLE` | `vccasc.vc` | `aes-twofish` | `da09622b78baeeb1fa8e6532f1eb23afc733a8449097d3a08d612286d4161492` |
| `tier1_cascade3_aes_twofish_serpent_matches_veracrypt` / `VC_CASCADE3_ORACLE` | `vccasc3.vc` | `aes-twofish-serpent` | `9ae00053bc19932a4b069c522ab0141863c434732a0e50450fb01ffcd2c58142` |

The two-cipher case is additionally cross-checked against **cryptsetup 2.7.0**
(`--type tcrypt --veracrypt`), so the cascade key layout is confirmed by two
independent code bases plus this crate. The three-cipher case pins the general
*n*-cipher offsets and the Serpent-inside-a-cascade path.

```bash
VC_SERPENT_ORACLE=/tmp/vc-oracle/vcserp.vc \
VC_CASCADE_ORACLE=/tmp/vc-oracle/vccasc.vc \
VC_CASCADE3_ORACLE=/tmp/vc-oracle/vccasc3.vc \
  cargo test -p veracrypt-core --test oracle_veracrypt -- --nocapture
```

## Tier-3 — hermetic round-trip and structural unit tests

Under the Tier-1 oracles sit fast, deterministic lib tests:

- **PBKDF2** — `PBKDF2-HMAC-SHA512("password","salt",1,32)` is checked against an
  independently computed vector; every PRF derives the requested key length.
- **Header validation** — `VeraHeader::validate` is exercised over hand-built
  448-byte buffers for the accept paths (`VERA` and `TRUE`) and every reject path
  (too short, bad magic, master-key CRC mismatch, header-field CRC mismatch).
- **Full unlock round-trip** — a synthetic AES-256-XTS volume is assembled in
  memory (real `VERA` header + both CRC-32s, XTS-encrypted under the SHA-512
  header key at PIM 1) and driven through `unlock_with_pim`, `read_at`, the
  `Read`/`Seek` impls, the too-small and wrong-password error paths, and the
  undeclared-size fallback.
- **Cascade round-trip** — a three-cipher `aes-twofish-serpent` chain is encrypted
  forward and decrypted through `xts_decrypt_chain`, recovering the plaintext; this
  independently confirms the reverse apply-order and per-cipher key offsets that the
  Tier-1 cascade oracles check against real VeraCrypt output.

These prove self-consistency only — a round-trip encoder and decoder can be wrong
the same way. The real correctness proof is the Tier-1 three-implementation
agreement above; the hermetic tests are regression scaffolding beneath it.

## Fuzzing

`core/fuzz/fuzz_targets/fuzz_header.rs` drives `VeraHeader::validate` over
arbitrary bytes, and `fuzz_unlock.rs` drives `VeraVolume::unlock_with_password`
over an arbitrary container plus a short password. Invariant: never panic.
