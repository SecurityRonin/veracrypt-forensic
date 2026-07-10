# VeraCrypt / TrueCrypt format research

This is the working reference the implementation is built to. It records the
authoritative sources, the on-disk header layout, and the exact unlock pipeline —
so the code can be checked against the spec line by line, and the next reader does
not have to re-derive VeraCrypt's layout from memory.

## Authoritative sources

| Source | Used for |
|---|---|
| **VeraCrypt documentation** — *VeraCrypt Volume Format Specification* ([veracrypt.fr](https://veracrypt.fr/en/VeraCrypt%20Volume%20Format%20Specification.html)) | Volume-header field layout, salt, CRC-32 fields, master-key area |
| **VeraCrypt source** (`Common/Volumes.c`, `Common/Pkcs5.c`, `Common/Crypto.c`) | PBKDF2 PRF list + iteration counts, PIM formula, header-decrypt XTS unit, master-key split |
| **cryptsetup / libcryptsetup** (`lib/tcrypt/tcrypt.c`) | Independent reimplementation used as a cross-check oracle; `aes-xts-plain64` data-unit numbering |
| **TrueCrypt 7.1a documentation** | Legacy `TRUE` magic, RIPEMD-160 iteration count, shared header layout |

## Volume header (first 512 bytes)

The volume header is a 64-byte salt followed by a 448-byte header that is
**XTS-encrypted** with a key derived from the password (data-unit 0, whole 448
bytes as one unit). Once decrypted, offsets (relative to the start of the 448-byte
region) are:

```text
   0  "VERA"  (TrueCrypt: "TRUE")        44  encrypted-area start   u64 (BE)
   4  format version          u16        52  encrypted-area size    u64 (BE)
   8  CRC-32 of dec[192..448]            64  sector size            u32 (BE)
  28  hidden-volume size      u64       188  CRC-32 of dec[0..188]
  36  volume size             u64       192  master keys[256]
```

All multi-byte integers are **big-endian**. A candidate decryption is accepted
only when the magic is `VERA` or `TRUE` **and** both CRC-32 checks pass:

- `dec[8..12]  == crc32(dec[192..448])` (the master-key area), and
- `dec[188..192] == crc32(dec[0..188])` (the header fields).

This dual-CRC gate is what lets the reader brute PRF × cipher with no false
positive: a wrong key produces random plaintext whose CRCs will not match.

- **Normal-volume header**: at byte offset 0.
- **Hidden-volume header**: at byte offset **65 536** (the second 64 KiB). A
  hidden volume is deniable — the outer volume's own header records a non-zero
  hidden-volume size at offset 28, which the analyzer surfaces.

## Header key derivation — PBKDF2 over five PRFs

The header key is `PBKDF2-HMAC-<PRF>(password, salt, iterations, 64)` — 64 bytes,
i.e. two 256-bit XTS sub-keys. VeraCrypt tries these PRFs:

| PRF | Non-system iterations | PIM formula (non-system) |
|---|---|---|
| SHA-512 | 500 000 | `15000 + PIM*1000` |
| SHA-256 | 500 000 | `15000 + PIM*1000` |
| Whirlpool | 500 000 | `15000 + PIM*1000` |
| Streebog-512 | 500 000 | `15000 + PIM*1000` |
| RIPEMD-160 | 655 331 | `PIM*2048` |

A PIM of 0 uses the default (non-system) count above; RIPEMD-160 is the
TrueCrypt-compatible legacy PRF. The reader tries every PRF, and within each PRF
every cipher, stopping at the first that yields a valid header.

## Master key and data-area decryption

The decrypted header carries 256 bytes of concatenated master-key material at
offset 192. For a single cipher the reader uses the **first `key_len` bytes** — 64
bytes (two 256-bit sub-keys) for AES-256-XTS and Twofish-256-XTS.

The data area is decrypted per 512-byte sector as one XTS data unit. The tweak
(data-unit number) for logical sector `LBA` is:

```text
tweak = encrypted_area_start / 512 + LBA        (little-endian, per XTS)
```

i.e. the data-unit numbering is anchored to the physical start of the encrypted
area (`aes-xts-plain64` with the area offset folded in), which the cryptsetup
oracle confirms: for `vc_1-sha512-xts-aes`, `encrypted_area_start = 131072`, base
data unit `256`, so LBA `k` decrypts with tweak `256 + k`.

## Ciphers

| Cipher | XTS key | Provided by |
|---|---|---|
| AES-256 | two 256-bit sub-keys (64 bytes) | `aes` + `xts-mode` (audited RustCrypto) |
| Twofish-256 | two 256-bit sub-keys (64 bytes) | `twofish` + `xts-mode` (audited RustCrypto) |

## Out of scope in this build

**Cipher cascades** (AES-Twofish, AES-Twofish-Serpent, Serpent-AES,
Serpent-Twofish-AES, Twofish-Serpent). All three single ciphers — AES-256,
Serpent-256, Twofish-256 — are supported via audited RustCrypto crates (Serpent
through `serpent::Serpent::new_from_slice`, which accepts the full 256-bit key;
the typed `new()` alone is 16-byte-capped). Cascades change the master-key split
and add per-cipher chaining, so each is deferred until validated alongside a
cascade oracle. The header brute and master-key recovery are cipher-agnostic, so
adding a cascade is a localized change to `Cipher` and its XTS keying.
