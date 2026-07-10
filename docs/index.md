# veracrypt-forensic

A from-scratch, pure-Rust **VeraCrypt / TrueCrypt reader and decryptor** — unlock a
volume from its password and read the plaintext, plus an anomaly auditor over the
recovered volume facts.

!!! info "Scope"
    This build brutes the header across **all five VeraCrypt PRFs** (SHA-512,
    SHA-256, Whirlpool, Streebog-512, RIPEMD-160) and decrypts **both single
    ciphers** (AES-256-XTS, Serpent-256-XTS, Twofish-256-XTS), with a PIM and normal
    *or* hidden volumes. **Cipher cascades** are the one deferred extension. See
    [Format Research](RESEARCH.md) and [Validation](validation.md).

## What it does

A VeraCrypt volume stores its master key inside a 512-byte header that is itself
encrypted with a key derived from the password. `veracrypt-core`:

- reads the 512-byte volume header (`salt[64]` + a 448-byte XTS-encrypted header),
- derives the header key with `PBKDF2-HMAC-<PRF>` and tries every PRF × cipher
  until the decrypted header shows a valid `VERA`/`TRUE` magic and both CRC-32s
  match — so a wrong password/PRF/cipher is rejected with no false positive,
- recovers the master key from the decrypted header, and
- decrypts the data area as AES-256 or Twofish-256 XTS (the tweak is
  `encrypted_area_start / 512 + LBA`), exposing a plaintext `Read + Seek` view
  (`read_at`).

`unlock_hidden_with_password` repeats the process against the hidden header at
64 KiB, to access or prove the presence of a deniable hidden volume.
`veracrypt-forensic` grades the recovered facts into observations (legacy
TrueCrypt, hidden volume declared, cipher inventory).

## The two-crate split

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| `veracrypt-core` | reader / decryptor | `aes`, `twofish`, `xts-mode`, `pbkdf2`, `sha2`, `whirlpool`, `streebog`, `ripemd`, `crc32fast`, `hmac`, `thiserror` | plaintext view + typed `VolumeInfo` |
| `veracrypt-forensic` | anomaly analyzer | `veracrypt-core` | graded observations |

## Trust but verify

Every primitive is an audited RustCrypto crate; no cryptography is hand-rolled.
Correctness is proven Tier-1 on a real VeraCrypt volume with a published
password, where **three independent implementations agree byte-for-byte** —
VeraCrypt 1.26.20, `cryptsetup` 2.7.0, and this crate. Panic-free,
bounds-checked parsing; `unwrap`/`expect` denied in production code
(`#![forbid(unsafe_code)]`); fuzzed header parser.

[Privacy Policy](https://securityronin.github.io/veracrypt-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/veracrypt-forensic/terms/) · © 2026 Security Ronin Ltd
