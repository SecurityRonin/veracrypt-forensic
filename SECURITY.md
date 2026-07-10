# Security Policy

`veracrypt-forensic` is designed to parse **untrusted VeraCrypt / TrueCrypt
volumes** — including containers acquired from compromised or actively hostile
systems. Hostile input is the expected case, not an edge case. Robustness against
crafted volume-header structures is a core design goal, and we take reports of
crashes, hangs, or memory-safety issues seriously.

The security posture below is the standard the crates are built and held to.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current development line |
| < 0.1   | ❌ — pre-release, unsupported |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`veracrypt-forensic` repository](https://github.com/SecurityRonin/veracrypt-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing VeraCrypt container or byte buffer (a fuzz corpus entry is ideal),
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`veracrypt-forensic` is hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **No panics on malicious input** — every length and offset is validated against
  both the structure's declared size and the actual buffer; bounds-checked readers
  return 0 rather than panic out of range.
- **Bounded reads** — the salt, the encrypted header, and the master-key area are
  length-checked before use, so a crafted length field cannot drive an
  out-of-bounds read.
- **No hand-rolled cryptography** — every primitive (PBKDF2, HMAC, SHA-256/512,
  Whirlpool, Streebog, RIPEMD-160, AES, Twofish, XTS, CRC-32) is an audited
  RustCrypto crate; a wrong key is rejected by a dual-CRC gate, never by a
  fabricated plaintext.
- **Pure auditor** — the analyzer is a side-effect-free function of already-decoded
  facts: no I/O.

Continuous fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
backs this hardening: `fuzz_header` drives the header validator and `fuzz_unlock`
drives the full unlock path over arbitrary bytes; each target's invariant is "must
not panic," and any panic found is fixed and pinned as a regression test.
