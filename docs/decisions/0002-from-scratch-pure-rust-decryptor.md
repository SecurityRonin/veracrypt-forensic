# 2. From-scratch pure-Rust decryptor over audited RustCrypto primitives

Date: 2026-07-24
Status: Accepted

## Context

Existing ways to read a VeraCrypt volume all shell out to a native tool or driver:
the `veracrypt` binary, `cryptsetup`/`dm-crypt`, or a FUSE mount. Each drags in a
runtime dependency an evidence workstation may not have, requires elevated
privileges or a kernel device-mapper, and mounts the volume as a side effect —
the opposite of what a read-only forensic pipeline wants. The fleet needs a
library that a Rust consumer links and calls with no external process, no mount,
and no root.

VeraCrypt's header-unlock and XTS data path are built from standard primitives
(PBKDF2 over five hashes; AES/Serpent/Twofish in XTS). Those primitives are
*solved* — hand-rolling any of them is the cardinal crypto sin
(`~/src/ronin-issen/CLAUDE.md`, `CLAUDE.core.md` → "Never hand-roll a
cryptographic primitive").

## Decision

Implement the VeraCrypt/TrueCrypt unlock and decrypt pipeline **from scratch in
pure Rust**, with every cryptographic primitive supplied by an audited RustCrypto
crate and nothing hand-rolled (`core/src/crypto.rs`):

- key derivation → `pbkdf2` + `hmac` over `sha2`/`whirlpool`/`streebog`/`ripemd`;
- data/header decryption → `aes`/`serpent`/`twofish` under `xts-mode`;
- header CRCs → `crc32fast`.

No `veracrypt` binary, no `cryptsetup`, no FUSE, no mounting — the crate turns a
container plus a password into a plaintext `Read + Seek` view in-process
(README; `core/src/volume.rs`). This is the one place the fleet's
"prefer our own crates" rule **inverts**: crypto reaches for the vetted ecosystem
crate, never a home-grown S-box or key schedule.

## Consequences

The decryptor is a single static library with no runtime dependency, callable
from any Rust tool with no privileges and no side effect on the evidence. The
attack surface for the crypto itself lives in maintained, audited crates rather
than in this repo. The remaining first-party code is *orchestration* — brute
order, key splitting, XTS tweak numbering — which is exactly the code Tier-1
oracle validation targets (ADR 0007). The trade-off is that VeraCrypt format
changes (new PRF, new cipher) must be tracked and re-implemented here rather than
inherited from an upstream binary.
