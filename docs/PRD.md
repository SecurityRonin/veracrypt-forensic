# veracrypt-forensic — Design, Purpose & Scope

*A library-tier design/scope doc (not a PRD — there is no runnable product here;
both crates are linked, never executed by an examiner). Every current-state claim
is grounded in a same-session read of the repo (2026-07-24); the load-bearing
decisions live as ADRs under [`docs/decisions/`](decisions/).*

## Purpose

`veracrypt-forensic` is a two-crate Rust workspace that unlocks and reads
**VeraCrypt** (and legacy **TrueCrypt**) volumes from a password, entirely
in-process. It exists so a fleet tool — a filesystem reader, a carver, an
orchestration layer — can get at the plaintext inside an encrypted container
**without** the `veracrypt` binary, `cryptsetup`/`dm-crypt`, FUSE, a kernel
device-mapper, elevated privileges, or mounting the volume (ADR 0002). Given a
container and a password, it brutes the header PRF and cipher, recovers the master
key, and exposes a plaintext `Read + Seek` view of the data area.

## Users (who links this)

- **Filesystem/VFS readers** that need the decrypted byte stream to mount or
  traverse the volume inside — reached through the optional `forensic-vfs`
  `EncryptionLayer` adapter so VeraCrypt composes into a layer stack such as
  `E01 → GPT → VeraCrypt → NTFS` (ADR 0004).
- **Orchestration / triage** code that wants graded observations about a volume
  (flavor, PRF/cipher inventory, declared hidden volume) as
  `forensicnomicon::report::Finding`s.
- **Rust DFIR tooling** that simply wants a pure-Rust, no-runtime-dependency
  VeraCrypt decryptor to call directly.

## What it does

- **`veracrypt-core`** (imported as `veracrypt`) — the reader/decryptor.
  `VeraVolume::unlock_with_password` / `unlock_with_pim` /
  `unlock_hidden_with_password` / `unlock_hidden_with_pim` try every PRF × cipher
  chain until one decrypts the header to a valid `VERA`/`TRUE` signature with both
  CRC-32s matching (ADR 0003), then return a `DecryptedVolume` exposing `read_at`
  and a typed `VolumeInfo` (flavor, PRF, cipher chain, encrypted-area offset).
- **`veracrypt-forensic`** — the analyzer. Over a recovered `VolumeInfo` it emits
  severity-graded findings: `VC-LEGACY-TRUECRYPT` (Low),
  `VC-HIDDEN-VOLUME-DECLARED` (Medium), `VC-CIPHER-INVENTORY` (Info). Findings are
  **observations, never verdicts** — the examiner draws conclusions.

## Scope

| Axis | Supported |
|---|---|
| PRF (header key derivation) | SHA-512 · SHA-256 · Whirlpool · Streebog-512 · RIPEMD-160 |
| Cipher (data area) | AES-256-XTS · Serpent-256-XTS · Twofish-256-XTS · all five VeraCrypt cascades |
| PIM | yes (`unlock_with_pim` / `unlock_hidden_with_pim`) |
| Volume layout | normal (header @ 0) · hidden (header @ 64 KiB) |
| Flavor | VeraCrypt (`VERA`) · legacy TrueCrypt (`TRUE`) |

Every cryptographic primitive is an audited RustCrypto crate; none is hand-rolled
(ADR 0002). Parsing is `forbid(unsafe)`, panic-free by lint, and fuzzed
(ADR 0005). Correctness is proven Tier-1 against VeraCrypt 1.26.20 and cryptsetup
2.7.0 on real volumes (ADR 0007, `docs/validation.md`).

## Non-goals

- **Not a mounter.** It exposes a byte view, not a mounted filesystem; mounting is
  a downstream concern (`4n6mount` / the VFS stack). No FUSE, no device-mapper.
- **Not a password cracker.** It tries the PRF/cipher space for a *given* password
  (and optional PIM); it does not run a dictionary or brute-force the password
  itself.
- **Not a re-encryptor / writer.** Read-only decryption only; it never modifies or
  re-writes a container.
- **No system-encryption / boot-loader volumes**, and **no whole-disk / partition
  auto-discovery** — the caller supplies the container (or the enclosing VFS layer
  does). System-partition iteration counts are out of scope.
- **No parsing of the decrypted filesystem** — that belongs to the filesystem
  reader layered on top of the plaintext view.

## Validation approach

Correctness is anchored on multi-implementation Tier-1 agreement — VeraCrypt
1.26.20 (the format's own reference), cryptsetup 2.7.0 (an independent
reimplementation), and this crate agree byte-for-byte on decrypted sectors of
real, third-party-authored volumes with published passwords (ADR 0007). The oracle
tests are env-gated and the volumes uncommitted (provenance in
`tests/data/README.md`); a fast hermetic Tier-3 suite (PBKDF2 vectors, header
accept/reject paths, unlock and cascade round-trips) sits beneath as regression
scaffolding and carries the committed line-coverage gate. The untrusted parse
paths are additionally fuzzed (`core/fuzz/`).
