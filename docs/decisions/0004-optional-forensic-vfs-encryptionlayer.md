# 4. Optional `forensic-vfs` EncryptionLayer adapter behind the `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

A VeraCrypt volume is rarely the whole story: in real evidence it sits inside a
stack — e.g. `E01 → GPT → VeraCrypt → NTFS`. The fleet reads such stacks through
one `forensic-vfs` `ImageSource`, where each layer (container, volume system,
crypto, filesystem) implements a contract and composes with the next
(`~/src/ronin-issen/CLAUDE.md` → "VFS & Universal Container Abstraction"). To
participate, `veracrypt-core` must be able to present its *decrypted* data area as
an `ImageSource` that a filesystem reader mounts unchanged.

But the pure decryptor also has consumers that want nothing to do with the VFS: a
standalone tool that only calls `unlock_with_password` and `read_at`. Forcing
`forensic-vfs` (and its dependency graph) onto every such consumer would be dead
weight.

## Decision

Provide a `forensic-vfs` adapter, but gate it behind a **non-default `vfs`
feature** (`core/Cargo.toml`: `vfs = ["dep:forensic-vfs"]`, and the manifest
comment already names this decision "ADR 0004"). With the feature on,
`core/src/vfs.rs` implements `EncryptionLayer` — `VeraCryptLayer::new(encrypted)`
wraps a ciphertext `DynSource` and, given a `Credential`, returns the decrypted
data area as a `DynSource` keyed by `EncryptionScheme::VeraCrypt`. The decryption
is veracrypt-core's own audited RustCrypto path (ADR 0002); the module only wires
the contract.

This is the fleet's *named-non-default-feature* exception to batteries-included:
the heavy, rarely-wanted subsystem is opt-in for outside library consumers, while
any fleet binary that mounts stacks turns `vfs` on.

## Consequences

The pure decryptor stays lean for third-party reuse; the VFS integration is there
for the mounters that need it, composing VeraCrypt into arbitrary layer stacks
with no special-casing in the consumer. The adapter is pinned to a specific
`forensic-vfs` contract version, so the crate follows that contract's evolution:
git history shows the tracked churn — `CryptoLayer → EncryptionLayer` rename to
align with `forensic-vfs 0.4` (commit `7e765ec`), then dependency bumps `0.2 →
0.4 → 0.5 → 0.7` (commits `11cc624`, `b756caf`, `7213292`, `e76ebe2`). That
coupling is the accepted cost of composability.
