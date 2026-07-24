# 8. Low, CI-verified library MSRV floor below the dev-toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet separates the **dev toolchain** (what contributors build with) from the
**declared MSRV** (a downstream-facing promise) (`CLAUDE.core.md` → "Rust MSRV &
Toolchain Policy"; `CLAUDE.personal.md` → fleet specifics). Apps pin their
declared MSRV to the toolchain; **published libraries keep a low, CI-verified
MSRV** because raising it narrows the crates.io audience. Both crates here are
libraries (ADR 0001), so they take the library rule, not the app rule.

## Decision

- `rust-toolchain.toml` pins the dev/CI toolchain to the current fleet stable
  (`channel = "1.96.0"`, with `clippy`/`rustfmt` components) — one version across
  all contributors and CI.
- The **declared MSRV is held low** and independent of that pin:
  `Cargo.toml` `[workspace.package] rust-version = "1.81"` (inherited by both
  members), advertised by the README `Rust 1.81+` badge and verified by a CI
  MSRV job.

## Consequences

The library crates stay consumable by toolchains well behind the bleeding edge
(the deliberate low-MSRV trust signal), while contributors develop on one pinned
current stable with no fmt/clippy drift. Raising `rust-version` is treated as a
near-breaking change requiring a real need, never bumped merely to match the
toolchain.

**Rationale for the specific floor:** the exact value `1.81` (rather than the
fleet's usual `1.75`/`1.80` library floor) is the minimum this crate's dependency
graph — the RustCrypto stack and `forensicnomicon` — resolves and compiles
against. The precise dependency that drove the floor to `1.81` is *not recovered
in available history* (no commit message records the bump); it is documented here
as the observed, CI-verified floor rather than an invented justification.
