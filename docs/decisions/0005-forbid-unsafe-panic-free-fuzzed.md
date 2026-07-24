# 5. `forbid(unsafe)` + panic-free-by-lint + fuzzed parsing of untrusted volumes

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse **untrusted, attacker-controllable** input: an arbitrary
container passed to `unlock_with_password` and an arbitrary 512-byte header run
through `VeraHeader::validate`. A crafted volume must never panic, read out of
bounds, or trust a length field (`~/src/ronin-issen/CLAUDE.md` → "Security &
Robustness Standard — Paranoid Gatekeeper"). Unlike ewf/memf, this crate does no
memory-mapping and has no C FFI, so it needs no `unsafe` at all — the strongest,
badge-able posture (`CLAUDE.core.md` → "unsafe Is an Avoidable Cost-Benefit
Exception": `forbid(unsafe)` is the default *and* the goal).

## Decision

Adopt the full panic-free posture at workspace scope (`Cargo.toml`
`[workspace.lints]`, mirrored by `#![forbid(unsafe_code)]` at the top of both
`core/src/lib.rs` and `forensic/src/lib.rs`):

- `unsafe_code = "forbid"` — no bounded-allow exception; the crate is provably
  free of any site where a crafted input can corrupt memory (backing the README
  `unsafe forbidden` badge).
- `unwrap_used = "deny"` and `expect_used = "deny"` in production, with tests
  exempted via `clippy.toml` (`allow-unwrap-in-tests`) rather than scattered
  `#[allow]`s.
- Two `cargo-fuzz` targets driving the untrusted parse paths
  (`core/fuzz/fuzz_targets/`): `fuzz_header.rs` over `VeraHeader::validate` and
  `fuzz_unlock.rs` over `VeraVolume::unlock_with_password`, invariant *never
  panic*, built and smoke-run by `.github/workflows/fuzz.yml`.

## Consequences

Memory-corruption from a hostile volume is impossible by construction, not by
discipline, and `rg 'unsafe'` returns nothing to audit. "Panic-free" is carried
as the qualified *static* half (by-lint, bounds-checked readers) beside the
*measured* evidence (the fuzz targets), per the fleet robustness-wording rule —
never a bare unprovable "cannot panic" claim. The cost is that any genuinely
performance-critical `unsafe` optimization is off the table here; given the crate
is crypto-bound, that cost is nil.
