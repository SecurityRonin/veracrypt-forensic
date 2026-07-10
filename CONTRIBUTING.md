# Contributing to veracrypt-forensic

Thanks for your interest in improving `veracrypt-forensic`. These crates parse
untrusted VeraCrypt / TrueCrypt volumes acquired from potentially compromised
systems, so correctness and robustness are not negotiable. The bar is high and the
workflow is strict — please read this before opening a pull request.

The VeraCrypt reader and analyzer ship on crates.io; see
[`docs/RESEARCH.md`](docs/RESEARCH.md) for the on-disk format research behind the
design. The disciplines below apply to every change.

## Test-Driven Development is mandatory

Every code change follows strict Red-Green-Refactor, and the RED and GREEN steps
land as **two separate commits**:

1. **RED** — write the failing test(s) first. They must define the expected
   behaviour and actually fail. Commit them alone. This commit is the verifiable
   proof that the test was written first.
2. **GREEN** — write the minimal implementation that makes the tests pass. Commit
   it separately.
3. **REFACTOR** — clean up while keeping every test green.

A single combined commit is not accepted. There is no "hard to test" exemption: if
something is awkward to unit test, use the closest testable abstraction, fixtures,
or an integration test — but write the test first.

Because you are validating code you wrote with tests you wrote, also validate
against **real external data** where it matters: cross-check decryption against a
real VeraCrypt volume and an independent oracle (`cryptsetup --veracrypt` and the
VeraCrypt binary itself), not only synthetic fixtures.

## Quality gates

All of the following must pass locally and in CI before a PR can merge:

```bash
cargo fmt --all -- --check                             # formatting
cargo clippy --workspace --all-targets -- -D warnings  # lints, warnings denied
cargo deny check                                       # license / advisory / source policy
cargo test --workspace                                 # unit + integration
cargo llvm-cov --workspace --show-missing-lines        # 100% line coverage
```

- **Formatting** — `cargo fmt`; do not hand-format.
- **Lints** — `cargo clippy` with warnings denied.
- **Dependencies** — `cargo deny` must pass (no copyleft, no flagged advisories).
- **Coverage** — 100% line coverage is enforced; no source line may be left
  uncovered unless it carries a `// cov:unreachable` marker for a provably-dead
  defensive arm. New code needs tests that exercise its error paths, not just the
  happy path.
- **Fuzzing** — every parsed structure gets a `cargo-fuzz` target whose invariant
  is "must not panic," plus a CI workflow that smoke-runs each target. A parser
  change must keep its fuzz targets green.

## Robustness expectations

- No panics on malicious input — validate every length and offset against both the
  declared size and the actual buffer; use bounds-checked readers.
- Fail loud — surface malformed input as a typed error with enough context to
  diagnose it. Never swallow an error or substitute a silent default.
- Never hand-roll a cryptographic primitive — reach for the audited RustCrypto
  crate. A missing audited implementation (e.g. 256-bit Serpent) is a reason to
  defer a feature, not to ship unaudited crypto.
- Keep `#![forbid(unsafe_code)]` intact.

## Commits and signing

- Keep diffs minimal — change only the lines the task requires; no drive-by
  reformatting of unrelated code.
- Commits are signed with [gitsign](https://github.com/sigstore/gitsign) (keyless
  Sigstore signing). Ensure your commits are signed before pushing.

## Reporting security issues

Do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for the private reporting process.
