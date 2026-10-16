---
status: Proposed
created: 2026-10-14
---

# SPEC-0003: cargo xtask Gates, ci and install

- Status: Proposed
- Target: unsigned-gg/idp
- License: CC0-1.0 OR Apache-2.0 OR MIT

## Abstract

Operator decision, Christian, 2026-10-13: `cargo xtask` is the one build entrypoint for every
estate repo, with nothing behind it but cargo and rustup. This spec adds the gates `cargo xtask
ci` and `cargo xtask install` run. They sit beside `xwork`, `check`, `graph-audit`, the
Makefile, the Justfile and the existing CI job. Nothing is removed.

## Requirements

- **XT-1 (ubiquitous):** xtask shall provide the commands `tools`, `toolchain-check`, `fmt`,
  `fmt-check`, `clippy`, `test`, `doc-test`, `deny`, `typos`, `machete`, `ci` and `install`, and
  keep every other command under its name.
- **XT-2 (ubiquitous):** xtask shall keep the version of each tool it runs in one table:
  cargo-deny 0.19.9, typos-cli 1.49.0, cargo-machete 0.9.1 and cargo-nextest 0.9.104.
- **XT-3 (event-driven):** When `tools` runs, xtask shall ask each tool for its version the way
  the gates run it, with `.tools/bin` first on `PATH`. Only for a tool that is missing or at
  another version shall it run `cargo install --locked --version <pin> --root .tools --force
  <crate>`, under Rust 1.94.1 (`rustup run --install 1.94.1`), because typos-cli 1.49.0 needs
  Rust 1.91 and the pinned toolchain is 1.88.0.
- **XT-4 (unwanted behaviour):** If a tool still reports another version after its install,
  then `tools` shall fail and name the tool and both versions.
- **XT-5 (unwanted behaviour):** If `rustc --version` differs from the `channel` in
  `rust-toolchain.toml`, then `toolchain-check` shall fail and name both. A channel of two parts
  (`1.88`) matches any patch of that minor version. `stable`, `beta` and `nightly` cannot be
  compared and pass, as before.
- **XT-6 (ubiquitous):** Each gate shall run from the repository root with `.tools/bin` first on
  `PATH`, and without the variables cargo sets for the xtask binary itself (`CARGO_PKG_*`,
  `CARGO_MANIFEST_DIR`, `CARGO_MANIFEST_PATH`, `CARGO_CRATE_NAME`, `CARGO_BIN_NAME`,
  `CARGO_PRIMARY_PACKAGE`). N is `JOBS`, else 2.
- **XT-7 (event-driven):** When `ci` runs, xtask shall run `tools`, `toolchain-check`,
  `fmt-check`, `clippy`, `test`, `doc-test`, `deny`, `typos` and `machete` in that order. It
  shall stop at the first step that fails, print one summary line per step, and exit non-zero
  if a step failed.
- **XT-8 (event-driven):** When `install` runs, xtask shall run `ci`, then
  `cargo build --release --workspace --exclude xtask --bins -j N`.
- **XT-9 (event-driven):** When CI runs for a push or a pull request, the job `xtask-ci` shall
  run `cargo xtask ci` on `ubuntu-latest`, the runner of the existing `check` job.

## Gates

| Gate | Runs |
|---|---|
| `fmt` | `cargo fmt --all` |
| `fmt-check` | `cargo fmt --all -- --check` |
| `clippy` | `cargo clippy --workspace --all-targets -j N -- -D warnings` |
| `test` | `cargo nextest run --workspace --build-jobs N`; `cargo test --workspace -j N` when nextest is missing |
| `doc-test` | `cargo test --doc --workspace -j N` |
| `deny` | `cargo deny check` |
| `typos` | `typos` |
| `machete` | `cargo machete` |

`.gitignore` keeps `Cargo.lock` out of the repository, so no gate passes `--locked`.
`cargo install --locked` for the tools uses each tool's own published lock file.

## Verification

```bash
cargo test -p xtask -j 2
cargo xtask ci
```

The code is `crates/xtask/src/gates.rs` and `crates/xtask/src/toolchain.rs`. Unit tests carry
the clause in their names. `.tools/` is gitignored.
