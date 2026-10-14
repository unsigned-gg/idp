# Justfile for idp (Identity Provider, Conclave Bot Manager & Directory Reconciler)
# Host Throttling: Physical host ceres runs multiple active agent sessions.
# Shared workstations keep jobs=2 to prevent CPU starvation and OOM.

set shell := ["bash", "-euo", "pipefail", "-c"]

jobs := "2"

# Display available commands
default:
    @just --list 2>/dev/null || make help

# Display this help message
help:
    @just --list 2>/dev/null || make help

# Execute the full compiled projectfile.yaml CI DAG (cargo xwork)
xwork:
    cargo xwork

# Run DBR-admitted verification pipeline with CAS receipts
check:
    cargo xtask check --enforce-dbr

# Verify workspace crate DAG and Wave-0 idp-domain purity
graph-audit:
    cargo xtask graph-audit --break-check

# Verify Wave-0 idp-domain has zero I/O or runtime dependencies
zero-io-domain:
    cargo xtask zero-io-domain

# Validate projectfile.yaml schema and CI nodes
projectfile-check:
    cargo xtask projectfile-check

# Verify stages.rs matches projectfile.yaml
stages-check:
    cargo xtask stages-check

# Validate markdown specs in specs/*.md
spec-check:
    cargo xtask spec-check

# Verify active rustc matches rust-toolchain.toml
toolchain-check:
    cargo xtask toolchain-check

# Audit merged local git branches
branch-hygiene:
    cargo xtask branch-hygiene --dry-run

# Compile the workspace with locked dependencies and host throttling
build:
    cargo build --workspace -j {{jobs}}

# Install idp CLI to ~/.cargo/bin/idp
install:
    cargo install --path crates/idp-cli -j {{jobs}}

# Format all code
fmt:
    cargo fmt --all

# Check code formatting without modifying
fmt-check:
    cargo fmt --all -- --check

# Lint with clippy, warnings are errors
clippy:
    cargo clippy --workspace --all-targets -j {{jobs}} -- -D warnings

# Run unit and integration tests with bounded threads
test:
    cargo test --workspace -j {{jobs}}

# Run doc tests
doc-test:
    cargo test --doc --workspace -j {{jobs}}

# What the CI rust job runs
ci:
    cargo xwork
    cargo xtask graph-audit --break-check
    cargo xtask check --break-check

# Audit licenses, bans, and advisories
deny:
    cargo deny check

# Check dependencies for known advisories
audit:
    cargo audit

# Build CLI and run smoke tests
smoke:
    cargo build --package idp-cli -j {{jobs}}
    cargo run --package idp-cli -j {{jobs}} -- list
