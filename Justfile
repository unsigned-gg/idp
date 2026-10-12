# Justfile for idp (Identity Provider & Conclave Bot Manager)
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

# Compile the workspace with locked dependencies and host throttling
build:
    cargo build --workspace -j {{jobs}}

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

# The push gate: fmt-check, clippy, test, doc-test
check: fmt-check clippy test doc-test

# What the CI rust job runs
ci:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -j {{jobs}} -- -D warnings
    cargo test --workspace -j {{jobs}}
    cargo test --doc --workspace -j {{jobs}}

# Audit licenses, bans, and advisories
deny:
    cargo deny check

# Check dependencies for known advisories
audit:
    cargo audit

# Build CLI and run smoke tests
smoke:
    cargo build --package idp-cli -j {{jobs}}
    cargo run --package idp-cli -j {{jobs}} -- bot list
