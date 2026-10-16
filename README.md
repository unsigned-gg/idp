# idp

Identity provider, Clockwork Conclave bot manager, and declarative multi-plane directory reconciliation engine for `unsigned-gg` and `cerebral-work/identity`.

## Overview

The `idp` workspace provides identity primitives across a 3-wave crate DAG:

- **Wave 0 (`crates/idp-domain`)**: Pure zero-I/O domain crate containing the 4-tier `Principal` authorization lattice, `CapabilityEnvelope` policy evaluators, GitHub App `AppManifest` models, and constant-time comparison / secret redaction primitives.
- **Wave 1 (`crates/idp`)**: Core identity library providing:
  - Declarative directory models (`directory/users.yaml`, `groups/*.yaml`, `orgunits.yaml`, `licenses.yaml`, `access-matrix.yaml`), schema validation, and byte-preserving `held_exceptions` YAML editing.
  - Group-declaration planes (`gam`, `foundation`, `unmanaged`) and undeclared groups detection.
  - Google Workspace and GitHub reconciliation planning, SHA-256 `plan_digest` verification, and structured `Findings` collection.
  - Cross-system `Presence` matrix evaluation across Google Workspace, GitHub, Slack, GCP IAM, Gitea, Tailscale, Keycloak, Teleport, and Bastion.
  - Clause-tested Kubernetes OIDC RBAC and `reflexd` `NetworkPolicy` admission detectors.
  - User onboarding and two-stage offboarding lifecycle primitives.
  - GitHub App Manifest conversion, RS256 JWT minting, installation token brokering, and 0600 keystore management for the 16 Clockwork Conclave elves.
- **Wave 2 (`crates/idp-cli`)**: Unified `idp` command-line interface (`list`, `manifest`, `token`, `validate`, `planes`, `undeclared-groups`, `reconcile`, `presence`, `detect`, `hold`, `unhold`, `onboard`, `offboard`, `check-principal`).
- **Automation (`crates/xtask`)**: Workspace DAG runner (`cargo xwork`, `cargo xtool`, `cargo xtask check --enforce-dbr --resume --break-check`, `cargo xtask graph-audit --break-check`).

## Quick Start

```bash
# Run the full compiled projectfile.yaml CI DAG
cargo xwork

# Run DBR-admitted verification pipeline with break-check
cargo xtask check --break-check --enforce-dbr

# Run workspace DAG and Wave-0 zero-I/O purity audit
cargo xtask graph-audit --break-check

# Validate declarative directory state
cargo run -j 2 --bin idp -- validate --repo /path/to/identity
```

## Build

```bash
cargo xtask ci        # tools, toolchain-check, fmt-check, clippy, test, doc-test, deny, typos, machete
cargo xtask install   # ci, then release builds of every binary
```

`cargo xtask ci` needs only cargo and rustup. rustup installs the Rust that
`rust-toolchain.toml` pins, and `cargo xtask tools` (the first step of `ci`) installs
cargo-deny, typos, cargo-machete and cargo-nextest at pinned versions into `.tools/`.
The steps are in [SPEC-0003](specs/0003-cargo-xtask-gates.md).

## License

Licensed under Apache-2.0 OR MIT OR CC0-1.0.
