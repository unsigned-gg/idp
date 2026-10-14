---
status: Active
created: 2026-10-14
---

# SPEC-0002: Multi-Plane Directory Reconciliation, Drift Detectors, and Lifecycle Engine

- Status: Accepted
- Authors: Christian M. Todie <chris@todie.io>
- Target: unsigned-gg/idp
- License: CC0-1.0 OR Apache-2.0 OR MIT

## Abstract

This document specifies the multi-plane identity directory, reconciliation planner, security invariant evaluation, drift detectors, and atomic lifecycle scaffold in `unsigned-gg/idp`.

## Workspace Wave Architecture

1. **Wave 0 (`crates/idp-domain`)**:
   - Pure zero-I/O leaf crate containing `Principal`, `PrincipalKind`, `AccessTier`, `SecurityPolicy`, `SecurityInvariant`, `Manifest`, `AppPermissions`, and the 16 Conclave Elves (`ELVES`).
   - Enforced by `cargo xtask zero-io-domain` and `cargo xtask graph-audit`.

2. **Wave 1 (`crates/idp`)**:
   - Re-exports `idp-domain` and adds directory parsing (`directory.rs`), GAM/Terraform plane membership projection (`planes.rs`), set-difference reconciliation (`reconcile.rs`), multi-plane presence matrix (`presence.rs`), SARIF/Markdown/JSON findings (`findings.rs`), drift detectors (`detectors.rs`), atomic user onboarding/offboarding (`lifecycle.rs`), and GitHub App token minting (`token.rs`, `registry.rs`).

3. **Wave 2 (`crates/idp-cli`)**:
   - Unified `idp` CLI providing `list`, `manifest`, `mint`, `token`, `validate`, `planes`, `reconcile`, `presence`, `detect`, `audit-security`, `onboard`, and `offboard`.
