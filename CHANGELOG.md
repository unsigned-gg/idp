# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `dfaroughy@cerebral.work` (`dfaroughy`) joins the Sovereign Root set, by operator ruling 2026-10-26.
- `SOVEREIGN_ROOT_EMAILS` and `SOVEREIGN_ROOT_GITHUBS` in `idp-domain::principal`: the Sovereign Root set now holds `ctodie`, `ahackley`, and the co-founders `pgray` and `mmasterson` (`madmax983`), by operator ruling 2026-10-26. `is_sovereign_root_email` and `is_sovereign_root_github` read the set. The existing single-root constants stay exported.
- Extracted pure Wave-0 domain leaf crate `idp-domain` (`principal`, `security`, `manifest`) enforcing zero runtime I/O (`cargo xtask zero-io-domain`).
- Extracted multi-plane identity primitives into `idp`:
  - `directory`: Declarative `directory/` models (`users.yaml`, `groups/*.yaml`, `orgunits.yaml`, `licenses.yaml`, `access-matrix.yaml`), schema validators, and byte-preserving `held_exceptions` YAML editor (`hold_text`, `unhold_text`).
  - `planes`: Group declaration planes (`gam`, `foundation`, `unmanaged`) and undeclared groups detector.
  - `reconcile`: Google Workspace and GitHub reconciliation planner (`plan_orgunits`, `plan_users`, `plan_admin`, `plan_groups`, `plan_licenses`, `plan_github`), SHA-256 `plan_digest` gate, `apply_refusal`, and structured findings mapper.
  - `presence`: Cross-system presence matrix (`users.yaml`, Google Workspace, GitHub orgs, Slack, GCP IAM, Gitea, Tailscale, Keycloak, Teleport, Bastion).
  - `detectors`: Clause-tested Kubernetes RBAC (`detect_oidc_bindings`) and `NetworkPolicy` (`detect_reflexd_admission`) drift detectors.
  - `findings`: Key-normalized deduplicated findings collector and `$FINDINGS_FILE` JSON emitter.
  - `lifecycle`: User onboarding (`stage_onboard`) and two-stage offboarding (`stage_offboard`) primitives.
- Added `xtask` workspace automation crate (`cargo xwork`, `cargo xtool`, `cargo xtask check --enforce-dbr --resume --break-check`, `cargo xtask graph-audit --break-check`, `projectfile-check`, `stages-check`, `spec-check`, `toolchain-check`, `branch-hygiene`).
- Added `projectfile.yaml`, `rust-toolchain.toml` (`1.88.0`), and `.cargo/config.toml` (`xtask`, `xwork`, `xtool` aliases with `-j 2`).
- Added Ory Hydra Dynamic Client Registration (RFC 7591 / RFC 7592), OAuth 2.0 Token Exchange (RFC 8693), Token Introspection (RFC 7662), and IETF `draft-klrc-aiagent-auth-03` WIMSE/SPIFFE Agent Identity adapter (`idp_domain::dcr`, `idp::hydra::OryHydraClient`, and `idp dcr` CLI subcommand).
- Added `GET /dcr/metadata/{bot}`, `GET /.well-known/jwks/{bot}`, and `POST /dcr/register` routes to `idp manifest serve` (`idp-cli`) with deterministic mesh inference (`mesh_for_bot`) and keystore-backed registration receipt persistence.
- Added co-protected Sovereign Root (`ctodie@cerebral.work` / `todie` and `ahackley@cerebral.work` / `LordVoid`) lockout guards across `idp-domain` (`principal`, `reconciler`) and `idp` (`directory`).
- Unified role, bundle, and policy schema validation (`roles.yaml` + `bundles.yaml` + `policies.yaml`), retiring legacy `role-matrix.yaml` and enforcing disjoint group declaration planes (`gam_declared ∩ foundation_declared == ∅`).
- Added live presence parsers and HTTP probes for `keycloak`, `tailscale`, `linear`, `cloudflare-access`, and `gitbook` (`idp presence`), plus `detect_tenant_appprojects` and `idp reconcile role-matrix-live`.
- Added in-cluster `GET /healthz`, `GET /readyz`, `POST /internal/group-decisions`, and `POST /oauth2/token-exchange` routes to `idp-cli` server.
