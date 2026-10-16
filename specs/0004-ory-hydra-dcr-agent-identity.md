---
status: Active
created: 2026-10-15
---

# Spec 0004: Ory Hydra Dynamic Client Registration (RFC 7591) & WIMSE Agent Identity Adapter

## 1. Objective

Provide an Ory Hydra OAuth 2.0 / OIDC Dynamic Client Registration (RFC 7591 / RFC 7592), Token Exchange (RFC 8693), Token Introspection (RFC 7662), and IETF `draft-klrc-aiagent-auth-03` WIMSE/SPIFFE Agent Identity adapter across Wave-0 (`idp-domain`), Wave-1 (`idp`), and Wave-2 (`idp-cli`) (Reverie `#36703`).

## 2. Wave Architecture

- **Wave-0 (`crates/idp-domain/src/dcr.rs`)**: Pure, zero-I/O domain types and validation rules:
  - `WimseAgentId` and `WimseScheme` (`spiffe://<trust_domain>/<workload_path>` and `wimse://<trust_domain>/<workload_path>`) with deterministic Clockwork Conclave elf builders (`WimseAgentId::for_conclave_elf`).
  - `OAuth2ClientMetadata` and `AgentClientMetadata` modeling RFC 7591 Section 2, RFC 7592 management responses, and Ory Hydra `/admin/clients` extensions, with mandatory secret redaction (`Debug` and `.redacted()`).
  - `OAuth2ClientMetadata::validate_rfc7591` enforcing RFC 7591 grant-type/response-type pairings, HTTPS/loopback redirect URI safety, cryptographic client authentication (`private_key_jwt` or `tls_client_auth`) for autonomous agents, and JWKS material presence (`jwks_uri` or inline `jwks`).
  - `TokenExchangeRequest` (RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange`) and RFC 3986 form-urlencoding helpers.
  - `IntrospectedOAuth2Token` and recursive `ActorClaim` (`act` delegation chain) mapping RFC 7662 introspection responses into the 4-tier `Principal` authorization lattice while preserving the Sovereign Root guard (`ctodie@cerebral.work` / `todie`).
- **Wave-1 (`crates/idp/src/hydra.rs`)**: Async `OryHydraClient` HTTP adapter:
  - OIDC Discovery (`GET /.well-known/openid-configuration`).
  - Public RFC 7591 registration (`POST /oauth2/register`) and RFC 7592 client configuration lifecycle (`GET`, `PUT`, `DELETE /oauth2/register/{client_id}`).
  - Admin API client CRUD (`/admin/clients`) and RFC 7662 token introspection (`POST /admin/oauth2/introspect`).
  - OAuth 2.0 `/oauth2/token` flows (`client_credentials` and RFC 8693 `token-exchange`) supporting `client_secret_basic`, `client_secret_post`, and RS256 `private_key_jwt` (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, RFC 7523).
- **Wave-2 (`crates/idp-cli/src/main.rs`)**:
  - `idp dcr metadata`, `idp dcr register`, and `idp dcr introspect` CLI subcommands.

## 3. Security Invariants

1. **Zero Secret Leakage in Debug/Display/CLI**: `OAuth2ClientMetadata`, `OAuth2TokenResponse`, `TokenExchangeRequest`, `OryHydraConfig`, and `ClientAuth` redact all client secrets, bearer tokens, and PEM keys in `Debug` implementations and `.redacted()` projections.
2. **Cryptographic Agent Authentication**: Autonomous agents registered with `AgentClientMetadata` (`require_cryptographic_agent_auth = true`) must authenticate via `private_key_jwt` or `tls_client_auth` and declare a valid WIMSE/SPIFFE workload URI (`spiffe://` or `wimse://`).
3. **Sovereign Root Guard on Introspection**: An introspected token carrying `estate:superuser` scope is rejected (`Principal::Anonymous`) unless its subject or verified email matches `SOLE_SUPERADMIN_EMAIL` (`ctodie@cerebral.work`) or `SOLE_SUPERADMIN_GITHUB` (`todie`).
