# SPEC-0001: Identity Provider and Conclave Bot Architecture

- Status: Accepted
- Authors: Christian M. Todie <chris@todie.io>
- Target: unsigned-gg/idp
- License: CC0-1.0 OR Apache-2.0 OR MIT

## Abstract

This document specifies the architecture for `idp`, the identity provider service for the unsigned-gg organization.
The system provisions dedicated GitHub App bot identities for 16 autonomous agent personas.
It stores private keys with strict host permissions and brokers installation access tokens.

## Problem Statement

Autonomous agent workflows across unsigned-gg require distinct Git committer and reviewer identities.
GitHub does not permit an API token to mint new GitHub Apps directly.
The GitHub App Manifest flow provides the only supported mechanism to create GitHub Apps programmatically.
Host environments require safe local storage and short-lived token brokering without long-lived personal access tokens.

## Architecture

The system consists of two primary operational components:

```
+-----------------------------------------------------------+
|                      Operator Browser                     |
+-----------------------------+-----------------------------+
                              | 1. Form POST
                              v
+-----------------------------------------------------------+
|               GitHub App Creation Endpoint                |
|  https://github.com/organizations/unsigned-gg/settings/   |
|                         apps/new                          |
+-----------------------------+-----------------------------+
                              | 2. Redirect with code
                              v
+-----------------------------------------------------------+
|                    idp Minting Server                     |
|           (Local Axum Service on :8787 / Tunnel)          |
+-----------------------------+-----------------------------+
                              | 3. POST /conversions
                              v
+-----------------------------------------------------------+
|                      GitHub REST API                      |
|          POST /app-manifests/{code}/conversions           |
+-----------------------------+-----------------------------+
                              | 4. Return PEM & Credentials
                              v
+-----------------------------------------------------------+
|                       Host Storage                        |
|       ~/.config/revenant/keys/<bot>.pem (mode 0600)       |
+-----------------------------------------------------------+
```

## Security Invariants

1. Inv-IDP-01 (Strict Permissions):
   Private key files on disk must hold POSIX file mode 0600.
   Parent key directories must hold POSIX directory mode 0700.

2. Inv-IDP-02 (JWT Lifetime Bound):
   RS256 JWT claims must set expiration to at most 600 seconds from issuance.
   Default issuance window sets `iat = now - 60` and `exp = now + 540`.

3. Inv-IDP-03 (Token Scope Singularity):
   Installation access tokens are ephemeral and requested on demand.
   Tokens inherit permissions defined in the static Conclave manifest.

4. Inv-IDP-04 (Host Throttling):
   All compilation and execution recipes must specify `-j 2` on ceres.

## Verification

The system enforces invariants through:
- Unit tests verifying manifest structure and permissions.
- File permission assertions in `test_keystore_permissions`.
- Zero-warning clippy and formatting gates.
