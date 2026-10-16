// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Wave-0 pure zero-I/O domain crate for `idp`.
//!
//! Contains pure algebraic types, the 4-tier [`Principal`] authorization lattice,
//! [`CapabilityEnvelope`] policy evaluators, GitHub App [`AppManifest`] definitions,
//! and constant-time comparison / secret redaction primitives.
//!
//! # Invariant
//! Zero runtime I/O (`std::net`, `std::fs`, `std::process`, `tokio::`) is permitted in this crate.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod dcr;
pub mod manifest;
pub mod principal;
pub mod reconciler;
pub mod security;

pub use dcr::{
    ActorClaim, AgentClientMetadata, CLIENT_ASSERTION_TYPE_JWT_BEARER, DcrValidationError,
    ESTATE_SUPERUSER_SCOPE, GRANT_TYPE_JWT_BEARER, GRANT_TYPE_TOKEN_EXCHANGE,
    IntrospectedOAuth2Token, OAuth2ClientMetadata, OAuth2GrantType, OAuth2ResponseType,
    OAuth2TokenResponse, OidcDiscoveryDocument, Rfc7591ErrorCode, Rfc7591ErrorResponse,
    TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT, TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_TRANSACTION_TOKEN, TokenEndpointAuthMethod, TokenExchangeRequest, WimseAgentId,
    WimseScheme, decode_form_urlencoded, encode_form_urlencoded,
};
pub use manifest::{AppManifest, ConversionResponse, HookAttributes};
pub use principal::{
    CapabilityEnvelope, GroupDecision, PROHIBITED_SENSITIVE_PATHS, Principal,
    SOLE_SUPERADMIN_EMAIL, SOLE_SUPERADMIN_GITHUB, SubjectMatterMesh, reconcile_group_decisions,
};
pub use reconciler::{
    GroupRecord, HeldException, LicenseRecord, LiveGroup, LiveUser, OrgUnitRecord, ReconcilePlan,
    UserRecord, apply_refusal, held_members, plan_admin, plan_digest, plan_github, plan_groups,
    plan_licenses, plan_orgunits, plan_users, redact, shlex_quote, uncreated,
};
pub use security::{
    COMPLIANCE_FAILED, COMPLIANCE_NOT_RUN, COMPLIANCE_OK, constant_time_eq, redact_password,
    redact_tokens,
};
