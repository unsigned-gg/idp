// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Identity Provider (`idp`) library for `unsigned-gg`, `cerebral-work/identity`, and Clockwork Conclave bots.
//!
//! Provides:
//! - GitHub App Manifest generation, conversion code exchange, RS256 JWT minting, and installation token brokering
//! - 4-tier [`Principal`] authorization lattice, [`CapabilityEnvelope`], and group reconciliation decisions
//! - Declarative directory models (`directory/`), schema validation, and hold/unhold YAML editing
//! - Google Workspace and GitHub reconciliation planning, SHA-256 plan digest verification, and structured [`Findings`]
//! - Cross-system [`Presence`] matrix evaluation and clause-tested Kubernetes RBAC / `NetworkPolicy` detectors
//! - User onboarding and two-stage offboarding lifecycle primitives

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod detectors;
pub mod directory;
pub mod error;
pub mod findings;
pub mod hydra;
pub mod lifecycle;
pub mod planes;
pub mod presence;
pub mod reconcile;
pub mod registry;
pub mod token;

pub use idp_domain::dcr;
pub use idp_domain::manifest;
pub use idp_domain::principal;
pub use idp_domain::security;
pub use reconcile as reconciler;

pub use dcr::{
    ActorClaim, AgentClientMetadata, CLIENT_ASSERTION_TYPE_JWT_BEARER, DcrValidationError,
    IntrospectedOAuth2Token, OAuth2ClientMetadata, OAuth2GrantType, OAuth2ResponseType,
    OAuth2TokenResponse, OidcDiscoveryDocument, Rfc7591ErrorCode, Rfc7591ErrorResponse,
    TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT, TokenEndpointAuthMethod,
    TokenExchangeRequest, WimseAgentId, WimseScheme,
};
pub use detectors::{
    DeclaredAdmission, FORBIDDEN_APPPROJECT_KINDS, Grant, OIDC_PREFIX, Rbac, SubmissionPeer,
    WIDE_ROLES, admits_port, bound_groups, canonical_peer, describe_peer, evaluate_oidc_bindings,
    evaluate_reflexd_admission, evaluate_tenant_appprojects, expected_cloudflare_emails,
    expected_tailscale_admins, load_declared_admission, missing_live_role_groups, oidc_grants,
    resolve_role, submission_peers, wildcard_rules,
};
pub use directory::{
    DesiredState, GroupRecord, HeldException, LicenseRecord, OrgUnitRecord, UserRecord, hold_text,
    load_desired_state, matrix_groups, missing_matrix_groups, missing_role_groups, split_header,
    unhold_text, validate_directory_schema, validate_identity_models,
};
pub use error::IdpError;
pub use findings::{FindingItem, Findings, FindingsPayload, part};
pub use hydra::{ClientAuth, OryHydraClient, OryHydraConfig, PrivateKeyJwtClaims};
pub use lifecycle::{OnboardRequest, stage_offboard, stage_onboard, stage_onboard_for_role};
pub use manifest::{AppManifest, ConversionResponse, HookAttributes};
pub use planes::{
    LiveGroupMember, all_declared, disjoint_planes_check, foundation_declared, gam_declared,
    undeclared_groups_report, unmanaged_declared,
};
pub use presence::{
    Presence, SlackMemberInput, collect_presence, declared_handles, evaluate_presence,
    parse_cloudflare_access_presence, parse_gitbook_presence, parse_keycloak_presence,
    parse_linear_presence, parse_slack_members, parse_tailscale_presence, src_cloudflare_access,
    src_declared, src_gitbook, src_keycloak, src_linear, src_tailscale, translate_github_members,
};
pub use principal::{
    CapabilityEnvelope, DELEGATED_SOVEREIGN_ROOT_EMAIL, DELEGATED_SOVEREIGN_ROOT_GITHUB,
    GroupDecision, PROHIBITED_SENSITIVE_PATHS, Principal, SOLE_SUPERADMIN_EMAIL,
    SOLE_SUPERADMIN_GITHUB, SOVEREIGN_ROOT_EMAILS, SOVEREIGN_ROOT_GITHUBS, SubjectMatterMesh,
    is_sovereign_root_email, is_sovereign_root_github, reconcile_group_decisions,
};
pub use reconcile::{
    LiveDirectoryState, LiveGroup, LiveUser, ReconcilePlan, apply_refusal, held_members,
    plan_admin, plan_digest, plan_findings, plan_github, plan_groups, plan_licenses, plan_orgunits,
    plan_users, reconcile_directory, redact, shlex_quote, uncreated,
};
pub use registry::{
    ALL_ESTATE_ELVES, CONCLAVE_ELVES, ElfPersona, KeyStore, find_elf, is_automation_login,
};
pub use security::{
    COMPLIANCE_FAILED, COMPLIANCE_NOT_RUN, COMPLIANCE_OK, constant_time_eq, redact_password,
    redact_tokens,
};
pub use token::{InstallationToken, TokenBroker};
