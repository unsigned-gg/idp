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
pub mod lifecycle;
pub mod planes;
pub mod presence;
pub mod reconcile;
pub mod registry;
pub mod token;

pub use idp_domain::manifest;
pub use idp_domain::principal;
pub use idp_domain::security;

pub use directory::{
    DesiredState, GroupRecord, HeldException, LicenseRecord, OrgUnitRecord, UserRecord, hold_text,
    load_desired_state, matrix_groups, missing_matrix_groups, split_header, unhold_text,
    validate_directory_schema, validate_identity_models,
};
pub use error::IdpError;
pub use findings::{FindingItem, Findings, FindingsPayload, part};
pub use lifecycle::{OnboardRequest, stage_offboard, stage_onboard};
pub use manifest::{AppManifest, ConversionResponse, HookAttributes};
pub use planes::{
    LiveGroupMember, all_declared, foundation_declared, gam_declared, undeclared_groups_report,
    unmanaged_declared,
};
pub use presence::{
    Presence, SlackMemberInput, declared_handles, evaluate_presence, parse_slack_members,
    src_declared, translate_github_members,
};
pub use principal::{
    CapabilityEnvelope, GroupDecision, PROHIBITED_SENSITIVE_PATHS, Principal,
    SOLE_SUPERADMIN_EMAIL, SOLE_SUPERADMIN_GITHUB, SubjectMatterMesh, reconcile_group_decisions,
};
pub use reconcile::{
    LiveGroup, LiveUser, ReconcilePlan, apply_refusal, held_members, plan_admin, plan_digest,
    plan_findings, plan_github, plan_groups, plan_licenses, plan_orgunits, plan_users, redact,
};
pub use registry::{
    ALL_ESTATE_ELVES, CONCLAVE_ELVES, ElfPersona, KeyStore, find_elf, is_automation_login,
};
pub use security::{
    COMPLIANCE_FAILED, COMPLIANCE_NOT_RUN, COMPLIANCE_OK, constant_time_eq, redact_password,
    redact_tokens,
};
pub use token::{InstallationToken, TokenBroker};
