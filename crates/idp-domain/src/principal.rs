// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! 4-tier Principal lattice, Clockwork Elf capability envelopes, and group reconciliation decisions.
//!
//! Borrowed from `xerj` (`Principal`), `researchd` (trusted root attestation),
//! `keycloak-extensions` (`GroupReconciler`), and `cerebral-work/identity` (`policies.yaml`).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Sole human superadmin email across all estate control planes.
pub const SOLE_SUPERADMIN_EMAIL: &str = "ctodie@cerebral.work";

/// Sole human superadmin GitHub login across all estate organizations.
pub const SOLE_SUPERADMIN_GITHUB: &str = "todie";

/// Paths in `cerebral-work/identity` that Clockwork Elves are never permitted to modify.
pub const PROHIBITED_SENSITIVE_PATHS: &[&str] = &[
    "directory/roles.yaml",
    "directory/policies.yaml",
    "directory/role-matrix.yaml",
    "terraform/org-admins/",
    ".github/workflows/",
    "CODEOWNERS",
];

/// Four-tier authorization lattice ordered strictly from least to greatest privilege:
/// `Denied < Unscoped < Scoped < Superuser`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "tier", rename_all = "snake_case")]
pub enum Principal {
    /// Unauthenticated, suspended, or explicitly denied subject.
    Denied,
    /// Authenticated subject whose scopes have not yet been narrowed to a mesh or org unit.
    Unscoped,
    /// Subject restricted to an explicit set of scopes (groups, repositories, or meshes).
    Scoped {
        /// Allowed scope identifiers (sorted set of groups, repos, or mesh tags).
        scopes: BTreeSet<String>,
    },
    /// Break-glass operator superadmin (`ctodie@cerebral.work` / `todie` only).
    Superuser,
}

impl Principal {
    /// Resolves a human user record into a `Principal` tier.
    ///
    /// Enforces the single-superadmin invariant: only `ctodie@cerebral.work` can hold `Superuser`
    /// when `is_super_admin` is true; any other user claiming `is_super_admin` is rejected (`Denied`).
    pub fn for_human(
        email: &str,
        suspended: bool,
        is_super_admin: bool,
        scopes: BTreeSet<String>,
    ) -> Self {
        if suspended {
            return Self::Denied;
        }
        if is_super_admin {
            if email.eq_ignore_ascii_case(SOLE_SUPERADMIN_EMAIL) {
                return Self::Superuser;
            }
            return Self::Denied;
        }
        if scopes.is_empty() {
            Self::Unscoped
        } else {
            Self::Scoped { scopes }
        }
    }

    /// Returns true if the principal is permitted to access the requested scope.
    pub fn allows_scope(&self, scope: &str) -> bool {
        match self {
            Self::Denied | Self::Unscoped => false,
            Self::Scoped { scopes } => scopes.contains(scope),
            Self::Superuser => true,
        }
    }
}

/// Subject-matter mesh classification for Clockwork Elves and estate services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectMatterMesh {
    /// Kernel, sandbox, Landlock, and process supervision (`idunn`, `brokkr`, `vali`, `gullveig`, `heimdall`).
    KernelRuntime,
    /// Memory, search, specification parsing, and autonomous research (`mimir`, `loki`, `thjalfi`, `sigyn`, `thuban`, `njord`, `norns`, `sol`).
    MemorySearch,
    /// Identity, attestation, policy enforcement, and charter (`vidar`, `tyr`, `bragi`).
    IdentityGovernance,
    /// Cluster control, workflow orchestration, and fleet reconciliation (`sindri`, `volva`, `kratos`, `forseti`, `ratatoskr`).
    PlatformControl,
    /// Ecosystem catalog and documentation (`alrisha`).
    EcosystemCatalog,
    /// Operator-owned estate control (`ctodie@cerebral.work`).
    OperatorEstate,
}

/// Bounded capability envelope for a Clockwork Elf automation identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEnvelope {
    /// Elf identifier (e.g. `"sindri"`).
    pub elf_id: String,
    /// Assigned subject-matter mesh.
    pub mesh: SubjectMatterMesh,
    /// Repositories this elf is permitted to operate on.
    pub allowed_repos: BTreeSet<String>,
}

impl CapabilityEnvelope {
    /// Checks whether the elf may modify `repo` and `file_path`.
    ///
    /// Elves are unconditionally barred from modifying [`PROHIBITED_SENSITIVE_PATHS`].
    pub fn can_modify_path(&self, repo: &str, file_path: &str) -> bool {
        if !self.allowed_repos.contains(repo) && !self.allowed_repos.contains("*") {
            return false;
        }
        let normalized = file_path.trim_start_matches('/');
        for forbidden in PROHIBITED_SENSITIVE_PATHS {
            if forbidden.ends_with('/') {
                if normalized.starts_with(forbidden) {
                    return false;
                }
            } else if normalized == *forbidden {
                return false;
            }
        }
        true
    }
}

/// Group membership reconciliation decision (extracted from `keycloak-extensions` `GroupReconciler`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupDecision {
    /// Add the user to the group (present in desired state, absent in live state).
    Join,
    /// Retain the user in the group (present in both desired and live state, or unmanaged group).
    Keep,
    /// Remove the user from the group (absent in desired state, present in live managed group).
    Leave,
    /// Refuse membership (group is protected/admin-tier and user is not authorized).
    Deny,
}

/// Computes per-group reconciliation decisions across `live_groups` and `desired_groups`.
///
/// Only groups in `managed_groups` are subject to `Leave`; unmanaged groups default to `Keep`.
/// Groups in `protected_admin_groups` yield `Deny` unless `is_authorized_admin` is true.
pub fn reconcile_group_decisions(
    desired_groups: &BTreeSet<String>,
    live_groups: &BTreeSet<String>,
    managed_groups: &BTreeSet<String>,
    protected_admin_groups: &BTreeSet<String>,
    is_authorized_admin: bool,
) -> BTreeMap<String, GroupDecision> {
    let mut decisions = BTreeMap::new();
    let all_groups: BTreeSet<&String> = desired_groups.union(live_groups).collect();

    for group in all_groups {
        if protected_admin_groups.contains(group) && !is_authorized_admin {
            decisions.insert(group.clone(), GroupDecision::Deny);
            continue;
        }
        let in_desired = desired_groups.contains(group);
        let in_live = live_groups.contains(group);
        let is_managed = managed_groups.contains(group);

        let decision = match (in_desired, in_live, is_managed) {
            (true, false, _) => GroupDecision::Join,
            (true, true, _) => GroupDecision::Keep,
            (false, true, true) => GroupDecision::Leave,
            (false, true, false) => GroupDecision::Keep,
            (false, false, _) => continue,
        };
        decisions.insert(group.clone(), decision);
    }

    decisions
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_ordering_and_sole_superadmin() {
        let scopes = BTreeSet::from(["gcp-developers".to_string()]);
        let denied = Principal::Denied;
        let unscoped = Principal::Unscoped;
        let scoped = Principal::Scoped {
            scopes: scopes.clone(),
        };
        let superuser = Principal::Superuser;

        assert!(denied < unscoped);
        assert!(unscoped < scoped);
        assert!(scoped < superuser);

        // Sole superadmin check
        assert_eq!(
            Principal::for_human("ctodie@cerebral.work", false, true, BTreeSet::new()),
            Principal::Superuser
        );
        assert_eq!(
            Principal::for_human("ahackley@cerebral.work", false, true, scopes),
            Principal::Denied
        );
    }

    #[test]
    fn test_capability_envelope_blocks_sensitive_paths() {
        let env = CapabilityEnvelope {
            elf_id: "vidar".to_string(),
            mesh: SubjectMatterMesh::IdentityGovernance,
            allowed_repos: BTreeSet::from(["identity".to_string()]),
        };
        assert!(env.can_modify_path("identity", "directory/users.yaml"));
        assert!(!env.can_modify_path("identity", "directory/policies.yaml"));
        assert!(!env.can_modify_path("identity", ".github/workflows/validate.yaml"));
        assert!(!env.can_modify_path("other-repo", "README.md"));
    }

    #[test]
    fn test_group_reconciler_decisions() {
        let desired = BTreeSet::from(["dev".to_string(), "new-team".to_string()]);
        let live = BTreeSet::from([
            "dev".to_string(),
            "old-team".to_string(),
            "unmanaged-club".to_string(),
            "gcp-organization-admins".to_string(),
        ]);
        let managed = BTreeSet::from([
            "dev".to_string(),
            "new-team".to_string(),
            "old-team".to_string(),
            "gcp-organization-admins".to_string(),
        ]);
        let protected = BTreeSet::from(["gcp-organization-admins".to_string()]);

        let res = reconcile_group_decisions(&desired, &live, &managed, &protected, false);
        assert_eq!(res.get("dev"), Some(&GroupDecision::Keep));
        assert_eq!(res.get("new-team"), Some(&GroupDecision::Join));
        assert_eq!(res.get("old-team"), Some(&GroupDecision::Leave));
        assert_eq!(res.get("unmanaged-club"), Some(&GroupDecision::Keep));
        assert_eq!(
            res.get("gcp-organization-admins"),
            Some(&GroupDecision::Deny)
        );
    }
}
