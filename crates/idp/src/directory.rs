// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Declarative directory models, desired-state loader, schema validators, and YAML hold/unhold editor.
//!
//! Extracted from `cerebral-work/identity/scripts/reconcile/reconcile.py`,
//! `test_reconcile.py`, `test_identity_models.py`, and `scripts/lifecycle/_yamlio.py`.

use crate::error::IdpError;
use crate::planes::{all_declared, disjoint_planes_check, unmanaged_declared};
use crate::principal::{
    DELEGATED_SOVEREIGN_ROOT_EMAIL, DELEGATED_SOVEREIGN_ROOT_GITHUB, SOLE_SUPERADMIN_EMAIL,
    SOLE_SUPERADMIN_GITHUB, is_sovereign_root_email,
};
use crate::registry::is_automation_login;
use chrono::NaiveDate;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

#[allow(clippy::expect_used)]
static GROUP_EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9-]+@cerebral\.work$").expect("valid group email regex"));

pub use idp_domain::reconciler::{
    GroupRecord, HeldException, LicenseRecord, OrgUnitRecord, UserRecord,
};

/// Complete desired directory state loaded from `directory/`.
#[derive(Debug, Clone)]
pub struct DesiredState {
    /// Users keyed by email address.
    pub users: BTreeMap<String, UserRecord>,
    /// Declared organizational unit paths.
    pub orgunits: BTreeSet<String>,
    /// Groups keyed by group email address.
    pub groups: BTreeMap<String, GroupRecord>,
    /// Licenses keyed by `sku_id`.
    pub licenses: BTreeMap<String, LicenseRecord>,
    /// Admin roles keyed by user email.
    pub admin_roles: BTreeMap<String, BTreeSet<String>>,
    /// Managed GitHub organizations mapping `org -> {lowercase_handle}` of active members.
    pub github_orgs: BTreeMap<String, BTreeSet<String>>,
    /// Lowercase GitHub handles of users who are `suspended: true` or in `/Offboarding` / `/Suspended-Offboarding`.
    pub leaving_github: BTreeSet<String>,
    /// Lowercase GitHub handles of all active users in `directory/users.yaml`.
    pub declared_github: BTreeSet<String>,
}

/// Loads the complete desired state from `repo/directory/`.
pub fn load_desired_state(repo: &Path) -> Result<DesiredState, IdpError> {
    let dir = repo.join("directory");

    // 1. Users
    let users_text = fs::read_to_string(dir.join("users.yaml"))?;
    let users_doc: serde_yaml::Value = serde_yaml::from_str(&users_text)?;
    let mut users = BTreeMap::new();
    let mut admin_roles = BTreeMap::new();
    let mut github_orgs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if let Some(orgs) = users_doc
        .get("managed_github_orgs")
        .and_then(|v| v.as_sequence())
    {
        for o in orgs {
            if let Some(org_str) = o.as_str() {
                github_orgs.insert(org_str.to_string(), BTreeSet::new());
            }
        }
    }

    let mut leaving_github = BTreeSet::new();
    let mut declared_github = BTreeSet::new();

    if let Some(seq) = users_doc.get("users").and_then(|v| v.as_sequence()) {
        for item in seq {
            let mut rec: UserRecord = serde_yaml::from_value(item.clone())?;
            if rec.admin.as_deref() == Some("super") {
                rec.is_super_admin = true;
            }
            admin_roles.insert(rec.email.clone(), rec.admin_roles.clone());
            if let Some(ref gh) = rec.github_handle {
                let lower = gh.to_lowercase();
                if rec.suspended
                    || rec.org_unit == "/Offboarding"
                    || rec.org_unit == "/Suspended-Offboarding"
                {
                    leaving_github.insert(lower);
                } else {
                    declared_github.insert(lower.clone());
                    for org in &rec.github_orgs {
                        github_orgs
                            .entry(org.clone())
                            .or_default()
                            .insert(lower.clone());
                    }
                }
            }
            users.insert(rec.email.clone(), rec);
        }
    }

    // 2. Orgunits
    let ou_text = fs::read_to_string(dir.join("orgunits.yaml"))?;
    let ou_doc: serde_yaml::Value = serde_yaml::from_str(&ou_text)?;
    let mut orgunits = BTreeSet::new();
    if let Some(seq) = ou_doc.get("orgunits").and_then(|v| v.as_sequence()) {
        for item in seq {
            if let Some(p) = item.get("path").and_then(|v| v.as_str()) {
                orgunits.insert(p.to_string());
            }
        }
    }

    // 3. Groups
    let mut groups = BTreeMap::new();
    let groups_dir = dir.join("groups");
    if groups_dir.exists() {
        let mut entries: Vec<_> = fs::read_dir(&groups_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
            .collect();
        entries.sort();
        for p in entries {
            let g_text = fs::read_to_string(&p)?;
            let g_val: serde_yaml::Value = serde_yaml::from_str(&g_text)?;
            let email = g_val
                .get("email")
                .and_then(|v| v.as_str())
                .ok_or_else(|| IdpError::Validation(format!("{}: missing email", p.display())))?
                .to_string();
            let name = g_val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&email)
                .to_string();
            let description = g_val
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let mut settings = BTreeMap::new();
            if let Some(s_map) = g_val.get("settings").and_then(|v| v.as_mapping()) {
                for (k, v) in s_map {
                    if let Some(ks) = k.as_str() {
                        let vs = match v {
                            serde_yaml::Value::String(s) => s.clone(),
                            serde_yaml::Value::Bool(b) => b.to_string(),
                            serde_yaml::Value::Number(n) => n.to_string(),
                            _ => continue,
                        };
                        settings.insert(ks.to_string(), vs);
                    }
                }
            }

            let mut members = BTreeSet::new();
            let mut managers = BTreeSet::new();
            let mut owners = BTreeSet::new();

            if let Some(seq) = g_val.get("members").and_then(|v| v.as_sequence()) {
                for x in seq {
                    if let Some(s) = x.as_str() {
                        members.insert(s.to_string());
                    } else if let Some(em) = x.get("email").and_then(|v| v.as_str()) {
                        let role = x
                            .get("role")
                            .and_then(|v| v.as_str())
                            .unwrap_or("MEMBER")
                            .to_uppercase();
                        match role.as_str() {
                            "OWNER" => {
                                owners.insert(em.to_string());
                            }
                            "MANAGER" => {
                                managers.insert(em.to_string());
                            }
                            _ => {
                                members.insert(em.to_string());
                            }
                        }
                    }
                }
            }
            if let Some(seq) = g_val.get("managers").and_then(|v| v.as_sequence()) {
                for x in seq {
                    if let Some(s) = x.as_str() {
                        managers.insert(s.to_string());
                    }
                }
            }
            if let Some(seq) = g_val.get("owners").and_then(|v| v.as_sequence()) {
                for x in seq {
                    if let Some(s) = x.as_str() {
                        owners.insert(s.to_string());
                    }
                }
            }

            let mut unreconciled_members = Vec::new();
            if let Some(seq) = g_val
                .get("unreconciled_members")
                .and_then(|v| v.as_sequence())
            {
                for entry in seq {
                    if let Some(em) = entry.get("email").and_then(|v| v.as_str()) {
                        let reason = entry
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let until = match entry.get("until") {
                            Some(serde_yaml::Value::String(s)) => Some(s.clone()),
                            _ => None,
                        };
                        unreconciled_members.push(HeldException {
                            email: em.to_string(),
                            reason,
                            until,
                        });
                    }
                }
            }

            let requires_2sv_enrolled = g_val
                .get("requires_2sv_enrolled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            groups.insert(
                email.clone(),
                GroupRecord {
                    email,
                    name,
                    description,
                    settings,
                    members,
                    managers,
                    owners,
                    unreconciled_members,
                    requires_2sv_enrolled,
                },
            );
        }
    }

    // 4. Licenses
    let mut licenses: BTreeMap<String, LicenseRecord> = BTreeMap::new();
    let lic_path = dir.join("licenses.yaml");
    if lic_path.exists() {
        let lic_text = fs::read_to_string(&lic_path)?;
        let lic_doc: serde_yaml::Value = serde_yaml::from_str(&lic_text)?;
        if let Some(seq) = lic_doc.get("licenses").and_then(|v| v.as_sequence()) {
            for item in seq {
                if item.get("sku_id").is_some() {
                    let rec: LicenseRecord = serde_yaml::from_value(item.clone())?;
                    licenses.insert(rec.sku_id.clone(), rec);
                } else if let (Some(u), Some(sku)) = (
                    item.get("user").and_then(|v| v.as_str()),
                    item.get("sku").and_then(|v| v.as_str()),
                ) {
                    let sku_name = item
                        .get("sku_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(sku)
                        .to_string();
                    let entry = licenses
                        .entry(sku.to_string())
                        .or_insert_with(|| LicenseRecord {
                            sku_id: sku.to_string(),
                            sku_name,
                            reconcile: true,
                            users: BTreeSet::new(),
                        });
                    entry.users.insert(u.to_string());
                }
            }
        }
    }

    Ok(DesiredState {
        users,
        orgunits,
        groups,
        licenses,
        admin_roles,
        github_orgs,
        leaving_github,
        declared_github,
    })
}

/// Recursively extracts every `<slug>@cerebral.work` group address referenced in a YAML document.
pub fn matrix_groups(node: &serde_yaml::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    match node {
        serde_yaml::Value::Mapping(m) => {
            for (_, v) in m {
                out.extend(matrix_groups(v));
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                out.extend(matrix_groups(item));
            }
        }
        serde_yaml::Value::String(s) if GROUP_EMAIL_RE.is_match(s) => {
            out.insert(s.clone());
        }
        _ => {}
    }
    out
}

/// Returns any `<slug>@cerebral.work` group referenced in `directory/roles.yaml`,
/// `directory/bundles.yaml`, or `directory/role-matrix.yaml` (if present) that is missing from
/// `all_declared(repo)` (`directory/groups/*.yaml` ∪ `terraform/groups/main.tf`).
pub fn missing_role_groups(repo: &Path) -> Result<BTreeSet<String>, IdpError> {
    let dir = repo.join("directory");
    let mut referenced = BTreeSet::new();
    let mut found_any = false;
    for filename in ["role-matrix.yaml", "roles.yaml", "bundles.yaml"] {
        let p = dir.join(filename);
        if p.exists() {
            found_any = true;
            let text = fs::read_to_string(&p)?;
            let doc: serde_yaml::Value = serde_yaml::from_str(&text)?;
            referenced.extend(matrix_groups(&doc));
        }
    }
    if !found_any {
        return Err(IdpError::Validation(
            "missing directory/roles.yaml, directory/bundles.yaml, or directory/role-matrix.yaml"
                .to_string(),
        ));
    }
    let declared = all_declared(repo)?;
    Ok(referenced.difference(&declared).cloned().collect())
}

/// Alias for [`missing_role_groups`] preserved for backwards compatibility.
pub fn missing_matrix_groups(repo: &Path) -> Result<BTreeSet<String>, IdpError> {
    missing_role_groups(repo)
}

/// Validates `directory/` desired-state referential integrity and schema invariants:
/// - Unique emails and unique `github_handle`s in `directory/users.yaml`
/// - Every user's `org_unit` exists in `directory/orgunits.yaml` (or `"/"`)
/// - `admin` (if set) is in `{"super", "delegated", "delegated-sovereign"}`
/// - `super` / `is_super_admin` is restricted to `ctodie@cerebral.work` and `delegated-sovereign` to `ahackley@cerebral.work`
/// - Sovereign roots (`ctodie@cerebral.work`, `ahackley@cerebral.work`) are never `suspended: true` and reside in `/Humans/Admins` when declared
/// - Every `groups/<stem>.yaml` matches `email` prefix `<stem>@`
/// - Every `unreconciled_members` entry has a non-empty `reason` and valid ISO `until` date
/// - Every user in `directory/licenses.yaml` exists in `directory/users.yaml`
/// - `directory/groups-unmanaged.yaml` has no overlap with declared groups
/// - GAM-managed groups (`directory/groups/*.yaml`) and Terraform foundation groups (`terraform/groups/main.tf`) are strictly disjoint
///
/// Returns the number of declared users on success.
pub fn validate_directory_schema(repo: &Path) -> Result<usize, IdpError> {
    let dir = repo.join("directory");
    let users_text = fs::read_to_string(dir.join("users.yaml"))?;
    let users_doc: serde_yaml::Value = serde_yaml::from_str(&users_text)?;
    let seq = users_doc
        .get("users")
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| IdpError::Validation("users.yaml: missing users list".to_string()))?;

    let mut email_set = BTreeSet::new();
    let mut gh_set = BTreeSet::new();

    for u in seq {
        let em = u
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Validation("user entry missing email".to_string()))?;
        if !email_set.insert(em.to_string()) {
            return Err(IdpError::Validation(format!(
                "duplicate email in users.yaml: {em}"
            )));
        }

        if let Some(gh) = u.get("github_handle").and_then(|v| v.as_str()) {
            let lower = gh.to_lowercase();
            if !gh_set.insert(lower.clone()) {
                return Err(IdpError::Validation(format!(
                    "duplicate github_handle in users.yaml: {lower}"
                )));
            }
        }
    }

    let state = load_desired_state(repo)?;
    let mut valid_ous = state.orgunits.clone();
    valid_ous.insert("/".to_string());

    for (email, u) in &state.users {
        if !valid_ous.contains(&u.org_unit) {
            return Err(IdpError::Validation(format!(
                "{email}: unknown org_unit {}",
                u.org_unit
            )));
        }
        if let Some(ref adm) = u.admin
            && adm != "super"
            && adm != "delegated"
            && adm != "delegated-sovereign"
        {
            return Err(IdpError::Validation(format!(
                "{email}: invalid admin level '{adm}'"
            )));
        }
        if u.is_super_admin && !is_sovereign_root_email(email) {
            return Err(IdpError::Validation(format!(
                "{email}: super admin is restricted exclusively to sovereign roots ({SOLE_SUPERADMIN_EMAIL} and {DELEGATED_SOVEREIGN_ROOT_EMAIL})"
            )));
        }
        if u.admin.as_deref() == Some("delegated-sovereign")
            && !email.eq_ignore_ascii_case(DELEGATED_SOVEREIGN_ROOT_EMAIL)
        {
            return Err(IdpError::Validation(format!(
                "{email}: delegated-sovereign admin is restricted exclusively to {DELEGATED_SOVEREIGN_ROOT_EMAIL}"
            )));
        }
        if is_sovereign_root_email(email) {
            if u.suspended {
                return Err(IdpError::Validation(format!(
                    "SOVEREIGN ROOT PROTECTED: {email} cannot be suspended in users.yaml"
                )));
            }
            if state.orgunits.contains("/Humans/Admins") && u.org_unit != "/Humans/Admins" {
                return Err(IdpError::Validation(format!(
                    "SOVEREIGN ROOT PROTECTED: {email} must remain in /Humans/Admins, found {}",
                    u.org_unit
                )));
            }
        }
    }

    let groups_dir = dir.join("groups");
    if groups_dir.exists() {
        let mut entries: Vec<_> = fs::read_dir(&groups_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
            .collect();
        entries.sort();
        for p in entries {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let g_text = fs::read_to_string(&p)?;
            let g_val: serde_yaml::Value = serde_yaml::from_str(&g_text)?;
            let email = g_val.get("email").and_then(|v| v.as_str()).unwrap_or("");
            if !email.starts_with(&format!("{stem}@")) {
                return Err(IdpError::Validation(format!(
                    "{}: email {email} does not match file stem {stem}",
                    p.display()
                )));
            }
        }
    }

    for (g_email, g) in &state.groups {
        for exc in &g.unreconciled_members {
            if exc.email.trim().is_empty() {
                return Err(IdpError::Validation(format!(
                    "{g_email}: unreconciled_members entry missing email"
                )));
            }
            if exc.reason.trim().is_empty() {
                return Err(IdpError::Validation(format!(
                    "{g_email}: unreconciled_members for {} needs a reason",
                    exc.email
                )));
            }
            if let Some(ref until) = exc.until
                && NaiveDate::parse_from_str(until, "%Y-%m-%d").is_err()
            {
                return Err(IdpError::Validation(format!(
                    "{g_email}: invalid until date '{until}' for {}",
                    exc.email
                )));
            }
        }
    }

    for (sku_id, lic) in &state.licenses {
        for u in &lic.users {
            if !state.users.contains_key(u) {
                return Err(IdpError::Validation(format!(
                    "license {sku_id}: unknown user {u}"
                )));
            }
        }
    }

    let unmanaged_path = dir.join("groups-unmanaged.yaml");
    if unmanaged_path.exists() {
        let unmanaged = unmanaged_declared(&unmanaged_path)?;
        let declared = all_declared(repo)?;
        let overlap: Vec<_> = unmanaged
            .keys()
            .filter(|k| declared.contains(*k))
            .cloned()
            .collect();
        if !overlap.is_empty() {
            return Err(IdpError::Validation(format!(
                "groups both unmanaged and declared: {overlap:?}"
            )));
        }
    }

    if repo.join("terraform/groups/main.tf").exists() {
        disjoint_planes_check(repo)?;
    }

    if dir.join("role-matrix.yaml").exists()
        || dir.join("roles.yaml").exists()
        || dir.join("bundles.yaml").exists()
    {
        let missing_groups = missing_role_groups(repo)?;
        if !missing_groups.is_empty() {
            return Err(IdpError::Validation(format!(
                "role/bundle definitions reference groups not declared in GAM or foundation: {missing_groups:?}"
            )));
        }
    }

    Ok(state.users.len())
}

/// Validates `roles.yaml`, `bundles.yaml`, `policies.yaml`, and optional `role-matrix.yaml` invariants,
/// including the sovereign root rules (`ctodie@cerebral.work` / `todie` and `ahackley@cerebral.work` / `LordVoid`)
/// and Clockwork Elf automation constraints.
pub fn validate_identity_models(repo: &Path) -> Result<(), IdpError> {
    let dir = repo.join("directory");
    let roles_doc: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(dir.join("roles.yaml"))?)?;
    let bundles_doc: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(dir.join("bundles.yaml"))?)?;
    let policies_doc: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(dir.join("policies.yaml"))?)?;
    let matrix_path = dir.join("role-matrix.yaml");
    let matrix_doc: Option<serde_yaml::Value> = if matrix_path.exists() {
        Some(serde_yaml::from_str(&fs::read_to_string(&matrix_path)?)?)
    } else {
        None
    };

    let state = load_desired_state(repo)?;
    let declared_groups = all_declared(repo)?;
    let mut valid_ous = state.orgunits.clone();
    valid_ous.insert("/".to_string());

    // 1. Parse bundles (either sequence of `{id, ...}` or mapping `{id: ...}`)
    let mut bundle_ids = BTreeSet::new();
    if let Some(seq) = bundles_doc.get("bundles").and_then(|v| v.as_sequence()) {
        for b in seq {
            let bid = b
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| IdpError::Validation("bundle missing id".to_string()))?;
            if !bundle_ids.insert(bid.to_string()) {
                return Err(IdpError::Validation(format!("duplicate bundle id {bid}")));
            }
            if let Some(ggs) = b.get("google_groups").and_then(|v| v.as_sequence()) {
                for g in ggs {
                    if let Some(gs) = g.as_str()
                        && !declared_groups.contains(gs)
                    {
                        return Err(IdpError::Validation(format!(
                            "bundle {bid} references undeclared google_group {gs}"
                        )));
                    }
                }
            }
        }
    } else if let Some(map) = bundles_doc.get("bundles").and_then(|v| v.as_mapping()) {
        for (bk, bv) in map {
            if let Some(bid) = bk.as_str() {
                bundle_ids.insert(bid.to_string());
                if let Some(ggs) = bv.get("google_groups").and_then(|v| v.as_sequence()) {
                    for g in ggs {
                        if let Some(gs) = g.as_str()
                            && !declared_groups.contains(gs)
                        {
                            return Err(IdpError::Validation(format!(
                                "bundle {bid} references undeclared google_group {gs}"
                            )));
                        }
                    }
                }
            }
        }
    } else {
        return Err(IdpError::Validation(
            "bundles.yaml: missing bundles".to_string(),
        ));
    }

    // 2. Parse roles (either sequence of `{id, ...}` or mapping `{id: ...}`)
    let mut role_ids = BTreeSet::new();
    if let Some(seq) = roles_doc.get("roles").and_then(|v| v.as_sequence()) {
        for r in seq {
            let rid = r
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| IdpError::Validation("role missing id".to_string()))?;
            if !role_ids.insert(rid.to_string()) {
                return Err(IdpError::Validation(format!("duplicate role id {rid}")));
            }
            validate_role_entry(rid, r, &valid_ous, &bundle_ids, &declared_groups)?;
        }
    } else if let Some(map) = roles_doc.get("roles").and_then(|v| v.as_mapping()) {
        for (k, rv) in map {
            if let Some(rid) = k.as_str() {
                role_ids.insert(rid.to_string());
                validate_role_entry(rid, rv, &valid_ous, &bundle_ids, &declared_groups)?;
            }
        }
    } else {
        return Err(IdpError::Validation(
            "roles.yaml: missing roles".to_string(),
        ));
    }

    // Check if mapping-style bundles reference valid roles
    if let Some(bundles_map) = bundles_doc.get("bundles").and_then(|v| v.as_mapping()) {
        for (bk, bv) in bundles_map {
            let bname = bk.as_str().unwrap_or("<unknown>");
            if let Some(inc) = bv.get("includes_roles").and_then(|v| v.as_sequence()) {
                for r in inc {
                    if let Some(rs) = r.as_str()
                        && !role_ids.contains(rs)
                    {
                        return Err(IdpError::Validation(format!(
                            "bundle {bname} includes unknown role {rs}"
                        )));
                    }
                }
            }
        }
    }

    // 3. Check policies.yaml (both `access_policies` sequence and `policies` mapping/sequence)
    if let Some(pols) = policies_doc
        .get("access_policies")
        .and_then(|v| v.as_sequence())
    {
        for p in pols {
            let pid = p.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            validate_policy_entry(pid, p, &bundle_ids, &role_ids, &state.users)?;
        }
    }
    if let Some(pols_map) = policies_doc.get("policies").and_then(|v| v.as_mapping()) {
        for (pk, pv) in pols_map {
            let pid = pk.as_str().unwrap_or("?");
            validate_policy_entry(pid, pv, &bundle_ids, &role_ids, &state.users)?;
        }
    } else if let Some(pols_seq) = policies_doc.get("policies").and_then(|v| v.as_sequence()) {
        for p in pols_seq {
            let pid = p.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            validate_policy_entry(pid, p, &bundle_ids, &role_ids, &state.users)?;
        }
    }

    // Check policies.yaml sole_superadmin invariant if present
    if let Some(sole) = policies_doc
        .get("invariants")
        .and_then(|v| v.get("sole_superadmin"))
    {
        let email = sole.get("email").and_then(|v| v.as_str()).unwrap_or("");
        let gh = sole
            .get("github_handle")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if email != SOLE_SUPERADMIN_EMAIL || gh != SOLE_SUPERADMIN_GITHUB {
            return Err(IdpError::Validation(format!(
                "policies.yaml sole_superadmin must be {SOLE_SUPERADMIN_EMAIL} ({SOLE_SUPERADMIN_GITHUB})"
            )));
        }
    }

    // Check policies.yaml delegated_sovereign_root invariant if present
    if let Some(del_root) = policies_doc
        .get("invariants")
        .and_then(|v| v.get("delegated_sovereign_root"))
    {
        let email = del_root.get("email").and_then(|v| v.as_str()).unwrap_or("");
        let gh = del_root
            .get("github_handle")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !email.eq_ignore_ascii_case(DELEGATED_SOVEREIGN_ROOT_EMAIL)
            || !gh.eq_ignore_ascii_case(DELEGATED_SOVEREIGN_ROOT_GITHUB)
        {
            return Err(IdpError::Validation(format!(
                "policies.yaml delegated_sovereign_root must be {DELEGATED_SOVEREIGN_ROOT_EMAIL} ({DELEGATED_SOVEREIGN_ROOT_GITHUB})"
            )));
        }
    }

    // Check break_glass_principals in policies.yaml and/or role-matrix.yaml
    for (doc_name, doc_opt) in [
        ("policies.yaml", Some(&policies_doc)),
        ("role-matrix.yaml", matrix_doc.as_ref()),
    ] {
        if let Some(bg) = doc_opt
            .and_then(|d| d.get("break_glass_principals"))
            .and_then(|v| v.as_sequence())
        {
            if bg.is_empty() || bg.len() > 2 {
                return Err(IdpError::Validation(format!(
                    "{doc_name} break_glass_principals must have 1 or 2 sovereign root entries, found {}",
                    bg.len()
                )));
            }
            for entry in bg {
                let email = entry.get("email").and_then(|v| v.as_str()).unwrap_or("");
                if !is_sovereign_root_email(email) {
                    return Err(IdpError::Validation(format!(
                        "{doc_name} break_glass_principals entry must be a sovereign root ({SOLE_SUPERADMIN_EMAIL} or {DELEGATED_SOVEREIGN_ROOT_EMAIL}), found {email}"
                    )));
                }
            }
        }
    }

    // Verify no Clockwork Elf appears in users.yaml outside /Service Accounts
    for (email, u) in &state.users {
        if u.org_unit != "/Service Accounts"
            && let Some(ref gh) = u.github_handle
            && is_automation_login(gh)
        {
            return Err(IdpError::Validation(format!(
                "users.yaml contains automation bot handle {gh} on user {email}"
            )));
        }
    }

    Ok(())
}

fn validate_role_entry(
    rid: &str,
    r: &serde_yaml::Value,
    valid_ous: &BTreeSet<String>,
    bundle_ids: &BTreeSet<String>,
    declared_groups: &BTreeSet<String>,
) -> Result<(), IdpError> {
    if let Some(priv_str) = r.get("privacy").and_then(|v| v.as_str())
        && !["internal", "tenant", "external"].contains(&priv_str)
    {
        return Err(IdpError::Validation(format!(
            "role {rid}: invalid privacy {priv_str}"
        )));
    }
    if let Some(ou_str) = r
        .get("ou")
        .or_else(|| r.get("org_unit"))
        .and_then(|v| v.as_str())
        && !valid_ous.contains(ou_str)
    {
        return Err(IdpError::Validation(format!(
            "role {rid}: unknown ou {ou_str}"
        )));
    }
    if let Some(bs) = r.get("bundles").and_then(|v| v.as_sequence()) {
        for b in bs {
            if let Some(bs_str) = b.as_str()
                && !bundle_ids.contains(bs_str)
            {
                return Err(IdpError::Validation(format!(
                    "role {rid} references unknown bundle {bs_str}"
                )));
            }
        }
    }
    if let Some(gs) = r.get("groups").and_then(|v| v.as_sequence()) {
        for g in gs {
            if let Some(gs_str) = g.as_str()
                && !declared_groups.contains(gs_str)
            {
                return Err(IdpError::Validation(format!(
                    "role {rid} references undeclared group {gs_str}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_policy_entry(
    pid: &str,
    p: &serde_yaml::Value,
    bundle_ids: &BTreeSet<String>,
    role_ids: &BTreeSet<String>,
    users: &BTreeMap<String, UserRecord>,
) -> Result<(), IdpError> {
    if let Some(b) = p.get("bundle").and_then(|v| v.as_str())
        && !bundle_ids.contains(b)
    {
        return Err(IdpError::Validation(format!(
            "policy {pid}: unknown bundle {b}"
        )));
    }
    for field in ["auto_assign", "requestable_by"] {
        if let Some(r_in) = p
            .get(field)
            .and_then(|v| v.get("role_in"))
            .and_then(|v| v.as_sequence())
        {
            for r in r_in {
                if let Some(rs) = r.as_str()
                    && !role_ids.contains(rs)
                {
                    return Err(IdpError::Validation(format!(
                        "policy {pid} ({field}): unknown role {rs}"
                    )));
                }
            }
        }
    }
    if let Some(apps_seq) = p.get("approvers").and_then(|v| v.as_sequence()) {
        for a in apps_seq {
            if let Some(u_in) = a.get("user_in").and_then(|v| v.as_sequence()) {
                for u in u_in {
                    if let Some(us) = u.as_str()
                        && !users.contains_key(us)
                    {
                        return Err(IdpError::Validation(format!(
                            "policy {pid}: unknown approver {us}"
                        )));
                    }
                }
            }
        }
    } else if let Some(u_in) = p
        .get("approvers")
        .and_then(|v| v.get("user_in"))
        .and_then(|v| v.as_sequence())
    {
        for u in u_in {
            if let Some(us) = u.as_str()
                && !users.contains_key(us)
            {
                return Err(IdpError::Validation(format!(
                    "policy {pid}: unknown approver {us}"
                )));
            }
        }
    }
    Ok(())
}

/// Splits a YAML document into its leading comment/blank header and body.
pub fn split_header(text: &str) -> (&str, &str) {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += line.len();
        } else {
            break;
        }
    }
    (&text[..offset], &text[offset..])
}

/// Pure text transformation that adds or updates an `unreconciled_members` hold exception
/// in a group YAML file while preserving leading comments and existing formatting.
pub fn hold_text(
    text: &str,
    email: &str,
    reason: &str,
    until: Option<&str>,
) -> Result<String, IdpError> {
    if let Some(u) = until {
        NaiveDate::parse_from_str(u, "%Y-%m-%d")
            .map_err(|e| IdpError::Validation(format!("--until must be YYYY-MM-DD ({e})")))?;
    }

    let (header, body) = split_header(text);
    let doc: serde_yaml::Value = serde_yaml::from_str(body)?;

    for role in ["members", "managers", "owners"] {
        if let Some(seq) = doc.get(role).and_then(|v| v.as_sequence())
            && seq.iter().any(|x| {
                x.as_str() == Some(email) || x.get("email").and_then(|v| v.as_str()) == Some(email)
            })
        {
            return Err(IdpError::Validation(format!(
                "{email} is already in {role} — no hold needed"
            )));
        }
    }

    // Parse existing unreconciled_members
    let mut holds: Vec<HeldException> = Vec::new();
    if let Some(seq) = doc
        .get("unreconciled_members")
        .and_then(|v| v.as_sequence())
    {
        for item in seq {
            if let Some(em) = item.get("email").and_then(|v| v.as_str())
                && em != email
            {
                let r = item
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let u = item
                    .get("until")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                holds.push(HeldException {
                    email: em.to_string(),
                    reason: r,
                    until: u,
                });
            }
        }
    }

    holds.push(HeldException {
        email: email.to_string(),
        reason: reason.to_string(),
        until: until.map(|s| s.to_string()),
    });
    holds.sort_by(|a, b| a.email.cmp(&b.email));

    let base_body = strip_unreconciled_section(body);
    let mut rendered = String::from(header);
    rendered.push_str(&base_body);
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    rendered.push_str("unreconciled_members:\n");
    for h in holds {
        rendered.push_str(&format!("  - email: {}\n", yaml_scalar(&h.email)));
        rendered.push_str(&format!("    reason: {}\n", yaml_scalar(&h.reason)));
        if let Some(u) = h.until {
            rendered.push_str(&format!("    until: {}\n", yaml_scalar(&u)));
        }
    }
    Ok(rendered)
}

/// Pure text transformation that removes `email` from `unreconciled_members` in a group YAML file,
/// preserving leading comments and original body formatting byte-for-byte when the last hold is removed.
pub fn unhold_text(text: &str, email: &str) -> Result<(String, bool), IdpError> {
    let (header, body) = split_header(text);
    let doc: serde_yaml::Value = serde_yaml::from_str(body)?;

    let mut holds: Vec<HeldException> = Vec::new();
    let mut found = false;
    if let Some(seq) = doc
        .get("unreconciled_members")
        .and_then(|v| v.as_sequence())
    {
        for item in seq {
            if let Some(em) = item.get("email").and_then(|v| v.as_str()) {
                if em == email {
                    found = true;
                } else {
                    let r = item
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let u = item
                        .get("until")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    holds.push(HeldException {
                        email: em.to_string(),
                        reason: r,
                        until: u,
                    });
                }
            }
        }
    }

    if !found {
        return Ok((text.to_string(), false));
    }

    let base_body = strip_unreconciled_section(body);
    let mut rendered = String::from(header);
    rendered.push_str(&base_body);
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    if !holds.is_empty() {
        rendered.push_str("unreconciled_members:\n");
        for h in holds {
            rendered.push_str(&format!("  - email: {}\n", yaml_scalar(&h.email)));
            rendered.push_str(&format!("    reason: {}\n", yaml_scalar(&h.reason)));
            if let Some(u) = h.until {
                rendered.push_str(&format!("    until: {}\n", yaml_scalar(&u)));
            }
        }
    }
    Ok((rendered, true))
}

fn strip_unreconciled_section(body: &str) -> String {
    let mut out_lines = Vec::new();
    let mut skipping = false;
    for line in body.lines() {
        if line.starts_with("unreconciled_members:") {
            skipping = true;
            continue;
        }
        if skipping {
            if line.starts_with(' ') || line.starts_with('\t') || line.trim().is_empty() {
                continue;
            } else {
                skipping = false;
            }
        }
        out_lines.push(line);
    }
    let mut joined = out_lines.join("\n");
    joined.push('\n');
    joined
}

fn yaml_scalar(s: &str) -> String {
    if s.contains(':')
        || s.contains('#')
        || s.contains('\'')
        || s.contains('"')
        || s.starts_with(' ')
        || s.ends_with(' ')
        || NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
    {
        format!("'{}'", s.replace('\'', "''"))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_GROUP: &str = "\
# leading comment preserved
# second comment line

email: devs@cerebral.work
name: Devs
description: Developers
settings:
  who_can_join: INVITED_CAN_JOIN
members:
  - alice@cerebral.work
managers: []
owners: []
";

    #[test]
    fn test_hold_and_unhold_roundtrip_preserves_bytes() {
        let held = hold_text(
            SAMPLE_GROUP,
            "temp@cerebral.work",
            "migration window",
            Some("2026-05-01"),
        )
        .expect("hold_text");
        assert!(held.starts_with("# leading comment preserved\n# second comment line\n\n"));
        assert!(held.contains("unreconciled_members:"));
        assert!(held.contains("temp@cerebral.work"));

        let (unheld, removed) = unhold_text(&held, "temp@cerebral.work").expect("unhold_text");
        assert!(removed);
        assert_eq!(unheld, SAMPLE_GROUP);
    }
}
