// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! User onboarding and two-stage offboarding (`T0` suspension + `/Suspended-Offboarding`, `--finalize` group/license removal).
//!
//! Extracted from `cerebral-work/identity/scripts/lifecycle/{onboard,offboard}.py`.

use crate::directory::{load_desired_state, split_header};
use crate::error::IdpError;
use std::fs;
use std::path::{Path, PathBuf};

/// Parameters for staging a new user in `directory/`.
#[derive(Debug, Clone)]
pub struct OnboardRequest {
    /// Primary email (`<user>@cerebral.work`).
    pub email: String,
    /// Given name.
    pub given_name: String,
    /// Family name.
    pub family_name: String,
    /// Organizational unit path (e.g. `"/Humans/Members"`).
    pub org_unit: String,
    /// Group slugs or emails to add the user to as `members`.
    pub groups: Vec<String>,
    /// Optional license SKU ID (`"1010020028"` or `"1010020020"`, or `None` if `--no-license`).
    pub sku_id: Option<String>,
    /// Optional GitHub handle.
    pub github_handle: Option<String>,
    /// GitHub organizations to grant membership in.
    pub github_orgs: Vec<String>,
    /// Whether the reconciler should create the Google account (`true` by default).
    pub create: bool,
}

/// Stages a new user across `directory/users.yaml`, `directory/groups/*.yaml`, and `directory/licenses.yaml`.
///
/// Returns the list of modified file paths.
pub fn stage_onboard(repo: &Path, req: &OnboardRequest) -> Result<Vec<PathBuf>, IdpError> {
    if !req.email.ends_with("@cerebral.work") {
        return Err(IdpError::Validation(format!(
            "email must end with @cerebral.work: {}",
            req.email
        )));
    }
    let state = load_desired_state(repo)?;
    if state.users.contains_key(&req.email) {
        return Err(IdpError::Validation(format!(
            "{} already exists in directory/users.yaml",
            req.email
        )));
    }
    if !state.orgunits.contains(&req.org_unit) {
        return Err(IdpError::Validation(format!(
            "unknown org_unit {} (not in directory/orgunits.yaml)",
            req.org_unit
        )));
    }

    let dir = repo.join("directory");
    let mut touched = Vec::new();

    // 1. Resolve group files first so we fail fast before mutating anything
    let mut group_paths = Vec::new();
    for g in &req.groups {
        let slug = g.strip_suffix("@cerebral.work").unwrap_or(g);
        let p = dir.join("groups").join(format!("{slug}.yaml"));
        if !p.exists() {
            return Err(IdpError::Validation(format!(
                "group file not found: {}",
                p.display()
            )));
        }
        group_paths.push(p);
    }

    // 2. Update directory/users.yaml
    let users_path = dir.join("users.yaml");
    let users_text = fs::read_to_string(&users_path)?;
    let (u_header, u_body) = split_header(&users_text);
    let mut u_doc: serde_yaml::Value = serde_yaml::from_str(u_body)?;
    if let Some(seq) = u_doc.get_mut("users").and_then(|v| v.as_sequence_mut()) {
        let mut entry = serde_yaml::Mapping::new();
        entry.insert(
            serde_yaml::Value::String("email".to_string()),
            serde_yaml::Value::String(req.email.clone()),
        );
        entry.insert(
            serde_yaml::Value::String("given_name".to_string()),
            serde_yaml::Value::String(req.given_name.clone()),
        );
        entry.insert(
            serde_yaml::Value::String("family_name".to_string()),
            serde_yaml::Value::String(req.family_name.clone()),
        );
        entry.insert(
            serde_yaml::Value::String("org_unit".to_string()),
            serde_yaml::Value::String(req.org_unit.clone()),
        );
        entry.insert(
            serde_yaml::Value::String("suspended".to_string()),
            serde_yaml::Value::Bool(false),
        );
        if !req.create {
            entry.insert(
                serde_yaml::Value::String("create".to_string()),
                serde_yaml::Value::Bool(false),
            );
        }
        if let Some(ref gh) = req.github_handle {
            entry.insert(
                serde_yaml::Value::String("github_handle".to_string()),
                serde_yaml::Value::String(gh.clone()),
            );
            let orgs_val: Vec<serde_yaml::Value> = req
                .github_orgs
                .iter()
                .map(|o| serde_yaml::Value::String(o.clone()))
                .collect();
            entry.insert(
                serde_yaml::Value::String("github_orgs".to_string()),
                serde_yaml::Value::Sequence(orgs_val),
            );
        }
        seq.push(serde_yaml::Value::Mapping(entry));
        seq.sort_by(|a, b| {
            let ea = a.get("email").and_then(|v| v.as_str()).unwrap_or("");
            let eb = b.get("email").and_then(|v| v.as_str()).unwrap_or("");
            ea.cmp(eb)
        });
    }
    write_yaml_preserving_header(&users_path, u_header, &u_doc)?;
    touched.push(users_path);

    // 3. Update group files (supports both `{email, role}` mappings and string lists)
    for gp in group_paths {
        let g_text = fs::read_to_string(&gp)?;
        let (gh, gb) = split_header(&g_text);
        let mut g_doc: serde_yaml::Value = serde_yaml::from_str(gb)?;
        if let Some(seq) = g_doc.get_mut("members").and_then(|v| v.as_sequence_mut()) {
            let already_present = seq.iter().any(|x| {
                x.as_str() == Some(req.email.as_str())
                    || x.get("email").and_then(|v| v.as_str()) == Some(req.email.as_str())
            });
            if !already_present {
                let uses_mapping = seq.first().is_none_or(|x| x.is_mapping());
                if uses_mapping {
                    let mut m = serde_yaml::Mapping::new();
                    m.insert(
                        serde_yaml::Value::String("email".to_string()),
                        serde_yaml::Value::String(req.email.clone()),
                    );
                    m.insert(
                        serde_yaml::Value::String("role".to_string()),
                        serde_yaml::Value::String("MEMBER".to_string()),
                    );
                    seq.push(serde_yaml::Value::Mapping(m));
                } else {
                    seq.push(serde_yaml::Value::String(req.email.clone()));
                }
            }
        }
        write_yaml_preserving_header(&gp, gh, &g_doc)?;
        touched.push(gp);
    }

    // 4. Update licenses.yaml if requested
    if let Some(ref sku) = req.sku_id {
        let lic_path = dir.join("licenses.yaml");
        if lic_path.exists() {
            let l_text = fs::read_to_string(&lic_path)?;
            let (lh, lb) = split_header(&l_text);
            let mut l_doc: serde_yaml::Value = serde_yaml::from_str(lb)?;
            if let Some(seq) = l_doc.get_mut("licenses").and_then(|v| v.as_sequence_mut()) {
                let uses_flat_rows = seq.first().is_none_or(|x| x.get("user").is_some());
                if uses_flat_rows {
                    let already = seq.iter().any(|x| {
                        x.get("user").and_then(|v| v.as_str()) == Some(req.email.as_str())
                            && x.get("sku").and_then(|v| v.as_str()) == Some(sku.as_str())
                    });
                    if !already {
                        let mut m = serde_yaml::Mapping::new();
                        m.insert(
                            serde_yaml::Value::String("user".to_string()),
                            serde_yaml::Value::String(req.email.clone()),
                        );
                        m.insert(
                            serde_yaml::Value::String("sku".to_string()),
                            serde_yaml::Value::String(sku.clone()),
                        );
                        m.insert(
                            serde_yaml::Value::String("sku_name".to_string()),
                            serde_yaml::Value::String(String::new()),
                        );
                        seq.push(serde_yaml::Value::Mapping(m));
                    }
                } else {
                    for item in seq {
                        if item.get("sku_id").and_then(|v| v.as_str()) == Some(sku.as_str())
                            && let Some(users_seq) =
                                item.get_mut("users").and_then(|v| v.as_sequence_mut())
                            && !users_seq
                                .iter()
                                .any(|x| x.as_str() == Some(req.email.as_str()))
                        {
                            users_seq.push(serde_yaml::Value::String(req.email.clone()));
                        }
                    }
                }
            }
            write_yaml_preserving_header(&lic_path, lh, &l_doc)?;
            touched.push(lic_path);
        }
    }

    Ok(touched)
}

/// Resolves `org_unit`, GAM-managed `groups`, `sku_id`, and `github_orgs` for `role_slug` from
/// `directory/roles.yaml` + `directory/bundles.yaml` and calls [`stage_onboard`].
pub fn stage_onboard_for_role(
    repo: &Path,
    email: &str,
    given_name: &str,
    family_name: &str,
    role_slug: &str,
    github_handle: Option<String>,
    create: bool,
) -> Result<Vec<PathBuf>, IdpError> {
    let dir = repo.join("directory");
    let roles_text = fs::read_to_string(dir.join("roles.yaml"))?;
    let roles_doc: serde_yaml::Value = serde_yaml::from_str(&roles_text)?;

    let role_val = if let Some(map) = roles_doc.get("roles").and_then(|v| v.as_mapping()) {
        map.get(serde_yaml::Value::String(role_slug.to_string()))
            .ok_or_else(|| {
                IdpError::Validation(format!("unknown role {role_slug:?} in roles.yaml"))
            })?
    } else if let Some(seq) = roles_doc.get("roles").and_then(|v| v.as_sequence()) {
        seq.iter()
            .find(|r| r.get("id").and_then(|v| v.as_str()) == Some(role_slug))
            .ok_or_else(|| {
                IdpError::Validation(format!("unknown role {role_slug:?} in roles.yaml"))
            })?
    } else {
        return Err(IdpError::Validation(
            "roles.yaml: missing roles".to_string(),
        ));
    };

    let org_unit = role_val
        .get("ou")
        .or_else(|| role_val.get("org_unit"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            IdpError::Validation(format!(
                "role {role_slug} missing ou/org_unit in roles.yaml"
            ))
        })?
        .to_string();

    let bundles_path = dir.join("bundles.yaml");
    let bundles_doc: Option<serde_yaml::Value> = if bundles_path.exists() {
        Some(serde_yaml::from_str(&fs::read_to_string(&bundles_path)?)?)
    } else {
        None
    };

    let lookup_bundle = |bid: &str| -> Option<&serde_yaml::Value> {
        let doc = bundles_doc.as_ref()?;
        if let Some(map) = doc.get("bundles").and_then(|v| v.as_mapping()) {
            map.get(serde_yaml::Value::String(bid.to_string()))
        } else if let Some(seq) = doc.get("bundles").and_then(|v| v.as_sequence()) {
            seq.iter()
                .find(|b| b.get("id").and_then(|v| v.as_str()) == Some(bid))
        } else {
            None
        }
    };

    let mut candidate_groups: Vec<String> = Vec::new();
    let role_group = format!("role-{role_slug}@cerebral.work");
    candidate_groups.push(role_group);

    if let Some(gs) = role_val.get("groups").and_then(|v| v.as_sequence()) {
        for g in gs {
            if let Some(gs_str) = g.as_str()
                && !candidate_groups.iter().any(|x| x == gs_str)
            {
                candidate_groups.push(gs_str.to_string());
            }
        }
    }

    let mut sku_id: Option<String> = match role_val.get("license") {
        Some(serde_yaml::Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(serde_yaml::Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };

    let mut github_orgs: Vec<String> = Vec::new();

    if let Some(bs) = role_val.get("bundles").and_then(|v| v.as_sequence()) {
        for b in bs {
            if let Some(bid) = b.as_str()
                && let Some(bval) = lookup_bundle(bid)
            {
                if sku_id.is_none() {
                    sku_id = match bval.get("license") {
                        Some(serde_yaml::Value::String(s)) if !s.is_empty() => Some(s.clone()),
                        Some(serde_yaml::Value::Number(n)) => Some(n.to_string()),
                        _ => None,
                    };
                }
                if let Some(ggs) = bval.get("google_groups").and_then(|v| v.as_sequence()) {
                    for g in ggs {
                        if let Some(gs_str) = g.as_str()
                            && !candidate_groups.iter().any(|x| x == gs_str)
                        {
                            candidate_groups.push(gs_str.to_string());
                        }
                    }
                }
                if let Some(gh_map) = bval.get("github").and_then(|v| v.as_mapping()) {
                    for (ok, _) in gh_map {
                        if let Some(org_str) = ok.as_str()
                            && !github_orgs.iter().any(|x| x == org_str)
                        {
                            github_orgs.push(org_str.to_string());
                        }
                    }
                }
            }
        }
    }

    // Filter candidate_groups to those that have a GAM-managed file in `directory/groups/<slug>.yaml`
    let mut gam_groups = Vec::new();
    for g in candidate_groups {
        let slug = g.strip_suffix("@cerebral.work").unwrap_or(&g);
        if dir.join("groups").join(format!("{slug}.yaml")).exists() {
            gam_groups.push(g);
        }
    }

    let req = OnboardRequest {
        email: email.to_string(),
        given_name: given_name.to_string(),
        family_name: family_name.to_string(),
        org_unit,
        groups: gam_groups,
        sku_id,
        github_handle,
        github_orgs,
        create,
    };
    stage_onboard(repo, &req)
}

/// Stages an offboarding change for `email`.
///
/// - When `finalize == false` (T0): sets `suspended: true` and `org_unit: /Suspended-Offboarding`
///   (or `/Offboarding` if declared) in `users.yaml`, and removes `email` from all `directory/groups/*.yaml`
///   files (killing group-derived access at T0 per `scripts/lifecycle/offboard.py`).
/// - When `finalize == true` (T+30d): removes `email` from `directory/licenses.yaml` as well as groups.
pub fn stage_offboard(repo: &Path, email: &str, finalize: bool) -> Result<Vec<PathBuf>, IdpError> {
    if idp_domain::principal::is_sovereign_root_email(email) {
        return Err(IdpError::Validation(format!(
            "SOVEREIGN ROOT PROTECTED: refusing to offboard {email}"
        )));
    }
    let state = load_desired_state(repo)?;
    let target_ou = if state.orgunits.contains("/Suspended-Offboarding") {
        "/Suspended-Offboarding"
    } else if state.orgunits.contains("/Offboarding") {
        "/Offboarding"
    } else {
        "/Suspended-Offboarding"
    };

    let dir = repo.join("directory");
    let mut touched = Vec::new();

    // 1. Update users.yaml
    let users_path = dir.join("users.yaml");
    let users_text = fs::read_to_string(&users_path)?;
    let (uh, ub) = split_header(&users_text);
    let mut u_doc: serde_yaml::Value = serde_yaml::from_str(ub)?;
    let mut found = false;
    if let Some(seq) = u_doc.get_mut("users").and_then(|v| v.as_sequence_mut()) {
        for u in seq {
            if u.get("email").and_then(|v| v.as_str()) == Some(email) {
                found = true;
                if let Some(m) = u.as_mapping_mut() {
                    m.insert(
                        serde_yaml::Value::String("suspended".to_string()),
                        serde_yaml::Value::Bool(true),
                    );
                    m.insert(
                        serde_yaml::Value::String("org_unit".to_string()),
                        serde_yaml::Value::String(target_ou.to_string()),
                    );
                }
            }
        }
    }
    if !found {
        return Err(IdpError::Validation(format!(
            "{email} not found in directory/users.yaml"
        )));
    }
    write_yaml_preserving_header(&users_path, uh, &u_doc)?;
    touched.push(users_path);

    // 2. Strip from all directory/groups/*.yaml (both `{email, role}` mappings and string items)
    let groups_dir = dir.join("groups");
    if groups_dir.exists() {
        let mut entries: Vec<_> = fs::read_dir(&groups_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
            .collect();
        entries.sort();
        for gp in entries {
            let g_text = fs::read_to_string(&gp)?;
            let (gh, gb) = split_header(&g_text);
            let mut g_doc: serde_yaml::Value = serde_yaml::from_str(gb)?;
            let mut g_changed = false;
            for role in ["members", "managers", "owners"] {
                if let Some(seq) = g_doc.get_mut(role).and_then(|v| v.as_sequence_mut()) {
                    let before = seq.len();
                    seq.retain(|x| {
                        x.as_str() != Some(email)
                            && x.get("email").and_then(|v| v.as_str()) != Some(email)
                    });
                    if seq.len() != before {
                        g_changed = true;
                    }
                }
            }
            if g_changed {
                write_yaml_preserving_header(&gp, gh, &g_doc)?;
                touched.push(gp);
            }
        }
    }

    // 3. If finalize, strip from licenses.yaml
    if finalize {
        let lic_path = dir.join("licenses.yaml");
        if lic_path.exists() {
            let l_text = fs::read_to_string(&lic_path)?;
            let (lh, lb) = split_header(&l_text);
            let mut l_doc: serde_yaml::Value = serde_yaml::from_str(lb)?;
            let mut lic_changed = false;
            if let Some(seq) = l_doc.get_mut("licenses").and_then(|v| v.as_sequence_mut()) {
                let before_top = seq.len();
                seq.retain(|item| item.get("user").and_then(|v| v.as_str()) != Some(email));
                if seq.len() != before_top {
                    lic_changed = true;
                }
                for item in seq {
                    if let Some(users_seq) = item.get_mut("users").and_then(|v| v.as_sequence_mut())
                    {
                        let before = users_seq.len();
                        users_seq.retain(|x| x.as_str() != Some(email));
                        if users_seq.len() != before {
                            lic_changed = true;
                        }
                    }
                }
            }
            if lic_changed {
                write_yaml_preserving_header(&lic_path, lh, &l_doc)?;
                touched.push(lic_path);
            }
        }
    }

    Ok(touched)
}

fn write_yaml_preserving_header(
    path: &Path,
    header: &str,
    doc: &serde_yaml::Value,
) -> Result<(), IdpError> {
    let body = serde_yaml::to_string(doc)?;
    let mut out = String::from(header);
    out.push_str(&body);
    fs::write(path, out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::validate_directory_schema;

    #[test]
    fn test_onboard_and_offboard_preserve_group_owners_and_validate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let dir = root.join("directory");
        let groups_dir = dir.join("groups");
        fs::create_dir_all(&groups_dir).expect("create groups dir");

        fs::write(
            dir.join("orgunits.yaml"),
            "orgunits:\n  - path: /Humans/Members\n  - path: /Suspended-Offboarding\n",
        )
        .expect("write orgunits");
        fs::write(
            dir.join("users.yaml"),
            "# Header comment\nusers:\n  - email: ctodie@cerebral.work\n    given_name: Chris\n    family_name: Todie\n    org_unit: /Humans/Members\n    admin: super\n    suspended: false\n",
        )
        .expect("write users");
        fs::write(
            groups_dir.join("admin.yaml"),
            "email: admin@cerebral.work\nname: IT Admin\nmembers:\n  - email: ctodie@cerebral.work\n    role: OWNER\n",
        )
        .expect("write group");
        fs::write(
            dir.join("licenses.yaml"),
            "licenses:\n  - user: ctodie@cerebral.work\n    sku: '1010020028'\n    sku_name: Google Workspace Business Standard\n",
        )
        .expect("write licenses");

        let req = OnboardRequest {
            email: "nhire@cerebral.work".to_string(),
            given_name: "New".to_string(),
            family_name: "Hire".to_string(),
            org_unit: "/Humans/Members".to_string(),
            groups: vec!["admin@cerebral.work".to_string()],
            sku_id: Some("1010020028".to_string()),
            github_handle: Some("nhire-gh".to_string()),
            github_orgs: vec!["cerebral-work".to_string()],
            create: true,
        };
        stage_onboard(root, &req).expect("stage_onboard");
        assert_eq!(
            validate_directory_schema(root).expect("valid after onboard"),
            2
        );

        let group_after_onboard = fs::read_to_string(groups_dir.join("admin.yaml")).expect("read");
        assert!(group_after_onboard.contains("ctodie@cerebral.work"));
        assert!(group_after_onboard.contains("OWNER"));
        assert!(group_after_onboard.contains("nhire@cerebral.work"));

        stage_offboard(root, "nhire@cerebral.work", false).expect("stage_offboard t0");
        assert_eq!(validate_directory_schema(root).expect("valid after t0"), 2);

        let group_after_t0 = fs::read_to_string(groups_dir.join("admin.yaml")).expect("read");
        assert!(group_after_t0.contains("ctodie@cerebral.work"));
        assert!(!group_after_t0.contains("nhire@cerebral.work"));

        stage_offboard(root, "nhire@cerebral.work", true).expect("stage_offboard finalize");
        assert_eq!(
            validate_directory_schema(root).expect("valid after finalize"),
            2
        );
        let lic_after = fs::read_to_string(dir.join("licenses.yaml")).expect("read licenses");
        assert!(!lic_after.contains("nhire@cerebral.work"));

        let err = stage_offboard(root, "ctodie@cerebral.work", false).unwrap_err();
        assert!(err.to_string().contains("SOVEREIGN ROOT PROTECTED"));
        let err_del = stage_offboard(root, "ahackley@cerebral.work", false).unwrap_err();
        assert!(err_del.to_string().contains("SOVEREIGN ROOT PROTECTED"));
    }
}
