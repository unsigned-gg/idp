// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! User onboarding and two-stage offboarding (`T0` suspension + `/Offboarding`, `--finalize` group/license removal).
//!
//! Extracted from `cerebral-work/identity/scripts/lifecycle/{onboard,offboard}.py`.

use crate::directory::{load_desired_state, split_header};
use crate::error::IdpError;
use std::collections::BTreeSet;
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
    /// Organizational unit path (e.g. `"/Engineering"`).
    pub org_unit: String,
    /// Group slugs or emails to add the user to as `members`.
    pub groups: Vec<String>,
    /// Optional license SKU ID (`"1010020020"` by default, or `None` if `--no-license`).
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

    // 3. Update group files
    for gp in group_paths {
        let g_text = fs::read_to_string(&gp)?;
        let (gh, gb) = split_header(&g_text);
        let mut g_doc: serde_yaml::Value = serde_yaml::from_str(gb)?;
        if let Some(seq) = g_doc.get_mut("members").and_then(|v| v.as_sequence_mut()) {
            let mut set: BTreeSet<String> = seq
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
            set.insert(req.email.clone());
            *seq = set.into_iter().map(serde_yaml::Value::String).collect();
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
                for item in seq {
                    if item.get("sku_id").and_then(|v| v.as_str()) == Some(sku.as_str())
                        && let Some(users_seq) =
                            item.get_mut("users").and_then(|v| v.as_sequence_mut())
                    {
                        let mut set: BTreeSet<String> = users_seq
                            .iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect();
                        set.insert(req.email.clone());
                        *users_seq = set.into_iter().map(serde_yaml::Value::String).collect();
                    }
                }
            }
            write_yaml_preserving_header(&lic_path, lh, &l_doc)?;
            touched.push(lic_path);
        }
    }

    Ok(touched)
}

/// Stages an offboarding change for `email`.
///
/// - When `finalize == false` (T0): sets `suspended: true` and `org_unit: /Offboarding` in `users.yaml`
///   and strips `email` from `licenses.yaml`, while keeping group memberships intact as an audit record.
/// - When `finalize == true` (T+30d): also removes `email` from all `directory/groups/*.yaml` files.
pub fn stage_offboard(repo: &Path, email: &str, finalize: bool) -> Result<Vec<PathBuf>, IdpError> {
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
                        serde_yaml::Value::String("/Offboarding".to_string()),
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

    // 2. Strip from licenses.yaml
    let lic_path = dir.join("licenses.yaml");
    if lic_path.exists() {
        let l_text = fs::read_to_string(&lic_path)?;
        let (lh, lb) = split_header(&l_text);
        let mut l_doc: serde_yaml::Value = serde_yaml::from_str(lb)?;
        let mut lic_changed = false;
        if let Some(seq) = l_doc.get_mut("licenses").and_then(|v| v.as_sequence_mut()) {
            for item in seq {
                if let Some(users_seq) = item.get_mut("users").and_then(|v| v.as_sequence_mut()) {
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

    // 3. If finalize, strip from all directory/groups/*.yaml
    if finalize {
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
                        seq.retain(|x| x.as_str() != Some(email));
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
