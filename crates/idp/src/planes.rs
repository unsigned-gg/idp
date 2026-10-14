// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Group-declaration planes (`gam`, `foundation`, `unmanaged`) and undeclared-groups detector.
//!
//! Extracted from `cerebral-work/identity/scripts/reconcile/planes.py` and `undeclared_groups.py`.

use crate::error::IdpError;
use crate::findings::Findings;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

#[allow(clippy::expect_used)]
static TF_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s{4}"?([a-z0-9-]+)"?\s*="#).expect("valid tf key regex"));

/// Reads `directory/groups/*.yaml` under `repo` and returns all declared group email addresses.
pub fn gam_declared(repo: &Path) -> Result<BTreeSet<String>, IdpError> {
    let groups_dir = repo.join("directory/groups");
    let mut out = BTreeSet::new();
    if !groups_dir.exists() {
        return Ok(out);
    }
    let mut entries: Vec<_> = fs::read_dir(&groups_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
        .collect();
    entries.sort();

    for path in entries {
        let text = fs::read_to_string(&path)?;
        let val: serde_yaml::Value = serde_yaml::from_str(&text)?;
        if let Some(email) = val.get("email").and_then(|v| v.as_str()) {
            out.insert(email.to_string());
        }
    }
    Ok(out)
}

/// Reads `terraform/groups/main.tf` under `repo` and returns all Terraform-managed group emails
/// across `gcp_groups`, `platform_groups`, `role_groups`, and `bundle_groups`.
pub fn foundation_declared(repo: &Path) -> Result<BTreeSet<String>, IdpError> {
    let tf_path = repo.join("terraform/groups/main.tf");
    let mut out = BTreeSet::new();
    if !tf_path.exists() {
        return Ok(out);
    }
    let src = fs::read_to_string(&tf_path)?;
    let target_blocks = [
        "gcp_groups",
        "platform_groups",
        "role_groups",
        "bundle_groups",
    ];

    let mut in_target_block = false;
    for line in src.lines() {
        if !in_target_block {
            let trimmed = line.trim_start();
            if target_blocks.iter().any(|b| {
                if let Some(rest) = trimmed.strip_prefix(b) {
                    let rest = rest.trim_start();
                    rest.starts_with('=') && rest.contains('{')
                } else {
                    false
                }
            }) {
                in_target_block = true;
            }
        } else if line == "  }" {
            in_target_block = false;
        } else if let Some(caps) = TF_KEY_RE.captures(line)
            && let Some(key) = caps.get(1)
        {
            out.insert(format!("{}@cerebral.work", key.as_str()));
        }
    }
    Ok(out)
}

/// Returns the union of GAM-declared (`directory/groups/*.yaml`) and foundation-declared
/// (`terraform/groups/main.tf`) group email addresses.
pub fn all_declared(repo: &Path) -> Result<BTreeSet<String>, IdpError> {
    let mut all = gam_declared(repo)?;
    all.extend(foundation_declared(repo)?);
    Ok(all)
}

/// Reads `directory/groups-unmanaged.yaml` (or the given path) and returns `{email: reason}`
/// for entries with a non-empty `email` and non-whitespace `reason`.
pub fn unmanaged_declared(path: &Path) -> Result<BTreeMap<String, String>, IdpError> {
    let mut out = BTreeMap::new();
    if !path.exists() {
        return Ok(out);
    }
    let text = fs::read_to_string(path)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)?;
    if let Some(items) = doc.get("unmanaged").and_then(|v| v.as_sequence()) {
        for item in items {
            let email = item
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let reason = item
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if !email.is_empty() && !reason.is_empty() {
                out.insert(email.to_string(), reason.to_string());
            }
        }
    }
    Ok(out)
}

/// Live group member entry (`email` and `role`, e.g. `"OWNER"`, `"MANAGER"`, `"MEMBER"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveGroupMember {
    /// Member email address.
    pub email: String,
    /// Member role in Google Workspace (`"OWNER"`, `"MANAGER"`, `"MEMBER"`).
    pub role: String,
}

/// Evaluates live Google Workspace groups against declared (`gam ∪ foundation`) and
/// explicitly `unmanaged` groups.
///
/// Returns `(exit_code, output_lines, findings)`.
pub fn undeclared_groups_report(
    groups: &BTreeMap<String, Vec<LiveGroupMember>>,
    declared: &BTreeSet<String>,
    unmanaged: &BTreeMap<String, String>,
) -> (i32, Vec<String>, Findings) {
    let live_keys: BTreeSet<String> = groups.keys().cloned().collect();
    let covered: BTreeSet<String> = declared
        .union(&unmanaged.keys().cloned().collect())
        .cloned()
        .collect();
    let undeclared: Vec<String> = live_keys.difference(&covered).cloned().collect();

    let mut lines = Vec::new();
    lines.push(format!(
        "== UNDECLARED GROUPS: {} of {} live ==",
        undeclared.len(),
        groups.len()
    ));

    for g in &undeclared {
        lines.push(String::new());
        lines.push(g.clone());
        let mut members = groups.get(g).cloned().unwrap_or_default();
        members.sort_by(|a, b| {
            let a_not_owner = a.role != "OWNER";
            let b_not_owner = b.role != "OWNER";
            (a_not_owner, &a.email).cmp(&(b_not_owner, &b.email))
        });
        if members.is_empty() {
            lines.push("  NONE — empty group".to_string());
        } else {
            for m in &members {
                lines.push(format!("  {:<7}  {}", m.role, m.email));
            }
        }
    }

    if !unmanaged.is_empty() {
        lines.push(String::new());
        lines.push("-- deliberately unmanaged (a human recorded why) --".to_string());
        for (g, why) in unmanaged {
            let mut stale = "";
            if !live_keys.contains(g) {
                stale = "  [NOT IN WORKSPACE — stale entry]";
            }
            lines.push(format!("  {g} — {why}{stale}"));
        }
    }

    let mut f = Findings::new("undeclared-groups");
    for g in &undeclared {
        let mut members = groups.get(g).cloned().unwrap_or_default();
        members.sort_by(|a, b| {
            let a_not_owner = a.role != "OWNER";
            let b_not_owner = b.role != "OWNER";
            (a_not_owner, &a.email).cmp(&(b_not_owner, &b.email))
        });
        let mlines: Vec<String> = if members.is_empty() {
            vec!["(empty group)".to_string()]
        } else {
            members
                .iter()
                .map(|m| format!("{:<7} {}", m.role, m.email))
                .collect()
        };
        let sev = if !members.is_empty() {
            "high"
        } else {
            "medium"
        };
        let slug = g.split('@').next().unwrap_or(g);
        f.add(
            "undeclared",
            g,
            sev,
            format!("{g}: live group not declared in git ({} member(s))", members.len()),
            mlines,
            Some(format!(
                "Claim in directory/groups/{slug}.yaml, terraform/groups/main.tf, or record in directory/groups-unmanaged.yaml with a reason — or delete the group in Workspace."
            )),
        );
    }
    f.evaluated("undeclared");

    for (g, why) in unmanaged {
        if !live_keys.contains(g) {
            f.add(
                "stale-unmanaged",
                g,
                "low",
                format!("{g}: listed in groups-unmanaged.yaml but does not exist in Workspace"),
                vec![format!("Recorded reason: {why}")],
                Some("Remove the stale entry from directory/groups-unmanaged.yaml.".to_string()),
            );
        }
    }
    f.evaluated("stale-unmanaged");

    let rc = if !undeclared.is_empty() { 2 } else { 0 };
    (rc, lines, f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_undeclared_groups_report_sorting_and_findings() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "declared@cerebral.work".to_string(),
            vec![LiveGroupMember {
                email: "a@cerebral.work".to_string(),
                role: "MEMBER".to_string(),
            }],
        );
        groups.insert(
            "mystery@cerebral.work".to_string(),
            vec![
                LiveGroupMember {
                    email: "z@cerebral.work".to_string(),
                    role: "MEMBER".to_string(),
                },
                LiveGroupMember {
                    email: "a@cerebral.work".to_string(),
                    role: "OWNER".to_string(),
                },
            ],
        );
        let declared = BTreeSet::from(["declared@cerebral.work".to_string()]);
        let unmanaged = BTreeMap::from([(
            "gone@cerebral.work".to_string(),
            "old mailing list".to_string(),
        )]);

        let (rc, lines, f) = undeclared_groups_report(&groups, &declared, &unmanaged);
        assert_eq!(rc, 2);
        let joined = lines.join("\n");
        assert!(joined.contains("== UNDECLARED GROUPS: 1 of 2 live =="));
        let owner_pos = joined.find("OWNER    a@cerebral.work").unwrap();
        let member_pos = joined.find("MEMBER   z@cerebral.work").unwrap();
        assert!(owner_pos < member_pos);
        assert!(joined.contains("[NOT IN WORKSPACE — stale entry]"));
        assert_eq!(f.items.len(), 2);
    }
}
