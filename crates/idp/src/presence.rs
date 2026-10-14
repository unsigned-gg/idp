// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Cross-system presence matrix (`users.yaml`, Google, Keycloak, Tailscale, GitHub, Cloudflare, Slack).
//!
//! Extracted from `cerebral-work/identity/scripts/reconcile/presence.py`.

use crate::error::IdpError;
use crate::findings::Findings;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Presence snapshot from a single identity source (`users.yaml`, `google`, `github:<org>`, `slack`, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    /// Source identifier (e.g. `"users.yaml"`, `"google"`, `"github:cerebral-work"`, `"slack"`).
    pub name: String,
    /// Map of identity key (email or `@handle`) to state string (`"active"`, `"suspended"`, `"member"`, etc.).
    #[serde(default)]
    pub members: BTreeMap<String, String>,
    /// Error message if probing the source failed (`1` exit code).
    #[serde(default)]
    pub error: Option<String>,
    /// Reason string if the source is unconfigured and skipped (`0` exit code).
    #[serde(default)]
    pub skipped: Option<String>,
    /// Keying mode (`"email"` or `"handle"`).
    #[serde(default = "default_email_key")]
    pub keyed_by: String,
}

fn default_email_key() -> String {
    "email".to_string()
}

/// Reads `directory/users.yaml` under `repo` and returns `{github_handle_lowercase: email}`.
pub fn declared_handles(repo: &Path) -> Result<BTreeMap<String, String>, IdpError> {
    let text = fs::read_to_string(repo.join("directory/users.yaml"))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)?;
    let mut out = BTreeMap::new();
    if let Some(seq) = doc.get("users").and_then(|v| v.as_sequence()) {
        for u in seq {
            if let (Some(gh), Some(em)) = (
                u.get("github_handle").and_then(|v| v.as_str()),
                u.get("email").and_then(|v| v.as_str()),
            ) {
                out.insert(gh.to_lowercase(), em.to_string());
            }
        }
    }
    Ok(out)
}

/// Loads the `users.yaml` baseline [`Presence`] (`active` or `suspended` for each declared user).
pub fn src_declared(repo: &Path) -> Result<Presence, IdpError> {
    let text = fs::read_to_string(repo.join("directory/users.yaml"))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)?;
    let mut members = BTreeMap::new();
    if let Some(seq) = doc.get("users").and_then(|v| v.as_sequence()) {
        for u in seq {
            if let Some(em) = u.get("email").and_then(|v| v.as_str()) {
                let suspended = u
                    .get("suspended")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let state = if suspended { "suspended" } else { "active" };
                members.insert(em.to_string(), state.to_string());
            }
        }
    }
    Ok(Presence {
        name: "users.yaml".to_string(),
        members,
        error: None,
        skipped: None,
        keyed_by: "email".to_string(),
    })
}

/// Translates live GitHub organization logins into a [`Presence`] keyed by email (when claimed in
/// `handles`) or `@<login>` (when unclaimed).
pub fn translate_github_members(
    org: &str,
    logins: &[String],
    handles: &BTreeMap<String, String>,
) -> Presence {
    let mut members = BTreeMap::new();
    for login in logins {
        let lower = login.to_lowercase();
        let key = handles
            .get(&lower)
            .cloned()
            .unwrap_or_else(|| format!("@{login}"));
        members.insert(key, "member".to_string());
    }
    Presence {
        name: format!("github:{org}"),
        members,
        error: None,
        skipped: None,
        keyed_by: "email".to_string(),
    }
}

/// Minimal representation of a Slack `users.list` entry for presence translation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlackMemberInput {
    /// Slack user ID (e.g. `"USLACKBOT"` or `"U012345"`).
    #[serde(default)]
    pub id: String,
    /// Slack username handle.
    #[serde(default)]
    pub name: String,
    /// Whether the user is a bot account.
    #[serde(default)]
    pub is_bot: bool,
    /// Whether the account is deactivated/deleted.
    #[serde(default)]
    pub deleted: bool,
    /// Whether the user is a workspace owner.
    #[serde(default)]
    pub is_owner: bool,
    /// Whether the user is the primary workspace owner.
    #[serde(default)]
    pub is_primary_owner: bool,
    /// Whether the user is a workspace admin.
    #[serde(default)]
    pub is_admin: bool,
    /// Whether the user is a multi-channel guest.
    #[serde(default)]
    pub is_restricted: bool,
    /// Whether the user is a single-channel guest.
    #[serde(default)]
    pub is_ultra_restricted: bool,
    /// Profile email address, if visible.
    #[serde(default)]
    pub email: Option<String>,
}

/// Converts Slack `users.list` entries into a [`Presence`] snapshot (filtering out bots,
/// `USLACKBOT`, and deactivated accounts).
pub fn parse_slack_members(entries: &[SlackMemberInput]) -> Presence {
    let mut members = BTreeMap::new();
    for m in entries {
        if m.is_bot || m.id == "USLACKBOT" || m.deleted {
            continue;
        }
        let key = m
            .email
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| format!("@{}", if m.name.is_empty() { "?" } else { &m.name }));
        let state = if m.is_owner || m.is_primary_owner {
            "owner"
        } else if m.is_admin {
            "admin"
        } else if m.is_restricted || m.is_ultra_restricted {
            "guest"
        } else {
            "member"
        };
        members.insert(key, state.to_string());
    }
    Presence {
        name: "slack".to_string(),
        members,
        error: None,
        skipped: None,
        keyed_by: "email".to_string(),
    }
}

/// Evaluates cross-system [`Presence`] snapshots, producing the human report lines,
/// structured [`Findings`], and exit code (`0` = clean, `1` = source error, `2` = findings).
pub fn evaluate_presence(results: &[Presence]) -> (i32, Vec<String>, Findings) {
    let active: Vec<&Presence> = results
        .iter()
        .filter(|r| r.error.is_none() && r.skipped.is_none())
        .collect();
    let email_sources: Vec<&Presence> = active
        .iter()
        .copied()
        .filter(|r| r.keyed_by == "email")
        .collect();
    let handle_sources: Vec<&Presence> = active
        .iter()
        .copied()
        .filter(|r| r.keyed_by == "handle")
        .collect();

    let mut all_emails = BTreeSet::new();
    let mut unclaimed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in &email_sources {
        for k in r.members.keys() {
            if k.starts_with('@') {
                unclaimed.entry(r.name.clone()).or_default().push(k.clone());
            } else {
                all_emails.insert(k.clone());
            }
        }
    }
    for v in unclaimed.values_mut() {
        v.sort();
    }

    let declared = results
        .iter()
        .find(|r| r.name == "users.yaml")
        .map(|r| &r.members);
    let google = results
        .iter()
        .find(|r| r.name == "google" && r.error.is_none() && r.skipped.is_none())
        .map(|r| &r.members);

    let mut disagree = Vec::new();
    let mut not_joined = Vec::new();

    for email in &all_emails {
        let mut row = BTreeMap::new();
        for r in &email_sources {
            let val = r.members.get(email).map(|s| s.as_str()).unwrap_or("—");
            row.insert(r.name.clone(), val.to_string());
        }
        let d = row.get("users.yaml").map(|s| s.as_str()).unwrap_or("—");
        let g = row.get("google").map(|s| s.as_str());
        let others: Vec<(&String, &String)> = row
            .iter()
            .filter(|(k, v)| k.as_str() != "users.yaml" && v.as_str() != "—")
            .collect();

        if d == "—" {
            disagree.push((
                email.clone(),
                "in live system(s) but NOT in users.yaml".to_string(),
                row,
            ));
        } else if d == "active" && g == Some("—") {
            if others.is_empty() {
                not_joined.push(email.clone());
            } else {
                disagree.push((
                    email.clone(),
                    "in downstream system(s) but has no Google account yet".to_string(),
                    row,
                ));
            }
        } else if d == "active" && g == Some("suspended") {
            disagree.push((
                email.clone(),
                "declared active, suspended in Google".to_string(),
                row,
            ));
        } else if d == "suspended" && g.is_some() && g != Some("suspended") {
            disagree.push((
                email.clone(),
                format!("declared suspended, Google says {}", g.unwrap_or("unknown")),
                row,
            ));
        } else if d == "suspended" {
            let linger: Vec<String> = row
                .iter()
                .filter(|(k, v)| {
                    k.as_str() != "users.yaml"
                        && k.as_str() != "google"
                        && v.as_str() != "—"
                        && v.as_str() != "disabled"
                        && v.as_str() != "suspended"
                })
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            if !linger.is_empty() {
                disagree.push((
                    email.clone(),
                    format!("suspended user still active in: {}", linger.join(", ")),
                    row,
                ));
            }
        }
    }

    let mut lines = Vec::new();
    let summary: Vec<String> = email_sources
        .iter()
        .map(|r| format!("{} ({})", r.name, r.members.len()))
        .collect();
    lines.push(format!("== PRESENCE across: {} ==", summary.join(", ")));

    let mut finding_count = 0usize;
    if !disagree.is_empty() {
        lines.push(String::new());
        lines.push(format!("DISAGREE ({}):", disagree.len()));
        for (email, why, row) in &disagree {
            let cells: Vec<String> = email_sources
                .iter()
                .map(|r| {
                    format!(
                        "{}={}",
                        r.name,
                        row.get(&r.name).map(|s| s.as_str()).unwrap_or("—")
                    )
                })
                .collect();
            lines.push(format!("  {email:<38} {why}"));
            lines.push(format!("    {}", cells.join("  ")));
            finding_count += 1;
        }
    }

    if !not_joined.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "NOT JOINED ({}) — declared in users.yaml with create: false, no live accounts yet:",
            not_joined.len()
        ));
        for email in &not_joined {
            lines.push(format!("  {email}"));
        }
    }

    for (src_name, handles) in &unclaimed {
        lines.push(String::new());
        lines.push(format!(
            "UNCLAIMED in {src_name} ({}) — no matching github_handle in users.yaml:",
            handles.len()
        ));
        lines.push(format!("  {}", handles.join(", ")));
        finding_count += handles.len();
    }

    for r in &handle_sources {
        lines.push(String::new());
        let mut keys: Vec<&String> = r.members.keys().collect();
        keys.sort();
        let joined: Vec<String> = keys.into_iter().cloned().collect();
        lines.push(format!(
            "{} ({} handles — keyed by login, not email; link via github_handle in users.yaml to unify):",
            r.name,
            r.members.len()
        ));
        lines.push(format!("  {}", joined.join(", ")));
    }

    let skipped: Vec<&Presence> = results.iter().filter(|r| r.skipped.is_some()).collect();
    let errored: Vec<&Presence> = results.iter().filter(|r| r.error.is_some()).collect();

    if !skipped.is_empty() {
        lines.push(String::new());
        lines.push("NOT CONFIGURED (skipped):".to_string());
        for r in &skipped {
            lines.push(format!(
                "  {:<22} {}",
                r.name,
                r.skipped.as_deref().unwrap_or("")
            ));
        }
    }
    if !errored.is_empty() {
        lines.push(String::new());
        lines.push("FAILED (source was configured, probe broke):".to_string());
        for r in &errored {
            lines.push(format!(
                "  {:<22} {}",
                r.name,
                r.error.as_deref().unwrap_or("")
            ));
        }
    }

    // Build structured Findings
    let f = build_presence_findings(results, &email_sources, declared, google);

    let rc = if !errored.is_empty() {
        1
    } else if finding_count > 0 {
        2
    } else {
        0
    };
    (rc, lines, f)
}

fn build_presence_findings(
    results: &[Presence],
    email_sources: &[&Presence],
    declared: Option<&BTreeMap<String, String>>,
    google: Option<&BTreeMap<String, String>>,
) -> Findings {
    let mut f = Findings::new("presence");
    for r in results {
        if let Some(ref err) = r.error {
            f.add(
                "source-failed",
                &r.name,
                "medium",
                format!("presence probe failed: {}", r.name),
                vec![err.clone()],
                Some(format!(
                    "Check credentials and reachability for `{}` on the reconciler host.",
                    r.name
                )),
            );
        }
    }
    f.evaluated("source-failed");

    let mut all_emails = BTreeSet::new();
    for r in email_sources {
        for k in r.members.keys() {
            if k.starts_with('@') {
                let org = r.name.split(':').next_back().unwrap_or(&r.name);
                let sev = if org == "cerebral-work" {
                    "high"
                } else {
                    "medium"
                };
                f.add(
                    "unclaimed-github",
                    &format!("{}:{k}", r.name),
                    sev,
                    format!("{k} in {} has no github_handle in users.yaml", r.name),
                    vec![format!(
                        "Live member `{k}` in `{}` is not linked to any person in `directory/users.yaml`.",
                        r.name
                    )],
                    Some(format!(
                        "Add `github_handle: {}` + `{org}` under `github_orgs` on their `users.yaml` entry, or remove `{k}` from `{org}`.",
                        k.trim_start_matches('@')
                    )),
                );
            } else {
                all_emails.insert(k.clone());
            }
        }
    }

    let gh_ok = results
        .iter()
        .any(|r| r.name.starts_with("github:") && r.error.is_none() && r.skipped.is_none())
        && !results
            .iter()
            .any(|r| r.name.starts_with("github:") && r.error.is_some());
    if gh_ok {
        f.evaluated("unclaimed-github");
    }

    let Some(decl_map) = declared else {
        return f;
    };

    for email in &all_emails {
        let mut row = BTreeMap::new();
        for r in email_sources {
            let v = r.members.get(email).map(|s| s.as_str()).unwrap_or("—");
            row.insert(r.name.clone(), v.to_string());
        }
        let d = row.get("users.yaml").map(|s| s.as_str()).unwrap_or("—");
        let g = google.and_then(|gm| gm.get(email).map(|s| s.as_str()));
        let cells: Vec<String> = email_sources
            .iter()
            .map(|r| {
                format!(
                    "{}={}",
                    r.name,
                    row.get(&r.name).map(|s| s.as_str()).unwrap_or("—")
                )
            })
            .collect();

        if d == "—" {
            for (src, state) in &row {
                if src != "users.yaml" && state != "—" {
                    f.add(
                        "undeclared-account",
                        &format!("{src}:{email}"),
                        "high",
                        format!("{email}: present in {src} ({state}) but not in users.yaml"),
                        vec![cells.join("  ")],
                        Some(format!(
                            "Add `{email}` to `directory/users.yaml` or remove the account from `{src}`."
                        )),
                    );
                }
            }
        } else if d == "active" && g == Some("—") {
            for (src, state) in &row {
                if src != "users.yaml" && src != "google" && state != "—" {
                    f.add(
                        "state",
                        &format!("no-google:{email}"),
                        "medium",
                        format!("{email}: in {src} ({state}) but has no Google account yet"),
                        vec![cells.join("  ")],
                        None,
                    );
                }
            }
        } else if d == "active" && g == Some("suspended") {
            f.add(
                "state",
                &format!("google-suspended:{email}"),
                "medium",
                format!("{email}: declared active in users.yaml, suspended in Google"),
                vec![cells.join("  ")],
                Some(format!(
                    "Set `suspended: true` in `directory/users.yaml` or reinstate with `gam update user {email} suspended off`."
                )),
            );
        } else if d == "suspended" && g.is_some() && g != Some("suspended") {
            f.add(
                "state",
                &format!("not-suspended:{email}"),
                "high",
                format!(
                    "{email}: declared suspended, Google is {}",
                    g.unwrap_or("unknown")
                ),
                vec![cells.join("  ")],
                Some(
                    "Run `reconcile.py apply` to suspend in Google, or update `users.yaml`."
                        .to_string(),
                ),
            );
        } else if d == "suspended" {
            for (src, state) in &row {
                if src != "users.yaml"
                    && src != "google"
                    && state != "—"
                    && state != "disabled"
                    && state != "suspended"
                {
                    f.add(
                        "leftover",
                        &format!("{src}:{email}"),
                        "high",
                        format!("{email}: suspended user still {state} in {src}"),
                        vec![cells.join("  ")],
                        Some(format!(
                            "Deprovision or suspend `{email}` in `{src}` (offboarding incomplete)."
                        )),
                    );
                }
            }
        }
    }

    let _ = decl_map;
    if google.is_some() {
        f.evaluated("state");
    }
    let all_live_ok = results
        .iter()
        .filter(|r| r.name != "users.yaml")
        .all(|r| r.error.is_none() && r.skipped.is_none());
    if all_live_ok {
        f.evaluated("undeclared-account");
        f.evaluated("leftover");
    }

    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_presence_detects_lingering_and_unclaimed() {
        let p_decl = Presence {
            name: "users.yaml".to_string(),
            members: BTreeMap::from([
                ("active@cerebral.work".to_string(), "active".to_string()),
                ("gone@cerebral.work".to_string(), "suspended".to_string()),
            ]),
            error: None,
            skipped: None,
            keyed_by: "email".to_string(),
        };
        let p_goog = Presence {
            name: "google".to_string(),
            members: BTreeMap::from([
                ("active@cerebral.work".to_string(), "active".to_string()),
                ("gone@cerebral.work".to_string(), "suspended".to_string()),
            ]),
            error: None,
            skipped: None,
            keyed_by: "email".to_string(),
        };
        let p_gh = Presence {
            name: "github:cerebral-work".to_string(),
            members: BTreeMap::from([
                ("active@cerebral.work".to_string(), "member".to_string()),
                ("gone@cerebral.work".to_string(), "member".to_string()),
                ("@stranger".to_string(), "member".to_string()),
            ]),
            error: None,
            skipped: None,
            keyed_by: "email".to_string(),
        };

        let (rc, lines, f) = evaluate_presence(&[p_decl, p_goog, p_gh]);
        assert_eq!(rc, 2);
        let joined = lines.join("\n");
        assert!(joined.contains("gone@cerebral.work"));
        assert!(joined.contains("UNCLAIMED in github:cerebral-work"));
        assert!(f.items.iter().any(|i| i.kind == "leftover"));
        assert!(f.items.iter().any(|i| i.kind == "unclaimed-github"));
    }
}
