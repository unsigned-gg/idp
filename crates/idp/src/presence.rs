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

/// Parses a Keycloak Admin REST API `/admin/realms/{realm}/users` JSON array into a [`Presence`] snapshot.
pub fn parse_keycloak_presence(
    realm: &str,
    users_json: &serde_json::Value,
) -> Result<Presence, IdpError> {
    let arr = users_json
        .as_array()
        .or_else(|| users_json.get("users").and_then(|v| v.as_array()))
        .ok_or_else(|| IdpError::Validation("keycloak users JSON must be an array".to_string()))?;
    let mut members = BTreeMap::new();
    for u in arr {
        let email = u
            .get("email")
            .and_then(|v| v.as_str())
            .or_else(|| u.get("username").and_then(|v| v.as_str()))
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if email.is_empty() {
            continue;
        }
        let enabled = u.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let state = if enabled { "active" } else { "disabled" };
        members.insert(email, state.to_string());
    }
    Ok(Presence {
        name: format!("keycloak:{realm}"),
        members,
        error: None,
        skipped: None,
        keyed_by: "email".to_string(),
    })
}

/// Reads Keycloak presence from `KEYCLOAK_USERS_JSON` (inline JSON or file path), or marks skipped when unconfigured.
pub fn src_keycloak(realm: &str) -> Presence {
    read_json_env_presence(
        &format!("keycloak:{realm}"),
        "KEYCLOAK_USERS_JSON",
        "not wired yet (KEYCLOAK_ADMIN_URL / KEYCLOAK_USERS_JSON unset)",
        |val| parse_keycloak_presence(realm, val),
    )
}

/// Parses a Tailscale `/api/v2/tailnet/{tailnet}/users` or `/devices` JSON payload into a [`Presence`] snapshot.
pub fn parse_tailscale_presence(payload: &serde_json::Value) -> Result<Presence, IdpError> {
    let mut members = BTreeMap::new();
    if let Some(users) = payload
        .get("users")
        .and_then(|v| v.as_array())
        .or_else(|| payload.as_array())
    {
        for u in users {
            let login = u
                .get("loginName")
                .and_then(|v| v.as_str())
                .or_else(|| u.get("user").and_then(|v| v.as_str()))
                .or_else(|| u.get("email").and_then(|v| v.as_str()))
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if login.is_empty() {
                continue;
            }
            let status = u
                .get("status")
                .and_then(|v| v.as_str())
                .or_else(|| u.get("role").and_then(|v| v.as_str()))
                .unwrap_or("active")
                .to_lowercase();
            let state = if status == "suspended" {
                "suspended".to_string()
            } else {
                status
            };
            members.insert(login, state);
        }
    } else if let Some(devices) = payload.get("devices").and_then(|v| v.as_array()) {
        for d in devices {
            let user = d
                .get("user")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if !user.is_empty() {
                members.insert(user, "active".to_string());
            }
        }
    } else {
        return Err(IdpError::Validation(
            "tailscale JSON must contain `users`, `devices`, or be a JSON array".to_string(),
        ));
    }
    Ok(Presence {
        name: "tailscale".to_string(),
        members,
        error: None,
        skipped: None,
        keyed_by: "email".to_string(),
    })
}

/// Reads Tailscale presence from `TAILSCALE_USERS_JSON` (inline JSON or file path), or marks skipped when unconfigured.
pub fn src_tailscale() -> Presence {
    read_json_env_presence(
        "tailscale",
        "TAILSCALE_USERS_JSON",
        "not wired yet (TAILSCALE_API_TOKEN / TAILSCALE_USERS_JSON unset)",
        parse_tailscale_presence,
    )
}

/// Parses a Linear GraphQL `{ users { nodes { email active admin guest } } }` or array payload into a [`Presence`] snapshot.
pub fn parse_linear_presence(payload: &serde_json::Value) -> Result<Presence, IdpError> {
    let nodes = payload
        .pointer("/data/users/nodes")
        .and_then(|v| v.as_array())
        .or_else(|| payload.pointer("/users/nodes").and_then(|v| v.as_array()))
        .or_else(|| payload.get("users").and_then(|v| v.as_array()))
        .or_else(|| payload.as_array())
        .ok_or_else(|| {
            IdpError::Validation("linear JSON must contain user nodes or be an array".to_string())
        })?;
    let mut members = BTreeMap::new();
    for u in nodes {
        let email = u
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if email.is_empty() {
            continue;
        }
        let active = u.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
        let admin = u.get("admin").and_then(|v| v.as_bool()).unwrap_or(false);
        let guest = u.get("guest").and_then(|v| v.as_bool()).unwrap_or(false);
        let state = if !active {
            "suspended"
        } else if admin {
            "admin"
        } else if guest {
            "guest"
        } else {
            "member"
        };
        members.insert(email, state.to_string());
    }
    Ok(Presence {
        name: "linear".to_string(),
        members,
        error: None,
        skipped: None,
        keyed_by: "email".to_string(),
    })
}

/// Reads Linear presence from `LINEAR_USERS_JSON` (inline JSON or file path), or marks skipped when unconfigured.
pub fn src_linear() -> Presence {
    read_json_env_presence(
        "linear",
        "LINEAR_USERS_JSON",
        "not wired yet (LINEAR_API_KEY / LINEAR_USERS_JSON unset)",
        parse_linear_presence,
    )
}

/// Parses a Cloudflare Zero Trust Access `/accounts/{id}/access/users` JSON payload into a [`Presence`] snapshot.
pub fn parse_cloudflare_access_presence(payload: &serde_json::Value) -> Result<Presence, IdpError> {
    let arr = payload
        .get("result")
        .and_then(|v| v.as_array())
        .or_else(|| payload.get("users").and_then(|v| v.as_array()))
        .or_else(|| payload.as_array())
        .ok_or_else(|| {
            IdpError::Validation(
                "cloudflare-access JSON must contain `result`, `users`, or be an array".to_string(),
            )
        })?;
    let mut members = BTreeMap::new();
    for u in arr {
        let email = u
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if email.is_empty() {
            continue;
        }
        let seat = u
            .get("access_seat")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let state = if seat { "active" } else { "inactive" };
        members.insert(email, state.to_string());
    }
    Ok(Presence {
        name: "cloudflare-access".to_string(),
        members,
        error: None,
        skipped: None,
        keyed_by: "email".to_string(),
    })
}

/// Reads Cloudflare Access presence from `CLOUDFLARE_ACCESS_USERS_JSON` (inline JSON or file path), or marks skipped when unconfigured.
pub fn src_cloudflare_access() -> Presence {
    read_json_env_presence(
        "cloudflare-access",
        "CLOUDFLARE_ACCESS_USERS_JSON",
        "not wired yet (CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCESS_USERS_JSON unset)",
        parse_cloudflare_access_presence,
    )
}

/// Parses a GitBook `/v1/orgs/{org}/members` JSON payload into a [`Presence`] snapshot.
pub fn parse_gitbook_presence(payload: &serde_json::Value) -> Result<Presence, IdpError> {
    let arr = payload
        .get("items")
        .and_then(|v| v.as_array())
        .or_else(|| payload.get("members").and_then(|v| v.as_array()))
        .or_else(|| payload.as_array())
        .ok_or_else(|| {
            IdpError::Validation(
                "gitbook JSON must contain `items`, `members`, or be an array".to_string(),
            )
        })?;
    let mut members = BTreeMap::new();
    for m in arr {
        let user_obj = m.get("user").unwrap_or(m);
        let email = user_obj
            .get("email")
            .and_then(|v| v.as_str())
            .or_else(|| m.get("email").and_then(|v| v.as_str()))
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if email.is_empty() {
            continue;
        }
        let role = m
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member")
            .to_lowercase();
        members.insert(email, role);
    }
    Ok(Presence {
        name: "gitbook".to_string(),
        members,
        error: None,
        skipped: None,
        keyed_by: "email".to_string(),
    })
}

/// Reads GitBook presence from `GITBOOK_MEMBERS_JSON` (inline JSON or file path), or marks skipped when unconfigured.
pub fn src_gitbook() -> Presence {
    read_json_env_presence(
        "gitbook",
        "GITBOOK_MEMBERS_JSON",
        "not wired yet (GITBOOK_API_TOKEN / GITBOOK_MEMBERS_JSON unset)",
        parse_gitbook_presence,
    )
}

fn read_json_env_presence<F>(name: &str, env_var: &str, skip_msg: &str, parser: F) -> Presence
where
    F: FnOnce(&serde_json::Value) -> Result<Presence, IdpError>,
{
    let raw = match std::env::var(env_var) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return Presence {
                name: name.to_string(),
                members: BTreeMap::new(),
                error: None,
                skipped: Some(skip_msg.to_string()),
                keyed_by: "email".to_string(),
            };
        }
    };
    let text = if Path::new(raw.trim()).exists() {
        match fs::read_to_string(raw.trim()) {
            Ok(t) => t,
            Err(e) => {
                return Presence {
                    name: name.to_string(),
                    members: BTreeMap::new(),
                    error: Some(e.to_string()),
                    skipped: None,
                    keyed_by: "email".to_string(),
                };
            }
        }
    } else {
        raw
    };
    match serde_json::from_str::<serde_json::Value>(&text)
        .and_then(|v| parser(&v).map_err(serde::de::Error::custom))
    {
        Ok(p) => p,
        Err(e) => Presence {
            name: name.to_string(),
            members: BTreeMap::new(),
            error: Some(e.to_string()),
            skipped: None,
            keyed_by: "email".to_string(),
        },
    }
}

/// Collects presence snapshots across declared `users.yaml` and all configured/stubbed planes,
/// optionally filtered to a single plane name (`keycloak`, `tailscale`, `linear`, `cloudflare-access`, `gitbook`).
pub fn collect_presence(
    repo: &Path,
    plane_filter: Option<&str>,
) -> Result<Vec<Presence>, IdpError> {
    let mut results = vec![src_declared(repo)?];
    let want = |name: &str| -> bool {
        match plane_filter {
            None => true,
            Some(f) => f == name || name.starts_with(&format!("{f}:")),
        }
    };
    if want("keycloak") {
        results.push(src_keycloak("cerebral"));
    }
    if want("tailscale") {
        results.push(src_tailscale());
    }
    if want("linear") {
        results.push(src_linear());
    }
    if want("cloudflare-access") {
        results.push(src_cloudflare_access());
    }
    if want("gitbook") {
        results.push(src_gitbook());
    }
    Ok(results)
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

    #[test]
    fn test_parse_five_planes_presence() {
        let kc_val = serde_json::json!([
            {"email": "ctodie@cerebral.work", "enabled": true},
            {"email": "gone@cerebral.work", "enabled": false}
        ]);
        let kc = parse_keycloak_presence("cerebral", &kc_val).unwrap();
        assert_eq!(kc.name, "keycloak:cerebral");
        assert_eq!(
            kc.members.get("ctodie@cerebral.work").map(|s| s.as_str()),
            Some("active")
        );
        assert_eq!(
            kc.members.get("gone@cerebral.work").map(|s| s.as_str()),
            Some("disabled")
        );

        let ts_val = serde_json::json!({
            "users": [
                {"loginName": "ctodie@cerebral.work", "status": "active"},
                {"loginName": "ahackley@cerebral.work", "status": "admin"}
            ]
        });
        let ts = parse_tailscale_presence(&ts_val).unwrap();
        assert_eq!(ts.name, "tailscale");
        assert_eq!(
            ts.members.get("ahackley@cerebral.work").map(|s| s.as_str()),
            Some("admin")
        );

        let lin_val = serde_json::json!({
            "data": {
                "users": {
                    "nodes": [
                        {"email": "ctodie@cerebral.work", "active": true, "admin": true},
                        {"email": "gone@cerebral.work", "active": false}
                    ]
                }
            }
        });
        let lin = parse_linear_presence(&lin_val).unwrap();
        assert_eq!(lin.name, "linear");
        assert_eq!(
            lin.members.get("ctodie@cerebral.work").map(|s| s.as_str()),
            Some("admin")
        );
        assert_eq!(
            lin.members.get("gone@cerebral.work").map(|s| s.as_str()),
            Some("suspended")
        );

        let cf_val = serde_json::json!({
            "result": [
                {"email": "ctodie@cerebral.work", "access_seat": true},
                {"email": "ahackley@cerebral.work", "access_seat": true}
            ]
        });
        let cf = parse_cloudflare_access_presence(&cf_val).unwrap();
        assert_eq!(cf.name, "cloudflare-access");
        assert_eq!(cf.members.len(), 2);

        let gb_val = serde_json::json!({
            "items": [
                {"user": {"email": "ctodie@cerebral.work"}, "role": "admin"}
            ]
        });
        let gb = parse_gitbook_presence(&gb_val).unwrap();
        assert_eq!(gb.name, "gitbook");
        assert_eq!(
            gb.members.get("ctodie@cerebral.work").map(|s| s.as_str()),
            Some("admin")
        );
    }
}
