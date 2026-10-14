// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Google Workspace and GitHub reconciliation planner, SHA-256 plan digest gate, and findings mapper.
//!
//! Extracted from `cerebral-work/identity/scripts/reconcile/reconcile.py`.

use crate::directory::{GroupRecord, LicenseRecord, UserRecord};
use crate::findings::Findings;
use crate::security::redact_password;
use chrono::NaiveDate;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

#[allow(clippy::expect_used)]
static TARGET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gam (?:create|update|delete) (?:user|group|alias \S+ user|license \S+ user) (\S+)|gh api -X DELETE /orgs/([^/]+)/memberships/(\S+)")
        .expect("valid target regex")
});

#[allow(clippy::expect_used)]
static HIGH_MANUAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(REVOKE |GRANT |ADMIN ROLE CHANGE |UNDECLARED .* ADMIN |UNDECLARED .* in cerebral-work)",
    )
    .expect("valid high manual regex")
});

/// Live user state read from Google Workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveUser {
    /// Primary email address.
    pub email: String,
    /// Given name.
    pub given_name: String,
    /// Family name.
    pub family_name: String,
    /// Organizational unit path.
    pub org_unit: String,
    /// Whether the user is suspended in Google Workspace.
    pub suspended: bool,
    /// Whether the user holds Google Super Admin privileges.
    #[serde(default)]
    pub is_super_admin: bool,
    /// Delegated admin roles currently assigned in Google Workspace.
    #[serde(default)]
    pub admin_roles: BTreeSet<String>,
    /// Active email aliases in Google Workspace.
    #[serde(default)]
    pub aliases: BTreeSet<String>,
}

/// Live group state read from Google Workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveGroup {
    /// Group email address.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Group description.
    pub description: String,
    /// Group settings map.
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    /// Group members (`MEMBER`).
    #[serde(default)]
    pub members: BTreeSet<String>,
    /// Group managers (`MANAGER`).
    #[serde(default)]
    pub managers: BTreeSet<String>,
    /// Group owners (`OWNER`).
    #[serde(default)]
    pub owners: BTreeSet<String>,
}

/// Output of a reconciliation planning stage (`serial` prerequisite commands, `batch` commands, and `manual` review notes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcilePlan {
    /// Commands that must run sequentially before `batch` (e.g. creating OUs, users, or groups).
    pub serial: Vec<String>,
    /// Independent commands that can run after `serial` completes.
    pub batch: Vec<String>,
    /// Human-review items that are never automated.
    pub manual: Vec<String>,
}

impl ReconcilePlan {
    /// Appends another [`ReconcilePlan`] into `self`.
    pub fn extend(&mut self, other: ReconcilePlan) {
        self.serial.extend(other.serial);
        self.batch.extend(other.batch);
        self.manual.extend(other.manual);
    }
}

/// Evaluates `unreconciled_members` hold exceptions on `group` as of `today`.
///
/// Returns `(held_emails, manual_notes)`.
pub fn held_members(group: &GroupRecord, today: NaiveDate) -> (BTreeSet<String>, Vec<String>) {
    let mut held = BTreeSet::new();
    let mut notes = Vec::new();
    for entry in &group.unreconciled_members {
        let who = &entry.email;
        let reason = entry.reason.trim();
        if reason.is_empty() {
            notes.push(format!(
                "EXCEPTION IGNORED for {who} — unreconciled_members entry has no reason"
            ));
            continue;
        }
        let mut span = String::new();
        if let Some(ref until_str) = entry.until {
            if let Ok(end) = NaiveDate::parse_from_str(until_str, "%Y-%m-%d")
                && end < today
            {
                notes.push(format!(
                    "EXCEPTION EXPIRED for {who} (until {end}: {reason}) — will be removed"
                ));
                continue;
            }
            span = format!(", until {until_str}");
        }
        held.insert(who.clone());
        notes.push(format!("HELD {who} (manual exception{span}: {reason})"));
    }
    (held, notes)
}

/// Plans organizational unit creation and flags manual deletions.
pub fn plan_orgunits(want: &BTreeSet<String>, have: &BTreeSet<String>) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    let mut to_create: Vec<&String> = want.difference(have).collect();
    to_create.sort_by_key(|p| (p.matches('/').count(), *p));
    for path in to_create {
        plan.serial.push(format!("gam create org '{path}'"));
    }
    for path in have.difference(want) {
        if path != "/" {
            plan.manual
                .push(format!("DELETE OU {path} (manual — never automated)"));
        }
    }
    plan
}

/// Plans Google Workspace user creation, attribute updates, suspension, and alias synchronization.
pub fn plan_users(
    want: &BTreeMap<String, UserRecord>,
    have: &BTreeMap<String, LiveUser>,
    subject: Option<&str>,
    initial_password: &str,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    let all_emails: BTreeSet<&String> = want.keys().chain(have.keys()).collect();

    for email in all_emails {
        let Some(w) = want.get(email) else {
            plan.manual
                .push(format!("DELETE USER {email} (never automated)"));
            continue;
        };
        let Some(h) = have.get(email) else {
            if !w.create {
                plan.manual.push(format!(
                    "NOT CREATED {email} (declared with create: false — account does not exist in Google yet)"
                ));
                continue;
            }
            plan.serial.push(format!(
                "gam create user {email} firstname '{}' lastname '{}' org '{}' password {initial_password} changepassword on",
                w.given_name, w.family_name, w.org_unit
            ));
            for a in &w.aliases {
                plan.batch
                    .push(format!("gam create alias {a} user {email}"));
            }
            if w.suspended {
                plan.batch
                    .push(format!("gam update user {email} suspended on"));
            }
            continue;
        };

        let mut updates = Vec::new();
        if w.given_name != h.given_name {
            updates.push(format!("firstname '{}'", w.given_name));
        }
        if w.family_name != h.family_name {
            updates.push(format!("lastname '{}'", w.family_name));
        }
        if w.org_unit != h.org_unit {
            updates.push(format!("org '{}'", w.org_unit));
        }
        if w.suspended != h.suspended {
            if w.suspended && subject == Some(email.as_str()) {
                plan.manual.push(format!(
                    "NOT SUSPENDED {email} (this is the account the reconciler authenticates as — suspending it stops the next run from being able to undo the change)"
                ));
            } else if !w.suspended && h.suspended {
                plan.manual.push(format!(
                    "NOT REINSTATED {email} (declared active, live is suspended — un-suspending an account is never automated; run: gam update user {email} suspended off)"
                ));
            } else {
                updates.push(format!(
                    "suspended {}",
                    if w.suspended { "on" } else { "off" }
                ));
            }
        }
        if !updates.is_empty() {
            plan.batch
                .push(format!("gam update user {email} {}", updates.join(" ")));
        }

        for a in w.aliases.difference(&h.aliases) {
            plan.batch
                .push(format!("gam create alias {a} user {email}"));
        }
        for a in h.aliases.difference(&w.aliases) {
            plan.batch.push(format!("gam delete alias {a}"));
        }
    }

    plan
}

/// Plans manual notifications for Google Super Admin and delegated admin role drift.
pub fn plan_admin(
    want: &BTreeMap<String, UserRecord>,
    have: &BTreeMap<String, LiveUser>,
    admin_roles: &BTreeMap<String, BTreeSet<String>>,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for (email, w) in want {
        let Some(h) = have.get(email) else {
            continue;
        };
        if w.is_super_admin && !h.is_super_admin {
            plan.manual.push(format!(
                "GRANT SUPER ADMIN to {email} (never automated; gam update user {email} admin on)"
            ));
        } else if !w.is_super_admin && h.is_super_admin {
            plan.manual.push(format!(
                "REVOKE SUPER ADMIN from {email} (never automated; gam update user {email} admin off)"
            ));
        }
        let w_roles: Vec<&String> = admin_roles
            .get(email)
            .map(|s| s.iter().collect())
            .unwrap_or_default();
        let h_roles: Vec<&String> = h.admin_roles.iter().collect();
        if w_roles != h_roles {
            plan.manual.push(format!(
                "ADMIN ROLE CHANGE for {email}: want {w_roles:?}, have {h_roles:?} (never automated)"
            ));
        }
    }
    for (email, h) in have {
        if !want.contains_key(email) && h.is_super_admin {
            plan.manual.push(format!(
                "UNDECLARED SUPER ADMIN {email} (in Google, not in users.yaml)"
            ));
        }
    }
    plan
}

/// Plans Google Workspace group creation, settings updates, and membership reconciliation.
pub fn plan_groups(
    want: &BTreeMap<String, GroupRecord>,
    have: &BTreeMap<String, LiveGroup>,
    today: NaiveDate,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();

    for (email, g) in want {
        let Some(h) = have.get(email) else {
            plan.serial.push(format!(
                "gam create group {email} name '{}' description '{}'",
                g.name, g.description
            ));
            if !g.settings.is_empty() {
                let kv: Vec<String> = g.settings.iter().map(|(k, v)| format!("{k} {v}")).collect();
                plan.serial
                    .push(format!("gam update group {email} {}", kv.join(" ")));
            }
            for (role, set) in [
                ("owner", &g.owners),
                ("manager", &g.managers),
                ("member", &g.members),
            ] {
                for m in set {
                    plan.batch
                        .push(format!("gam update group {email} add {role} user {m}"));
                }
            }
            continue;
        };

        let mut meta = Vec::new();
        if g.name != h.name {
            meta.push(format!("name '{}'", g.name));
        }
        if g.description != h.description {
            meta.push(format!("description '{}'", g.description));
        }
        if !meta.is_empty() {
            plan.batch
                .push(format!("gam update group {email} {}", meta.join(" ")));
        }

        let mut sdiff = Vec::new();
        for (k, v) in &g.settings {
            let live_v = h.settings.get(k).map(|s| s.to_uppercase());
            if live_v.as_deref() != Some(&v.to_uppercase()) {
                sdiff.push(format!("{k} {v}"));
            }
        }
        if !sdiff.is_empty() {
            plan.batch
                .push(format!("gam update group {email} {}", sdiff.join(" ")));
        }

        let (held, notes) = held_members(g, today);
        for n in notes {
            plan.manual.push(format!("{email}: {n}"));
        }

        let w_all: BTreeSet<&String> = g
            .owners
            .iter()
            .chain(g.managers.iter())
            .chain(g.members.iter())
            .collect();
        let h_all: BTreeSet<&String> = h
            .owners
            .iter()
            .chain(h.managers.iter())
            .chain(h.members.iter())
            .collect();

        for (role_singular, w_set, h_set) in [
            ("owner", &g.owners, &h.owners),
            ("manager", &g.managers, &h.managers),
            ("member", &g.members, &h.members),
        ] {
            for m in w_set.difference(h_set) {
                if h_all.contains(m) {
                    plan.batch.push(format!(
                        "gam update group {email} update {role_singular} user {m}"
                    ));
                } else {
                    plan.batch.push(format!(
                        "gam update group {email} add {role_singular} user {m}"
                    ));
                }
            }
            for m in h_set {
                if !w_all.contains(m) && !held.contains(m) {
                    plan.batch
                        .push(format!("gam update group {email} remove user {m}"));
                }
            }
        }
    }

    for email in have.keys() {
        if !want.contains_key(email) {
            plan.manual.push(format!(
                "UNMANAGED: group {email} exists in Google but has no directory/groups/*.yaml file (left untouched)"
            ));
        }
    }

    plan
}

/// Plans Google Workspace license assignment and revocation.
pub fn plan_licenses(
    want: &BTreeMap<String, LicenseRecord>,
    have: Option<&BTreeMap<String, BTreeSet<String>>>,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    let Some(have_map) = have else {
        plan.manual
            .push("LICENCES NOT CHECKED: gam print licenses failed".to_string());
        return plan;
    };

    for (sku, spec) in want {
        let live = have_map.get(sku).cloned().unwrap_or_default();
        if !spec.reconcile {
            if !live.is_empty() {
                plan.manual.push(format!(
                    "UNMANAGED: {} ({sku}) has {} live holder(s); reconcile: false",
                    spec.sku_name,
                    live.len()
                ));
            }
            continue;
        }
        for u in spec.users.difference(&live) {
            plan.batch
                .push(format!("gam create license {sku} user {u}"));
        }
        for u in live.difference(&spec.users) {
            plan.batch
                .push(format!("gam delete license {sku} user {u}"));
        }
    }
    plan
}

/// Plans GitHub organization membership removals for offboarded users and flags manual additions/undeclared accounts.
///
/// Returns `(plan, github_stakes)` where `github_stakes` records `"TAILNET"` for commands affecting `cerebral-work`.
pub fn plan_github(
    want: &BTreeMap<String, BTreeSet<String>>,
    have: &BTreeMap<String, BTreeSet<String>>,
    leaving: &BTreeSet<String>,
    declared: &BTreeSet<String>,
    self_login: Option<&str>,
) -> (ReconcilePlan, BTreeMap<String, String>) {
    let mut plan = ReconcilePlan::default();
    let mut stakes = BTreeMap::new();
    let self_norm = self_login.map(|s| s.to_lowercase());
    let covered: BTreeSet<String> = declared.union(leaving).cloned().collect();

    if self_norm.is_none() {
        plan.manual.push(
            "GITHUB SELF UNKNOWN (gh api /user failed) — holding all GitHub removals this run so the token owner cannot remove itself"
                .to_string(),
        );
    }

    for (org, w_raw) in want {
        let stake = if org == "cerebral-work" {
            " [TAILNET]"
        } else {
            ""
        };
        let Some(h_raw) = have.get(org) else {
            plan.manual.push(format!(
                "GITHUB {org}: could not read live members — skipped"
            ));
            continue;
        };
        let w: BTreeSet<String> = w_raw.iter().map(|s| s.to_lowercase()).collect();
        let h: BTreeSet<String> = h_raw.iter().map(|s| s.to_lowercase()).collect();

        let mut extra: Vec<String> = h.difference(&w).cloned().collect();
        extra.sort();
        for login in extra {
            if self_norm.as_deref() == Some(login.as_str()) {
                plan.manual.push(format!(
                    "NOT REMOVED {login} from {org}{stake} (this is the GitHub account the reconciler authenticates as — removing it revokes its own org access)"
                ));
            } else if !covered.contains(&login) {
                plan.manual.push(format!(
                    "UNDECLARED {login} in {org}{stake} (not in users.yaml — add github_handle + github_orgs or remove manually)"
                ));
            } else if leaving.contains(&login) {
                if self_norm.is_some() {
                    let cmd = format!("gh api -X DELETE /orgs/{org}/memberships/{login}");
                    if !stake.is_empty() {
                        stakes.insert(cmd.clone(), "TAILNET".to_string());
                    }
                    plan.batch.push(cmd);
                }
            } else {
                plan.manual.push(format!(
                    "NOT REMOVED {login} from {org}{stake} (active user in users.yaml without {org} in github_orgs — add {org} to their github_orgs, or remove from org manually)"
                ));
            }
        }

        let mut missing: Vec<String> = w.difference(&h).cloned().collect();
        missing.sort();
        for login in missing {
            plan.manual.push(format!(
                "NOT ADDED {login} to {org}{stake} (org invitations are never automated; invite via GitHub UI or: gh api -X PUT /orgs/{org}/memberships/{login})"
            ));
        }
    }

    (plan, stakes)
}

/// Redacts inline passwords in GAM commands (`password \S+` -> `password <redacted>`).
pub fn redact(cmd: &str) -> String {
    redact_password(cmd)
}

/// Computes the 16-character hex SHA-256 digest over `serial` and password-redacted `batch` commands.
pub fn plan_digest(serial: &[String], batch: &[String]) -> String {
    let mut lines = Vec::with_capacity(serial.len() + batch.len() + 2);
    lines.push("SERIAL".to_string());
    lines.extend(serial.iter().cloned());
    lines.push("BATCH".to_string());
    lines.extend(batch.iter().map(|c| redact(c)));
    let body = lines.join("\n");
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex[..16].to_string()
}

/// Verifies `--expect-plan-sha256` against the actual plan digest before applying changes.
///
/// Returns `Some(refusal_message)` if `expected` is missing or mismatches `actual`, or `None` when valid.
pub fn apply_refusal(expected: Option<&str>, actual: &str) -> Option<String> {
    let Some(exp) = expected.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
        return Some(format!(
            "refusing to apply without --expect-plan-sha256 {actual}\nRun `reconcile.py plan` first, review the output, and pass the Plan SHA256 it prints (--expect-plan-sha256 is required)."
        ));
    };
    if exp.to_lowercase() != actual {
        return Some(format!(
            "refusing to apply: the plan has changed since it was reviewed.\n  reviewed: {exp}\n  current:  {actual}\nRe-run plan, read the diff, and pass the new digest."
        ));
    }
    None
}

/// Converts a reconciliation plan (`serial`, `batch`, `manual`, `digest`) into structured [`Findings`].
pub fn plan_findings(
    serial: &[String],
    batch: &[String],
    manual: &[String],
    digest: &str,
    github_stakes: &BTreeMap<String, String>,
) -> Findings {
    let mut f = Findings::new("reconcile");
    let mut by_target: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for raw in serial.iter().chain(batch.iter()) {
        let cmd = redact(raw);
        let key = if let Some(caps) = TARGET_RE.captures(&cmd) {
            if let Some(m1) = caps.get(1) {
                m1.as_str().trim_matches('\'').to_string()
            } else if let (Some(org), Some(login)) = (caps.get(2), caps.get(3)) {
                format!("gh:{}:{}", org.as_str(), login.as_str())
            } else {
                cmd.clone()
            }
        } else {
            cmd.clone()
        };
        let mut display = cmd;
        if let Some(s) = github_stakes.get(raw) {
            display = format!("{display}  # [{s}]");
        }
        by_target.entry(key).or_default().push(display);
    }

    for (target, cmds) in &by_target {
        let joined = cmds.join(" ");
        let sev = if joined.contains(" remove ")
            || joined.contains(" delete ")
            || joined.contains(" suspended on")
        {
            "medium"
        } else {
            "low"
        };
        f.add(
            "pending",
            target,
            sev,
            format!("{target}: {} unapplied directory change(s)", cmds.len()),
            cmds.iter().map(|c| format!("`{c}`")).collect(),
            Some(format!(
                "Run `python3 scripts/reconcile/reconcile.py apply --expect-plan-sha256 {digest}` (or revert the git change if unintended)."
            )),
        );
    }
    f.evaluated("pending");

    let ignore_prefixes = [
        "NOT CREATED ",
        "UNMANAGED:",
        "NOT CHECKED:",
        "LICENCES NOT CHECKED",
        "GITHUB ",
    ];
    for m in manual {
        if ignore_prefixes.iter().any(|p| m.starts_with(p)) || m.contains(": HELD ") {
            continue;
        }
        let sev = if HIGH_MANUAL_RE.is_match(m) {
            "high"
        } else {
            "medium"
        };
        let head = m.split(" (").next().unwrap_or(m);
        f.add("manual", head, sev, head.to_string(), vec![m.clone()], None);
    }
    f.evaluated("manual");

    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_digest_and_apply_refusal() {
        let s =
            ["gam create user a@cerebral.work password secretOne changepassword on".to_string()];
        let b1 = ["gam update user a@cerebral.work password secretOne".to_string()];
        let b2 = ["gam update user a@cerebral.work password secretTwo".to_string()];
        assert_eq!(plan_digest(&[], &b1), plan_digest(&[], &b2));
        assert_ne!(plan_digest(&s, &[]), plan_digest(&[], &[]));

        let d = plan_digest(&[], &b1);
        assert!(apply_refusal(None, &d).unwrap().contains("required"));
        assert!(apply_refusal(Some("deadbeef00000000"), &d).is_some());
        assert!(apply_refusal(Some(&d.to_uppercase()), &d).is_none());
    }
}
