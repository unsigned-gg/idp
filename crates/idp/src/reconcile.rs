// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Google Workspace and GitHub reconciliation planner, SHA-256 plan digest gate, and findings mapper.
//!
//! Re-exports the pure Wave-0 reconciler engine from [`idp_domain::reconciler`] and provides
//! repository-level directory reconciliation ([`reconcile_directory`]) and [`Findings`] mapping ([`plan_findings`]).

pub use idp_domain::reconciler::{
    GroupRecord, HeldException, LicenseRecord, LiveGroup, LiveUser, OrgUnitRecord, ReconcilePlan,
    UserRecord, apply_refusal, held_members, plan_admin, plan_digest, plan_github, plan_groups,
    plan_licenses, plan_orgunits, plan_users, redact, shlex_quote, uncreated,
};

use crate::directory::DesiredState;
use crate::findings::Findings;
use chrono::NaiveDate;
use regex::Regex;
use serde::{Deserialize, Serialize};
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

/// Live state snapshot across Google Workspace and GitHub for offline or live reconciliation planning.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveDirectoryState {
    /// Live Google Workspace users keyed by email.
    #[serde(default)]
    pub users: BTreeMap<String, LiveUser>,
    /// Live Google Workspace organizational unit paths.
    #[serde(default)]
    pub orgunits: BTreeSet<String>,
    /// Live Google Workspace groups keyed by group email.
    #[serde(default)]
    pub groups: BTreeMap<String, LiveGroup>,
    /// Live Google Workspace license assignments (`(user_email, sku_id)`), or `None` if license check failed.
    #[serde(default)]
    pub licenses: Option<BTreeSet<(String, String)>>,
    /// Live GitHub organization members mapping `org -> {lowercase_login}`.
    #[serde(default)]
    pub github_orgs: BTreeMap<String, BTreeSet<String>>,
    /// Authenticated Google Workspace subject email (for self-lockout guard).
    #[serde(default)]
    pub google_subject: Option<String>,
    /// Authenticated GitHub login (for self-lockout guard).
    #[serde(default)]
    pub github_self: Option<String>,
}

/// Runs the complete directory reconciliation plan (`orgunits`, `users`, `admin`, `groups`, `licenses`, `github`)
/// against [`DesiredState`] and [`LiveDirectoryState`].
pub fn reconcile_directory(
    desired: &DesiredState,
    live: &LiveDirectoryState,
    elsewhere_groups: &BTreeSet<String>,
    unmanaged_groups: &BTreeMap<String, String>,
    today: NaiveDate,
    initial_password: &str,
) -> (ReconcilePlan, BTreeMap<String, String>) {
    let mut plan = ReconcilePlan::default();
    plan.extend(plan_orgunits(&desired.orgunits, &live.orgunits));
    plan.extend(plan_users(
        &desired.users,
        &live.users,
        live.google_subject.as_deref(),
        initial_password,
    ));
    plan.extend(plan_admin(
        &desired.users,
        &live.users,
        &desired.admin_roles,
    ));
    plan.extend(plan_groups(
        &desired.groups,
        &live.groups,
        &desired.users,
        &live.users,
        elsewhere_groups,
        unmanaged_groups,
        today,
    ));

    let mut want_licenses = BTreeSet::new();
    for (sku, rec) in &desired.licenses {
        if rec.reconcile {
            for u in &rec.users {
                want_licenses.insert((u.clone(), sku.clone()));
            }
        }
    }
    plan.extend(plan_licenses(&want_licenses, live.licenses.as_ref()));

    let (gh_plan, stakes) = plan_github(
        &desired.github_orgs,
        &live.github_orgs,
        &desired.leaving_github,
        &desired.declared_github,
        live.github_self.as_deref(),
    );
    plan.extend(gh_plan);

    (plan, stakes)
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

    #[test]
    fn test_plan_findings_maps_targets_and_severities() {
        let serial = vec![
            "gam create user new@cerebral.work firstname New lastname User org /Engineering password secret changepassword on".to_string(),
        ];
        let batch = vec![
            "gam update group devs@cerebral.work remove user old@cerebral.work".to_string(),
            "gh api -X DELETE /orgs/cerebral-work/memberships/exhandle".to_string(),
        ];
        let manual = vec![
            "REVOKE SUPER ADMIN from rogue@cerebral.work (never automated)".to_string(),
            "NOT CREATED pending@cerebral.work (declared with create: false)".to_string(),
            "devs@cerebral.work: HELD temp@cerebral.work (manual exception: test)".to_string(),
        ];
        let digest = plan_digest(&serial, &batch);
        let stakes = BTreeMap::from([(
            "gh api -X DELETE /orgs/cerebral-work/memberships/exhandle".to_string(),
            "TAILNET".to_string(),
        )]);
        let f = plan_findings(&serial, &batch, &manual, &digest, &stakes);
        assert_eq!(
            f.complete,
            vec![
                "identity-detectors:reconcile:pending:".to_string(),
                "identity-detectors:reconcile:manual:".to_string(),
            ]
        );
        assert!(f.items.iter().any(|i| i.key
            == "identity-detectors:reconcile:pending:new@cerebral.work"
            && i.severity == "low"));
        assert!(f.items.iter().any(|i| i.key
            == "identity-detectors:reconcile:pending:devs@cerebral.work"
            && i.severity == "medium"));
        assert!(f.items.iter().any(|i| i.key
            == "identity-detectors:reconcile:pending:gh-cerebral-work-exhandle"
            && i.detail[0].contains("[TAILNET]")));
        assert!(f.items.iter().any(|i| i.key
            == "identity-detectors:reconcile:manual:revoke-super-admin-from-rogue@cerebral.work"
            && i.severity == "high"));
        assert_eq!(f.items.len(), 4);
    }
}
