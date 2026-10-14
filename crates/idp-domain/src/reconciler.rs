// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Pure Wave-0 zero-I/O Google Workspace and GitHub directory reconciler engine.
//!
//! Extracted from `cerebral-work/identity/scripts/reconcile/reconcile.py`.
//!
//! # Safety Model
//! - **Asymmetric suspension**: Suspending an account (`suspended: true`) is automated for fast `T+0`
//!   offboarding; un-suspending (`suspended: false` against a live suspended account) is NEVER
//!   automated (`NOT REINSTATED`).
//! - **Self-lockout refusal**: Suspending the Google Workspace `subject` account or removing the
//!   GitHub `self_login` account that authenticates the reconciler is refused (`NOT SUSPENDED` / `NOT REMOVED`).
//! - **2SV enrollment gate**: Adding a member to a group with `requires_2sv_enrolled: true` is
//!   refused unless the live user has `enrolled_2sv: true`.
//! - **SHA-256 plan digest handshake**: `apply_refusal` refuses `apply` unless `--expect-plan-sha256`
//!   matches the exact SHA-256 digest of the JSON-structured `{"serial": [...], "batch": [...]}`
//!   command list with throwaway passwords redacted to `<random>`.

use chrono::NaiveDate;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

#[allow(clippy::expect_used)]
static PASSWORD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bpassword \S+").expect("valid password regex"));

/// Irrevocable Sovereign Root Google Workspace primary email address.
pub const SOVEREIGN_ROOT_EMAIL: &str = "ctodie@cerebral.work";

/// Irrevocable Sovereign Root GitHub login handle (lowercase).
pub const SOVEREIGN_ROOT_GITHUB: &str = "todie";

/// Irrevocable Sovereign Root organizational unit path.
pub const SOVEREIGN_ROOT_ORG_UNIT: &str = "/Humans/Admins";

fn default_true() -> bool {
    true
}

/// User record declared in `directory/users.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    /// Primary Google Workspace email address.
    pub email: String,
    /// Given (first) name.
    pub given_name: String,
    /// Family (last) name.
    pub family_name: String,
    /// Google Workspace organizational unit path (e.g. `"/Engineering"`).
    pub org_unit: String,
    /// Whether the user account is suspended.
    #[serde(default)]
    pub suspended: bool,
    /// Whether the reconciler may create the account in Google Workspace (defaults to `true`).
    #[serde(default = "default_true")]
    pub create: bool,
    /// Whether the user holds Google Workspace Super Admin privileges.
    #[serde(default)]
    pub is_super_admin: bool,
    /// Optional admin level string (`"super"` or `"delegated"`).
    #[serde(default)]
    pub admin: Option<String>,
    /// Delegated Google Workspace admin roles held by the user.
    #[serde(default)]
    pub admin_roles: BTreeSet<String>,
    /// Email aliases assigned to the user.
    #[serde(default)]
    pub aliases: BTreeSet<String>,
    /// Optional GitHub login handle (case-insensitive for matching).
    #[serde(default)]
    pub github_handle: Option<String>,
    /// GitHub organizations the user should belong to.
    #[serde(default)]
    pub github_orgs: BTreeSet<String>,
}

/// Organizational unit declared in `directory/orgunits.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgUnitRecord {
    /// Organizational unit path (e.g. `"/Engineering"`).
    pub path: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
}

/// Manual hold exception in `unreconciled_members` of a group file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldException {
    /// Member email address held from removal.
    pub email: String,
    /// Human explanation for the exception.
    #[serde(default)]
    pub reason: String,
    /// Optional `YYYY-MM-DD` expiration date.
    #[serde(default)]
    pub until: Option<String>,
}

/// Group record declared in `directory/groups/*.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRecord {
    /// Group email address (`<slug>@cerebral.work`).
    pub email: String,
    /// Display name of the group.
    pub name: String,
    /// Group description.
    #[serde(default)]
    pub description: String,
    /// Whether the group requires 2-Step Verification (`isEnrolledIn2Sv`) before adding a member.
    #[serde(default)]
    pub requires_2sv_enrolled: bool,
    /// Group settings map.
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    /// Regular members (`MEMBER`).
    #[serde(default)]
    pub members: BTreeSet<String>,
    /// Group managers (`MANAGER`).
    #[serde(default)]
    pub managers: BTreeSet<String>,
    /// Group owners (`OWNER`).
    #[serde(default)]
    pub owners: BTreeSet<String>,
    /// Manual hold exceptions (`unreconciled_members`).
    #[serde(default)]
    pub unreconciled_members: Vec<HeldException>,
}

/// License assignment block declared in `directory/licenses.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseRecord {
    /// Google Workspace SKU ID.
    pub sku_id: String,
    /// Human-readable SKU name.
    pub sku_name: String,
    /// Whether the reconciler manages this SKU (`false` skips automated assignment/revocation).
    #[serde(default)]
    pub reconcile: bool,
    /// Users assigned this license SKU.
    #[serde(default)]
    pub users: BTreeSet<String>,
}

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
    /// Whether the user is enrolled in 2-Step Verification (`isEnrolledIn2Sv`).
    #[serde(default)]
    pub enrolled_2sv: bool,
    /// Optional admin level string (`"super"` or `"delegated"`).
    #[serde(default)]
    pub admin: Option<String>,
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
    #[serde(default)]
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

/// Output of a reconciliation planning stage (`serial`, `batch`, `gh_batch`, and `manual` review notes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcilePlan {
    /// Order-sensitive commands that run sequentially before `batch` (e.g. creating parent OUs before children).
    pub serial: Vec<String>,
    /// Independent Google Workspace (`gam`) commands that run after `serial` completes.
    pub batch: Vec<String>,
    /// GitHub organization membership removal commands (`gh api -X DELETE /orgs/.../memberships/...`).
    #[serde(default)]
    pub gh_batch: Vec<String>,
    /// Human-review items that are never automated.
    pub manual: Vec<String>,
}

impl ReconcilePlan {
    /// Appends another [`ReconcilePlan`] into `self`.
    pub fn extend(&mut self, other: ReconcilePlan) {
        self.serial.extend(other.serial);
        self.batch.extend(other.batch);
        self.gh_batch.extend(other.gh_batch);
        self.manual.extend(other.manual);
    }

    /// Returns true if no automated (`serial`, `batch`, `gh_batch`) or manual actions are present.
    pub fn is_empty(&self) -> bool {
        self.serial.is_empty()
            && self.batch.is_empty()
            && self.gh_batch.is_empty()
            && self.manual.is_empty()
    }
}

/// Shell-escapes `s` identically to Python's `shlex.quote(s)`.
pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let is_safe = s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
            )
    });
    if is_safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

/// Returns true if `user` is declared with `create: false` (recorded intent, not yet created in Google).
pub fn uncreated(user: &UserRecord) -> bool {
    !user.create
}

/// Replaces inline passwords in GAM commands (`password \S+` -> `password <random>`).
pub fn redact(cmd: &str) -> String {
    PASSWORD_RE
        .replace_all(cmd, "password <random>")
        .into_owned()
}

/// Computes the 64-character lowercase hex SHA-256 digest of the JSON-serialized
/// `{"serial": [redact(c) ...], "batch": [redact(c) ...]}` command payload.
///
/// Matches Python's `reconcile.plan_digest(serial, batch)` byte-for-byte.
pub fn plan_digest(serial: &[String], batch: &[String]) -> String {
    let encode_list = |items: &[String]| -> String {
        items
            .iter()
            .map(|c| {
                let r = redact(c);
                serde_json::to_string(&r).unwrap_or_else(|_| format!("\"{r}\""))
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let payload = format!(
        "{{\"serial\": [{}], \"batch\": [{}]}}",
        encode_list(serial),
        encode_list(batch)
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verifies `--expect-plan-sha256` against the freshly computed `digest` before applying changes.
///
/// Returns `Some(refusal_message)` if `expected` is missing or mismatches `digest`, or `None` when valid.
pub fn apply_refusal(expected: Option<&str>, digest: &str) -> Option<String> {
    let Some(exp) = expected.map(str::trim).filter(|s| !s.is_empty()) else {
        return Some(format!(
            "REFUSING TO APPLY: --expect-plan-sha256 is required.\n  This plan is {digest}\n  Re-run with that value once you have read the plan above."
        ));
    };
    if !exp.eq_ignore_ascii_case(digest.trim()) {
        return Some(format!(
            "REFUSING TO APPLY: the plan changed since it was reviewed.\n  reviewed: {exp}\n  now:      {digest}\n  Something moved in Google or in directory/. Read the new plan."
        ));
    }
    None
}

/// Evaluates `unreconciled_members` hold exceptions on `group` as of `today`.
///
/// Returns `(held_map, manual_notes)` where `held_map` maps `member_email -> reason`.
pub fn held_members(
    group: &GroupRecord,
    today: NaiveDate,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut held = BTreeMap::new();
    let mut notes = Vec::new();
    for entry in &group.unreconciled_members {
        let member = entry.email.trim();
        if member.is_empty() {
            continue;
        }
        let reason = entry.reason.trim();
        if reason.is_empty() {
            notes.push(format!(
                "EXCEPTION IGNORED for {member} — no reason given, so it does not hold. Removal is proposed as normal; add a reason to keep them."
            ));
            continue;
        }
        if let Some(ref until_raw) = entry.until {
            let until_str = until_raw.trim();
            if !until_str.is_empty() {
                if let Ok(end) = NaiveDate::parse_from_str(until_str, "%Y-%m-%d") {
                    if end < today {
                        notes.push(format!(
                            "EXCEPTION EXPIRED for {member} on {end} ({reason}). Removal is proposed again — renew the date or let them go."
                        ));
                        continue;
                    }
                    notes.push(format!("HELD {member} until {end} — {reason}"));
                } else {
                    notes.push(format!("HELD {member} until {until_str} — {reason}"));
                }
                held.insert(member.to_string(), reason.to_string());
                continue;
            }
        }
        notes.push(format!("HELD {member} (no end date) — {reason}"));
        held.insert(member.to_string(), reason.to_string());
    }
    (held, notes)
}

/// Plans organizational unit creation (parents before children in `serial`) and flags manual deletions.
pub fn plan_orgunits(want: &BTreeSet<String>, have: &BTreeSet<String>) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    let mut sorted_want: Vec<&String> = want.iter().collect();
    sorted_want.sort_by_key(|p| (p.matches('/').count(), *p));
    for path in sorted_want {
        if !have.contains(path) {
            plan.serial
                .push(format!("gam create org {}", shlex_quote(path)));
        }
    }
    for path in have {
        if !want.contains(path) && path != "/" {
            plan.manual.push(format!(
                "DELETE OU {path} (never automated — must be empty first)"
            ));
        }
    }
    plan
}

/// Plans Google Workspace user creation, OU updates, asymmetric suspension, and self-lockout protection.
pub fn plan_users(
    want: &BTreeMap<String, UserRecord>,
    have: &BTreeMap<String, LiveUser>,
    subject: Option<&str>,
    initial_password: &str,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    let subj = subject.map(str::trim).filter(|s| !s.is_empty());

    for (email, w) in want {
        let Some(h) = have.get(email) else {
            if uncreated(w) {
                plan.manual.push(format!(
                    "NOT CREATED {email} (declared with create: false — remove the flag to create, or delete the row)"
                ));
                continue;
            }
            plan.batch.push(format!(
                "gam create user {email} firstname {} lastname {} password {initial_password} changepassword on org {}",
                shlex_quote(&w.given_name),
                shlex_quote(&w.family_name),
                shlex_quote(&w.org_unit)
            ));
            continue;
        };

        if h.org_unit != w.org_unit {
            if email.eq_ignore_ascii_case(SOVEREIGN_ROOT_EMAIL)
                && w.org_unit != SOVEREIGN_ROOT_ORG_UNIT
            {
                plan.manual.push(format!(
                    "SOVEREIGN ROOT PROTECTED {email} (refusing to move sovereign root out of {SOVEREIGN_ROOT_ORG_UNIT})"
                ));
            } else {
                plan.batch.push(format!(
                    "gam update user {email} org {}",
                    shlex_quote(&w.org_unit)
                ));
            }
        }

        if h.suspended != w.suspended {
            if !w.suspended {
                plan.manual.push(format!(
                    "NOT REINSTATED {email} (declared suspended: false, live is SUSPENDED — un-suspending is never automated; it is the offboarding-reversal path. Run `gam update user {email} suspended off` deliberately, or correct the row)"
                ));
            } else if email.eq_ignore_ascii_case(SOVEREIGN_ROOT_EMAIL) {
                plan.manual.push(format!(
                    "SOVEREIGN ROOT PROTECTED {email} (refusing to suspend sovereign root)"
                ));
            } else if subj == Some(email.as_str()) {
                plan.manual.push(format!(
                    "NOT SUSPENDED {email} (this is the account the reconciler authenticates as — suspending it disables the reconciler itself, and the next run could not undo it. Do it by hand with a replacement subject already in place)"
                ));
            } else {
                plan.batch
                    .push(format!("gam update user {email} suspended on"));
            }
        }
    }

    for email in have.keys() {
        if !want.contains_key(email) {
            plan.manual.push(format!(
                "DELETE USER {email} (never automated — gam delete user)"
            ));
        }
    }

    plan
}

fn effective_user_admin(u: &UserRecord) -> Option<&str> {
    if let Some(ref a) = u.admin {
        let trimmed = a.trim();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    if u.is_super_admin {
        Some("super")
    } else {
        None
    }
}

fn effective_live_admin(u: &LiveUser) -> Option<&str> {
    if let Some(ref a) = u.admin {
        let trimmed = a.trim();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    if u.is_super_admin {
        Some("super")
    } else {
        None
    }
}

/// Plans manual notifications for Google Super Admin and delegated admin role drift.
pub fn plan_admin(
    want: &BTreeMap<String, UserRecord>,
    have: &BTreeMap<String, LiveUser>,
    _admin_roles: &BTreeMap<String, BTreeSet<String>>,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for (email, w) in want {
        let Some(h) = have.get(email) else {
            continue;
        };
        let want_role = effective_user_admin(w);
        let have_role = effective_live_admin(h);
        if want_role == have_role {
            continue;
        }
        match (want_role, have_role) {
            (None, Some(hr)) => {
                plan.manual.push(format!(
                    "REVOKE {} ADMIN from {email} (console: Directory > Users > Admin roles and privileges)",
                    hr.to_uppercase()
                ));
            }
            (Some(wr), None) => {
                plan.manual.push(format!(
                    "GRANT {} ADMIN to {email} (console only — the API cannot assign Super Admin)",
                    wr.to_uppercase()
                ));
            }
            (Some(wr), Some(hr)) => {
                plan.manual
                    .push(format!("ADMIN ROLE CHANGE {email}: {hr} -> {wr} (console)"));
            }
            (None, None) => {}
        }
    }
    for (email, h) in have {
        if !want.contains_key(email)
            && let Some(hr) = effective_live_admin(h)
        {
            plan.manual.push(format!(
                "UNDECLARED {} ADMIN {email} (holds admin in Google, absent from users.yaml)",
                hr.to_uppercase()
            ));
        }
    }
    plan
}

/// Plans Google Workspace group creation, metadata updates, 2SV-gated membership changes,
/// hold exceptions, and cross-plane (`elsewhere`, `unmanaged`) reporting.
pub fn plan_groups(
    want: &BTreeMap<String, GroupRecord>,
    have: &BTreeMap<String, LiveGroup>,
    users: &BTreeMap<String, UserRecord>,
    live_users: &BTreeMap<String, LiveUser>,
    elsewhere: &BTreeSet<String>,
    unmanaged: &BTreeMap<String, String>,
    today: NaiveDate,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    let absent: BTreeSet<&str> = users
        .iter()
        .filter(|(_, u)| uncreated(u))
        .map(|(e, _)| e.as_str())
        .collect();

    for (email, w) in want {
        let have_m: BTreeSet<(String, String)> = if let Some(h) = have.get(email) {
            if w.name != h.name || w.description != h.description {
                plan.batch.push(format!(
                    "gam update group {email} name {} description {}",
                    shlex_quote(&w.name),
                    shlex_quote(&w.description)
                ));
            }
            let mut set = BTreeSet::new();
            for m in &h.owners {
                set.insert((m.clone(), "OWNER".to_string()));
            }
            for m in &h.managers {
                set.insert((m.clone(), "MANAGER".to_string()));
            }
            for m in &h.members {
                set.insert((m.clone(), "MEMBER".to_string()));
            }
            set
        } else {
            plan.batch.push(format!(
                "gam create group {email} name {} description {}",
                shlex_quote(&w.name),
                shlex_quote(&w.description)
            ));
            BTreeSet::new()
        };

        let mut want_m: BTreeSet<(String, String)> = BTreeSet::new();
        for m in &w.owners {
            if !absent.contains(m.as_str()) {
                want_m.insert((m.clone(), "OWNER".to_string()));
            }
        }
        for m in &w.managers {
            if !absent.contains(m.as_str()) {
                want_m.insert((m.clone(), "MANAGER".to_string()));
            }
        }
        for m in &w.members {
            if !absent.contains(m.as_str()) {
                want_m.insert((m.clone(), "MEMBER".to_string()));
            }
        }

        let gate_2sv = w.requires_2sv_enrolled;
        for (member, role) in want_m.difference(&have_m) {
            if gate_2sv {
                let Some(h_user) = live_users.get(member) else {
                    plan.manual.push(format!(
                        "NOT ADDED {member} to {email} (requires_2sv_enrolled, and they are not in the live directory to check)"
                    ));
                    continue;
                };
                if !h_user.enrolled_2sv {
                    plan.manual.push(format!(
                        "NOT ADDED {member} to {email} (requires_2sv_enrolled and isEnrolledIn2Sv is false — adding them would lock them out; have them enrol first)"
                    ));
                    continue;
                }
            }
            plan.batch.push(format!(
                "gam update group {email} add {} {member}",
                role.to_lowercase()
            ));
        }

        let (held, held_notes) = held_members(w, today);
        for note in held_notes {
            plan.manual.push(format!("{email}: {note}"));
        }
        for member in held.keys() {
            if !have_m.iter().any(|(m, _)| m == member) {
                plan.manual.push(format!(
                    "{email}: EXCEPTION STALE for {member} — held, but they are not in the group. Drop the entry."
                ));
            }
        }

        for (member, _role) in have_m.difference(&want_m) {
            if !want_m.iter().any(|(m, _)| m == member) {
                if held.contains_key(member) {
                    continue;
                }
                if member.eq_ignore_ascii_case(SOVEREIGN_ROOT_EMAIL) {
                    plan.manual.push(format!(
                        "SOVEREIGN ROOT PROTECTED {member} in {email} (refusing to remove sovereign root from group)"
                    ));
                    continue;
                }
                plan.batch
                    .push(format!("gam update group {email} remove {member}"));
            }
        }
    }

    let mut other_plane = Vec::new();
    for email in have.keys() {
        if !want.contains_key(email) {
            if elsewhere.contains(email) {
                other_plane.push(email.clone());
                continue;
            }
            if let Some(reason) = unmanaged.get(email) {
                plan.manual.push(format!(
                    "UNMANAGED: {email} — listed in directory/groups-unmanaged.yaml, not reconciled: {reason}"
                ));
                continue;
            }
            plan.manual
                .push(format!("DELETE GROUP {email} (never automated)"));
        }
    }
    if !other_plane.is_empty() {
        other_plane.sort();
        plan.manual.push(format!(
            "NOT CHECKED: {} group(s) declared on the foundation plane — existence is fine, membership is not reconciled here: {}",
            other_plane.len(),
            other_plane.join(", ")
        ));
    }

    plan
}

/// Plans Google Workspace license assignment and revocation over `(user_email, sku_id)` pairs.
pub fn plan_licenses(
    want: &BTreeSet<(String, String)>,
    have: Option<&BTreeSet<(String, String)>>,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    let Some(have_set) = have else {
        plan.manual
            .push("LICENCES NOT CHECKED — apps.licensing scope not held".to_string());
        return plan;
    };
    for (user, sku) in want.difference(have_set) {
        plan.batch
            .push(format!("gam user {user} add license {sku}"));
    }
    for (user, sku) in have_set.difference(want) {
        if user.eq_ignore_ascii_case(SOVEREIGN_ROOT_EMAIL) {
            plan.manual.push(format!(
                "SOVEREIGN ROOT PROTECTED {user} (refusing to delete license {sku} from sovereign root)"
            ));
            continue;
        }
        plan.batch
            .push(format!("gam user {user} delete license {sku}"));
    }
    plan
}

/// Plans GitHub organization membership removals for offboarded users (`leaving`) and flags
/// manual additions, self-lockout refusals, and undeclared accounts.
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
    let leaving_norm: BTreeSet<String> = leaving.iter().map(|s| s.to_lowercase()).collect();
    let declared_norm: BTreeSet<String> = declared.iter().map(|s| s.to_lowercase()).collect();
    let covered: BTreeSet<String> = want
        .values()
        .flat_map(|logins| logins.iter().map(|s| s.to_lowercase()))
        .collect();
    let self_norm = self_login.map(|s| s.to_lowercase());
    let all_orgs: BTreeSet<&String> = want.keys().chain(have.keys()).collect();

    for org in all_orgs {
        let w: BTreeSet<String> = want
            .get(org)
            .map(|s| s.iter().map(|x| x.to_lowercase()).collect())
            .unwrap_or_default();
        let h: BTreeSet<String> = have
            .get(org)
            .map(|s| s.iter().map(|x| x.to_lowercase()).collect())
            .unwrap_or_default();
        let stake = if org == "cerebral-work" {
            " [TAILNET]"
        } else {
            ""
        };

        for login in h.difference(&w) {
            if login.eq_ignore_ascii_case(SOVEREIGN_ROOT_GITHUB) {
                plan.manual.push(format!(
                    "SOVEREIGN ROOT PROTECTED {login} in {org}{stake} (refusing to remove sovereign root from GitHub organization)"
                ));
            } else if self_norm.as_deref() == Some(login.as_str()) {
                plan.manual.push(format!(
                    "NOT REMOVED {login} from {org} (this is the account the reconciler authenticates as -- removing it stops the next run from being able to undo the change)"
                ));
            } else if leaving_norm.contains(login) && self_norm.is_none() {
                plan.manual.push(format!(
                    "NOT REMOVED {login} from {org}{stake} (marked leaving, but the token's own account is unknown, so this could be it)"
                ));
            } else if leaving_norm.contains(login) {
                let cmd = format!("gh api -X DELETE /orgs/{org}/memberships/{login}");
                if !stake.is_empty() {
                    stakes.insert(cmd.clone(), "TAILNET".to_string());
                }
                plan.gh_batch.push(cmd.clone());
                plan.batch.push(cmd);
            } else if !declared_norm.contains(login) {
                plan.manual.push(format!(
                    "UNDECLARED {login} in {org}{stake} (no row in directory/users.yaml has this github_handle -- not removed; declare them, or remove them by hand if they have left)"
                ));
            } else if covered.contains(login) {
                plan.manual.push(format!(
                    "NOT REMOVED {login} from {org}{stake} (their row's github_orgs leaves {org} out, but they are not marked leaving -- removal is automated only for leavers)"
                ));
            }
        }

        for login in w.difference(&h) {
            let tail = if org == "cerebral-work" {
                ", and membership of this one IS the tailnet identity"
            } else {
                ""
            };
            plan.manual.push(format!(
                "NOT ADDED {login} to {org}{stake} (declared but not a member -- adding somebody to a GitHub org is never automated{tail})"
            ));
        }
    }

    (plan, stakes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user(email: &str) -> UserRecord {
        UserRecord {
            email: email.to_string(),
            given_name: "Ada".to_string(),
            family_name: "Lovelace".to_string(),
            org_unit: "/Engineering".to_string(),
            suspended: false,
            create: true,
            is_super_admin: false,
            admin: None,
            admin_roles: BTreeSet::new(),
            aliases: BTreeSet::new(),
            github_handle: None,
            github_orgs: BTreeSet::new(),
        }
    }

    fn sample_live_user(email: &str) -> LiveUser {
        LiveUser {
            email: email.to_string(),
            given_name: "Ada".to_string(),
            family_name: "Lovelace".to_string(),
            org_unit: "/Engineering".to_string(),
            suspended: false,
            enrolled_2sv: true,
            admin: None,
            is_super_admin: false,
            admin_roles: BTreeSet::new(),
            aliases: BTreeSet::new(),
        }
    }

    #[test]
    fn test_redact_and_plan_digest_match_python() {
        let s = ["gam create org /Offboarding".to_string()];
        let b1 = [
            "gam create user a@cerebral.work firstname Ada lastname L password secretOne changepassword on org /".to_string(),
        ];
        let b2 = [
            "gam create user a@cerebral.work firstname Ada lastname L password secretTwo changepassword on org /".to_string(),
        ];
        assert_eq!(
            redact(&b1[0]),
            "gam create user a@cerebral.work firstname Ada lastname L password <random> changepassword on org /"
        );
        assert_eq!(plan_digest(&[], &b1), plan_digest(&[], &b2));
        assert_ne!(plan_digest(&s, &[]), plan_digest(&[], &s));

        let d = plan_digest(&[], &b1);
        assert_eq!(d.len(), 64);
        assert!(
            apply_refusal(None, &d)
                .unwrap()
                .contains("--expect-plan-sha256 is required")
        );
        assert!(
            apply_refusal(Some("deadbeef"), &d)
                .unwrap()
                .contains("the plan changed since it was reviewed")
        );
        assert!(apply_refusal(Some(&d), &d).is_none());
    }

    #[test]
    fn test_plan_users_asymmetric_suspension_and_self_guard() {
        let mut want = BTreeMap::new();
        let mut have = BTreeMap::new();

        // 1. Reinstatement is never automated
        let u1 = sample_user("former@cerebral.work");
        let mut l1 = sample_live_user("former@cerebral.work");
        l1.suspended = true;
        want.insert(u1.email.clone(), u1);
        have.insert(l1.email.clone(), l1);

        // 2. Self-suspension is refused
        let mut u2 = sample_user("admin@cerebral.work");
        u2.suspended = true;
        let l2 = sample_live_user("admin@cerebral.work");
        want.insert(u2.email.clone(), u2);
        have.insert(l2.email.clone(), l2);

        // 3. Normal suspension is batched
        let mut u3 = sample_user("leaver@cerebral.work");
        u3.suspended = true;
        let l3 = sample_live_user("leaver@cerebral.work");
        want.insert(u3.email.clone(), u3);
        have.insert(l3.email.clone(), l3);

        // 4. create: false is skipped
        let mut u4 = sample_user("ghost@cerebral.work");
        u4.create = false;
        want.insert(u4.email.clone(), u4);

        let plan = plan_users(&want, &have, Some("admin@cerebral.work"), "randpw");
        assert_eq!(
            plan.batch,
            vec!["gam update user leaver@cerebral.work suspended on"]
        );
        assert!(
            plan.manual
                .iter()
                .any(|m| m.starts_with("NOT REINSTATED former@cerebral.work"))
        );
        assert!(
            plan.manual
                .iter()
                .any(|m| m.starts_with("NOT SUSPENDED admin@cerebral.work"))
        );
        assert!(
            plan.manual
                .iter()
                .any(|m| m.starts_with("NOT CREATED ghost@cerebral.work"))
        );
    }

    #[test]
    fn test_plan_groups_2sv_and_holds_and_planes() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 14).unwrap();
        let mut want = BTreeMap::new();
        want.insert(
            "eng@cerebral.work".to_string(),
            GroupRecord {
                email: "eng@cerebral.work".to_string(),
                name: "Engineering".to_string(),
                description: "Eng".to_string(),
                requires_2sv_enrolled: true,
                settings: BTreeMap::new(),
                members: BTreeSet::from([
                    "enrolled@cerebral.work".to_string(),
                    "unenrolled@cerebral.work".to_string(),
                ]),
                managers: BTreeSet::new(),
                owners: BTreeSet::new(),
                unreconciled_members: vec![HeldException {
                    email: "contractor@cerebral.work".to_string(),
                    reason: "incident support".to_string(),
                    until: Some("2026-12-01".to_string()),
                }],
            },
        );

        let mut have = BTreeMap::new();
        have.insert(
            "eng@cerebral.work".to_string(),
            LiveGroup {
                email: "eng@cerebral.work".to_string(),
                name: "Engineering".to_string(),
                description: "Eng".to_string(),
                settings: BTreeMap::new(),
                members: BTreeSet::from([
                    "contractor@cerebral.work".to_string(),
                    "extra@cerebral.work".to_string(),
                ]),
                managers: BTreeSet::new(),
                owners: BTreeSet::new(),
            },
        );
        have.insert(
            "gcp-billing-admins@cerebral.work".to_string(),
            LiveGroup {
                email: "gcp-billing-admins@cerebral.work".to_string(),
                name: "GCP Billing".to_string(),
                description: "".to_string(),
                settings: BTreeMap::new(),
                members: BTreeSet::new(),
                managers: BTreeSet::new(),
                owners: BTreeSet::new(),
            },
        );

        let mut live_users = BTreeMap::new();
        live_users.insert(
            "enrolled@cerebral.work".to_string(),
            sample_live_user("enrolled@cerebral.work"),
        );
        let mut u_no2sv = sample_live_user("unenrolled@cerebral.work");
        u_no2sv.enrolled_2sv = false;
        live_users.insert("unenrolled@cerebral.work".to_string(), u_no2sv);

        let elsewhere = BTreeSet::from(["gcp-billing-admins@cerebral.work".to_string()]);
        let unmanaged = BTreeMap::new();

        let plan = plan_groups(
            &want,
            &have,
            &BTreeMap::new(),
            &live_users,
            &elsewhere,
            &unmanaged,
            today,
        );
        assert_eq!(
            plan.batch,
            vec![
                "gam update group eng@cerebral.work add member enrolled@cerebral.work",
                "gam update group eng@cerebral.work remove extra@cerebral.work",
            ]
        );
        assert!(
            plan.manual
                .iter()
                .any(|m| m.starts_with("NOT ADDED unenrolled@cerebral.work to eng@cerebral.work"))
        );
        assert!(
            plan.manual
                .iter()
                .any(|m| m.contains("HELD contractor@cerebral.work until 2026-12-01"))
        );
        assert!(
            plan.manual
                .iter()
                .any(|m| m.starts_with("NOT CHECKED: 1 group(s) declared on the foundation plane"))
        );
    }

    #[test]
    fn test_plan_github_leavers_and_tailnet_stake() {
        let want = BTreeMap::from([(
            "cerebral-work".to_string(),
            BTreeSet::from(["todie".to_string()]),
        )]);
        let have = BTreeMap::from([(
            "cerebral-work".to_string(),
            BTreeSet::from([
                "todie".to_string(),
                "leaver".to_string(),
                "stranger".to_string(),
            ]),
        )]);
        let leaving = BTreeSet::from(["leaver".to_string()]);
        let declared = BTreeSet::from(["todie".to_string(), "leaver".to_string()]);

        let (plan, stakes) = plan_github(&want, &have, &leaving, &declared, Some("todie"));
        assert_eq!(
            plan.gh_batch,
            vec!["gh api -X DELETE /orgs/cerebral-work/memberships/leaver"]
        );
        assert_eq!(
            stakes.get("gh api -X DELETE /orgs/cerebral-work/memberships/leaver"),
            Some(&"TAILNET".to_string())
        );
        assert!(
            plan.manual
                .iter()
                .any(|m| m.starts_with("UNDECLARED stranger in cerebral-work [TAILNET]"))
        );
    }

    #[test]
    fn test_sovereign_root_protection() {
        let mut want_users = BTreeMap::new();
        let mut have_users = BTreeMap::new();

        let mut u_root = sample_user("ctodie@cerebral.work");
        u_root.org_unit = "/Suspended-Offboarding".to_string();
        u_root.suspended = true;
        let mut l_root = sample_live_user("ctodie@cerebral.work");
        l_root.org_unit = "/Humans/Admins".to_string();
        l_root.suspended = false;
        want_users.insert(u_root.email.clone(), u_root);
        have_users.insert(l_root.email.clone(), l_root.clone());

        let user_plan = plan_users(
            &want_users,
            &have_users,
            Some("ahackley@cerebral.work"),
            "pw",
        );
        assert!(user_plan.batch.is_empty());
        assert_eq!(user_plan.manual.len(), 2);
        assert!(
            user_plan
                .manual
                .iter()
                .all(|m| m.starts_with("SOVEREIGN ROOT PROTECTED ctodie@cerebral.work"))
        );

        let today = NaiveDate::from_ymd_opt(2026, 10, 14).unwrap();
        let mut want_groups = BTreeMap::new();
        want_groups.insert(
            "gcp-organization-admins@cerebral.work".to_string(),
            GroupRecord {
                email: "gcp-organization-admins@cerebral.work".to_string(),
                name: "GCP Org Admins".to_string(),
                description: "Org Admins".to_string(),
                requires_2sv_enrolled: true,
                settings: BTreeMap::new(),
                members: BTreeSet::new(),
                managers: BTreeSet::new(),
                owners: BTreeSet::new(),
                unreconciled_members: vec![],
            },
        );
        let mut have_groups = BTreeMap::new();
        have_groups.insert(
            "gcp-organization-admins@cerebral.work".to_string(),
            LiveGroup {
                email: "gcp-organization-admins@cerebral.work".to_string(),
                name: "GCP Org Admins".to_string(),
                description: "Org Admins".to_string(),
                settings: BTreeMap::new(),
                members: BTreeSet::new(),
                managers: BTreeSet::new(),
                owners: BTreeSet::from(["ctodie@cerebral.work".to_string()]),
            },
        );
        let group_plan = plan_groups(
            &want_groups,
            &have_groups,
            &want_users,
            &have_users,
            &BTreeSet::new(),
            &BTreeMap::new(),
            today,
        );
        assert!(group_plan.batch.is_empty());
        assert!(
            group_plan
                .manual
                .iter()
                .any(|m| m.starts_with("SOVEREIGN ROOT PROTECTED ctodie@cerebral.work"))
        );

        let lic_plan = plan_licenses(
            &BTreeSet::new(),
            Some(&BTreeSet::from([(
                "ctodie@cerebral.work".to_string(),
                "1010020020".to_string(),
            )])),
        );
        assert!(lic_plan.batch.is_empty());
        assert!(
            lic_plan
                .manual
                .iter()
                .any(|m| m.starts_with("SOVEREIGN ROOT PROTECTED ctodie@cerebral.work"))
        );

        let want_gh = BTreeMap::from([("cerebral-work".to_string(), BTreeSet::new())]);
        let have_gh = BTreeMap::from([(
            "cerebral-work".to_string(),
            BTreeSet::from(["todie".to_string()]),
        )]);
        let (gh_plan, _) = plan_github(
            &want_gh,
            &have_gh,
            &BTreeSet::from(["todie".to_string()]),
            &BTreeSet::from(["todie".to_string()]),
            Some("lordvoid"),
        );
        assert!(gh_plan.batch.is_empty());
        assert!(gh_plan.gh_batch.is_empty());
        assert!(
            gh_plan
                .manual
                .iter()
                .any(|m| m.starts_with("SOVEREIGN ROOT PROTECTED todie in cerebral-work"))
        );
    }
}
