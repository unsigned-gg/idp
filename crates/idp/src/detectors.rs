// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Clause-tested infrastructure detectors:
//! - `oidc_bindings`: Kubernetes RBAC grants to OIDC `User` and `Group` subjects
//! - `reflexd_admission`: Kubernetes `NetworkPolicy` ingress admission for `reflexd`
//! - `role_matrix_live`: Live group-membership expansion against `directory/role-matrix.yaml`
//!
//! Extracted from `cerebral-work/identity/scripts/reconcile/{oidc_bindings,reflexd_admission,role_matrix_live}.py`.

use crate::directory::load_desired_state;
use crate::error::IdpError;
use crate::findings::Findings;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Standard Kubernetes OIDC username/group prefix configured on `kube-apiserver`.
pub const OIDC_PREFIX: &str = "oidc:";

/// Roles considered cluster-wide administrative grants in [`evaluate_oidc_bindings`].
pub const WIDE_ROLES: &[&str] = &["cluster-admin", "admin", "edit"];

/// A single Kubernetes RBAC grant to a human or OIDC group subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// `"cluster"` for `ClusterRoleBinding`, or the namespace name for `RoleBinding`.
    pub scope: String,
    /// Binding resource name.
    pub binding: String,
    /// Subject kind (`"User"` or `"Group"`).
    pub subject_kind: String,
    /// Subject name (e.g. `"oidc:platform-admins"` or `"ctodie@cerebral.work"`).
    pub subject: String,
    /// Referenced role kind (`"ClusterRole"` or `"Role"`).
    pub role_kind: String,
    /// Referenced role name (e.g. `"cluster-admin"`).
    pub role_name: String,
}

/// Snapshot of Kubernetes RBAC resources for offline/live evaluation.
#[derive(Debug, Clone, Default)]
pub struct Rbac {
    /// Map of `ClusterRole` name -> resource JSON.
    pub cluster_roles: BTreeMap<String, Value>,
    /// Map of `(namespace, Role name)` -> resource JSON.
    pub roles: BTreeMap<(String, String), Value>,
    /// List of `ClusterRoleBinding` resource JSON objects.
    pub cluster_role_bindings: Vec<Value>,
    /// List of `RoleBinding` resource JSON objects.
    pub role_bindings: Vec<Value>,
}

/// Extracts all non-`system:` [`Grant`]s to `User` or `Group` subjects from `rbac`.
pub fn oidc_grants(rbac: &Rbac) -> Vec<Grant> {
    let mut out = Vec::new();
    let iter_crb = rbac.cluster_role_bindings.iter().map(|b| (true, b));
    let iter_rb = rbac.role_bindings.iter().map(|b| (false, b));

    for (cluster_wide, b) in iter_crb.chain(iter_rb) {
        let meta = b.get("metadata").unwrap_or(&Value::Null);
        let scope = if cluster_wide {
            "cluster".to_string()
        } else {
            meta.get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string()
        };
        let bname = meta
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let rref = b.get("roleRef").unwrap_or(&Value::Null);
        let role_kind = rref
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("ClusterRole")
            .to_string();
        let role_name = rref
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();

        if let Some(subjects) = b.get("subjects").and_then(|v| v.as_array()) {
            for s in subjects {
                let kind = s.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if kind != "User" && kind != "Group" {
                    continue;
                }
                if name.starts_with("system:") {
                    continue;
                }
                if name.starts_with(OIDC_PREFIX)
                    || name.contains('@')
                    || (kind == "Group" && !name.starts_with("system:"))
                {
                    out.push(Grant {
                        scope: scope.clone(),
                        binding: bname.clone(),
                        subject_kind: kind.to_string(),
                        subject: name.to_string(),
                        role_kind: role_kind.clone(),
                        role_name: role_name.clone(),
                    });
                }
            }
        }
    }
    out
}

/// Resolves the target `ClusterRole` or namespaced `Role` for a [`Grant`].
pub fn resolve_role<'a>(rbac: &'a Rbac, g: &Grant) -> Option<&'a Value> {
    if g.role_kind == "ClusterRole" {
        rbac.cluster_roles.get(&g.role_name)
    } else {
        rbac.roles.get(&(g.scope.clone(), g.role_name.clone()))
    }
}

/// Returns human-readable descriptions of any wildcard (`*`) rules inside `role_obj`.
pub fn wildcard_rules(role_obj: Option<&Value>) -> Vec<String> {
    let mut hits = Vec::new();
    let Some(obj) = role_obj else {
        return hits;
    };
    let Some(rules) = obj.get("rules").and_then(|v| v.as_array()) else {
        return hits;
    };

    for rule in rules {
        let to_vec = |field: &str| -> Vec<String> {
            rule.get(field)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };
        let verbs = to_vec("verbs");
        let resources = to_vec("resources");
        let groups = to_vec("apiGroups");

        if verbs.iter().any(|x| x == "*")
            || resources.iter().any(|x| x == "*")
            || groups.iter().any(|x| x == "*")
        {
            let v_str = verbs.join(",");
            let g_str = groups
                .iter()
                .map(|g| if g.is_empty() { "core" } else { g.as_str() })
                .collect::<Vec<_>>()
                .join(",");
            let r_str = resources.join(",");
            hits.push(format!("{v_str} on {g_str}/{r_str}"));
        }
    }
    hits
}

/// Extracts all group names (with any `oidc:` prefix stripped) bound in `grants`.
pub fn bound_groups(grants: &[Grant]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for g in grants {
        if g.subject_kind == "Group" {
            let stripped = g.subject.strip_prefix(OIDC_PREFIX).unwrap_or(&g.subject);
            out.insert(stripped.to_string());
        }
    }
    out
}

/// Evaluates Kubernetes RBAC OIDC grants, returning `(exit_code, report_lines, findings)`.
pub fn evaluate_oidc_bindings(rbac: &Rbac) -> (i32, Vec<String>, Findings) {
    let mut grants = oidc_grants(rbac);
    grants.sort_by(|a, b| {
        (
            a.scope != "cluster",
            &a.scope,
            &a.subject_kind,
            &a.subject,
            &a.role_name,
        )
            .cmp(&(
                b.scope != "cluster",
                &b.scope,
                &b.subject_kind,
                &b.subject,
                &b.role_name,
            ))
    });

    let mut lines = Vec::new();
    lines.push(format!(
        "== K8S OIDC RBAC GRANTS: {} binding subject(s) ==",
        grants.len()
    ));

    let mut findings_count = 0usize;
    let mut f = Findings::new("oidc-bindings");

    for g in &grants {
        let role_obj = resolve_role(rbac, g);
        let wild = wildcard_rules(role_obj);
        let mut flags = Vec::new();
        let is_wide_name = WIDE_ROLES.contains(&g.role_name.as_str());
        if is_wide_name {
            flags.push(format!("WIDE({})", g.role_name));
        } else if !wild.is_empty() {
            flags.push(format!("WILDCARD({})", wild.join("; ")));
        }
        if role_obj.is_none() {
            flags.push("UNRESOLVED-ROLE".to_string());
        }
        if !g.subject.starts_with(OIDC_PREFIX) {
            flags.push(format!("NO-{OIDC_PREFIX}-PREFIX"));
        }

        let flag_str = if flags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", flags.join(", "))
        };
        lines.push(format!(
            "  {:<16} {:<6} {:<36} -> {}/{:<28} (via {}){}",
            g.scope, g.subject_kind, g.subject, g.role_kind, g.role_name, g.binding, flag_str
        ));
        if !flags.is_empty() {
            findings_count += 1;
        }

        let gkey = format!(
            "{}:{}:{}:{}:{}",
            g.scope, g.binding, g.subject_kind, g.subject, g.role_name
        );
        if is_wide_name || !wild.is_empty() {
            let sev = if g.scope == "cluster" && g.role_name == "cluster-admin" {
                "high"
            } else {
                "medium"
            };
            let why = if is_wide_name {
                g.role_name.clone()
            } else {
                format!("wildcard: {}", wild.join("; "))
            };
            f.add(
                "wide-role",
                &gkey,
                sev,
                format!(
                    "k8s {}: {} {} holds {} ({why})",
                    g.scope, g.subject_kind, g.subject, g.role_name
                ),
                vec![format!(
                    "Binding `{}` in `{}` grants `{}/{}` to `{}:{}`.",
                    g.binding, g.scope, g.role_kind, g.role_name, g.subject_kind, g.subject
                )],
                Some(format!(
                    "Verify `{}` is covered by the role matrix (`directory/role-matrix.yaml`) or narrow `{}`.",
                    g.subject, g.binding
                )),
            );
        }
        if role_obj.is_none() {
            f.add(
                "unresolved-role",
                &gkey,
                "low",
                format!(
                    "k8s {}: binding {} references missing {}/{}",
                    g.scope, g.binding, g.role_kind, g.role_name
                ),
                vec![format!(
                    "Subject `{}:{}` is bound to a role that does not exist.",
                    g.subject_kind, g.subject
                )],
                Some(format!(
                    "Delete dangling binding `{}` or create `{}/{}`.",
                    g.binding, g.role_kind, g.role_name
                )),
            );
        }
        if !g.subject.starts_with(OIDC_PREFIX) {
            f.add(
                "bare-name",
                &gkey,
                "medium",
                format!(
                    "k8s {}: {} {} lacks `{OIDC_PREFIX}` prefix",
                    g.scope, g.subject_kind, g.subject
                ),
                vec![format!(
                    "Binding `{}` matches bare subject `{}`; if apiserver sets `--oidc-username-prefix={OIDC_PREFIX}` this binding is inert or matches a non-OIDC subject.",
                    g.binding, g.subject
                )],
                None,
            );
        }
    }

    f.evaluated("wide-role");
    f.evaluated("unresolved-role");
    f.evaluated("bare-name");

    let groups = bound_groups(&grants);
    if !groups.is_empty() {
        lines.push(String::new());
        let g_vec: Vec<String> = groups.into_iter().collect();
        lines.push(format!(
            "  Keycloak groups reaching k8s RBAC ({}): {}",
            g_vec.len(),
            g_vec.join(", ")
        ));
    }

    let rc = if findings_count > 0 { 2 } else { 0 };
    (rc, lines, f)
}

// ---------------------------------------------------------------------------
// reflexd_admission detector
// ---------------------------------------------------------------------------

/// Declared `reflexd` submission admission state loaded from `directory/reflexd-admission.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredAdmission {
    /// Target namespace where `reflexd` runs (`"cortex-system"`).
    pub namespace: String,
    /// Submission TCP port (`4000`).
    pub port: i64,
    /// Map of canonical peer key -> human reason.
    pub allow_from: BTreeMap<String, String>,
}

/// Loads `directory/reflexd-admission.yaml` (or the given path).
pub fn load_declared_admission(path: &Path) -> Result<DeclaredAdmission, IdpError> {
    let text = fs::read_to_string(path)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)?;

    if let Some(s) = doc.get("submission") {
        let namespace = s
            .get("namespace")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Validation("missing submission.namespace".to_string()))?
            .to_string();
        let port = s
            .get("port")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| IdpError::Validation("missing submission.port".to_string()))?;

        let mut allow_from = BTreeMap::new();
        if let Some(seq) = s.get("allow_from").and_then(|v| v.as_sequence()) {
            for item in seq {
                let p = item
                    .get("peer")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                let r = item
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                if p.is_empty() || r.is_empty() {
                    return Err(IdpError::Validation(format!(
                        "{}: allow_from entries require non-empty peer and reason",
                        path.display()
                    )));
                }
                if allow_from.insert(p.to_string(), r.to_string()).is_some() {
                    return Err(IdpError::Validation(format!(
                        "{}: duplicate allow_from peer {p}",
                        path.display()
                    )));
                }
            }
        }
        return Ok(DeclaredAdmission {
            namespace,
            port,
            allow_from,
        });
    }

    let namespace = doc
        .get("namespace")
        .and_then(|v| v.as_str())
        .ok_or_else(|| IdpError::Validation("missing namespace".to_string()))?
        .to_string();
    let port = doc
        .get("submissionPort")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| IdpError::Validation("missing submissionPort".to_string()))?;

    let mut allow_from = BTreeMap::new();
    if let Some(seq) = doc.get("admitted").and_then(|v| v.as_sequence()) {
        for item in seq {
            let reason = item
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let from_yaml = item
                .get("from")
                .ok_or_else(|| IdpError::Validation("admitted entry missing from".to_string()))?;
            let from_json: Value = serde_json::to_value(from_yaml)
                .map_err(|e| IdpError::Validation(format!("invalid admitted.from: {e}")))?;
            let p = canonical_peer(&from_json, &namespace);
            if p.is_empty() || reason.is_empty() {
                return Err(IdpError::Validation(format!(
                    "{}: admitted entries require non-empty from and reason",
                    path.display()
                )));
            }
            if allow_from.insert(p.clone(), reason.to_string()).is_some() {
                return Err(IdpError::Validation(format!(
                    "{}: duplicate admitted peer {p}",
                    path.display()
                )));
            }
        }
    }
    Ok(DeclaredAdmission {
        namespace,
        port,
        allow_from,
    })
}

fn fmt_selector(sel: Option<&Value>, empty_word: &str) -> String {
    let Some(s) = sel else {
        return "none".to_string();
    };
    let Some(obj) = s.as_object() else {
        return "none".to_string();
    };
    if obj.is_empty() {
        return empty_word.to_string();
    }
    let mut parts = Vec::new();
    if let Some(ml) = obj.get("matchLabels").and_then(|v| v.as_object()) {
        let mut sorted: Vec<_> = ml.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);
        for (k, v) in sorted {
            parts.push(format!("{}={}", k, v.as_str().unwrap_or("")));
        }
    }
    if let Some(me) = obj.get("matchExpressions").and_then(|v| v.as_array()) {
        for expr in me {
            let key = expr.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let op = expr.get("operator").and_then(|v| v.as_str()).unwrap_or("");
            let vals: Vec<String> = expr
                .get("values")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            parts.push(format!("{key} {op} ({})", vals.join(",")));
        }
    }
    if parts.is_empty() {
        empty_word.to_string()
    } else {
        parts.join(",")
    }
}

/// Formats a `NetworkPolicyPeer` JSON object into its canonical key (`ns=<sel>;pod=<sel>` or `cidr=...`).
pub fn canonical_peer(peer: &Value, default_ns: &str) -> String {
    if let Some(ipb) = peer.get("ipBlock") {
        let cidr = ipb.get("cidr").and_then(|v| v.as_str()).unwrap_or("?");
        let mut exc: Vec<String> = ipb
            .get("except")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        exc.sort();
        let tail = if exc.is_empty() {
            String::new()
        } else {
            format!(" except {}", exc.join(","))
        };
        return format!("cidr={cidr}{tail}");
    }
    let ns_sel = peer.get("namespaceSelector");
    let pod_sel = peer.get("podSelector");
    let ns_part = if ns_sel.is_some() {
        format!("ns={}", fmt_selector(ns_sel, "*"))
    } else {
        format!("ns=same({default_ns})")
    };
    let pod_part = if pod_sel.is_some() {
        format!("pod={}", fmt_selector(pod_sel, "*"))
    } else {
        "pod=*".to_string()
    };
    format!("{ns_part};{pod_part}")
}

/// Formats a `NetworkPolicyPeer` JSON object into a human-readable summary string.
pub fn describe_peer(peer: &Value, default_ns: &str) -> String {
    if let Some(ipb) = peer.get("ipBlock") {
        let cidr = ipb.get("cidr").and_then(|v| v.as_str()).unwrap_or("?");
        let exc: Vec<String> = ipb
            .get("except")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let suffix = if exc.is_empty() {
            String::new()
        } else {
            format!(" (except {})", exc.join(", "))
        };
        return format!("ipBlock {cidr}{suffix}");
    }
    let ns_sel = peer.get("namespaceSelector");
    let pod_sel = peer.get("podSelector");
    let ns_part = if ns_sel.is_some() {
        format!("ns[{}]", fmt_selector(ns_sel, "ALL"))
    } else {
        format!("ns={default_ns}")
    };
    let pod_part = if pod_sel.is_some() {
        format!("pods[{}]", fmt_selector(pod_sel, "ALL"))
    } else {
        "pods[ALL]".to_string()
    };
    format!("{ns_part} / {pod_part}")
}

/// Returns true if a `NetworkPolicyIngressRule.ports` JSON value admits `port`.
pub fn admits_port(ports: Option<&Value>, port: i64) -> bool {
    let Some(arr) = ports.and_then(|v| v.as_array()) else {
        return true;
    };
    if arr.is_empty() {
        return true;
    }
    for p in arr {
        let proto = p.get("protocol").and_then(|v| v.as_str()).unwrap_or("TCP");
        if proto != "TCP" {
            continue;
        }
        let Some(pv) = p.get("port") else {
            return true;
        };
        if pv.is_null() {
            return true;
        }
        if let Some(s) = pv.as_str() {
            if s.contains("submit") || s == port.to_string() {
                return true;
            }
            continue;
        }
        if let Some(lo) = pv.as_i64() {
            let hi = p.get("endPort").and_then(|v| v.as_i64()).unwrap_or(lo);
            if lo <= port && port <= hi {
                return true;
            }
        }
    }
    false
}

fn targets_reflexd(spec: &Value) -> bool {
    let Some(ps) = spec.get("podSelector").and_then(|v| v.as_object()) else {
        return true;
    };
    if ps.is_empty() {
        return true;
    }
    let Some(labels) = ps.get("matchLabels").and_then(|v| v.as_object()) else {
        return true;
    };
    for key in ["app.kubernetes.io/name", "app", "name"] {
        if let Some(val) = labels.get(key).and_then(|v| v.as_str()) {
            return val == "reflexd";
        }
    }
    true
}

/// Extracted ingress peer entry from a `NetworkPolicy` admitting the submission port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionPeer {
    /// Policy name.
    pub policy: String,
    /// Canonical peer key.
    pub key: String,
    /// Human-readable description.
    pub human: String,
    /// Raw peer JSON object.
    pub raw: Value,
}

/// Inspects `policies` in `namespace` and returns `(no_matching_policies, admitted_peers)`.
pub fn submission_peers(
    policies: &[Value],
    namespace: &str,
    port: i64,
) -> (bool, Vec<SubmissionPeer>) {
    let mut targeted = Vec::new();
    for p in policies {
        let ns = p
            .get("metadata")
            .and_then(|m| m.get("namespace"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if ns == namespace
            && let Some(spec) = p.get("spec")
            && targets_reflexd(spec)
        {
            targeted.push(p);
        }
    }
    if targeted.is_empty() {
        return (true, Vec::new());
    }

    let mut peers = Vec::new();
    for pol in targeted {
        let pname = pol
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let spec = pol.get("spec").unwrap_or(&Value::Null);
        let ptypes: Vec<&str> = spec
            .get("policyTypes")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let has_ingress = ptypes.contains(&"Ingress") || spec.get("ingress").is_some();
        if !has_ingress {
            continue;
        }
        let Some(rules) = spec.get("ingress").and_then(|v| v.as_array()) else {
            continue;
        };
        for rule in rules {
            if !admits_port(rule.get("ports"), port) {
                continue;
            }
            let frm = rule.get("from").and_then(|v| v.as_array());
            if frm.is_none_or(|a| a.is_empty()) {
                peers.push(SubmissionPeer {
                    policy: pname.clone(),
                    key: "ns=*;pod=*".to_string(),
                    human: "ALL pods / ALL external (empty `from:`)".to_string(),
                    raw: serde_json::json!({"namespaceSelector": {}, "podSelector": {}}),
                });
            } else if let Some(arr) = frm {
                for peer in arr {
                    peers.push(SubmissionPeer {
                        policy: pname.clone(),
                        key: canonical_peer(peer, namespace),
                        human: describe_peer(peer, namespace),
                        raw: peer.clone(),
                    });
                }
            }
        }
    }
    (false, peers)
}

/// Evaluates live Kubernetes `NetworkPolicy` and `Namespace` objects against `declared` admission.
pub fn evaluate_reflexd_admission(
    declared: &DeclaredAdmission,
    policies: &[Value],
    namespaces: &[Value],
) -> (i32, Vec<String>, Findings) {
    let (unisolated, peers) = submission_peers(policies, &declared.namespace, declared.port);
    let mut lines = Vec::new();
    let mut findings_count = 0usize;
    let mut f = Findings::new("reflexd-admission");

    if unisolated {
        let msg = format!(
            "UNISOLATED: no NetworkPolicy in {} selects reflexd — every pod in the cluster can reach :{}",
            declared.namespace, declared.port
        );
        lines.push(format!("== REFLEXD SUBMISSION ADMISSION: {msg} =="));
        f.add(
            "unlisted",
            "unisolated",
            "high",
            format!(
                "reflexd :{}: no NetworkPolicy in {} selects reflexd",
                declared.port, declared.namespace
            ),
            vec![msg],
            Some(format!(
                "Apply the reflexd NetworkPolicy in `{}` so only declared peers reach `:{}`.",
                declared.namespace, declared.port
            )),
        );
        f.evaluated("unlisted");
        f.evaluated("stale-allow");
        f.evaluated("claimable");
        return (2, lines, f);
    }

    let mut by_key: BTreeMap<String, Vec<&SubmissionPeer>> = BTreeMap::new();
    for p in &peers {
        by_key.entry(p.key.clone()).or_default().push(p);
    }
    let live_keys: BTreeSet<String> = by_key.keys().cloned().collect();
    let decl_keys: BTreeSet<String> = declared.allow_from.keys().cloned().collect();
    let unlisted: Vec<String> = live_keys.difference(&decl_keys).cloned().collect();
    let stale: Vec<String> = decl_keys.difference(&live_keys).cloned().collect();

    lines.push(format!(
        "== REFLEXD SUBMISSION ADMISSION ({}:{}): {} live peer(s), {} unlisted ==",
        declared.namespace,
        declared.port,
        live_keys.len(),
        unlisted.len()
    ));

    for k in &live_keys {
        let entries = &by_key[k];
        let pols: BTreeSet<&str> = entries.iter().map(|e| e.policy.as_str()).collect();
        let pols_vec: Vec<&str> = pols.into_iter().collect();
        let tag = if let Some(why) = declared.allow_from.get(k) {
            format!("DECLARED — {why}")
        } else {
            "UNLISTED (not in directory/reflexd-admission.yaml)".to_string()
        };
        lines.push(format!("  {k:<62}  via {}  [{tag}]", pols_vec.join(",")));
    }

    for k in &unlisted {
        findings_count += 1;
        let entries = &by_key[k];
        let pols: BTreeSet<&str> = entries.iter().map(|e| e.policy.as_str()).collect();
        let pols_vec: Vec<&str> = pols.into_iter().collect();
        let wide = k.contains("ns=*") || k.starts_with("cidr=0.0.0.0/0");
        f.add(
            "unlisted",
            k,
            if wide { "high" } else { "medium" },
            format!(
                "reflexd :{}: unlisted peer `{k}` admitted by NetworkPolicy",
                declared.port
            ),
            vec![format!(
                "`{}` ({}) is admitted by `{}` in `{}`.",
                k,
                entries[0].human,
                pols_vec.join(", "),
                declared.namespace
            )],
            Some(
                "Record the peer + reason in `directory/reflexd-admission.yaml`, or tighten the NetworkPolicy."
                    .to_string(),
            ),
        );
    }
    f.evaluated("unlisted");

    for k in &stale {
        lines.push(format!(
            "  {k:<62}  [STALE — declared in git, not in live NetworkPolicy]"
        ));
        f.add(
            "stale-allow",
            k,
            "low",
            format!(
                "reflexd :{}: declared peer `{k}` not present in live NetworkPolicy",
                declared.port
            ),
            vec![format!("Recorded reason: {}", declared.allow_from[k])],
            Some(
                "Remove the stale entry from `directory/reflexd-admission.yaml` or re-apply the NetworkPolicy."
                    .to_string(),
            ),
        );
    }
    f.evaluated("stale-allow");

    // Check namespace label claimability
    let mut label_selecting = Vec::new();
    for p in &peers {
        let Some(ns_sel) = p.raw.get("namespaceSelector").and_then(|v| v.as_object()) else {
            continue;
        };
        if ns_sel.is_empty() {
            continue;
        }
        let ml = ns_sel
            .get("matchLabels")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let only_metadata_name = ml.len() == 1
            && ml.contains_key("kubernetes.io/metadata.name")
            && !ns_sel.contains_key("matchExpressions");
        if !only_metadata_name {
            let mut matched = Vec::new();
            for n in namespaces {
                let n_labels = n
                    .get("metadata")
                    .and_then(|m| m.get("labels"))
                    .and_then(|v| v.as_object());
                let matches = ml.iter().all(|(lk, lv)| {
                    n_labels.and_then(|nl| nl.get(lk)).and_then(|v| v.as_str()) == lv.as_str()
                });
                if matches
                    && let Some(nname) = n
                        .get("metadata")
                        .and_then(|m| m.get("name"))
                        .and_then(|v| v.as_str())
                {
                    matched.push(nname.to_string());
                }
            }
            matched.sort();
            label_selecting.push((p, matched));
        }
    }

    if !label_selecting.is_empty() {
        lines.push(String::new());
        lines.push(
            "  WARNING — peer uses arbitrary namespace label(s), not kubernetes.io/metadata.name:"
                .to_string(),
        );
        for (p, matched) in label_selecting {
            findings_count += 1;
            let m_str = if matched.is_empty() {
                "(none)".to_string()
            } else {
                matched.join(", ")
            };
            lines.push(format!(
                "    {} in {}: currently matches namespaces: {m_str}",
                p.key, p.policy
            ));
            lines.push(
                "      (any principal who can label a Namespace can join this selector)"
                    .to_string(),
            );
            f.add(
                "claimable",
                &format!("{}:{}", p.policy, p.key),
                "medium",
                format!(
                    "reflexd :{}: peer `{}` selects by mutable namespace label",
                    declared.port, p.key
                ),
                vec![format!(
                    "Policy `{}` admits `{}` (currently matching: {}). Any principal with `patch namespaces` can self-admit.",
                    p.policy, p.human, m_str
                )],
                Some(
                    "Pin the peer to `kubernetes.io/metadata.name: <ns>` (immutable system label)."
                        .to_string(),
                ),
            );
        }
    }
    f.evaluated("claimable");

    let rc = if findings_count > 0 { 2 } else { 0 };
    (rc, lines, f)
}

// ---------------------------------------------------------------------------
// role_matrix_live helpers
// ---------------------------------------------------------------------------

/// Expands `directory/role-matrix.yaml` and `directory/` to compute the set of active user
/// emails expected to exist in Cloudflare (`super_administrators` ∪ `domain_administrators`).
pub fn expected_cloudflare_emails(repo: &Path) -> Result<BTreeSet<String>, IdpError> {
    let state = load_desired_state(repo)?;
    let text = fs::read_to_string(repo.join("directory/role-matrix.yaml"))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)?;
    let mut group_emails = BTreeSet::new();
    if let Some(cf) = doc.get("cloudflare") {
        for tier in ["super_administrators", "domain_administrators"] {
            if let Some(seq) = cf
                .get(tier)
                .and_then(|t| t.get("groups"))
                .and_then(|v| v.as_sequence())
            {
                for g in seq {
                    if let Some(gs) = g.as_str() {
                        group_emails.insert(gs.to_string());
                    }
                }
            }
        }
    }
    expand_active_group_members(&state, &group_emails)
}

/// Expands `directory/role-matrix.yaml` and `directory/` to compute the set of active user
/// emails expected to hold `Role::Admin` in Tailscale.
pub fn expected_tailscale_admins(repo: &Path) -> Result<BTreeSet<String>, IdpError> {
    let state = load_desired_state(repo)?;
    let text = fs::read_to_string(repo.join("directory/role-matrix.yaml"))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)?;
    let mut group_emails = BTreeSet::new();
    if let Some(seq) = doc
        .get("tailscale")
        .and_then(|t| t.get("Role::Admin"))
        .and_then(|r| r.get("groups"))
        .and_then(|v| v.as_sequence())
    {
        for g in seq {
            if let Some(gs) = g.as_str() {
                group_emails.insert(gs.to_string());
            }
        }
    }
    expand_active_group_members(&state, &group_emails)
}

fn expand_active_group_members(
    state: &crate::directory::DesiredState,
    group_emails: &BTreeSet<String>,
) -> Result<BTreeSet<String>, IdpError> {
    let mut out = BTreeSet::new();
    for ge in group_emails {
        if let Some(g) = state.groups.get(ge) {
            for m in g
                .owners
                .iter()
                .chain(g.managers.iter())
                .chain(g.members.iter())
            {
                if let Some(u) = state.users.get(m)
                    && !u.suspended
                {
                    out.insert(u.email.to_lowercase());
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_oidc_bindings_detector() {
        let mut cluster_roles = BTreeMap::new();
        cluster_roles.insert(
            "cluster-admin".to_string(),
            json!({"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}),
        );
        let rbac = Rbac {
            cluster_roles,
            roles: BTreeMap::new(),
            cluster_role_bindings: vec![json!({
                "metadata": {"name": "oidc-admins"},
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [
                    {"kind": "Group", "name": "oidc:platform-admins"},
                    {"kind": "Group", "name": "system:masters"}
                ]
            })],
            role_bindings: vec![],
        };
        let (rc, lines, f) = evaluate_oidc_bindings(&rbac);
        assert_eq!(rc, 2);
        assert!(lines.join("\n").contains("WIDE(cluster-admin)"));
        assert_eq!(f.items.len(), 1);
        assert_eq!(f.items[0].severity, "high");
    }

    #[test]
    fn test_reflexd_admission_detector() {
        let decl = DeclaredAdmission {
            namespace: "cortex-system".to_string(),
            port: 4000,
            allow_from: BTreeMap::from([(
                "ns=same(cortex-system);pod=*".to_string(),
                "same namespace".to_string(),
            )]),
        };
        let pols = vec![json!({
            "metadata": {"name": "reflexd", "namespace": "cortex-system"},
            "spec": {
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "reflexd"}},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "ports": [{"protocol": "TCP", "port": 4000}],
                    "from": [{"podSelector": {}}]
                }]
            }
        })];
        let (rc, _lines, f) = evaluate_reflexd_admission(&decl, &pols, &[]);
        assert_eq!(rc, 0);
        assert!(f.items.is_empty());
    }
}
