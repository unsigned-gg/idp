// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Structured findings collector for identity detectors.
//!
//! Extracted from `cerebral-work/identity/scripts/reconcile/findings.py`.
//! Preserves exact key formatting, 80-character segment normalization, deduplication,
//! and `$FINDINGS_FILE` JSON output for Linear issue synchronization.

use crate::error::IdpError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

#[allow(clippy::expect_used)]
static NON_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^a-z0-9@._-]+").expect("valid key regex"));

/// Normalizes a finding key segment: lowercases, replaces runs of non-`[a-z0-9@._-]`
/// characters with `-`, strips leading/trailing `-`, and truncates to 80 characters.
pub fn part(s: &str) -> String {
    let lower = s.to_lowercase();
    let replaced = NON_KEY_RE.replace_all(&lower, "-");
    let stripped = replaced.trim_matches('-');
    stripped.chars().take(80).collect()
}

/// A single structured detector finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingItem {
    /// Stable deduplication key (`identity-detectors:<detector>:<kind>:<key>`).
    pub key: String,
    /// Detector name (e.g. `"reconcile"`, `"presence"`, `"oidc-bindings"`).
    pub detector: String,
    /// Finding kind within the detector (e.g. `"pending"`, `"manual"`, `"undeclared"`).
    pub kind: String,
    /// Severity level (`"high"`, `"medium"`, `"low"`).
    pub severity: String,
    /// Short summary title for the ticket.
    pub title: String,
    /// Markdown detail lines explaining the finding.
    pub detail: Vec<String>,
    /// Optional remediation command or step.
    pub remediation: Option<String>,
}

/// Serialized JSON payload written to `$FINDINGS_FILE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingsPayload {
    /// Collected finding items.
    pub findings: Vec<FindingItem>,
    /// Completed detector-kind prefixes (`identity-detectors:<detector>:<kind>:`).
    pub complete: Vec<String>,
}

/// Accumulates structured findings and evaluated kind prefixes for a single detector run.
#[derive(Debug, Clone)]
pub struct Findings {
    /// Detector identifier.
    pub detector: String,
    /// Ordered list of deduplicated findings.
    pub items: Vec<FindingItem>,
    /// Ordered list of evaluated `identity-detectors:<detector>:<kind>:` prefixes.
    pub complete: Vec<String>,
    seen: HashSet<String>,
}

impl Findings {
    /// Creates a new findings collector for `detector`.
    pub fn new(detector: impl Into<String>) -> Self {
        Self {
            detector: detector.into(),
            items: Vec::new(),
            complete: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// Adds a finding if its normalized key has not been recorded yet.
    pub fn add(
        &mut self,
        kind: &str,
        key: &str,
        severity: &str,
        title: impl Into<String>,
        detail: Vec<String>,
        remediation: Option<String>,
    ) {
        let full_key = format!(
            "identity-detectors:{}:{}:{}",
            part(&self.detector),
            part(kind),
            part(key)
        );
        if !self.seen.insert(full_key.clone()) {
            return;
        }
        self.items.push(FindingItem {
            key: full_key,
            detector: self.detector.clone(),
            kind: kind.to_string(),
            severity: severity.to_string(),
            title: title.into(),
            detail,
            remediation,
        });
    }

    /// Marks `kind` as completely evaluated during this run so resolved tickets under its prefix can be auto-closed.
    pub fn evaluated(&mut self, kind: &str) {
        let prefix = format!(
            "identity-detectors:{}:{}:",
            part(&self.detector),
            part(kind)
        );
        if !self.complete.contains(&prefix) {
            self.complete.push(prefix);
        }
    }

    /// Converts the collected findings into a [`FindingsPayload`].
    pub fn payload(&self) -> FindingsPayload {
        FindingsPayload {
            findings: self.items.clone(),
            complete: self.complete.clone(),
        }
    }

    /// Formats the payload as 2-space indented JSON with a trailing newline.
    pub fn to_json(&self) -> Result<String, IdpError> {
        let mut s = serde_json::to_string_pretty(&self.payload())?;
        s.push('\n');
        Ok(s)
    }

    /// Writes the findings JSON to `path`, creating parent directories if needed.
    pub fn write_to_path(&self, path: &Path) -> Result<(), IdpError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.to_json()?)?;
        Ok(())
    }

    /// Writes the findings JSON to the path in `$FINDINGS_FILE` if set and non-empty.
    pub fn write_to_env(&self) -> Result<(), IdpError> {
        if let Ok(target) = std::env::var("FINDINGS_FILE") {
            let trimmed = target.trim();
            if !trimmed.is_empty() {
                self.write_to_path(Path::new(trimmed))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_part_normalization_and_dedup() {
        assert_eq!(
            part("Undeclared User / Foo@Bar.com!"),
            "undeclared-user-foo@bar.com"
        );
        let mut f = Findings::new("presence");
        f.add(
            "unclaimed-github",
            "vesperan-ai:@stranger",
            "high",
            "unclaimed handle",
            vec!["line 1".to_string()],
            None,
        );
        f.add(
            "unclaimed-github",
            "vesperan-ai:@stranger",
            "high",
            "duplicate",
            vec![],
            None,
        );
        f.evaluated("unclaimed-github");
        assert_eq!(f.items.len(), 1);
        assert_eq!(
            f.items[0].key,
            "identity-detectors:presence:unclaimed-github:vesperan-ai-@stranger"
        );
        assert_eq!(
            f.complete,
            vec!["identity-detectors:presence:unclaimed-github:".to_string()]
        );
    }
}
