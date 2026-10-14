// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Cryptographic comparison, secret redaction, and compliance status primitives.
//!
//! Extracted from `pact`, `gh-token-mint`, `token-mint`, `reconcile.py`, and `compliance/common.py`.

use regex::Regex;
use std::sync::LazyLock;

/// Exit code when all compliance checks pass (`0`).
pub const COMPLIANCE_OK: i32 = 0;

/// Exit code when one or more compliance checks fail (`1`).
pub const COMPLIANCE_FAILED: i32 = 1;

/// Exit code when a compliance check could not run because credentials or external tools are absent (`3`).
pub const COMPLIANCE_NOT_RUN: i32 = 3;

#[allow(clippy::expect_used)]
static PASSWORD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bpassword \S+").expect("valid regex"));

#[allow(clippy::expect_used)]
static TOKEN_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"ya29\.[A-Za-z0-9._\-]+").expect("valid ya29 regex"),
            "ya29.<redacted>",
        ),
        (
            Regex::new(r"gh[pousr]_[A-Za-z0-9_]+").expect("valid github token regex"),
            "gh_<redacted>",
        ),
        (
            Regex::new(r"github_pat_[A-Za-z0-9_]+").expect("valid github pat regex"),
            "github_pat_<redacted>",
        ),
        (
            Regex::new(r"xox[baprs]-[A-Za-z0-9\-]+").expect("valid slack token regex"),
            "xox-<redacted>",
        ),
    ]
});

/// Constant-time byte comparison for bearer tokens and secrets.
///
/// Prevents timing side-channel leaks when validating `Authorization: Bearer` headers
/// in token-mint and admission services.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Redacts `password <secret>` arguments in GAM command lines before printing or hashing.
pub fn redact_password(cmd: &str) -> String {
    PASSWORD_RE
        .replace_all(cmd, "password <redacted>")
        .into_owned()
}

/// Redacts OAuth, GitHub, and Slack tokens as well as inline passwords from log output.
pub fn redact_tokens(input: &str) -> String {
    let mut out = redact_password(input);
    for (re, replacement) in TOKEN_PATTERNS.iter() {
        out = re.replace_all(&out, *replacement).into_owned();
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("secret-token-123", "secret-token-123"));
        assert!(!constant_time_eq("secret-token-123", "secret-token-124"));
        assert!(!constant_time_eq("short", "longer"));
    }

    #[test]
    fn test_redact_password_and_tokens() {
        let cmd = "gam create user a@cerebral.work password supersecret changepassword on";
        assert_eq!(
            redact_password(cmd),
            "gam create user a@cerebral.work password <redacted> changepassword on"
        );

        let log = "token=ya29.a0AfH6SMBx123 gh=ghs_AbCdEf123456 slack=xoxb-123-456-abc";
        let scrubbed = redact_tokens(log);
        assert!(!scrubbed.contains("a0AfH6SMBx123"));
        assert!(!scrubbed.contains("AbCdEf123456"));
        assert!(!scrubbed.contains("123-456-abc"));
        assert!(scrubbed.contains("ya29.<redacted>"));
        assert!(scrubbed.contains("gh_<redacted>"));
        assert!(scrubbed.contains("xox-<redacted>"));
    }
}
