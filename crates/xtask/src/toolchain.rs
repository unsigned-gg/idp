//! Rust toolchain channel verification against `rust-toolchain.toml`.

use std::fs;
use std::path::Path;
use std::process::Command;

/// Verifies that the active `rustc` version matches the channel pinned in `rust-toolchain.toml`.
pub fn check_toolchain(workspace_root: &Path) -> Result<(), String> {
    let toolchain_path = workspace_root.join("rust-toolchain.toml");
    let content = fs::read_to_string(&toolchain_path)
        .map_err(|e| format!("Failed to read {}: {e}", toolchain_path.display()))?;

    let mut channel: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("channel") {
            let rest = rest.trim().strip_prefix('=').unwrap_or("").trim();
            let unquoted = rest.trim_matches('"').trim_matches('\'');
            if !unquoted.is_empty() {
                channel = Some(unquoted.to_string());
                break;
            }
        }
    }

    let expected_channel =
        channel.ok_or_else(|| format!("Missing `channel` key in {}", toolchain_path.display()))?;

    let output = Command::new("rustc")
        .arg("--version")
        .output()
        .map_err(|e| format!("Failed to execute `rustc --version`: {e}"))?;

    if !output.status.success() {
        return Err("`rustc --version` exited with non-zero status".to_string());
    }

    let version_str = String::from_utf8_lossy(&output.stdout);
    let actual_version = version_str.split_whitespace().nth(1).unwrap_or("unknown");

    if expected_channel != "stable"
        && expected_channel != "nightly"
        && !actual_version.starts_with(&expected_channel)
    {
        return Err(format!(
            "Toolchain mismatch: rust-toolchain.toml expects '{expected_channel}', active rustc is '{actual_version}'"
        ));
    }

    println!("Toolchain verified: channel='{expected_channel}', active rustc='{actual_version}'");
    Ok(())
}
