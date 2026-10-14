//! Rust toolchain channel verification against `rust-toolchain.toml` (SPEC-0003, XT-5).

use std::fs;
use std::path::Path;
use std::process::Command;

/// Verifies that the active `rustc` version matches the channel pinned in `rust-toolchain.toml`.
pub fn check_toolchain(workspace_root: &Path) -> Result<(), String> {
    let toolchain_path = workspace_root.join("rust-toolchain.toml");
    let content = fs::read_to_string(&toolchain_path)
        .map_err(|e| format!("Failed to read {}: {e}", toolchain_path.display()))?;

    let expected_channel = channel_of(&content)
        .ok_or_else(|| format!("Missing `channel` key in {}", toolchain_path.display()))?;

    let output = Command::new("rustc")
        .arg("--version")
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("Failed to execute `rustc --version`: {e}"))?;

    if !output.status.success() {
        return Err("`rustc --version` exited with non-zero status".to_string());
    }

    let version_str = String::from_utf8_lossy(&output.stdout);
    verify_channel(&expected_channel, &version_str)?;
    let actual_version = version_str.split_whitespace().nth(1).unwrap_or("unknown");

    println!("Toolchain verified: channel='{expected_channel}', active rustc='{actual_version}'");
    Ok(())
}

/// The `channel` value of a `rust-toolchain.toml` document: the first non-empty
/// `channel = "..."` line.
pub fn channel_of(content: &str) -> Option<String> {
    let _ = content;
    None
}

/// Compare the pinned channel with a `rustc --version` line (XT-5).
///
/// A channel of three parts must equal the active version. A channel of two parts matches any
/// patch of that minor version. `stable`, `beta` and `nightly` channels cannot be compared and
/// pass.
pub fn verify_channel(channel: &str, rustc_line: &str) -> Result<(), String> {
    let _ = (channel, rustc_line);
    Err(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xt5_the_exact_version_matches() {
        assert_eq!(
            verify_channel("1.88.0", "rustc 1.88.0 (6b00bc388 2025-06-23)\n"),
            Ok(())
        );
    }

    #[test]
    fn xt5_another_version_fails_and_names_both() {
        let err = verify_channel("1.88.0", "rustc 1.89.0 (29483883e 2025-08-04)").err();
        let err = err.unwrap_or_default();
        assert!(err.contains("1.88.0"), "{err}");
        assert!(err.contains("1.89.0"), "{err}");
        assert!(verify_channel("1.88.0", "rustc 1.88.1 (abc 2025-07-01)").is_err());
    }

    #[test]
    fn xt5_a_prefix_is_not_a_match() {
        assert!(verify_channel("1.8", "rustc 1.88.0 (6b00bc388 2025-06-23)").is_err());
        assert!(verify_channel("1.88.0", "rustc 1.88.01 (abc 2025-06-23)").is_err());
    }

    #[test]
    fn xt5_a_two_part_channel_matches_any_patch() {
        assert_eq!(
            verify_channel("1.88", "rustc 1.88.2 (abc 2025-08-01)"),
            Ok(())
        );
        assert!(verify_channel("1.88", "rustc 1.89.0 (abc 2025-08-01)").is_err());
    }

    #[test]
    fn xt5_named_channels_pass() {
        assert_eq!(
            verify_channel("stable", "rustc 1.96.1 (abc 2026-09-01)"),
            Ok(())
        );
        assert_eq!(
            verify_channel("nightly", "rustc 1.97.0-nightly (abc 2026-09-30)"),
            Ok(())
        );
        assert_eq!(
            verify_channel(
                "nightly-2026-09-30",
                "rustc 1.97.0-nightly (abc 2026-09-29)"
            ),
            Ok(())
        );
    }

    #[test]
    fn xt5_unparsable_rustc_output_fails() {
        assert!(verify_channel("1.88.0", "").is_err());
        assert!(verify_channel("1.88.0", "rustc").is_err());
    }

    #[test]
    fn xt5_the_channel_is_read_from_rust_toolchain_toml() {
        let file = "[toolchain]\nchannel = \"1.88.0\"\ncomponents = [\"rustfmt\", \"clippy\"]\nprofile = \"minimal\"\n";
        assert_eq!(channel_of(file).as_deref(), Some("1.88.0"));
        assert_eq!(
            channel_of("[toolchain]\nchannel='1.85'\n").as_deref(),
            Some("1.85")
        );
        assert_eq!(channel_of("[toolchain]\nprofile = \"minimal\"\n"), None);
        assert_eq!(channel_of("[toolchain]\nchannel = \"\"\n"), None);
    }
}
