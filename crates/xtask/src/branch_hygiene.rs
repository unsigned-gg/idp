//! Post-merge branch hygiene audit and cleanup (`--dry-run` default, `--apply`).

use std::path::Path;
use std::process::Command;

/// Audits local git branches that are fully merged into `main` or `origin/main`.
pub fn run_branch_hygiene(workspace_root: &Path, apply: bool) -> Result<(), String> {
    let output = Command::new("git")
        .args(["branch", "--merged", "HEAD"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("Failed to run `git branch --merged HEAD`: {e}"))?;

    if !output.status.success() {
        return Err("`git branch --merged HEAD` failed".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut candidates = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('*') || trimmed.starts_with('+') {
            continue;
        }
        if trimmed == "main" || trimmed == "master" || trimmed.is_empty() {
            continue;
        }
        candidates.push(trimmed.to_string());
    }

    if candidates.is_empty() {
        println!("Branch hygiene: 0 stale merged local branches.");
        return Ok(());
    }

    if !apply {
        println!(
            "Branch hygiene (dry-run): {} merged branch(es) eligible for deletion: {}",
            candidates.len(),
            candidates.join(", ")
        );
        return Ok(());
    }

    for branch in &candidates {
        let status = Command::new("git")
            .args(["branch", "-d", branch])
            .current_dir(workspace_root)
            .status()
            .map_err(|e| format!("Failed to delete branch {branch}: {e}"))?;
        if !status.success() {
            return Err(format!("`git branch -d {branch}` failed"));
        }
        println!("Deleted merged branch: {branch}");
    }

    Ok(())
}
