//! Spec document validation (`specs/*.md` frontmatter and body checks).

use std::fs;
use std::path::Path;

/// Validates all markdown specifications under `specs/`.
pub fn check_specs(workspace_root: &Path) -> Result<(), String> {
    let specs_dir = workspace_root.join("specs");
    if !specs_dir.is_dir() {
        return Err(format!("Missing specs directory: {}", specs_dir.display()));
    }

    let entries = fs::read_dir(&specs_dir)
        .map_err(|e| format!("Failed to read {}: {e}", specs_dir.display()))?;

    let mut spec_files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("md") {
            spec_files.push(path);
        }
    }
    spec_files.sort();

    if spec_files.is_empty() {
        return Err("No markdown spec files found in specs/".to_string());
    }

    for path in &spec_files {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

        let trimmed = content.trim_start();
        if !trimmed.starts_with("---") {
            return Err(format!(
                "Spec {} is missing YAML frontmatter (`---`)",
                path.display()
            ));
        }

        let after_open = &trimmed[3..];
        let close_idx = after_open.find("\n---").ok_or_else(|| {
            format!(
                "Spec {} has unclosed YAML frontmatter (`---`)",
                path.display()
            )
        })?;

        let frontmatter = &after_open[..close_idx];
        let body = after_open[close_idx + 4..].trim();

        let has_status = frontmatter
            .lines()
            .any(|l| l.trim_start().starts_with("status:"));
        let has_created = frontmatter
            .lines()
            .any(|l| l.trim_start().starts_with("created:"));

        if !has_status || !has_created {
            return Err(format!(
                "Spec {} frontmatter must include `status:` and `created:`",
                path.display()
            ));
        }

        if body.is_empty() {
            return Err(format!("Spec {} has an empty body", path.display()));
        }
    }

    println!("Spec check passed ({} specs verified)", spec_files.len());
    Ok(())
}
