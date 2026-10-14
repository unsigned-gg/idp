//! Workspace dependency DAG topological audit (Kahn's algorithm) and Wave-0 zero-I/O purity check.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::process::Command;

const FORBIDDEN_WAVE0_DEPS: &[&str] = &[
    "tokio", "reqwest", "axum", "hyper", "sqlx", "rusqlite", "tower", "idp", "idp-cli",
];

const FORBIDDEN_WAVE0_TOKENS: &[&str] = &[
    "std::fs",
    "std::net",
    "std::process",
    "std::env",
    "tokio::",
    "reqwest::",
    "axum::",
];

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    dependencies: Vec<CargoDep>,
}

#[derive(Deserialize)]
struct CargoDep {
    name: String,
    kind: Option<String>,
}

/// Runs the workspace crate DAG audit and Wave-0 (`idp-domain`) zero-I/O purity check.
pub fn run_graph_audit(workspace_root: &Path, break_check: bool) -> Result<(), String> {
    if break_check {
        verify_break_check()?;
    }

    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("Failed to run `cargo metadata`: {e}"))?;

    if !output.status.success() {
        return Err("`cargo metadata` exited with non-zero status".to_string());
    }

    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse `cargo metadata` JSON: {e}"))?;

    let member_ids: BTreeSet<String> = metadata.workspace_members.into_iter().collect();
    let mut workspace_names = BTreeSet::new();
    let mut packages = Vec::new();
    for pkg in metadata.packages {
        if member_ids.contains(&pkg.id) {
            workspace_names.insert(pkg.name.clone());
            packages.push(pkg);
        }
    }

    let mut deps_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for pkg in &packages {
        let mut ws_deps = BTreeSet::new();
        for dep in &pkg.dependencies {
            if dep.kind.as_deref() == Some("dev") {
                continue;
            }
            if workspace_names.contains(&dep.name) {
                ws_deps.insert(dep.name.clone());
            }
        }
        deps_map.insert(pkg.name.clone(), ws_deps);
    }

    let waves = kahn_toposort(&deps_map)?;
    for (idx, wave) in waves.iter().enumerate() {
        println!("Wave {idx}: {}", wave.join(", "));
    }

    verify_wave0_domain_purity(workspace_root, &deps_map)?;

    println!(
        "Graph audit passed ({} workspace crates across {} waves)",
        workspace_names.len(),
        waves.len()
    );
    Ok(())
}

/// Verifies that `idp-domain` has zero workspace dependencies, zero forbidden crates, and zero I/O tokens.
pub fn verify_wave0_domain_purity(
    workspace_root: &Path,
    deps_map: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), String> {
    if let Some(ws_deps) = deps_map.get("idp-domain") {
        if !ws_deps.is_empty() {
            return Err(format!(
                "Wave-0 purity violation: `idp-domain` depends on workspace crates: {ws_deps:?}"
            ));
        }
    } else {
        return Err("Missing Wave-0 crate `idp-domain` in workspace".to_string());
    }

    let cargo_toml_path = workspace_root.join("crates/idp-domain/Cargo.toml");
    let cargo_toml = fs::read_to_string(&cargo_toml_path)
        .map_err(|e| format!("Failed to read {}: {e}", cargo_toml_path.display()))?;

    for forbidden in FORBIDDEN_WAVE0_DEPS {
        for line in cargo_toml.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            if let Some((key, _)) = trimmed.split_once('=') {
                let key = key.trim().trim_end_matches(".workspace");
                if key == *forbidden {
                    return Err(format!(
                        "Wave-0 purity violation: `idp-domain/Cargo.toml` references forbidden dependency `{forbidden}`"
                    ));
                }
            }
        }
    }

    let src_dir = workspace_root.join("crates/idp-domain/src");
    scan_dir_for_io(&src_dir)?;

    println!("Wave-0 purity verified: `idp-domain` has zero I/O or runtime dependencies.");
    Ok(())
}

fn scan_dir_for_io(dir: &Path) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|e| format!("Failed to read {}: {e}", dir.display()))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir_for_io(&path)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            let content = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
            scan_source_for_io(&path.display().to_string(), &content)?;
        }
    }
    Ok(())
}

fn scan_source_for_io(label: &str, content: &str) -> Result<(), String> {
    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        for token in FORBIDDEN_WAVE0_TOKENS {
            if trimmed.contains(token) {
                return Err(format!(
                    "Wave-0 I/O violation in {label}:{}: found forbidden token `{token}`",
                    line_no + 1
                ));
            }
        }
    }
    Ok(())
}

fn kahn_toposort(
    deps_map: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<Vec<String>>, String> {
    let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (node, deps) in deps_map {
        in_degree.insert(node.clone(), deps.len());
        for dep in deps {
            dependents
                .entry(dep.clone())
                .or_default()
                .push(node.clone());
        }
    }

    let mut queue: VecDeque<String> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(node, _)| node.clone())
        .collect();

    let mut visited = 0usize;
    let mut waves = Vec::new();

    while !queue.is_empty() {
        let wave_len = queue.len();
        let mut wave = Vec::with_capacity(wave_len);
        for _ in 0..wave_len {
            if let Some(node) = queue.pop_front() {
                visited += 1;
                wave.push(node.clone());
                if let Some(children) = dependents.get(&node) {
                    for child in children {
                        if let Some(deg) = in_degree.get_mut(child) {
                            *deg = deg.saturating_sub(1);
                            if *deg == 0 {
                                queue.push_back(child.clone());
                            }
                        }
                    }
                }
            }
        }
        wave.sort();
        waves.push(wave);
    }

    if visited != deps_map.len() {
        return Err("Dependency cycle detected in workspace crate DAG".to_string());
    }

    Ok(waves)
}

fn verify_break_check() -> Result<(), String> {
    let mut cyclic: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    cyclic.insert(
        "crate-a".to_string(),
        BTreeSet::from(["crate-b".to_string()]),
    );
    cyclic.insert(
        "crate-b".to_string(),
        BTreeSet::from(["crate-a".to_string()]),
    );
    if kahn_toposort(&cyclic).is_ok() {
        return Err("Break-check failed: cyclic DAG was not rejected".to_string());
    }

    if scan_source_for_io("synthetic.rs", "let _ = std::fs::read_to_string(\"x\");").is_ok() {
        return Err("Break-check failed: Wave-0 I/O token was not rejected".to_string());
    }

    println!("[BREAK-CHECK] Verified synthetic DAG cycle and Wave-0 I/O violation are caught.");
    Ok(())
}
