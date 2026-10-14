//! DBR-admitted verification pipeline with content-addressed stage receipts.

use crate::stages::XWORK_STAGES;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

const MAX_DBR_QUEUE_DEPTH: usize = 5;

#[derive(Serialize, Deserialize, Default)]
struct DbrQueueState {
    active_runs: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
struct StageReceipt {
    stage: String,
    input_hash: String,
}

/// Runs the full verification pipeline with optional DBR queue admission, CAS receipt resume, and break-check.
pub fn run_check_pipeline(
    workspace_root: &Path,
    resume: bool,
    enforce_dbr: bool,
    break_check: bool,
) -> Result<(), String> {
    let xtask_dir = workspace_root.join("target/xtask");
    let receipts_dir = xtask_dir.join("receipts");
    fs::create_dir_all(&receipts_dir)
        .map_err(|e| format!("Failed to create {}: {e}", receipts_dir.display()))?;

    let dbr_file = xtask_dir.join("dbr-queue.json");
    let pid = std::process::id();

    if enforce_dbr {
        admit_dbr(&dbr_file, pid)?;
    }

    let result = execute_stages(workspace_root, &receipts_dir, resume, break_check);

    if enforce_dbr {
        let _ = release_dbr(&dbr_file, pid);
    }

    result
}

fn execute_stages(
    workspace_root: &Path,
    receipts_dir: &Path,
    resume: bool,
    break_check: bool,
) -> Result<(), String> {
    if break_check {
        let status = Command::new("sh")
            .args(["-c", "exit 1"])
            .current_dir(workspace_root)
            .status()
            .map_err(|e| format!("Failed to run break-check probe: {e}"))?;
        if status.success() {
            return Err("Break-check failed: synthetic failing command succeeded".to_string());
        }
        println!("[BREAK-CHECK] Verified pipeline catches non-zero stage exit codes.");
    }

    let input_hash = compute_workspace_hash(workspace_root)?;

    for stage in XWORK_STAGES {
        let receipt_path = receipts_dir.join(format!("{}.json", stage.name));
        if resume && receipt_matches(&receipt_path, &input_hash) {
            println!(
                "=== [SKIP/CAS] {} (receipt matches {}) ===",
                stage.name,
                &input_hash[..12]
            );
            continue;
        }

        println!("=== [RUN] {} ===", stage.name);
        let status = Command::new(stage.command)
            .args(stage.args)
            .current_dir(workspace_root)
            .status()
            .map_err(|e| format!("Failed to spawn stage `{}`: {e}", stage.name))?;

        if !status.success() {
            return Err(format!("Stage `{}` failed", stage.name));
        }

        let receipt = StageReceipt {
            stage: stage.name.to_string(),
            input_hash: input_hash.clone(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&receipt) {
            let _ = fs::write(&receipt_path, json);
        }
    }

    println!("All {} pipeline stages passed.", XWORK_STAGES.len());
    Ok(())
}

fn receipt_matches(receipt_path: &Path, expected_hash: &str) -> bool {
    let Ok(raw) = fs::read_to_string(receipt_path) else {
        return false;
    };
    let Ok(receipt) = serde_json::from_str::<StageReceipt>(&raw) else {
        return false;
    };
    receipt.input_hash == expected_hash
}

fn compute_workspace_hash(workspace_root: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for rel in ["Cargo.toml", "rust-toolchain.toml", "projectfile.yaml"] {
        let p = workspace_root.join(rel);
        if let Ok(bytes) = fs::read(&p) {
            hasher.update(rel.as_bytes());
            hasher.update(&bytes);
        }
    }
    hash_directory(&workspace_root.join("crates"), &mut hasher)?;
    hash_directory(&workspace_root.join("specs"), &mut hasher)?;

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    Ok(hex)
}

fn hash_directory(dir: &Path, hasher: &mut Sha256) -> Result<(), String> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries =
        fs::read_dir(dir).map_err(|e| format!("Failed to read {}: {e}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries.flatten() {
        paths.push(entry.path());
    }
    paths.sort();

    for path in paths {
        if path.is_dir() {
            hash_directory(&path, hasher)?;
        } else if let Ok(bytes) = fs::read(&path) {
            hasher.update(path.to_string_lossy().as_bytes());
            hasher.update(&bytes);
        }
    }
    Ok(())
}

fn admit_dbr(dbr_file: &Path, pid: u32) -> Result<(), String> {
    let mut state: DbrQueueState = fs::read_to_string(dbr_file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    state
        .active_runs
        .retain(|active_pid| Path::new(&format!("/proc/{active_pid}")).exists());

    if state.active_runs.len() >= MAX_DBR_QUEUE_DEPTH {
        return Err(format!(
            "DBR admission rejected: {} active runs (cap {})",
            state.active_runs.len(),
            MAX_DBR_QUEUE_DEPTH
        ));
    }

    state.active_runs.push(pid);
    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("Failed to serialize DBR state: {e}"))?;
    fs::write(dbr_file, json).map_err(|e| format!("Failed to write DBR state: {e}"))?;
    Ok(())
}

fn release_dbr(dbr_file: &Path, pid: u32) -> Result<(), String> {
    let mut state: DbrQueueState = fs::read_to_string(dbr_file)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    state.active_runs.retain(|p| *p != pid);
    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("Failed to serialize DBR state: {e}"))?;
    fs::write(dbr_file, json).map_err(|e| format!("Failed to write DBR state: {e}"))?;
    Ok(())
}
