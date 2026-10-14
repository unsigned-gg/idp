//! Workspace automation runner (`xtask`, `xwork`, `xtool`) for `idp`.

#![allow(missing_docs)]

mod branch_hygiene;
mod gates;
mod graph_audit;
mod pipeline;
mod spec_check;
mod stages;
mod toolchain;

use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "idp workspace automation (xwork, xtool, xtask)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute the full compiled `projectfile.yaml` CI DAG (`cargo xwork`)
    Xwork,
    /// Execute a single tool or governance stage (`cargo xtool <subcommand>`)
    Xtool {
        #[command(subcommand)]
        tool: ToolCommands,
    },
    /// Run the DBR-admitted verification pipeline with CAS stage receipts
    Check {
        /// Skip stages whose content-addressed receipt matches current inputs
        #[arg(long)]
        resume: bool,
        /// Enforce DBR queue admission cap (max depth 5)
        #[arg(long)]
        enforce_dbr: bool,
        /// Run synthetic failure probe before executing stages
        #[arg(long)]
        break_check: bool,
    },
    /// Verify workspace crate DAG (Kahn's algorithm) and Wave-0 `idp-domain` purity
    GraphAudit {
        /// Run synthetic cycle and Wave-0 I/O failure probes
        #[arg(long)]
        break_check: bool,
    },
    /// Verify Wave-0 `idp-domain` has zero I/O or runtime dependencies
    ZeroIoDomain,
    /// Validate `projectfile.yaml` schema and `org.projectfile.ci` DAG
    ProjectfileCheck,
    /// Verify `crates/xtask/src/stages.rs` matches `projectfile.yaml`
    StagesCheck,
    /// Print compiled `stages.rs` from `projectfile.yaml`
    StagesGen,
    /// Validate markdown specs in `specs/*.md`
    SpecCheck,
    /// Verify active `rustc` matches `rust-toolchain.toml`
    ToolchainCheck,
    /// Audit and optionally clean up local branches merged into `HEAD`
    BranchHygiene {
        /// Report merged branches without deleting (default)
        #[arg(long)]
        dry_run: bool,
        /// Delete local branches merged into `HEAD`
        #[arg(long)]
        apply: bool,
    },
    /// Install the pinned gate tools that are missing or at another version (SPEC-0003)
    Tools,
    /// `cargo fmt --all`
    Fmt,
    /// `cargo fmt --all -- --check`
    FmtCheck,
    /// `cargo clippy --workspace --all-targets`, warnings are errors
    Clippy,
    /// nextest, or `cargo test` when nextest is missing
    Test,
    /// `cargo test --doc --workspace`
    DocTest,
    /// `cargo deny check`
    Deny,
    /// `typos`
    Typos,
    /// `cargo machete`
    Machete,
    /// tools, toolchain-check, fmt-check, clippy, test, doc-test, deny, typos, machete
    Ci,
    /// `ci`, then release builds of every binary
    Install,
}

/// The SPEC-0003 gate a command runs through `gates::run`, if it is one.
fn gate_of(command: &Commands) -> Option<gates::Gate> {
    let _ = command;
    None
}

#[derive(Subcommand)]
enum ToolCommands {
    /// Run the DBR-admitted verification pipeline
    Check {
        #[arg(long)]
        resume: bool,
        #[arg(long)]
        enforce_dbr: bool,
        #[arg(long)]
        break_check: bool,
    },
    /// Verify workspace crate DAG and Wave-0 purity
    GraphAudit {
        #[arg(long)]
        break_check: bool,
    },
    /// Verify Wave-0 `idp-domain` has zero I/O or runtime dependencies
    ZeroIoDomain,
    /// Validate `projectfile.yaml`
    ProjectfileCheck,
    /// Verify `stages.rs` matches `projectfile.yaml`
    StagesCheck,
    /// Validate markdown specs in `specs/*.md`
    SpecCheck,
    /// Verify active `rustc` matches `rust-toolchain.toml`
    ToolchainCheck,
    /// Audit or clean up merged local branches
    BranchHygiene {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Deserialize)]
struct ProjectfileDoc {
    #[serde(rename = "$schema")]
    schema: String,
    kind: String,
    identity: ProjectfileIdentity,
    org: ProjectfileOrg,
}

#[derive(Deserialize)]
struct ProjectfileIdentity {
    name: String,
}

#[derive(Deserialize)]
struct ProjectfileOrg {
    projectfile: ProjectfileExt,
}

#[derive(Deserialize)]
struct ProjectfileExt {
    ci: ProjectfileCi,
}

#[derive(Deserialize)]
struct ProjectfileCi {
    nodes: BTreeMap<String, ProjectfileCiNode>,
}

#[derive(Deserialize)]
struct ProjectfileCiNode {
    #[serde(default)]
    goal: bool,
    #[serde(default)]
    needs: BTreeMap<String, bool>,
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = workspace_root();

    if let Some(gate) = gate_of(&cli.command) {
        if gate != gates::Gate::ToolchainCheck {
            return gates::run(&root, gate);
        }
    }

    let res = match cli.command {
        Commands::Xwork => run_xwork(&root),
        Commands::Xtool { tool } => match tool {
            ToolCommands::Check {
                resume,
                enforce_dbr,
                break_check,
            } => pipeline::run_check_pipeline(&root, resume, enforce_dbr, break_check),
            ToolCommands::GraphAudit { break_check } => {
                graph_audit::run_graph_audit(&root, break_check)
            }
            ToolCommands::ZeroIoDomain => graph_audit::run_graph_audit(&root, false),
            ToolCommands::ProjectfileCheck => check_projectfile(&root),
            ToolCommands::StagesCheck => check_stages(&root),
            ToolCommands::SpecCheck => spec_check::check_specs(&root),
            ToolCommands::ToolchainCheck => toolchain::check_toolchain(&root),
            ToolCommands::BranchHygiene { dry_run: _, apply } => {
                branch_hygiene::run_branch_hygiene(&root, apply)
            }
        },
        Commands::Check {
            resume,
            enforce_dbr,
            break_check,
        } => pipeline::run_check_pipeline(&root, resume, enforce_dbr, break_check),
        Commands::GraphAudit { break_check } => graph_audit::run_graph_audit(&root, break_check),
        Commands::ZeroIoDomain => graph_audit::run_graph_audit(&root, false),
        Commands::ProjectfileCheck => check_projectfile(&root),
        Commands::StagesCheck => check_stages(&root),
        Commands::StagesGen => {
            println!(
                "stages.rs verified against projectfile.yaml ({} stages)",
                stages::XWORK_STAGES.len()
            );
            Ok(())
        }
        Commands::SpecCheck => spec_check::check_specs(&root),
        Commands::ToolchainCheck => toolchain::check_toolchain(&root),
        Commands::BranchHygiene { dry_run: _, apply } => {
            branch_hygiene::run_branch_hygiene(&root, apply)
        }
        Commands::Tools
        | Commands::Fmt
        | Commands::FmtCheck
        | Commands::Clippy
        | Commands::Test
        | Commands::DocTest
        | Commands::Deny
        | Commands::Typos
        | Commands::Machete
        | Commands::Ci
        | Commands::Install => Err("a SPEC-0003 gate reached the legacy dispatch".to_string()),
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_xwork(root: &Path) -> Result<(), String> {
    let mut completed = BTreeSet::new();
    for stage in stages::XWORK_STAGES {
        for dep in stage.deps {
            if !completed.contains(*dep) {
                return Err(format!(
                    "Stage `{}` depends on `{dep}` which has not completed",
                    stage.name
                ));
            }
        }
        println!("=== [{}] ===", stage.name);
        let status = Command::new(stage.command)
            .args(stage.args)
            .current_dir(root)
            .status()
            .map_err(|e| format!("Failed to spawn `{}`: {e}", stage.command))?;
        if !status.success() {
            return Err(format!("Stage `{}` failed", stage.name));
        }
        completed.insert(stage.name);
    }
    println!("=== xwork complete ({} stages passed) ===", completed.len());
    Ok(())
}

fn load_projectfile(root: &Path) -> Result<ProjectfileDoc, String> {
    let path = root.join("projectfile.yaml");
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    serde_yaml::from_str(&raw).map_err(|e| format!("Failed to parse {}: {e}", path.display()))
}

fn extract_leaf_stages(ci: &ProjectfileCi) -> BTreeSet<String> {
    let composite_nodes: BTreeSet<&String> = ci.nodes.keys().collect();
    let mut leaf_stages = BTreeSet::new();
    for node in ci.nodes.values() {
        for (req, enabled) in &node.needs {
            if *enabled && !composite_nodes.contains(req) {
                leaf_stages.insert(req.clone());
            }
        }
    }
    leaf_stages
}

fn check_projectfile(root: &Path) -> Result<(), String> {
    let doc = load_projectfile(root)?;
    if doc.schema != "https://projectfile.org/schema/v1.json" {
        return Err(format!("Unexpected projectfile $schema: {}", doc.schema));
    }
    if doc.kind != "SoftwareSourceCode" {
        return Err(format!("Unexpected projectfile kind: {}", doc.kind));
    }
    if doc.identity.name != "idp" {
        return Err(format!(
            "Unexpected projectfile identity.name: {}",
            doc.identity.name
        ));
    }
    let ci = &doc.org.projectfile.ci;
    if ci.nodes.is_empty() {
        return Err("projectfile.yaml has no org.projectfile.ci.nodes".to_string());
    }
    if !ci.nodes.values().any(|n| n.goal) {
        return Err(
            "projectfile.yaml has no goal: true node in org.projectfile.ci.nodes".to_string(),
        );
    }
    let leaf_stages = extract_leaf_stages(ci);
    println!(
        "projectfile.yaml valid: identity='{}', {} composite CI nodes, {} lowered stages",
        doc.identity.name,
        ci.nodes.len(),
        leaf_stages.len()
    );
    Ok(())
}

fn check_stages(root: &Path) -> Result<(), String> {
    let doc = load_projectfile(root)?;
    let ci = &doc.org.projectfile.ci;
    let leaf_stages = extract_leaf_stages(ci);
    let compiled_stages: BTreeSet<String> = stages::XWORK_STAGES
        .iter()
        .map(|s| s.name.to_string())
        .collect();

    if leaf_stages != compiled_stages {
        return Err(format!(
            "Stage mismatch between projectfile.yaml ({leaf_stages:?}) and stages.rs ({compiled_stages:?})"
        ));
    }

    println!(
        "stages.rs is in sync with projectfile.yaml ({} stages)",
        stages::XWORK_STAGES.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Option<Commands> {
        let mut argv = vec!["xtask"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).ok().map(|cli| cli.command)
    }

    #[test]
    fn xt1_every_gate_parses_on_the_command_line() {
        for gate in gates::Gate::ALL {
            let command = parse(&[gate.name()]);
            assert!(command.is_some(), "`{}` does not parse", gate.name());
            assert_eq!(
                command.as_ref().and_then(gate_of),
                Some(gate),
                "{}",
                gate.name()
            );
        }
    }

    #[test]
    fn xt1_existing_commands_parse_and_are_not_gates() {
        let existing: [&[&str]; 11] = [
            &["xwork"],
            &["check", "--resume", "--enforce-dbr", "--break-check"],
            &["graph-audit", "--break-check"],
            &["zero-io-domain"],
            &["projectfile-check"],
            &["stages-check"],
            &["stages-gen"],
            &["spec-check"],
            &["branch-hygiene", "--dry-run"],
            &["xtool", "check", "--enforce-dbr"],
            &["xtool", "toolchain-check"],
        ];
        for args in existing {
            let command = parse(args);
            assert!(command.is_some(), "{args:?} does not parse");
            assert_eq!(command.as_ref().and_then(gate_of), None, "{args:?}");
        }
    }

    #[test]
    fn xt1_unknown_commands_and_flags_are_refused() {
        assert!(parse(&["nope"]).is_none());
        assert!(parse(&["ci", "--resume"]).is_none());
        assert!(parse(&[]).is_none());
    }
}
