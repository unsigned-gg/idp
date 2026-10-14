// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Identity Provider CLI (`idp`) for `unsigned-gg`, `cerebral-work/identity`, and Clockwork Conclave bots.

mod server;

use anyhow::{Context, Result, bail};
use chrono::{NaiveDate, Utc};
use clap::{Args, Parser, Subcommand};
use idp::detectors::{
    Rbac, evaluate_oidc_bindings, evaluate_reflexd_admission, evaluate_tenant_appprojects,
    expected_cloudflare_emails, expected_tailscale_admins, load_declared_admission,
};
use idp::directory::{
    hold_text, load_desired_state, unhold_text, validate_directory_schema, validate_identity_models,
};
use idp::lifecycle::{OnboardRequest, stage_offboard, stage_onboard};
use idp::manifest::AppManifest;
use idp::planes::{
    LiveGroupMember, all_declared, foundation_declared, gam_declared, undeclared_groups_report,
    unmanaged_declared,
};
use idp::reconcile::{
    LiveDirectoryState, apply_refusal, plan_digest, plan_findings, reconcile_directory, redact,
};
use idp::registry::{ALL_ESTATE_ELVES, CONCLAVE_ELVES, KeyStore};
use idp::token::TokenBroker;
use server::{AppState, create_router};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[derive(Parser)]
#[command(name = "idp")]
#[command(about = "Identity Provider CLI, Directory Reconciler, and Conclave Bot Manager")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// GitHub App manifest operations
    Manifest(ManifestArgs),

    /// Token brokering and JWT minting
    Token(TokenArgs),

    /// List Conclave bot identities and host registration status
    Bot(BotArgs),

    /// Validate declarative identity directory (`users.yaml`, `groups/*.yaml`, `role-matrix.yaml`, `policies.yaml`)
    Validate {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },

    /// Inspect declared group planes (`gam`, `foundation`, `unmanaged`, `all`)
    Planes {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,

        /// Plane to print (`all`, `gam`, `foundation`, `unmanaged`)
        #[arg(long, default_value = "all")]
        plane: String,
    },

    /// Reconciliation plan digest and hold/unhold operations
    Reconcile(ReconcileArgs),

    /// User onboarding and two-stage offboarding lifecycle operations
    Lifecycle(LifecycleArgs),

    /// Run clause-tested identity detectors over JSON snapshots or repository state
    Detectors(DetectorArgs),
}

#[derive(Args)]
struct ManifestArgs {
    #[command(subcommand)]
    command: ManifestCommands,
}

#[derive(Subcommand)]
enum ManifestCommands {
    /// Generate a GitHub App manifest JSON for a bot
    Generate {
        /// Bot identity tag (e.g. sindri, idunn, brokkr)
        #[arg(long, default_value = "sindri")]
        bot: String,

        /// Callback redirect URL
        #[arg(long, default_value = "http://127.0.0.1:8787/callback")]
        redirect_url: String,
    },

    /// Launch local web server to mint GitHub App identities via browser
    Serve {
        /// Local port to listen on
        #[arg(long, default_value_t = 8787)]
        port: u16,

        /// Explicit public base URL (e.g. Cloudflare tunnel)
        #[arg(long)]
        public_url: Option<String>,
    },
}

#[derive(Args)]
struct TokenArgs {
    #[command(subcommand)]
    command: TokenCommands,
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Mint an RS256 JWT or exchange for an installation token
    Get {
        /// GitHub App ID
        #[arg(long)]
        app_id: u64,

        /// Path to PEM private key file
        #[arg(long)]
        key: PathBuf,

        /// Optional installation ID. If omitted, outputs App JWT
        #[arg(long)]
        installation_id: Option<u64>,
    },
}

#[derive(Args)]
struct BotArgs {
    #[command(subcommand)]
    command: BotCommands,
}

#[derive(Subcommand)]
enum BotCommands {
    /// List Clockwork Conclave bots and key statuses
    List {
        /// Include all 22 extended estate elves (default: 16 core Conclave elves)
        #[arg(long)]
        all: bool,
    },
}

#[derive(Args)]
struct ReconcileArgs {
    #[command(subcommand)]
    command: ReconcileCommands,
}

#[derive(Subcommand)]
enum ReconcileCommands {
    /// Compute a reconciliation plan over `directory/` and a live directory snapshot JSON
    Plan {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Path to a `LiveDirectoryState` JSON snapshot
        #[arg(long)]
        live_json: PathBuf,
        /// Optional `YYYY-MM-DD` evaluation date (defaults to UTC today)
        #[arg(long)]
        today: Option<String>,
        /// Initial password placeholder for newly created users
        #[arg(long, default_value = "<generated>")]
        initial_password: String,
    },

    /// Add or update an `unreconciled_members` hold exception on a group YAML file
    Hold {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Group slug or email
        group: String,
        /// Member email address to hold
        email: String,
        /// Human explanation for the exception
        #[arg(long)]
        reason: String,
        /// Optional `YYYY-MM-DD` expiration date
        #[arg(long)]
        until: Option<String>,
    },

    /// Remove an `unreconciled_members` hold exception from a group YAML file
    Unhold {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Group slug or email
        group: String,
        /// Member email address to unhold
        email: String,
    },

    /// Verify an expected plan SHA-256 digest against a current digest
    VerifyDigest {
        /// Expected digest passed via `--expect-plan-sha256`
        #[arg(long)]
        expected: Option<String>,
        /// Actual computed 16-char digest
        #[arg(long)]
        actual: String,
    },
}

#[derive(Args)]
struct LifecycleArgs {
    #[command(subcommand)]
    command: LifecycleCommands,
}

#[derive(Subcommand)]
enum LifecycleCommands {
    /// Stage a new user in `directory/`
    Onboard {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// User email (`<handle>@cerebral.work`)
        email: String,
        /// Given (first) name
        given_name: String,
        /// Family (last) name
        family_name: String,
        /// Google Workspace organizational unit path
        #[arg(long, default_value = "/Engineering")]
        org_unit: String,
        /// Comma-separated group slugs or emails
        #[arg(long, default_value = "")]
        groups: String,
        /// Google Workspace license SKU ID
        #[arg(long, default_value = "1010020020")]
        sku_id: String,
        /// Skip license assignment
        #[arg(long)]
        no_license: bool,
        /// Optional GitHub login handle
        #[arg(long)]
        github: Option<String>,
        /// Comma-separated GitHub orgs (defaults to `managed_github_orgs` when `--github` is set)
        #[arg(long)]
        github_orgs: Option<String>,
        /// Set `create: false` on the user record
        #[arg(long)]
        no_create: bool,
    },

    /// Stage user offboarding (`T0` suspension or `--finalize` group removal)
    Offboard {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// User email (`<handle>@cerebral.work`)
        email: String,
        /// Finalize (`T+30d`): remove user from all group files
        #[arg(long)]
        finalize: bool,
    },
}

#[derive(Args)]
struct DetectorArgs {
    #[command(subcommand)]
    command: DetectorCommands,
}

#[derive(Subcommand)]
enum DetectorCommands {
    /// Evaluate undeclared Google Workspace groups from a live groups JSON file
    UndeclaredGroups {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Path to JSON file mapping `{group_email: [{"email": "...", "role": "..."}]}`
        #[arg(long)]
        live_json: PathBuf,
    },

    /// Evaluate Kubernetes OIDC RBAC bindings from a JSON snapshot
    OidcBindings {
        /// Path to JSON file with `cluster_roles`, `roles`, `cluster_role_bindings`, `role_bindings`
        #[arg(long)]
        rbac_json: PathBuf,
    },

    /// Evaluate `reflexd` NetworkPolicy ingress admission from JSON snapshots
    ReflexdAdmission {
        /// Path to `reflexd-admission.yaml`
        #[arg(long, default_value = "directory/reflexd-admission.yaml")]
        declared: PathBuf,
        /// Path to JSON list of NetworkPolicy objects
        #[arg(long)]
        policies_json: PathBuf,
        /// Path to JSON list of Namespace objects
        #[arg(long)]
        namespaces_json: PathBuf,
    },

    /// Evaluate tenant ArgoCD AppProjects for forbidden cluster-RBAC whitelist entries
    TenantAppprojects {
        /// Path to JSON `AppProjectList` object
        #[arg(long)]
        appprojects_json: PathBuf,
        /// ArgoCD namespace
        #[arg(long, default_value = "argocd")]
        namespace: String,
        /// Tenant AppProject name prefix
        #[arg(long, default_value = "tenant-")]
        prefix: String,
    },

    /// Print expected active Cloudflare and Tailscale admin emails from `role-matrix.yaml`
    RoleMatrixExpected {
        /// Path to the identity repository root
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let key_store = KeyStore::default();

    match cli.command {
        Commands::Manifest(args) => match args.command {
            ManifestCommands::Generate { bot, redirect_url } => {
                let manifest = AppManifest::for_conclave_bot(&bot, &redirect_url);
                let json = serde_json::to_string_pretty(&manifest)
                    .context("Failed to serialize manifest")?;
                println!("{json}");
            }
            ManifestCommands::Serve { port, public_url } => {
                let public_url = public_url.unwrap_or_else(|| format!("http://127.0.0.1:{port}"));
                let state = Arc::new(AppState {
                    public_url: public_url.clone(),
                    key_store,
                });

                let app = create_router(state);
                let addr = SocketAddr::from(([0, 0, 0, 0], port));
                info!("Listening on http://{addr}");
                println!("============================================================");
                println!("  Clockwork Conclave Mint Server Live");
                println!("  Dashboard: {public_url}");
                println!("  Local:     http://127.0.0.1:{port}");
                println!("============================================================");

                let listener = tokio::net::TcpListener::bind(addr).await?;
                axum::serve(listener, app).await?;
            }
        },
        Commands::Token(args) => match args.command {
            TokenCommands::Get {
                app_id,
                key,
                installation_id,
            } => {
                let pem = std::fs::read_to_string(&key)
                    .with_context(|| format!("Failed to read private key at {}", key.display()))?;
                let broker = TokenBroker::new();

                match installation_id {
                    Some(inst_id) => {
                        let token = broker
                            .create_installation_token(app_id, &pem, inst_id)
                            .await
                            .context("Failed to exchange installation token")?;
                        println!("{}", token.token);
                    }
                    None => {
                        let jwt = broker
                            .mint_jwt(app_id, &pem)
                            .context("Failed to mint App JWT")?;
                        println!("{jwt}");
                    }
                }
            }
        },
        Commands::Bot(args) => match args.command {
            BotCommands::List { all } => {
                let elves = if all {
                    ALL_ESTATE_ELVES
                } else {
                    CONCLAVE_ELVES
                };
                println!(
                    "{:<4} | {:<10} | {:<14} | {:<10} | {:<30}",
                    "NUM", "BOT", "REPO", "STATUS", "KEY FILE"
                );
                println!(
                    "{:-<4}-+-{:-<10}-+-{:-<14}-+-{:-<10}-+-{:-<30}",
                    "", "", "", "", ""
                );

                for (idx, elf) in elves.iter().enumerate() {
                    let has_key = key_store.has_key(elf.id);
                    let status = if has_key { "MINTED" } else { "PENDING" };
                    let key_path = if has_key {
                        key_store.key_path(elf.id).display().to_string()
                    } else {
                        "-".to_string()
                    };

                    println!(
                        "{:<4} | {:<10} | {:<14} | {:<10} | {:<30}",
                        idx + 1,
                        elf.name,
                        elf.repo,
                        status,
                        key_path
                    );
                }
            }
        },
        Commands::Validate { repo } => {
            let user_count = validate_directory_schema(&repo)?;
            validate_identity_models(&repo)?;
            let reflexd_path = repo.join("directory/reflexd-admission.yaml");
            if reflexd_path.exists() {
                load_declared_admission(&reflexd_path)?;
            }
            let declared_groups = all_declared(&repo)?;
            println!(
                "Desired state valid: {user_count} users, {} declared groups across GAM + foundation",
                declared_groups.len()
            );
        }
        Commands::Planes { repo, plane } => match plane.as_str() {
            "gam" => {
                for g in gam_declared(&repo)? {
                    println!("{g}");
                }
            }
            "foundation" => {
                for g in foundation_declared(&repo)? {
                    println!("{g}");
                }
            }
            "unmanaged" => {
                for (g, why) in unmanaged_declared(&repo.join("directory/groups-unmanaged.yaml"))? {
                    println!("{g}\t{why}");
                }
            }
            "all" => {
                for g in all_declared(&repo)? {
                    println!("{g}");
                }
            }
            other => bail!("unknown plane '{other}' (expected all, gam, foundation, or unmanaged)"),
        },
        Commands::Reconcile(args) => match args.command {
            ReconcileCommands::Plan {
                repo,
                live_json,
                today,
                initial_password,
            } => {
                let desired = load_desired_state(&repo)?;
                let raw = std::fs::read_to_string(&live_json)?;
                let live: LiveDirectoryState = serde_json::from_str(&raw)?;
                let elsewhere = foundation_declared(&repo)?;
                let unmanaged_path = repo.join("directory/groups-unmanaged.yaml");
                let unmanaged = if unmanaged_path.exists() {
                    unmanaged_declared(&unmanaged_path)?
                } else {
                    BTreeMap::new()
                };
                let eval_date = match today {
                    Some(s) => NaiveDate::parse_from_str(&s, "%Y-%m-%d")
                        .with_context(|| format!("invalid --today date '{s}'"))?,
                    None => Utc::now().date_naive(),
                };
                let (plan, stakes) = reconcile_directory(
                    &desired,
                    &live,
                    &elsewhere,
                    &unmanaged,
                    eval_date,
                    &initial_password,
                );
                let digest = plan_digest(&plan.serial, &plan.batch);
                let total = plan.serial.len() + plan.batch.len();
                println!(
                    "== PLAN: {total} command(s) ({} prerequisite, {} batch) ==",
                    plan.serial.len(),
                    plan.batch.len()
                );
                println!("== Plan SHA256: {digest} ==");
                for c in plan.serial.iter().chain(plan.batch.iter()) {
                    let tag = stakes
                        .get(c)
                        .map(|s| format!("  # [{s}]"))
                        .unwrap_or_default();
                    println!("  {}{tag}", redact(c));
                }
                if !plan.manual.is_empty() {
                    println!("\n== MANUAL REVIEW ({}) ==", plan.manual.len());
                    for m in &plan.manual {
                        println!("  ! {m}");
                    }
                }
                let f = plan_findings(&plan.serial, &plan.batch, &plan.manual, &digest, &stakes);
                f.write_to_env()?;
            }
            ReconcileCommands::Hold {
                repo,
                group,
                email,
                reason,
                until,
            } => {
                let slug = group.strip_suffix("@cerebral.work").unwrap_or(&group);
                let path = repo.join("directory/groups").join(format!("{slug}.yaml"));
                if !path.exists() {
                    bail!("unknown group {group} (no {})", path.display());
                }
                let text = std::fs::read_to_string(&path)?;
                let updated = hold_text(&text, &email, &reason, until.as_deref())?;
                std::fs::write(&path, updated)?;
                let span = until.map(|u| format!(" (until {u})")).unwrap_or_default();
                println!("held {email} in {}: {reason}{span}", path.display());
            }
            ReconcileCommands::Unhold { repo, group, email } => {
                let slug = group.strip_suffix("@cerebral.work").unwrap_or(&group);
                let path = repo.join("directory/groups").join(format!("{slug}.yaml"));
                if !path.exists() {
                    bail!("unknown group {group} (no {})", path.display());
                }
                let text = std::fs::read_to_string(&path)?;
                let (updated, removed) = unhold_text(&text, &email)?;
                if !removed {
                    bail!("{email} has no hold entry in {}", path.display());
                }
                std::fs::write(&path, updated)?;
                println!("removed hold for {email} in {}", path.display());
            }
            ReconcileCommands::VerifyDigest { expected, actual } => {
                if let Some(msg) = apply_refusal(expected.as_deref(), &actual) {
                    eprintln!("{msg}");
                    std::process::exit(2);
                }
                println!("plan digest verified: {actual}");
            }
        },
        Commands::Lifecycle(args) => match args.command {
            LifecycleCommands::Onboard {
                repo,
                email,
                given_name,
                family_name,
                org_unit,
                groups,
                sku_id,
                no_license,
                github,
                github_orgs,
                no_create,
            } => {
                let group_list: Vec<String> = groups
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let gh_orgs = if let Some(ref csv) = github_orgs {
                    csv.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                } else if github.is_some() {
                    let state = load_desired_state(&repo)?;
                    state.github_orgs.keys().cloned().collect()
                } else {
                    Vec::new()
                };
                let req = OnboardRequest {
                    email,
                    given_name,
                    family_name,
                    org_unit,
                    groups: group_list,
                    sku_id: if no_license { None } else { Some(sku_id) },
                    github_handle: github,
                    github_orgs: gh_orgs,
                    create: !no_create,
                };
                let touched = stage_onboard(&repo, &req)?;
                println!("Staged onboarding changes in:");
                for p in touched {
                    println!("  {}", p.display());
                }
            }
            LifecycleCommands::Offboard {
                repo,
                email,
                finalize,
            } => {
                let touched = stage_offboard(&repo, &email, finalize)?;
                let mode = if finalize {
                    "finalize (T+30d)"
                } else {
                    "T0 immediate suspension"
                };
                println!("Staged offboarding ({mode}) for {email} in:");
                for p in touched {
                    println!("  {}", p.display());
                }
            }
        },
        Commands::Detectors(args) => match args.command {
            DetectorCommands::UndeclaredGroups { repo, live_json } => {
                let raw = std::fs::read_to_string(&live_json)?;
                let groups: BTreeMap<String, Vec<LiveGroupMember>> = serde_json::from_str(&raw)?;
                let declared = all_declared(&repo)?;
                let unmanaged = unmanaged_declared(&repo.join("directory/groups-unmanaged.yaml"))?;
                let (rc, lines, f) = undeclared_groups_report(&groups, &declared, &unmanaged);
                for line in lines {
                    println!("{line}");
                }
                f.write_to_env()?;
                std::process::exit(rc);
            }
            DetectorCommands::OidcBindings { rbac_json } => {
                let raw = std::fs::read_to_string(&rbac_json)?;
                let val: serde_json::Value = serde_json::from_str(&raw)?;
                let mut rbac = Rbac::default();
                if let Some(arr) = val.get("cluster_roles").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(n) = item
                            .get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|v| v.as_str())
                        {
                            rbac.cluster_roles.insert(n.to_string(), item.clone());
                        }
                    }
                }
                if let Some(arr) = val.get("roles").and_then(|v| v.as_array()) {
                    for item in arr {
                        let ns = item
                            .get("metadata")
                            .and_then(|m| m.get("namespace"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("default");
                        if let Some(n) = item
                            .get("metadata")
                            .and_then(|m| m.get("name"))
                            .and_then(|v| v.as_str())
                        {
                            rbac.roles
                                .insert((ns.to_string(), n.to_string()), item.clone());
                        }
                    }
                }
                if let Some(arr) = val.get("cluster_role_bindings").and_then(|v| v.as_array()) {
                    rbac.cluster_role_bindings = arr.clone();
                }
                if let Some(arr) = val.get("role_bindings").and_then(|v| v.as_array()) {
                    rbac.role_bindings = arr.clone();
                }
                let (rc, lines, f) = evaluate_oidc_bindings(&rbac);
                for line in lines {
                    println!("{line}");
                }
                f.write_to_env()?;
                std::process::exit(rc);
            }
            DetectorCommands::ReflexdAdmission {
                declared,
                policies_json,
                namespaces_json,
            } => {
                let decl = load_declared_admission(&declared)?;
                let pols: Vec<serde_json::Value> =
                    serde_json::from_str(&std::fs::read_to_string(&policies_json)?)?;
                let nss: Vec<serde_json::Value> =
                    serde_json::from_str(&std::fs::read_to_string(&namespaces_json)?)?;
                let (rc, lines, f) = evaluate_reflexd_admission(&decl, &pols, &nss);
                for line in lines {
                    println!("{line}");
                }
                f.write_to_env()?;
                std::process::exit(rc);
            }
            DetectorCommands::TenantAppprojects {
                appprojects_json,
                namespace,
                prefix,
            } => {
                let listing: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(&appprojects_json)?)?;
                match evaluate_tenant_appprojects(&listing, &namespace, &prefix) {
                    Ok((rc, lines, f)) => {
                        for line in lines {
                            println!("{line}");
                        }
                        f.write_to_env()?;
                        std::process::exit(rc);
                    }
                    Err(e) => {
                        eprintln!("ERROR: {e}");
                        std::process::exit(1);
                    }
                }
            }
            DetectorCommands::RoleMatrixExpected { repo } => {
                let cf = expected_cloudflare_emails(&repo)?;
                let ts = expected_tailscale_admins(&repo)?;
                let out = serde_json::json!({
                    "cloudflare_emails": cf,
                    "tailscale_admins": ts,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        },
    }

    Ok(())
}
