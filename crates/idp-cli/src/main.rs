// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Identity Provider CLI (`idp`) for unsigned-gg and Clockwork Conclave bots.

mod server;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use idp::manifest::AppManifest;
use idp::registry::{CONCLAVE_ELVES, KeyStore};
use idp::token::TokenBroker;
use server::{AppState, create_router};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[derive(Parser)]
#[command(name = "idp")]
#[command(about = "Identity Provider CLI and Conclave Bot Manager for unsigned-gg")]
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
    /// List all 16 canonical Clockwork Conclave bots and key statuses
    List,
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
            BotCommands::List => {
                println!(
                    "{:<4} | {:<10} | {:<12} | {:<10} | {:<30}",
                    "NUM", "BOT", "REPO", "STATUS", "KEY FILE"
                );
                println!(
                    "{:-<4}-+-{:-<10}-+-{:-<12}-+-{:-<10}-+-{:-<30}",
                    "", "", "", "", ""
                );

                for (idx, elf) in CONCLAVE_ELVES.iter().enumerate() {
                    let has_key = key_store.has_key(elf.id);
                    let status = if has_key { "MINTED" } else { "PENDING" };
                    let key_path = if has_key {
                        key_store.key_path(elf.id).display().to_string()
                    } else {
                        "-".to_string()
                    };

                    println!(
                        "{:<4} | {:<10} | {:<12} | {:<10} | {:<30}",
                        idx + 1,
                        elf.name,
                        elf.repo,
                        status,
                        key_path
                    );
                }
            }
        },
    }

    Ok(())
}
