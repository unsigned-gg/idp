// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Local HTTP server providing the Conclave App Manifest minting dashboard, JWKS discovery, and RFC 7591 DCR endpoints.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use idp::dcr::{OAuth2ClientMetadata, WimseAgentId};
use idp::hydra::{OryHydraClient, OryHydraConfig};
use idp::manifest::AppManifest;
use idp::principal::SubjectMatterMesh;
use idp::registry::{ALL_ESTATE_ELVES, CONCLAVE_ELVES, KeyStore};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Shared application state for the minting and DCR server.
pub struct AppState {
    /// Public base URL (e.g. Cloudflare tunnel or localhost).
    pub public_url: String,
    /// Backing key store for saving credentials.
    pub key_store: KeyStore,
    /// WIMSE/SPIFFE trust domain (default: `estate.cerebral.work`).
    pub trust_domain: String,
    /// Optional default Ory Hydra Public API base URL for `/dcr/register`.
    pub hydra_public_url: Option<String>,
}

/// Request payload for `POST /dcr/register`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DcrRegisterRequest {
    /// Conclave elf identifier (e.g. `sindri`, `idunn`, `brokkr`).
    pub bot: String,
    /// Optional Ory Hydra Public API base URL override.
    #[serde(default)]
    pub hydra_public_url: Option<String>,
    /// Optional RFC 7591 initial access token.
    #[serde(default)]
    pub initial_access_token: Option<String>,
    /// Optional OAuth2 scopes list (defaults to `["openid", "estate:agent:execute"]`).
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Optional audience URIs (defaults to `["https://api.cerebral.work"]`).
    #[serde(default)]
    pub audiences: Option<Vec<String>>,
}

/// Public JWK descriptor served at `/.well-known/jwks/{bot}.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicJwkDescriptor {
    /// Key type (`RSA`).
    pub kty: String,
    /// Public key use (`sig`).
    #[serde(rename = "use")]
    pub key_use: String,
    /// Signing algorithm (`RS256`).
    pub alg: String,
    /// Deterministic key identifier (`<bot>-<sha256_prefix>`).
    pub kid: String,
    /// Bot WIMSE SPIFFE URI bound to this key.
    pub x5u_spiffe_id: String,
}

/// RFC 7517 JWK Set document served at `/.well-known/jwks/{bot}.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicJwkSet {
    /// Active signing keys for the Conclave bot.
    pub keys: Vec<PublicJwkDescriptor>,
}

/// Constructs the Axum router for the minting and DCR server.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/callback", get(callback_handler))
        .route("/dcr/metadata/{bot}", get(dcr_metadata_handler))
        .route("/dcr/register", post(dcr_register_handler))
        .route("/.well-known/jwks/{bot}", get(jwks_handler))
        .with_state(state)
}

/// Handler for the root dashboard showing the 16 Conclave bots.
async fn index_handler(State(state): State<Arc<AppState>>) -> Html<String> {
    let callback_url = format!("{}/callback", state.public_url);

    let mut minted_count = 0;
    for elf in CONCLAVE_ELVES {
        if state.key_store.has_key(elf.id) {
            minted_count += 1;
        }
    }

    let progress_pct = (minted_count as f64 / CONCLAVE_ELVES.len() as f64) * 100.0;

    let mut cards_html = String::new();

    for elf in CONCLAVE_ELVES {
        let is_minted = state.key_store.has_key(elf.id);
        let manifest = AppManifest::for_conclave_bot(elf.id, &callback_url);
        let manifest_json = manifest.to_json().unwrap_or_default();

        if is_minted {
            let key_path = state.key_store.key_path(elf.id);
            cards_html.push_str(&format!(
                r#"
    <div class="card minted">
      <div>
        <div class="card-header">
          <span class="card-title">{}</span>
          <span class="badge badge-minted">✓ Minted</span>
        </div>
        <div class="role">{} / {}</div>
        <div class="desc">{}</div>
      </div>
      <div class="minted-box">
        <strong>Status:</strong> Active<br>
        <span style="font-size:11px; opacity:0.85;">Key: {}</span>
      </div>
    </div>
"#,
                elf.name,
                elf.repo,
                elf.role,
                elf.desc,
                key_path.display()
            ));
        } else {
            cards_html.push_str(&format!(
                r#"
    <div class="card">
      <div>
        <div class="card-header">
          <span class="card-title">{}</span>
          <span class="badge badge-pending">Ready</span>
        </div>
        <div class="role">{} / {}</div>
        <div class="desc">{}</div>
      </div>
      <form action="https://github.com/organizations/unsigned-gg/settings/apps/new" method="post" target="_blank">
        <input type="hidden" name="manifest" value='{}'>
        <button type="submit" class="mint-btn">
          <span>Mint {} [bot]</span>
          <span>→</span>
        </button>
      </form>
    </div>
"#,
                elf.name, elf.repo, elf.role, elf.desc, manifest_json, elf.name
            ));
        }
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Clockwork Conclave — GitHub App Minting</title>
  <style>
    :root {{
      --bg: #0d1117;
      --card-bg: #161b22;
      --card-border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --accent: #238636;
      --accent-hover: #2ea043;
      --minted: #388bfd;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      max-width: 980px;
      margin: 40px auto;
      padding: 0 24px;
      line-height: 1.5;
    }}
    header {{
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 20px;
      margin-bottom: 28px;
    }}
    h1 {{
      font-size: 26px;
      color: var(--text-bright);
      margin: 0 0 8px 0;
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .progress-bar {{
      background: var(--card-border);
      height: 8px;
      border-radius: 4px;
      overflow: hidden;
      margin-top: 14px;
    }}
    .progress-fill {{
      background: var(--accent);
      height: 100%;
      width: {:.1}%;
      transition: width 0.3s ease;
    }}
    .tunnel-pill {{
      display: inline-block;
      background: #21262d;
      border: 1px solid var(--card-border);
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 12px;
      font-family: ui-monospace, SFMono-Regular, monospace;
      color: #58a6ff;
      margin-top: 8px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 16px;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    .card.minted {{
      border-color: #1f6feb66;
    }}
    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      margin-bottom: 6px;
    }}
    .card-title {{
      font-size: 17px;
      font-weight: 600;
      color: var(--text-bright);
    }}
    .badge {{
      font-size: 11px;
      padding: 2px 7px;
      border-radius: 12px;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .badge-pending {{
      background: #30363d;
      color: #8b949e;
    }}
    .badge-minted {{
      background: #23863626;
      color: #3fb950;
      border: 1px solid #2386364d;
    }}
    .role {{
      font-size: 12px;
      font-family: ui-monospace, SFMono-Regular, monospace;
      color: #8b949e;
      margin-bottom: 8px;
    }}
    .desc {{
      font-size: 13px;
      color: var(--text);
      margin-bottom: 16px;
      flex-grow: 1;
    }}
    button.mint-btn {{
      width: 100%;
      background: var(--accent);
      color: #ffffff;
      border: none;
      padding: 10px 14px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 6px;
      transition: background 0.15s ease;
    }}
    button.mint-btn:hover {{
      background: var(--accent-hover);
    }}
    .minted-box {{
      background: #1f6feb14;
      border: 1px dashed #388bfd66;
      border-radius: 6px;
      padding: 9px;
      font-size: 12px;
      color: #58a6ff;
      font-family: ui-monospace, SFMono-Regular, monospace;
    }}
  </style>
</head>
<body>
  <header>
    <h1>Clockwork Conclave — GitHub App Minting</h1>
    <div>Autonomous Bot Identity Provisioning for Organization: <strong style="color:var(--text-bright);">unsigned-gg</strong></div>
    <div class="tunnel-pill">Ingress Endpoint: {}</div>
    <div class="progress-bar">
      <div class="progress-fill"></div>
    </div>
    <div style="font-size:12px; color:#8b949e; margin-top:6px; display:flex; justify-content:space-between;">
      <span>Minted Identities: {} / {}</span>
      <span>Target Org: unsigned-gg</span>
    </div>
  </header>

  <div class="grid">
    {}
  </div>
</body>
</html>
"#,
        progress_pct,
        state.public_url,
        minted_count,
        CONCLAVE_ELVES.len(),
        cards_html
    );

    Html(html)
}

/// Handler for the /callback route receiving conversion code from GitHub.
async fn callback_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let code = match params.get("code") {
        Some(c) if !c.is_empty() => c,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Html("<h1>400 Bad Request</h1><p>Missing conversion code parameter.</p>"),
            )
                .into_response();
        }
    };

    let client = reqwest::Client::new();
    let url = format!("https://api.github.com/app-manifests/{code}/conversions");

    let resp = match client
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "unsigned-idp/0.1.0")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Html(format!(
                    "<h1>502 Bad Gateway</h1><p>Failed to contact GitHub: {e}</p>"
                )),
            )
                .into_response();
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(format!(
                "<h1>500 Conversion Failed</h1><p>GitHub returned status {status}: {body}</p>"
            )),
        )
            .into_response();
    }

    let payload: idp::manifest::ConversionResponse = match resp.json().await {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(format!(
                    "<h1>500 Parse Error</h1><p>Failed to parse conversion payload: {e}</p>"
                )),
            )
                .into_response();
        }
    };

    // Save PEM private key
    if let Err(e) = state.key_store.write_key(&payload.name, &payload.pem) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(format!(
                "<h1>500 Key Storage Error</h1><p>Failed to write PEM key: {e}</p>"
            )),
        )
            .into_response();
    }

    // Save JSON metadata
    let json_text = serde_json::to_string_pretty(&payload).unwrap_or_default();
    let _ = state.key_store.write_metadata(&payload.name, &json_text);

    let key_path = state.key_store.key_path(&payload.name);

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Identity Minted — {}</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; max-width: 600px; margin: 80px auto; padding: 0 20px; text-align: center; }}
    .box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 32px; }}
    h1 {{ color: #3fb950; font-size: 24px; margin-top: 0; }}
    .detail {{ font-family: monospace; background: #0d1117; padding: 12px; border-radius: 6px; text-align: left; font-size: 13px; margin: 20px 0; color: #58a6ff; }}
    a.btn {{ display: inline-block; background: #238636; color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 600; margin-top: 10px; }}
    a.btn:hover {{ background: #2ea043; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>✓ {} Successfully Minted!</h1>
    <p>GitHub App registration complete. Private key and configuration securely saved to host storage.</p>
    <div class="detail">
      <strong>App Name:</strong> {}<br>
      <strong>App ID:</strong> {}<br>
      <strong>Client ID:</strong> {}<br>
      <strong>Private Key:</strong> {} (mode 0600)
    </div>
    <a href="/" class="btn">← Return to Conclave Dashboard</a>
  </div>
</body>
</html>
"#,
        payload.name,
        payload.name,
        payload.name,
        payload.id,
        payload.client_id,
        key_path.display()
    );

    Html(html).into_response()
}

/// Resolves the canonical [`SubjectMatterMesh`] for a Conclave elf persona slug.
pub fn mesh_for_bot(bot: &str) -> SubjectMatterMesh {
    match bot {
        "idunn" | "brokkr" | "vali" | "gullveig" | "heimdall" => SubjectMatterMesh::KernelRuntime,
        "mimir" | "loki" | "thjalfi" | "sigyn" | "thuban" | "njord" | "norns" | "sol" => {
            SubjectMatterMesh::MemorySearch
        }
        "vidar" | "tyr" | "bragi" => SubjectMatterMesh::IdentityGovernance,
        "alrisha" => SubjectMatterMesh::EcosystemCatalog,
        "sindri" | "volva" | "kratos" | "forseti" | "ratatoskr" => {
            SubjectMatterMesh::PlatformControl
        }
        _ => SubjectMatterMesh::KernelRuntime,
    }
}

/// Checks if `bot_id` is a registered Conclave or extended estate elf.
pub fn is_known_elf(bot_id: &str) -> bool {
    ALL_ESTATE_ELVES.iter().any(|e| e.id == bot_id)
}

/// Builds a validated [`OAuth2ClientMetadata`] for `bot_id` using the server's `AppState`.
pub fn build_bot_dcr_metadata(
    state: &AppState,
    bot_id: &str,
    scopes: Option<Vec<String>>,
    audiences: Option<Vec<String>>,
) -> Result<OAuth2ClientMetadata, String> {
    if !is_known_elf(bot_id) {
        return Err(format!("Unknown Conclave elf identity: '{bot_id}'"));
    }
    let mesh = mesh_for_bot(bot_id);
    let agent_id = WimseAgentId::for_conclave_elf(&state.trust_domain, bot_id, mesh)
        .map_err(|e| e.to_string())?;

    let scope_set: std::collections::BTreeSet<String> = scopes
        .unwrap_or_else(|| {
            vec![
                "openid".to_string(),
                "estate:agent:execute".to_string(),
            ]
        })
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect();

    let aud_vec: Vec<String> = audiences
        .unwrap_or_else(|| vec!["https://api.cerebral.work".to_string()])
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect();

    let jwks_uri = format!(
        "{}/.well-known/jwks/{bot_id}.json",
        state.public_url.trim_end_matches('/')
    );

    let meta = OAuth2ClientMetadata::for_agent(
        &agent_id,
        Some(bot_id),
        Some(mesh),
        &scope_set,
        aud_vec,
        Some(jwks_uri),
    );
    meta.validate_rfc7591(true).map_err(|e| e.to_string())?;
    Ok(meta)
}

/// Handler for `GET /dcr/metadata/{bot}` returning RFC 7591 + WIMSE client metadata JSON.
async fn dcr_metadata_handler(
    State(state): State<Arc<AppState>>,
    Path(bot): Path<String>,
) -> Response {
    let bot_id = bot.trim_end_matches(".json");
    match build_bot_dcr_metadata(&state, bot_id, None, None) {
        Ok(meta) => (StatusCode::OK, Json(meta)).into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_client_metadata", "error_description": msg })),
        )
            .into_response(),
    }
}

/// Handler for `GET /.well-known/jwks/{bot}` serving the bot's public JWK Set descriptor.
async fn jwks_handler(State(state): State<Arc<AppState>>, Path(bot): Path<String>) -> Response {
    let bot_id = bot.trim_end_matches(".json");
    if !is_known_elf(bot_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown_bot", "bot": bot_id })),
        )
            .into_response();
    }

    let pem = match state.key_store.read_key(bot_id) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "key_missing",
                    "error_description": format!("No minted key found in KeyStore for '{bot_id}'")
                })),
            )
                .into_response();
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(pem.as_bytes());
    let digest = hasher.finalize();
    let hex_prefix: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let kid = format!("{bot_id}-{hex_prefix}");

    let mesh = mesh_for_bot(bot_id);
    let spiffe_uri = match WimseAgentId::for_conclave_elf(&state.trust_domain, bot_id, mesh) {
        Ok(id) => id.to_uri(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "invalid_spiffe_id", "error_description": e.to_string() })),
            )
                .into_response();
        }
    };

    let jwks = PublicJwkSet {
        keys: vec![PublicJwkDescriptor {
            kty: "RSA".to_string(),
            key_use: "sig".to_string(),
            alg: "RS256".to_string(),
            kid,
            x5u_spiffe_id: spiffe_uri,
        }],
    };
    (StatusCode::OK, Json(jwks)).into_response()
}

/// Handler for `POST /dcr/register` registering a Conclave Elf with Ory Hydra via RFC 7591.
async fn dcr_register_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DcrRegisterRequest>,
) -> Response {
    let hydra_url = match req
        .hydra_public_url
        .clone()
        .or_else(|| state.hydra_public_url.clone())
    {
        Some(u) if !u.trim().is_empty() => u,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "missing_hydra_url",
                    "error_description": "hydra_public_url must be provided in request or server --hydra-url"
                })),
            )
                .into_response();
        }
    };

    let meta = match build_bot_dcr_metadata(&state, &req.bot, req.scopes, req.audiences) {
        Ok(m) => m,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_client_metadata",
                    "error_description": msg
                })),
            )
                .into_response();
        }
    };

    let cfg = OryHydraConfig {
        public_url: hydra_url.clone(),
        admin_url: hydra_url,
        initial_access_token: req.initial_access_token,
        admin_bearer_token: None,
        require_cryptographic_agent_auth: true,
    };
    let client = OryHydraClient::with_config(cfg);
    let registered = match client.register_client_rfc7591(&meta).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "hydra_registration_failed",
                    "error_description": e.to_string()
                })),
            )
                .into_response();
        }
    };

    let redacted = registered.redacted();
    if let Ok(json_text) = serde_json::to_string_pretty(&redacted) {
        let _ = state
            .key_store
            .write_metadata(&format!("{}-dcr", req.bot), &json_text);
    }

    (StatusCode::CREATED, Json(redacted)).into_response()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn spawn_test_server(state: Arc<AppState>) -> String {
        let app = create_router(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn test_dcr_metadata_and_jwks_positive_and_negative_controls() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = KeyStore::new(temp.path());
        store.ensure_dir().expect("ensure_dir");

        let state = Arc::new(AppState {
            public_url: "https://idp.cerebral.work".to_string(),
            key_store: store,
            trust_domain: "estate.cerebral.work".to_string(),
            hydra_public_url: None,
        });

        let base_url = spawn_test_server(state.clone()).await;
        let http = reqwest::Client::new();

        // 1. Positive control: GET /dcr/metadata/sindri returns valid RFC 7591 + WIMSE metadata
        let meta_resp = http
            .get(format!("{base_url}/dcr/metadata/sindri"))
            .send()
            .await
            .expect("send metadata req");
        assert_eq!(meta_resp.status(), StatusCode::OK);
        let meta: OAuth2ClientMetadata = meta_resp.json().await.expect("parse metadata");
        assert_eq!(
            meta.software_id.as_deref(),
            Some("spiffe://estate.cerebral.work/elf/platform-control/sindri")
        );
        assert_eq!(
            meta.jwks_uri.as_deref(),
            Some("https://idp.cerebral.work/.well-known/jwks/sindri.json")
        );

        // 2. Negative control: unknown bot returns 400 Bad Request
        let bad_meta = http
            .get(format!("{base_url}/dcr/metadata/nonexistent-bot"))
            .send()
            .await
            .expect("send bad metadata req");
        assert_eq!(bad_meta.status(), StatusCode::BAD_REQUEST);

        // 3. Negative control: /.well-known/jwks/sindri.json returns 404 before key is minted
        let missing_jwks = http
            .get(format!("{base_url}/.well-known/jwks/sindri.json"))
            .send()
            .await
            .expect("send missing jwks");
        assert_eq!(missing_jwks.status(), StatusCode::NOT_FOUND);

        // 4. Positive control: write PEM key and verify /.well-known/jwks/sindri.json returns 200 OK
        state
            .key_store
            .write_key("sindri", "-----BEGIN RSA PRIVATE KEY-----\nTEST_SINDRI_KEY\n-----END RSA PRIVATE KEY-----\n")
            .expect("write sindri key");

        let ok_jwks = http
            .get(format!("{base_url}/.well-known/jwks/sindri.json"))
            .send()
            .await
            .expect("send ok jwks");
        assert_eq!(ok_jwks.status(), StatusCode::OK);
        let jwk_set: PublicJwkSet = ok_jwks.json().await.expect("parse jwks");
        assert_eq!(jwk_set.keys.len(), 1);
        assert_eq!(jwk_set.keys[0].kty, "RSA");
        assert_eq!(jwk_set.keys[0].alg, "RS256");
        assert!(jwk_set.keys[0].kid.starts_with("sindri-"));
        assert_eq!(
            jwk_set.keys[0].x5u_spiffe_id,
            "spiffe://estate.cerebral.work/elf/platform-control/sindri"
        );
    }

    #[tokio::test]
    async fn test_dcr_register_round_trip_and_keystore_receipt() {
        // Spawn a mock Ory Hydra /oauth2/register endpoint
        let hydra_router = Router::new().route(
            "/oauth2/register",
            post(|Json(meta): Json<OAuth2ClientMetadata>| async move {
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({
                        "client_id": "hydra-elf-sindri-001",
                        "client_secret": "super-secret-do-not-persist",
                        "registration_access_token": "rat-secret-token",
                        "client_name": meta.client_name,
                        "token_endpoint_auth_method": meta.token_endpoint_auth_method,
                        "grant_types": meta.grant_types,
                        "response_types": meta.response_types,
                        "scope": meta.scope,
                        "audience": meta.audience,
                        "jwks_uri": meta.jwks_uri,
                        "software_id": meta.software_id,
                        "metadata": meta.metadata
                    })),
                )
            }),
        );
        let hydra_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock hydra");
        let hydra_addr = hydra_listener.local_addr().expect("hydra addr");
        tokio::spawn(async move {
            let _ = axum::serve(hydra_listener, hydra_router).await;
        });

        let temp = tempfile::tempdir().expect("tempdir");
        let store = KeyStore::new(temp.path());
        store.ensure_dir().expect("ensure_dir");

        let state = Arc::new(AppState {
            public_url: "https://idp.cerebral.work".to_string(),
            key_store: store,
            trust_domain: "estate.cerebral.work".to_string(),
            hydra_public_url: Some(format!("http://{hydra_addr}")),
        });

        let base_url = spawn_test_server(state.clone()).await;
        let http = reqwest::Client::new();

        let resp = http
            .post(format!("{base_url}/dcr/register"))
            .json(&DcrRegisterRequest {
                bot: "sindri".to_string(),
                hydra_public_url: None,
                initial_access_token: None,
                scopes: None,
                audiences: None,
            })
            .send()
            .await
            .expect("post /dcr/register");

        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: serde_json::Value = resp.json().await.expect("parse response");
        assert_eq!(body["client_id"], "hydra-elf-sindri-001");
        assert_eq!(body["client_secret"], "<redacted>");
        assert_eq!(body["registration_access_token"], "<redacted>");

        // Verify by a second path: read the persisted receipt from disk and confirm secrets are redacted
        let receipt_path = temp.path().join("sindri-dcr.json");
        assert!(receipt_path.exists(), "sindri-dcr.json must be written to KeyStore");
        let persisted_raw = std::fs::read_to_string(&receipt_path).expect("read receipt");
        assert!(!persisted_raw.contains("super-secret-do-not-persist"));
        assert!(!persisted_raw.contains("rat-secret-token"));
        assert!(persisted_raw.contains("hydra-elf-sindri-001"));
    }
}

