// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Local HTTP server providing the Conclave App Manifest minting dashboard and callback handler.

use axum::{
    Router,
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use idp::manifest::AppManifest;
use idp::registry::{CONCLAVE_ELVES, KeyStore};
use reqwest::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;

/// Shared application state for the minting server.
pub struct AppState {
    /// Public base URL (e.g. Cloudflare tunnel or localhost).
    pub public_url: String,
    /// Backing key store for saving credentials.
    pub key_store: KeyStore,
}

/// Constructs the Axum router for the minting server.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/callback", get(callback_handler))
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
