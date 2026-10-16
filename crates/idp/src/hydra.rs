// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Ory Hydra Dynamic Client Registration (RFC 7591 / RFC 7592), Admin OAuth2 Client API,
//! OAuth 2.0 Token Exchange (RFC 8693), and Token Introspection (RFC 7662) adapter.
//!
//! Aligned with Reverie `#36703` (`architecture/agent-identity/dynamic-client-registration`),
//! `ory-hydra-client` v26.2.0 wire schemas, and IETF `draft-klrc-aiagent-auth-03`.

use crate::error::IdpError;
use idp_domain::dcr::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, IntrospectedOAuth2Token, OAuth2ClientMetadata,
    OAuth2TokenResponse, OidcDiscoveryDocument, TokenExchangeRequest, encode_form_urlencoded,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration for connecting to Ory Hydra Public (`:4444`) and Admin (`:4445`) endpoints.
#[derive(Clone, PartialEq, Eq)]
pub struct OryHydraConfig {
    /// Base URL for Ory Hydra's public endpoints (`/.well-known/*`, `/oauth2/register`, `/oauth2/token`).
    pub public_url: String,
    /// Base URL for Ory Hydra's administrative endpoints (`/admin/clients`, `/admin/oauth2/introspect`).
    pub admin_url: String,
    /// Optional RFC 7591 Initial Access Token presented as `Authorization: Bearer` to `POST /oauth2/register`.
    pub initial_access_token: Option<String>,
    /// Optional administrative bearer token presented to `/admin/*` endpoints.
    pub admin_bearer_token: Option<String>,
    /// When `true`, enforces `draft-klrc-aiagent-auth-03` §10.4.2 cryptographic client auth
    /// (`private_key_jwt` or mTLS) for all clients carrying `AgentClientMetadata`.
    pub require_cryptographic_agent_auth: bool,
}

impl Default for OryHydraConfig {
    fn default() -> Self {
        Self {
            public_url: "http://127.0.0.1:4444".to_string(),
            admin_url: "http://127.0.0.1:4445".to_string(),
            initial_access_token: None,
            admin_bearer_token: None,
            require_cryptographic_agent_auth: false,
        }
    }
}

impl fmt::Debug for OryHydraConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OryHydraConfig")
            .field("public_url", &self.public_url)
            .field("admin_url", &self.admin_url)
            .field(
                "initial_access_token",
                &self.initial_access_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "admin_bearer_token",
                &self.admin_bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "require_cryptographic_agent_auth",
                &self.require_cryptographic_agent_auth,
            )
            .finish()
    }
}

/// Client authentication credentials presented to Ory Hydra's `/oauth2/token` endpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth<'a> {
    /// HTTP Basic authentication (`Authorization: Basic base64(client_id:client_secret)`).
    ClientSecretBasic {
        /// Registered OAuth 2.0 `client_id`.
        client_id: &'a str,
        /// Registered OAuth 2.0 `client_secret` (redacted in `Debug`).
        client_secret: &'a str,
    },
    /// Form body authentication (`client_id` and `client_secret` in POST form fields).
    ClientSecretPost {
        /// Registered OAuth 2.0 `client_id`.
        client_id: &'a str,
        /// Registered OAuth 2.0 `client_secret` (redacted in `Debug`).
        client_secret: &'a str,
    },
    /// RFC 7523 `private_key_jwt` authentication (`client_assertion_type` + signed JWT `client_assertion`).
    PrivateKeyJwt {
        /// Registered OAuth 2.0 `client_id`.
        client_id: &'a str,
        /// Signed RS256 JWT assertion proving key possession (redacted in `Debug`).
        client_assertion: &'a str,
    },
}

impl fmt::Debug for ClientAuth<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientSecretBasic { client_id, .. } => f
                .debug_struct("ClientSecretBasic")
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .finish(),
            Self::ClientSecretPost { client_id, .. } => f
                .debug_struct("ClientSecretPost")
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .finish(),
            Self::PrivateKeyJwt { client_id, .. } => f
                .debug_struct("PrivateKeyJwt")
                .field("client_id", client_id)
                .field("client_assertion", &"<redacted>")
                .finish(),
        }
    }
}

/// JWT claims for RFC 7523 Section 3 `private_key_jwt` client authentication assertions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKeyJwtClaims {
    /// Issuer (`client_id` of the OAuth client).
    pub iss: String,
    /// Subject (`client_id` of the OAuth client).
    pub sub: String,
    /// Audience (URL of the authorization server's token endpoint).
    pub aud: String,
    /// Unique token identifier (`jti`) preventing assertion replay.
    pub jti: String,
    /// Issued-at timestamp (seconds since Unix epoch).
    pub iat: u64,
    /// Expiration timestamp (seconds since Unix epoch, bounded to `<= iat + 600` per `Inv-IDP-02`).
    pub exp: u64,
}

/// Async client adapter for Ory Hydra Dynamic Client Registration (RFC 7591 / RFC 7592),
/// Admin OAuth2 Client management, OAuth 2.0 Token Exchange (RFC 8693), and Token Introspection (RFC 7662).
pub struct OryHydraClient {
    config: OryHydraConfig,
    http: reqwest::Client,
}

impl Default for OryHydraClient {
    fn default() -> Self {
        Self::with_config(OryHydraConfig::default())
    }
}

impl OryHydraClient {
    /// Creates a new Ory Hydra adapter with the given endpoint and authentication configuration.
    pub fn with_config(config: OryHydraConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { config, http }
    }

    /// Returns a reference to the adapter configuration.
    pub const fn config(&self) -> &OryHydraConfig {
        &self.config
    }

    /// Mints a short-lived RS256 `private_key_jwt` assertion (RFC 7523 §2.2) for authenticating
    /// an AI Agent at Ory Hydra's token endpoint (`{public_url}/oauth2/token`).
    ///
    /// Enforces `Inv-IDP-02`: 60s backward drift allowance and 540s forward lifetime (`exp - iat == 600`).
    pub fn mint_private_key_jwt(&self, client_id: &str, pem_key: &str) -> Result<String, IdpError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let iat = now.saturating_sub(60);
        let exp = now.saturating_add(540);
        let token_endpoint = format!(
            "{}/oauth2/token",
            self.config.public_url.trim_end_matches('/')
        );

        let mut hasher = Sha256::new();
        hasher.update(client_id.as_bytes());
        hasher.update(b":");
        hasher.update(now.to_le_bytes());
        let digest = hasher.finalize();
        let jti = format!(
            "jti-{client_id}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
        );

        let claims = PrivateKeyJwtClaims {
            iss: client_id.to_string(),
            sub: client_id.to_string(),
            aud: token_endpoint,
            jti,
            iat,
            exp,
        };

        let key = EncodingKey::from_rsa_pem(pem_key.as_bytes())?;
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &key)?;
        Ok(token)
    }

    /// Fetches the OpenID Connect Discovery 1.0 / RFC 8414 metadata document from
    /// `GET {public_url}/.well-known/openid-configuration`.
    pub async fn discover(&self) -> Result<OidcDiscoveryDocument, IdpError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.public_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Registers a new OAuth 2.0 client via Ory Hydra's public RFC 7591 endpoint
    /// (`POST {public_url}/oauth2/register`).
    ///
    /// Validates RFC 7591 and `draft-klrc-aiagent-auth-03` invariants before transmitting.
    pub async fn register_client_rfc7591(
        &self,
        metadata: &OAuth2ClientMetadata,
    ) -> Result<OAuth2ClientMetadata, IdpError> {
        metadata.validate_rfc7591(self.config.require_cryptographic_agent_auth)?;

        let url = format!(
            "{}/oauth2/register",
            self.config.public_url.trim_end_matches('/')
        );
        let mut req = self
            .http
            .post(&url)
            .header("Accept", "application/json")
            .json(metadata);

        if let Some(ref iat) = self.config.initial_access_token {
            req = req.header("Authorization", format!("Bearer {iat}"));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Reads a registered client configuration via RFC 7592 (`GET {public_url}/oauth2/register/{client_id}`).
    pub async fn get_registered_client_rfc7592(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<OAuth2ClientMetadata, IdpError> {
        let url = format!(
            "{}/oauth2/register/{client_id}",
            self.config.public_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {registration_access_token}"),
            )
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Updates a registered client configuration via RFC 7592 (`PUT {public_url}/oauth2/register/{client_id}`).
    pub async fn update_registered_client_rfc7592(
        &self,
        client_id: &str,
        registration_access_token: &str,
        metadata: &OAuth2ClientMetadata,
    ) -> Result<OAuth2ClientMetadata, IdpError> {
        metadata.validate_rfc7591(self.config.require_cryptographic_agent_auth)?;

        let url = format!(
            "{}/oauth2/register/{client_id}",
            self.config.public_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .put(&url)
            .header(
                "Authorization",
                format!("Bearer {registration_access_token}"),
            )
            .header("Accept", "application/json")
            .json(metadata)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Deletes a registered client via RFC 7592 (`DELETE {public_url}/oauth2/register/{client_id}`).
    pub async fn delete_registered_client_rfc7592(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<(), IdpError> {
        let url = format!(
            "{}/oauth2/register/{client_id}",
            self.config.public_url.trim_end_matches('/')
        );
        let resp = self
            .http
            .delete(&url)
            .header(
                "Authorization",
                format!("Bearer {registration_access_token}"),
            )
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(())
    }

    /// Creates an OAuth 2.0 client via Ory Hydra's Admin API (`POST {admin_url}/admin/clients`).
    pub async fn admin_create_client(
        &self,
        metadata: &OAuth2ClientMetadata,
    ) -> Result<OAuth2ClientMetadata, IdpError> {
        metadata.validate_rfc7591(self.config.require_cryptographic_agent_auth)?;

        let url = format!(
            "{}/admin/clients",
            self.config.admin_url.trim_end_matches('/')
        );
        let mut req = self
            .http
            .post(&url)
            .header("Accept", "application/json")
            .json(metadata);
        if let Some(ref bearer) = self.config.admin_bearer_token {
            req = req.header("Authorization", format!("Bearer {bearer}"));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Retrieves an OAuth 2.0 client via Ory Hydra's Admin API (`GET {admin_url}/admin/clients/{client_id}`).
    pub async fn admin_get_client(
        &self,
        client_id: &str,
    ) -> Result<OAuth2ClientMetadata, IdpError> {
        let url = format!(
            "{}/admin/clients/{client_id}",
            self.config.admin_url.trim_end_matches('/')
        );
        let mut req = self.http.get(&url).header("Accept", "application/json");
        if let Some(ref bearer) = self.config.admin_bearer_token {
            req = req.header("Authorization", format!("Bearer {bearer}"));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Lists OAuth 2.0 clients via Ory Hydra's Admin API (`GET {admin_url}/admin/clients`).
    pub async fn admin_list_clients(&self) -> Result<Vec<OAuth2ClientMetadata>, IdpError> {
        let url = format!(
            "{}/admin/clients",
            self.config.admin_url.trim_end_matches('/')
        );
        let mut req = self.http.get(&url).header("Accept", "application/json");
        if let Some(ref bearer) = self.config.admin_bearer_token {
            req = req.header("Authorization", format!("Bearer {bearer}"));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Updates an OAuth 2.0 client via Ory Hydra's Admin API (`PUT {admin_url}/admin/clients/{client_id}`).
    pub async fn admin_update_client(
        &self,
        client_id: &str,
        metadata: &OAuth2ClientMetadata,
    ) -> Result<OAuth2ClientMetadata, IdpError> {
        metadata.validate_rfc7591(self.config.require_cryptographic_agent_auth)?;

        let url = format!(
            "{}/admin/clients/{client_id}",
            self.config.admin_url.trim_end_matches('/')
        );
        let mut req = self
            .http
            .put(&url)
            .header("Accept", "application/json")
            .json(metadata);
        if let Some(ref bearer) = self.config.admin_bearer_token {
            req = req.header("Authorization", format!("Bearer {bearer}"));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(resp.json().await?)
    }

    /// Deletes an OAuth 2.0 client via Ory Hydra's Admin API (`DELETE {admin_url}/admin/clients/{client_id}`).
    pub async fn admin_delete_client(&self, client_id: &str) -> Result<(), IdpError> {
        let url = format!(
            "{}/admin/clients/{client_id}",
            self.config.admin_url.trim_end_matches('/')
        );
        let mut req = self.http.delete(&url);
        if let Some(ref bearer) = self.config.admin_bearer_token {
            req = req.header("Authorization", format!("Bearer {bearer}"));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi { status, body });
        }
        Ok(())
    }

    /// Introspects an OAuth 2.0 token via Ory Hydra's Admin API (`POST {admin_url}/admin/oauth2/introspect`, RFC 7662).
    pub async fn introspect_token(
        &self,
        token: &str,
        scope: Option<&str>,
    ) -> Result<IntrospectedOAuth2Token, IdpError> {
        let url = format!(
            "{}/admin/oauth2/introspect",
            self.config.admin_url.trim_end_matches('/')
        );
        let mut pairs = vec![("token", token)];
        if let Some(s) = scope {
            pairs.push(("scope", s));
        }
        let body = encode_form_urlencoded(&pairs);

        let mut req = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body);
        if let Some(ref bearer) = self.config.admin_bearer_token {
            req = req.header("Authorization", format!("Bearer {bearer}"));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi {
                status,
                body: err_body,
            });
        }
        Ok(resp.json().await?)
    }

    /// Acquires an OAuth 2.0 access token via the `client_credentials` grant (`POST {public_url}/oauth2/token`).
    pub async fn exchange_client_credentials(
        &self,
        auth: ClientAuth<'_>,
        scopes: &[&str],
        audience: &[&str],
    ) -> Result<OAuth2TokenResponse, IdpError> {
        let mut pairs: Vec<(String, String)> =
            vec![("grant_type".to_string(), "client_credentials".to_string())];
        if !scopes.is_empty() {
            pairs.push(("scope".to_string(), scopes.join(" ")));
        }
        for aud in audience {
            pairs.push(("audience".to_string(), (*aud).to_string()));
        }
        self.post_token_form(auth, pairs).await
    }

    /// Exchanges a subject token (and optional actor token) for a downscoped access or transaction token
    /// via RFC 8693 OAuth 2.0 Token Exchange (`POST {public_url}/oauth2/token`).
    pub async fn exchange_token_rfc8693(
        &self,
        auth: ClientAuth<'_>,
        req: &TokenExchangeRequest,
    ) -> Result<OAuth2TokenResponse, IdpError> {
        req.validate()?;
        let pairs = req.to_form_pairs();
        self.post_token_form(auth, pairs).await
    }

    async fn post_token_form(
        &self,
        auth: ClientAuth<'_>,
        mut pairs: Vec<(String, String)>,
    ) -> Result<OAuth2TokenResponse, IdpError> {
        let url = format!(
            "{}/oauth2/token",
            self.config.public_url.trim_end_matches('/')
        );
        let mut req = self
            .http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json");

        match auth {
            ClientAuth::ClientSecretBasic {
                client_id,
                client_secret,
            } => {
                req = req.basic_auth(client_id, Some(client_secret));
            }
            ClientAuth::ClientSecretPost {
                client_id,
                client_secret,
            } => {
                pairs.push(("client_id".to_string(), client_id.to_string()));
                pairs.push(("client_secret".to_string(), client_secret.to_string()));
            }
            ClientAuth::PrivateKeyJwt {
                client_id,
                client_assertion,
            } => {
                pairs.push(("client_id".to_string(), client_id.to_string()));
                pairs.push((
                    "client_assertion_type".to_string(),
                    CLIENT_ASSERTION_TYPE_JWT_BEARER.to_string(),
                ));
                pairs.push(("client_assertion".to_string(), client_assertion.to_string()));
            }
        }

        let body = encode_form_urlencoded(&pairs);
        let resp = req.body(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(IdpError::HydraApi {
                status,
                body: err_body,
            });
        }
        Ok(resp.json().await?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use idp_domain::dcr::{
        ActorClaim, Rfc7591ErrorCode, Rfc7591ErrorResponse, TOKEN_TYPE_ACCESS_TOKEN,
        TOKEN_TYPE_JWT, TOKEN_TYPE_TRANSACTION_TOKEN, WimseAgentId, decode_form_urlencoded,
    };
    use idp_domain::principal::{Principal, SubjectMatterMesh};
    use idp_domain::security::constant_time_eq;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct MockHydraState {
        clients: BTreeMap<String, OAuth2ClientMetadata>,
        tokens: BTreeMap<String, IntrospectedOAuth2Token>,
        next_id: u64,
    }

    async fn spawn_mock_hydra_server() -> (String, Arc<Mutex<MockHydraState>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        let state = Arc::new(Mutex::new(MockHydraState::default()));
        let state_clone = Arc::clone(&state);
        let base_url_clone = base_url.clone();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let st = Arc::clone(&state_clone);
                let url = base_url_clone.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    let mut total = 0usize;
                    let header_end = loop {
                        let n = stream.read(&mut buf[total..]).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        total += n;
                        if let Some(pos) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    };
                    let header_str = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                    let mut lines = header_str.lines();
                    let req_line = lines.next().unwrap_or("");
                    let parts: Vec<&str> = req_line.split_whitespace().collect();
                    if parts.len() < 2 {
                        return;
                    }
                    let method = parts[0];
                    let path = parts[1];

                    let mut content_len = 0usize;
                    let mut auth_header = None;
                    for line in lines {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                content_len = v.trim().parse().unwrap_or(0);
                            } else if k.eq_ignore_ascii_case("authorization") {
                                auth_header = Some(v.trim().to_string());
                            }
                        }
                    }

                    while total < header_end + content_len {
                        let n = stream.read(&mut buf[total..]).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        total += n;
                    }
                    let body = String::from_utf8_lossy(&buf[header_end..header_end + content_len])
                        .into_owned();

                    let (status, resp_body) =
                        handle_mock_hydra(method, path, auth_header.as_deref(), &body, &url, &st)
                            .await;
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                        resp_body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        (base_url, state)
    }

    async fn handle_mock_hydra(
        method: &str,
        path: &str,
        auth_header: Option<&str>,
        body: &str,
        base_url: &str,
        state: &Arc<Mutex<MockHydraState>>,
    ) -> (&'static str, String) {
        if method == "GET" && path == "/.well-known/openid-configuration" {
            let doc = OidcDiscoveryDocument {
                issuer: base_url.to_string(),
                authorization_endpoint: format!("{base_url}/oauth2/auth"),
                token_endpoint: format!("{base_url}/oauth2/token"),
                jwks_uri: format!("{base_url}/.well-known/jwks.json"),
                registration_endpoint: Some(format!("{base_url}/oauth2/register")),
                introspection_endpoint: Some(format!("{base_url}/admin/oauth2/introspect")),
                revocation_endpoint: Some(format!("{base_url}/oauth2/revoke")),
                grant_types_supported: vec![
                    "client_credentials".to_string(),
                    "authorization_code".to_string(),
                    "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                ],
                response_types_supported: vec!["code".to_string(), "token".to_string()],
                token_endpoint_auth_methods_supported: vec![
                    "client_secret_basic".to_string(),
                    "client_secret_post".to_string(),
                    "private_key_jwt".to_string(),
                ],
            };
            return ("200 OK", serde_json::to_string(&doc).unwrap());
        }

        if method == "POST" && (path == "/oauth2/register" || path == "/admin/clients") {
            let Ok(mut client): Result<OAuth2ClientMetadata, _> = serde_json::from_str(body) else {
                let err = Rfc7591ErrorResponse {
                    error: Rfc7591ErrorCode::InvalidClientMetadata.as_str().to_string(),
                    error_description: Some("Malformed JSON payload".to_string()),
                };
                return ("400 Bad Request", serde_json::to_string(&err).unwrap());
            };
            if let Err(e) = client.validate_rfc7591(false) {
                let err = Rfc7591ErrorResponse::from(e);
                return ("400 Bad Request", serde_json::to_string(&err).unwrap());
            }

            let mut guard = state.lock().await;
            guard.next_id += 1;
            let cid = client
                .client_id
                .clone()
                .unwrap_or_else(|| format!("hydra-client-{}", guard.next_id));
            let reg_token = format!("ory_reg_tok_{}", guard.next_id);
            client.client_id = Some(cid.clone());
            client.client_secret = Some(format!("ory_cs_{}", guard.next_id));
            client.client_id_issued_at = Some(1_800_000_000);
            client.client_secret_expires_at = Some(0);
            client.registration_access_token = Some(reg_token);
            client.registration_client_uri = Some(format!("{base_url}/oauth2/register/{cid}"));
            guard.clients.insert(cid, client.clone());
            return ("201 Created", serde_json::to_string(&client).unwrap());
        }

        if let Some(cid) = path.strip_prefix("/oauth2/register/") {
            let mut guard = state.lock().await;
            let Some(existing) = guard.clients.get(cid).cloned() else {
                return ("404 Not Found", r#"{"error":"not_found"}"#.to_string());
            };
            let expected_bearer = format!(
                "Bearer {}",
                existing
                    .registration_access_token
                    .as_deref()
                    .unwrap_or_default()
            );
            if !auth_header.is_some_and(|h| constant_time_eq(h, &expected_bearer)) {
                let err = Rfc7591ErrorResponse {
                    error: Rfc7591ErrorCode::InvalidClient.as_str().to_string(),
                    error_description: Some("Invalid registration_access_token".to_string()),
                };
                return ("401 Unauthorized", serde_json::to_string(&err).unwrap());
            }
            match method {
                "GET" => return ("200 OK", serde_json::to_string(&existing).unwrap()),
                "PUT" => {
                    let mut updated: OAuth2ClientMetadata = serde_json::from_str(body).unwrap();
                    updated.client_id = Some(cid.to_string());
                    updated.registration_access_token = existing.registration_access_token;
                    updated.registration_client_uri = existing.registration_client_uri;
                    guard.clients.insert(cid.to_string(), updated.clone());
                    return ("200 OK", serde_json::to_string(&updated).unwrap());
                }
                "DELETE" => {
                    guard.clients.remove(cid);
                    return ("204 No Content", String::new());
                }
                _ => {}
            }
        }

        if method == "GET" && path == "/admin/clients" {
            let guard = state.lock().await;
            let list: Vec<OAuth2ClientMetadata> = guard.clients.values().cloned().collect();
            return ("200 OK", serde_json::to_string(&list).unwrap());
        }

        if let Some(cid) = path.strip_prefix("/admin/clients/") {
            let mut guard = state.lock().await;
            match method {
                "GET" => {
                    if let Some(c) = guard.clients.get(cid) {
                        return ("200 OK", serde_json::to_string(c).unwrap());
                    }
                    return ("404 Not Found", r#"{"error":"not_found"}"#.to_string());
                }
                "PUT" => {
                    let mut updated: OAuth2ClientMetadata = serde_json::from_str(body).unwrap();
                    updated.client_id = Some(cid.to_string());
                    guard.clients.insert(cid.to_string(), updated.clone());
                    return ("200 OK", serde_json::to_string(&updated).unwrap());
                }
                "DELETE" => {
                    guard.clients.remove(cid);
                    return ("204 No Content", String::new());
                }
                _ => {}
            }
        }

        if method == "POST" && path == "/oauth2/token" {
            let form: BTreeMap<String, String> = decode_form_urlencoded(body).into_iter().collect();
            let grant_type = form.get("grant_type").map(String::as_str).unwrap_or("");
            let client_id = form
                .get("client_id")
                .cloned()
                .unwrap_or_else(|| "hydra-client-1".to_string());
            let scope = form
                .get("scope")
                .cloned()
                .unwrap_or_else(|| "idp:read".to_string());

            let mut guard = state.lock().await;
            guard.next_id += 1;
            let access_token = format!("ory_at_minted_{}", guard.next_id);

            let (sub, act, issued_type) =
                if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange" {
                    let req_type = form
                        .get("requested_token_type")
                        .cloned()
                        .unwrap_or_else(|| TOKEN_TYPE_ACCESS_TOKEN.to_string());
                    let actor = form.get("actor_token").map(|_| ActorClaim {
                        sub: format!("spiffe://cerebral.work/elf/platform-control/{client_id}"),
                        client_id: Some(client_id.clone()),
                        iss: Some(base_url.to_string()),
                        act: None,
                    });
                    ("ctodie@cerebral.work".to_string(), actor, Some(req_type))
                } else {
                    (
                        format!("spiffe://cerebral.work/elf/platform-control/{client_id}"),
                        None,
                        None,
                    )
                };

            guard.tokens.insert(
                access_token.clone(),
                IntrospectedOAuth2Token {
                    active: true,
                    client_id: Some(client_id),
                    sub: Some(sub),
                    scope: Some(scope.clone()),
                    aud: vec!["https://api.cerebral.work".to_string()],
                    iss: Some(base_url.to_string()),
                    exp: Some(1_900_000_000),
                    iat: Some(1_800_000_000),
                    nbf: Some(1_800_000_000),
                    token_type: Some("Bearer".to_string()),
                    token_use: Some("access_token".to_string()),
                    act,
                    ext: BTreeMap::new(),
                },
            );

            let resp = OAuth2TokenResponse {
                access_token,
                token_type: "bearer".to_string(),
                expires_in: Some(600),
                refresh_token: None,
                scope: Some(scope),
                issued_token_type: issued_type,
            };
            return ("200 OK", serde_json::to_string(&resp).unwrap());
        }

        if method == "POST" && path == "/admin/oauth2/introspect" {
            let form: BTreeMap<String, String> = decode_form_urlencoded(body).into_iter().collect();
            let tok = form.get("token").map(String::as_str).unwrap_or("");
            let guard = state.lock().await;
            let result = guard
                .tokens
                .get(tok)
                .cloned()
                .unwrap_or(IntrospectedOAuth2Token {
                    active: false,
                    ..Default::default()
                });
            return ("200 OK", serde_json::to_string(&result).unwrap());
        }

        ("404 Not Found", r#"{"error":"not_found"}"#.to_string())
    }

    #[tokio::test]
    async fn test_ory_hydra_rfc7591_rfc7592_token_exchange_and_introspection_end_to_end() {
        let (base_url, _state) = spawn_mock_hydra_server().await;
        let client = OryHydraClient::with_config(OryHydraConfig {
            public_url: base_url.clone(),
            admin_url: base_url.clone(),
            initial_access_token: Some("initial-reg-token".to_string()),
            admin_bearer_token: Some("admin-token".to_string()),
            require_cryptographic_agent_auth: true,
        });

        // 1. OIDC Discovery
        let discovery = client.discover().await.unwrap();
        assert_eq!(discovery.issuer, base_url);
        assert_eq!(
            discovery.registration_endpoint.as_deref(),
            Some(format!("{base_url}/oauth2/register").as_str())
        );

        // 2. Dynamic Client Registration (RFC 7591) for Clockwork Elf `sindri` with `private_key_jwt`
        let agent_id = WimseAgentId::for_conclave_elf(
            "cerebral.work",
            "sindri",
            SubjectMatterMesh::PlatformControl,
        )
        .unwrap();
        let scopes = BTreeSet::from(["idp:read".to_string(), "mesh:control".to_string()]);
        let req_meta = OAuth2ClientMetadata::for_agent(
            &agent_id,
            Some("sindri"),
            Some(SubjectMatterMesh::PlatformControl),
            &scopes,
            vec!["https://api.cerebral.work".to_string()],
            Some("https://idp.cerebral.work/.well-known/jwks.json".to_string()),
        );

        let registered = client.register_client_rfc7591(&req_meta).await.unwrap();
        let client_id = registered.client_id.clone().unwrap();
        let reg_token = registered.registration_access_token.clone().unwrap();

        // 3. RFC 7592 Client Configuration Read & Wrong Token Rejection
        let fetched = client
            .get_registered_client_rfc7592(&client_id, &reg_token)
            .await
            .unwrap();
        assert_eq!(fetched.client_id.as_deref(), Some(client_id.as_str()));
        assert!(
            client
                .get_registered_client_rfc7592(&client_id, "wrong-token")
                .await
                .is_err()
        );

        // 4. RFC 7592 Update
        let mut updated_req = fetched.clone();
        updated_req.scope = Some("idp:read mesh:control xerj:search".to_string());
        let updated = client
            .update_registered_client_rfc7592(&client_id, &reg_token, &updated_req)
            .await
            .unwrap();
        assert!(updated.scopes_set().contains("xerj:search"));

        // 5. Client Credentials Grant with PrivateKeyJwt
        let tok_resp = client
            .exchange_client_credentials(
                ClientAuth::PrivateKeyJwt {
                    client_id: &client_id,
                    client_assertion: "eyJhbGciOiJSUzI1NiJ9.mock_assertion",
                },
                &["idp:read", "mesh:control"],
                &["https://api.cerebral.work"],
            )
            .await
            .unwrap();
        assert_eq!(tok_resp.token_type, "bearer");

        // 6. Token Introspection (RFC 7662) -> Principal Lattice Evaluation
        let introspected = client
            .introspect_token(&tok_resp.access_token, None)
            .await
            .unwrap();
        assert!(introspected.active);
        assert_eq!(
            introspected.to_principal(1_850_000_000),
            Principal::Scoped {
                scopes: BTreeSet::from(["idp:read".to_string(), "mesh:control".to_string()])
            }
        );

        // 7. RFC 8693 Token Exchange for downscoped Transaction Token (`draft-klrc-aiagent-auth-03` §10.5)
        let exchange_req = TokenExchangeRequest {
            subject_token: "user-delegated-token".to_string(),
            subject_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
            actor_token: Some(tok_resp.access_token.clone()),
            actor_token_type: Some(TOKEN_TYPE_JWT.to_string()),
            requested_token_type: Some(TOKEN_TYPE_TRANSACTION_TOKEN.to_string()),
            audience: vec!["https://llm.unsigned.gg/v1".to_string()],
            scope: Some("idp:read".to_string()),
            resource: None,
        };
        let txn_tok = client
            .exchange_token_rfc8693(
                ClientAuth::PrivateKeyJwt {
                    client_id: &client_id,
                    client_assertion: "eyJhbGciOiJSUzI1NiJ9.mock_assertion",
                },
                &exchange_req,
            )
            .await
            .unwrap();
        assert_eq!(
            txn_tok.issued_token_type.as_deref(),
            Some(TOKEN_TYPE_TRANSACTION_TOKEN)
        );

        let txn_introspected = client
            .introspect_token(&txn_tok.access_token, None)
            .await
            .unwrap();
        assert!(txn_introspected.active);
        assert_eq!(
            txn_introspected
                .resolved_actor()
                .unwrap()
                .client_id
                .as_deref(),
            Some(client_id.as_str())
        );

        // 8. Admin List & RFC 7592 Delete
        let all_clients = client.admin_list_clients().await.unwrap();
        assert_eq!(all_clients.len(), 1);
        client
            .delete_registered_client_rfc7592(&client_id, &reg_token)
            .await
            .unwrap();
        assert!(client.admin_list_clients().await.unwrap().is_empty());
    }
}
