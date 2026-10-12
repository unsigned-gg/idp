// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! RS256 JWT generation and GitHub App installation token brokering.

use crate::error::IdpError;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// JWT claims for authenticating as a GitHub App.
#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubAppClaims {
    /// Issued at timestamp (seconds since Unix epoch).
    pub iat: u64,
    /// Expiration timestamp (seconds since Unix epoch, max 10 minutes from iat).
    pub exp: u64,
    /// Issuer (GitHub App ID as string).
    pub iss: String,
}

/// Installation token response returned by GitHub API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationToken {
    /// The minted bearer token (e.g. "ghs_...").
    pub token: String,
    /// ISO 8601 expiration timestamp.
    pub expires_at: String,
    /// Selected repository scope ("all" or "selected").
    #[serde(default)]
    pub repository_selection: Option<String>,
}

/// Summary of an installation associated with an App.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationSummary {
    /// Unique installation identifier.
    pub id: u64,
    /// Target account or organization login.
    pub account: InstallationAccount,
    /// Repository selection mode.
    pub repository_selection: String,
}

/// Account entity owning the installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationAccount {
    /// Account login name.
    pub login: String,
    /// Account ID.
    pub id: u64,
}

/// Client for brokering GitHub App tokens.
pub struct TokenBroker {
    client: reqwest::Client,
}

impl Default for TokenBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenBroker {
    /// Creates a new token broker with default configuration.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Mints a signed RS256 JWT for the given GitHub App ID using its PEM private key.
    pub fn mint_jwt(&self, app_id: u64, pem_key: &str) -> Result<String, IdpError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 60-second backward drift allowance, 9-minute lifetime (max allowed is 10 min)
        let claims = GitHubAppClaims {
            iat: now.saturating_sub(60),
            exp: now.saturating_add(540),
            iss: app_id.to_string(),
        };

        let key = EncodingKey::from_rsa_pem(pem_key.as_bytes())?;
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &key)?;
        Ok(token)
    }

    /// Lists active installations for the GitHub App.
    pub async fn list_installations(
        &self,
        app_id: u64,
        pem_key: &str,
    ) -> Result<Vec<InstallationSummary>, IdpError> {
        let jwt = self.mint_jwt(app_id, pem_key)?;

        let resp = self
            .client
            .get("https://api.github.com/app/installations")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "unsigned-idp/0.1.0")
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::GitHubApi { status, body });
        }

        let installations: Vec<InstallationSummary> = resp.json().await?;
        Ok(installations)
    }

    /// Exchanges a GitHub App JWT for a scoped installation access token.
    pub async fn create_installation_token(
        &self,
        app_id: u64,
        pem_key: &str,
        installation_id: u64,
    ) -> Result<InstallationToken, IdpError> {
        let jwt = self.mint_jwt(app_id, pem_key)?;

        let url =
            format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "unsigned-idp/0.1.0")
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(IdpError::GitHubApi { status, body });
        }

        let token: InstallationToken = resp.json().await?;
        Ok(token)
    }
}
