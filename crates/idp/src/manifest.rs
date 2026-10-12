// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! GitHub App Manifest generation and conversion structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Webhook configuration attributes for a GitHub App.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookAttributes {
    /// Webhook endpoint URL.
    pub url: String,
    /// Whether webhooks are active.
    pub active: bool,
}

/// GitHub App Manifest specification.
/// Follows the GitHub App Manifest flow specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    /// Name of the GitHub App.
    pub name: String,
    /// Homepage or description URL.
    pub url: String,
    /// Webhook attributes.
    pub hook_attributes: HookAttributes,
    /// Callback URL redirected to with the conversion code.
    pub redirect_url: String,
    /// Optional post-install setup URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_url: Option<String>,
    /// Whether the app is public or private.
    pub public: bool,
    /// Default permissions granted to the App upon installation.
    pub default_permissions: HashMap<String, String>,
    /// Default event subscriptions.
    pub default_events: Vec<String>,
}

impl AppManifest {
    /// Creates a default bot manifest tailored for an unsigned-gg conclave elf.
    pub fn for_conclave_bot(bot_name: &str, redirect_url: &str) -> Self {
        let mut permissions = HashMap::new();
        permissions.insert("contents".to_string(), "write".to_string());
        permissions.insert("pull_requests".to_string(), "write".to_string());
        permissions.insert("issues".to_string(), "write".to_string());
        permissions.insert("metadata".to_string(), "read".to_string());
        permissions.insert("checks".to_string(), "write".to_string());
        permissions.insert("statuses".to_string(), "write".to_string());

        let events = vec![
            "pull_request".to_string(),
            "pull_request_review".to_string(),
            "issue_comment".to_string(),
        ];

        Self {
            name: format!("{bot_name}-bot"),
            url: "https://unsigned.gg".to_string(),
            hook_attributes: HookAttributes {
                url: "https://cortex.unsigned.gg/webhook".to_string(),
                active: false,
            },
            redirect_url: redirect_url.to_string(),
            setup_url: None,
            public: false,
            default_permissions: permissions,
            default_events: events,
        }
    }

    /// Serializes manifest to JSON string for HTML form embedding.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Conversion response payload returned by GitHub when exchanging the conversion code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionResponse {
    /// Unique GitHub App ID.
    pub id: u64,
    /// Application display name.
    pub name: String,
    /// Unique slug for the application.
    #[serde(default)]
    pub slug: Option<String>,
    /// OAuth Client ID.
    pub client_id: String,
    /// OAuth Client Secret.
    pub client_secret: String,
    /// RSA private key in PEM format.
    pub pem: String,
    /// Webhook signing secret if configured.
    #[serde(default)]
    pub webhook_secret: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_for_conclave_bot() {
        let manifest = AppManifest::for_conclave_bot("sindri", "https://example.com/callback");
        assert_eq!(manifest.name, "sindri-bot");
        assert_eq!(manifest.redirect_url, "https://example.com/callback");
        assert_eq!(
            manifest
                .default_permissions
                .get("contents")
                .map(String::as_str),
            Some("write")
        );
        assert_eq!(
            manifest
                .default_permissions
                .get("pull_requests")
                .map(String::as_str),
            Some("write")
        );
        assert!(!manifest.public);

        let json = manifest.to_json().expect("serialize manifest");
        assert!(json.contains("\"name\":\"sindri-bot\""));
    }
}
