// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Error types for the identity provider library.

use thiserror::Error;

/// Error conditions encountered during identity provider operations.
#[derive(Debug, Error)]
pub enum IdpError {
    /// Failure during JWT encoding or RS256 signing.
    #[error("JWT signing failure: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Network or HTTP transport error.
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    /// File or storage I/O error.
    #[error("Filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization error.
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// GitHub API returned an error status code or unexpected body.
    #[error("GitHub API error: status {status}, body: {body}")]
    GitHubApi {
        /// HTTP status code returned by GitHub API.
        status: reqwest::StatusCode,
        /// Response body or error description from GitHub API.
        body: String,
    },

    /// The specified bot identity was not found in the local registry.
    #[error("Bot identity '{0}' not found in registry")]
    BotNotFound(String),

    /// Private key file is missing or invalid.
    #[error("Private key missing or unreadable at path: {0}")]
    KeyMissing(String),
}
