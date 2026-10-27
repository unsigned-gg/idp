// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Pure zero-I/O domain types for Ory Hydra Dynamic Client Registration (RFC 7591 / RFC 7592),
//! OAuth 2.0 Token Exchange (RFC 8693), Token Introspection (RFC 7662), and AI Agent Identity
//! (`draft-klrc-aiagent-auth-03`).
//!
//! # Security Invariants
//! - `OAuth2ClientMetadata` and `OAuth2TokenResponse` redact secrets (`client_secret`,
//!   `registration_access_token`, `access_token`, `refresh_token`) in `Debug` output and via
//!   explicit `.redacted()` projections.
//! - Agent identities must bind to a canonical WIMSE / SPIFFE workload identifier
//!   (`spiffe://<trust-domain>/<path>` or `wimse://<trust-domain>/<path>`).
//! - Non-superadmin subjects can never obtain `Principal::Superuser` via token introspection,
//!   even if the token scope string contains `"estate:superuser"`.

use crate::principal::{
    Principal, SOLE_SUPERADMIN_EMAIL, SubjectMatterMesh, is_sovereign_root_email,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Scope token required (alongside a Sovereign Root `sub`) to resolve `Principal::Superuser`.
pub const ESTATE_SUPERUSER_SCOPE: &str = "estate:superuser";

/// OAuth 2.0 Grant Type URI for Token Exchange (RFC 8693).
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// OAuth 2.0 Grant Type URI for JWT Bearer Client/Authorization Grants (RFC 7523).
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// OAuth 2.0 Client Assertion Type URI for `private_key_jwt` (RFC 7523 Section 2.2).
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// RFC 8693 Token Type URI for an OAuth 2.0 access token.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 Token Type URI for an OAuth 2.0 refresh token.
pub const TOKEN_TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";

/// RFC 8693 Token Type URI for an OIDC ID Token.
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// RFC 8693 Token Type URI for a generic JWT.
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// IETF `draft-ietf-oauth-transaction-tokens` Token Type URI for downscoped Transaction Tokens
/// (`draft-klrc-aiagent-auth-03` Section 10.5).
pub const TOKEN_TYPE_TRANSACTION_TOKEN: &str = "urn:ietf:params:oauth:token-type:txn_token";

/// Validation error returned when RFC 7591 client metadata, WIMSE agent identifiers,
/// or RFC 8693 token exchange requests violate protocol or estate security invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcrValidationError {
    /// RFC 7591 / OAuth 2.0 error code classification.
    pub code: Rfc7591ErrorCode,
    /// Human-readable description of the invariant violation.
    pub description: String,
}

impl DcrValidationError {
    /// Constructs a new validation error with the given RFC 7591 error code and description.
    pub fn new(code: Rfc7591ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }
}

impl fmt::Display for DcrValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.description)
    }
}

impl std::error::Error for DcrValidationError {}

/// Standard RFC 7591 Section 3.2.2 and OAuth 2.0 error codes for Dynamic Client Registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rfc7591ErrorCode {
    /// One or more `redirect_uris` values are invalid (`RFC 7591 §3.2.2`).
    InvalidRedirectUri,
    /// One of the client metadata fields is invalid (`RFC 7591 §3.2.2`).
    InvalidClientMetadata,
    /// The software statement presented is invalid (`RFC 7591 §3.2.2`).
    InvalidSoftwareStatement,
    /// The software statement presented is not approved for use (`RFC 7591 §3.2.2`).
    UnapprovedSoftwareStatement,
    /// Client authentication failed or registration access token is invalid (`RFC 6749` / `RFC 7592`).
    InvalidClient,
    /// The client is not authorized to use this grant type or registration endpoint.
    UnauthorizedClient,
    /// The requested scope is invalid, unknown, or malformed.
    InvalidScope,
    /// The request is missing a required parameter or is otherwise malformed.
    InvalidRequest,
}

impl Rfc7591ErrorCode {
    /// Returns the wire-format snake_case string for this RFC 7591 error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::InvalidSoftwareStatement => "invalid_software_statement",
            Self::UnapprovedSoftwareStatement => "unapproved_software_statement",
            Self::InvalidClient => "invalid_client",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidRequest => "invalid_request",
        }
    }
}

/// Wire-format RFC 7591 Section 3.2.2 / Ory Hydra OAuth2 error response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc7591ErrorResponse {
    /// RFC 7591 / OAuth 2.0 error code (`invalid_client_metadata`, `invalid_redirect_uri`, etc.).
    pub error: String,
    /// Human-readable error description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl From<DcrValidationError> for Rfc7591ErrorResponse {
    fn from(err: DcrValidationError) -> Self {
        Self {
            error: err.code.as_str().to_string(),
            error_description: Some(err.description),
        }
    }
}

/// URI scheme for a WIMSE or SPIFFE agent workload identifier (`draft-klrc-aiagent-auth-03` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WimseScheme {
    /// SPIFFE ID scheme (`spiffe://<trust-domain>/<path>`).
    Spiffe,
    /// WIMSE ID scheme (`wimse://<trust-domain>/<path>`).
    Wimse,
}

impl WimseScheme {
    /// Returns the lowercase URI scheme string (`"spiffe"` or `"wimse"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spiffe => "spiffe",
            Self::Wimse => "wimse",
        }
    }
}

/// Validated WIMSE / SPIFFE workload identifier for an AI Agent (`draft-klrc-aiagent-auth-03` §6).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WimseAgentId {
    /// Identifier URI scheme (`spiffe` or `wimse`).
    pub scheme: WimseScheme,
    /// Lowercase ASCII trust domain (e.g. `"cerebral.work"` or `"unsigned.gg"`).
    pub trust_domain: String,
    /// Canonical workload path without leading slash (e.g. `"elf/platform-control/sindri"`).
    pub path: String,
}

impl WimseAgentId {
    /// Parses and validates a `spiffe://` or `wimse://` workload identifier URI.
    pub fn parse(uri: &str) -> Result<Self, DcrValidationError> {
        let (scheme, rest) = if let Some(r) = uri.strip_prefix("spiffe://") {
            (WimseScheme::Spiffe, r)
        } else if let Some(r) = uri.strip_prefix("wimse://") {
            (WimseScheme::Wimse, r)
        } else {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                format!("WIMSE agent ID must start with spiffe:// or wimse:// (got '{uri}')"),
            ));
        };

        if rest.contains('?') || rest.contains('#') {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                "WIMSE agent ID must not contain query or fragment components",
            ));
        }

        let Some((trust_domain, path)) = rest.split_once('/') else {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                "WIMSE agent ID must include both a trust domain and a workload path",
            ));
        };

        Self::validate_trust_domain(trust_domain)?;
        Self::validate_path(path)?;

        Ok(Self {
            scheme,
            trust_domain: trust_domain.to_string(),
            path: path.to_string(),
        })
    }

    /// Constructs a canonical SPIFFE ID for a Clockwork Conclave Elf:
    /// `spiffe://<trust_domain>/elf/<mesh>/<elf_id>`.
    pub fn for_conclave_elf(
        trust_domain: &str,
        elf_id: &str,
        mesh: SubjectMatterMesh,
    ) -> Result<Self, DcrValidationError> {
        Self::validate_trust_domain(trust_domain)?;
        let elf_trimmed = elf_id.trim();
        if elf_trimmed.is_empty()
            || !elf_trimmed
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                format!("Invalid Clockwork Elf identifier '{elf_id}'"),
            ));
        }
        let mesh_slug = match mesh {
            SubjectMatterMesh::KernelRuntime => "kernel-runtime",
            SubjectMatterMesh::MemorySearch => "memory-search",
            SubjectMatterMesh::IdentityGovernance => "identity-governance",
            SubjectMatterMesh::PlatformControl => "platform-control",
            SubjectMatterMesh::EcosystemCatalog => "ecosystem-catalog",
            SubjectMatterMesh::OperatorEstate => "operator-estate",
        };
        let path = format!("elf/{mesh_slug}/{elf_trimmed}");
        Ok(Self {
            scheme: WimseScheme::Spiffe,
            trust_domain: trust_domain.to_string(),
            path,
        })
    }

    /// Formats the canonical URI string (`spiffe://<trust_domain>/<path>`).
    pub fn to_uri(&self) -> String {
        format!(
            "{}://{}/{}",
            self.scheme.as_str(),
            self.trust_domain,
            self.path
        )
    }

    fn validate_trust_domain(td: &str) -> Result<(), DcrValidationError> {
        if td.is_empty()
            || td.starts_with('.')
            || td.ends_with('.')
            || !td.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
            })
        {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                format!("Invalid WIMSE/SPIFFE trust domain '{td}'"),
            ));
        }
        Ok(())
    }

    fn validate_path(path: &str) -> Result<(), DcrValidationError> {
        if path.is_empty() || path.ends_with('/') {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                "WIMSE/SPIFFE workload path must not be empty or end with '/'",
            ));
        }
        for segment in path.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(DcrValidationError::new(
                    Rfc7591ErrorCode::InvalidClientMetadata,
                    format!("WIMSE/SPIFFE workload path contains invalid segment '{segment}'"),
                ));
            }
            if !segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                return Err(DcrValidationError::new(
                    Rfc7591ErrorCode::InvalidClientMetadata,
                    format!(
                        "WIMSE/SPIFFE workload path segment '{segment}' contains invalid characters"
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Display for WimseAgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}/{}",
            self.scheme.as_str(),
            self.trust_domain,
            self.path
        )
    }
}

/// OAuth 2.0 Grant Types supported by Ory Hydra and RFC 7591 Dynamic Client Registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OAuth2GrantType {
    /// OAuth 2.0 Client Credentials Grant (`client_credentials`, RFC 6749 §4.4).
    #[serde(rename = "client_credentials")]
    ClientCredentials,
    /// OAuth 2.0 Authorization Code Grant (`authorization_code`, RFC 6749 §4.1).
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    /// OAuth 2.0 Refresh Token Grant (`refresh_token`, RFC 6749 §6).
    #[serde(rename = "refresh_token")]
    RefreshToken,
    /// OAuth 2.0 Token Exchange Grant (`urn:ietf:params:oauth:grant-type:token-exchange`, RFC 8693).
    #[serde(rename = "urn:ietf:params:oauth:grant-type:token-exchange")]
    TokenExchange,
    /// OAuth 2.0 JWT Bearer Grant (`urn:ietf:params:oauth:grant-type:jwt-bearer`, RFC 7523).
    #[serde(rename = "urn:ietf:params:oauth:grant-type:jwt-bearer")]
    JwtBearer,
}

impl OAuth2GrantType {
    /// Returns the wire-format grant_type string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientCredentials => "client_credentials",
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::TokenExchange => GRANT_TYPE_TOKEN_EXCHANGE,
            Self::JwtBearer => GRANT_TYPE_JWT_BEARER,
        }
    }
}

/// OAuth 2.0 / OIDC Response Types (`response_types` in RFC 7591).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OAuth2ResponseType {
    /// Authorization code response type (`code`).
    #[serde(rename = "code")]
    Code,
    /// Access token response type (`token`).
    #[serde(rename = "token")]
    Token,
    /// OIDC ID token response type (`id_token`).
    #[serde(rename = "id_token")]
    IdToken,
}

/// OAuth 2.0 Token Endpoint Authentication Methods (`token_endpoint_auth_method` in RFC 7591 §2).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum TokenEndpointAuthMethod {
    /// HTTP Basic authentication using client_id and client_secret (`client_secret_basic`).
    #[default]
    #[serde(rename = "client_secret_basic")]
    ClientSecretBasic,
    /// Form body authentication using client_id and client_secret (`client_secret_post`).
    #[serde(rename = "client_secret_post")]
    ClientSecretPost,
    /// Asymmetric JWT assertion signed by client's private key (`private_key_jwt`, RFC 7523).
    #[serde(rename = "private_key_jwt")]
    PrivateKeyJwt,
    /// PKI Mutual-TLS OAuth Client Authentication (`tls_client_auth`, RFC 8705).
    #[serde(rename = "tls_client_auth")]
    TlsClientAuth,
    /// Self-Signed Certificate Mutual-TLS OAuth Client Authentication (`self_signed_tls_client_auth`, RFC 8705).
    #[serde(rename = "self_signed_tls_client_auth")]
    SelfSignedTlsClientAuth,
    /// Public client without secret (`none`). Prohibited for `client_credentials`.
    #[serde(rename = "none")]
    None,
}

impl TokenEndpointAuthMethod {
    /// Returns true if this authentication method uses asymmetric cryptographic proof of possession
    /// (`private_key_jwt`, `tls_client_auth`, or `self_signed_tls_client_auth`) as required by
    /// `draft-klrc-aiagent-auth-03` Section 10.4.2.
    pub const fn is_cryptographic(self) -> bool {
        matches!(
            self,
            Self::PrivateKeyJwt | Self::TlsClientAuth | Self::SelfSignedTlsClientAuth
        )
    }
}

/// Structured AI Agent identity metadata persisted in Ory Hydra's `OAuth2Client.metadata` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentClientMetadata {
    /// Canonical WIMSE or SPIFFE identifier (`spiffe://<trust_domain>/<path>`).
    pub wimse_id: String,
    /// Optional Clockwork Conclave Elf persona identifier (e.g. `"sindri"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_id: Option<String>,
    /// Assigned subject-matter mesh for policy routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<SubjectMatterMesh>,
    /// Trust domain owning the workload.
    pub trust_domain: String,
    /// Optional human or parent-agent principal identifier that delegated the mission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_actor: Option<String>,
    /// Runtime posture assessment signals attested at provisioning time (`draft-klrc-aiagent-auth-03` §8).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub posture_signals: BTreeSet<String>,
}

/// Ory Hydra `o_auth2_client` / RFC 7591 Dynamic Client Registration & RFC 7592 Client Configuration payload.
///
/// Custom [`fmt::Debug`] implementation redacts `client_secret` and `registration_access_token`
/// so credentials are never emitted to logs or test output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OAuth2ClientMetadata {
    /// Unique OAuth 2.0 client identifier assigned by Ory Hydra or requested at admin creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Human-readable name of the client or AI agent persona (`RFC 7591 §2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// Client secret returned by Ory Hydra upon registration (redacted in `Debug`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Unix timestamp at which `client_secret` expires (`0` means non-expiring).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,

    /// Unix timestamp at which `client_id` was issued (`RFC 7591 §3.2.1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<u64>,

    /// Redirection URI strings for use in redirect-based flows (`authorization_code`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,

    /// OAuth 2.0 grant types that the client may use at the token endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<OAuth2GrantType>,

    /// OAuth 2.0 `response_type` values that the client may use at the authorization endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<OAuth2ResponseType>,

    /// Space-delimited list of scope values (`RFC 7591 §2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Allowed target audiences (`aud`) for tokens minted for this client (Ory Hydra extension).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,

    /// Client authentication method for the token endpoint (`RFC 7591 §2`).
    #[serde(default)]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,

    /// JWS `alg` algorithm required for signing client authentication JWTs (e.g. `"RS256"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,

    /// URL for the client's JSON Web Key Set (`RFC 7591 §2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Inline JSON Web Key Set document (`RFC 7591 §2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,

    /// Unique identifier string (e.g. UUID or URI) for the client software (`RFC 7591 §2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,

    /// Version identifier string for the client software (`RFC 7591 §2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,

    /// Administrative contact email addresses (`RFC 7591 §2`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,

    /// OIDC `subject_type` requested for responses (`"public"` or `"pairwise"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    /// RFC 7592 Registration Access Token used to read, update, or delete the client registration (redacted in `Debug`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,

    /// RFC 7592 Registration Client URI where the client configuration resource resides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,

    /// Structured AI agent identity metadata (`draft-klrc-aiagent-auth-03`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AgentClientMetadata>,
}

impl fmt::Debug for OAuth2ClientMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2ClientMetadata")
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("client_secret_expires_at", &self.client_secret_expires_at)
            .field("client_id_issued_at", &self.client_id_issued_at)
            .field("redirect_uris", &self.redirect_uris)
            .field("grant_types", &self.grant_types)
            .field("response_types", &self.response_types)
            .field("scope", &self.scope)
            .field("audience", &self.audience)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field(
                "token_endpoint_auth_signing_alg",
                &self.token_endpoint_auth_signing_alg,
            )
            .field("jwks_uri", &self.jwks_uri)
            .field("jwks", &self.jwks)
            .field("software_id", &self.software_id)
            .field("software_version", &self.software_version)
            .field("contacts", &self.contacts)
            .field("subject_type", &self.subject_type)
            .field(
                "registration_access_token",
                &self
                    .registration_access_token
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("registration_client_uri", &self.registration_client_uri)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl OAuth2ClientMetadata {
    /// Builds an RFC 7591 + Ory Hydra client registration request for a Clockwork Conclave Elf or AI Agent.
    pub fn for_agent(
        agent_id: &WimseAgentId,
        elf_id: Option<&str>,
        mesh: Option<SubjectMatterMesh>,
        scopes: &BTreeSet<String>,
        audience: Vec<String>,
        jwks_uri: Option<String>,
    ) -> Self {
        let auth_method = if jwks_uri.is_some() {
            TokenEndpointAuthMethod::PrivateKeyJwt
        } else {
            TokenEndpointAuthMethod::ClientSecretBasic
        };
        let signing_alg = if jwks_uri.is_some() {
            Some("RS256".to_string())
        } else {
            None
        };
        let scope_str = if scopes.is_empty() {
            None
        } else {
            Some(scopes.iter().cloned().collect::<Vec<_>>().join(" "))
        };
        let display_name = match elf_id {
            Some(elf) => format!("{elf}-agent ({})", agent_id.trust_domain),
            None => format!("agent ({agent_id})"),
        };

        Self {
            client_id: None,
            client_name: Some(display_name),
            client_secret: None,
            client_secret_expires_at: None,
            client_id_issued_at: None,
            redirect_uris: Vec::new(),
            grant_types: vec![
                OAuth2GrantType::ClientCredentials,
                OAuth2GrantType::TokenExchange,
            ],
            response_types: vec![OAuth2ResponseType::Token],
            scope: scope_str,
            audience,
            token_endpoint_auth_method: auth_method,
            token_endpoint_auth_signing_alg: signing_alg,
            jwks_uri,
            jwks: None,
            software_id: Some(agent_id.to_uri()),
            software_version: Some("0.1.0".to_string()),
            contacts: vec![SOLE_SUPERADMIN_EMAIL.to_string()],
            subject_type: Some("public".to_string()),
            registration_access_token: None,
            registration_client_uri: None,
            metadata: Some(AgentClientMetadata {
                wimse_id: agent_id.to_uri(),
                elf_id: elf_id.map(str::to_string),
                mesh,
                trust_domain: agent_id.trust_domain.clone(),
                delegated_actor: None,
                posture_signals: BTreeSet::new(),
            }),
        }
    }

    /// Parses the space-delimited `scope` string into a deterministic sorted set.
    pub fn scopes_set(&self) -> BTreeSet<String> {
        self.scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Returns a redacted copy with `client_secret` and `registration_access_token` scrubbed.
    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        if copy.client_secret.is_some() {
            copy.client_secret = Some("<redacted>".to_string());
        }
        if copy.registration_access_token.is_some() {
            copy.registration_access_token = Some("<redacted>".to_string());
        }
        copy
    }

    /// Validates client registration metadata against RFC 7591, OAuth 2.0 Security BCP,
    /// and `draft-klrc-aiagent-auth-03` agent invariants.
    ///
    /// When `require_cryptographic_agent_auth` is `true`, agent clients (`metadata.is_some()`)
    /// must authenticate with `private_key_jwt` or mTLS (`tls_client_auth` / `self_signed_tls_client_auth`)
    /// and cannot rely on static client secrets (`draft-klrc-aiagent-auth-03` §10.4.2).
    pub fn validate_rfc7591(
        &self,
        require_cryptographic_agent_auth: bool,
    ) -> Result<(), DcrValidationError> {
        if self.grant_types.is_empty() {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                "grant_types must not be empty",
            ));
        }

        // Clause 1: Redirect-based flows require validated HTTPS or loopback redirect_uris.
        if self
            .grant_types
            .contains(&OAuth2GrantType::AuthorizationCode)
            && self.redirect_uris.is_empty()
        {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidRedirectUri,
                "authorization_code grant requires at least one redirect_uri",
            ));
        }
        for uri in &self.redirect_uris {
            validate_redirect_uri(uri)?;
        }

        // Clause 2: Public clients (`token_endpoint_auth_method == none`) cannot use `client_credentials`.
        if self.token_endpoint_auth_method == TokenEndpointAuthMethod::None
            && self
                .grant_types
                .contains(&OAuth2GrantType::ClientCredentials)
        {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                "token_endpoint_auth_method 'none' is not permitted with client_credentials grant",
            ));
        }

        // Clause 3: `private_key_jwt` requires either `jwks_uri` or inline `jwks`.
        if self.token_endpoint_auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
            && self.jwks_uri.is_none()
            && self.jwks.is_none()
        {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidClientMetadata,
                "private_key_jwt requires either jwks_uri or inline jwks",
            ));
        }

        // Clause 4: Scope tokens must not request wildcard `*` or superuser escalation via DCR.
        let scopes = self.scopes_set();
        if scopes.contains("*") || scopes.contains(ESTATE_SUPERUSER_SCOPE) {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidScope,
                "Dynamic Client Registration cannot request wildcard '*' or 'estate:superuser' scope",
            ));
        }

        // Clause 5: AI Agent metadata invariants (`draft-klrc-aiagent-auth-03`).
        if let Some(ref agent_meta) = self.metadata {
            let parsed = WimseAgentId::parse(&agent_meta.wimse_id)?;
            if parsed.trust_domain != agent_meta.trust_domain {
                return Err(DcrValidationError::new(
                    Rfc7591ErrorCode::InvalidClientMetadata,
                    format!(
                        "WIMSE ID trust domain '{}' does not match metadata.trust_domain '{}'",
                        parsed.trust_domain, agent_meta.trust_domain
                    ),
                ));
            }
            if require_cryptographic_agent_auth
                && !self.token_endpoint_auth_method.is_cryptographic()
            {
                return Err(DcrValidationError::new(
                    Rfc7591ErrorCode::InvalidClientMetadata,
                    "AI agent strict mode (draft-klrc-aiagent-auth-03 §10.4.2) requires cryptographic client auth (private_key_jwt or mTLS)",
                ));
            }
        }

        Ok(())
    }
}

fn validate_redirect_uri(uri: &str) -> Result<(), DcrValidationError> {
    if uri.contains('#') {
        return Err(DcrValidationError::new(
            Rfc7591ErrorCode::InvalidRedirectUri,
            format!("redirect_uri '{uri}' must not contain a URI fragment ('#')"),
        ));
    }
    let is_https = uri.starts_with("https://") && uri.len() > "https://".len();
    let is_loopback = uri.starts_with("http://127.0.0.1:")
        || uri.starts_with("http://127.0.0.1/")
        || uri.starts_with("http://localhost:")
        || uri.starts_with("http://localhost/");
    if !is_https && !is_loopback {
        return Err(DcrValidationError::new(
            Rfc7591ErrorCode::InvalidRedirectUri,
            format!(
                "redirect_uri '{uri}' must use https:// or loopback http://127.0.0.1 / http://localhost"
            ),
        ));
    }
    Ok(())
}

/// OpenID Connect Discovery 1.0 / RFC 8414 Authorization Server Metadata returned by Ory Hydra
/// at `/.well-known/openid-configuration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    /// Issuer URL (`iss`).
    pub issuer: String,
    /// OAuth 2.0 Authorization Endpoint URL.
    pub authorization_endpoint: String,
    /// OAuth 2.0 Token Endpoint URL.
    pub token_endpoint: String,
    /// JSON Web Key Set URL (`/.well-known/jwks.json`).
    pub jwks_uri: String,
    /// Optional RFC 7591 Dynamic Client Registration Endpoint URL (`/oauth2/register`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Optional RFC 7662 Token Introspection Endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    /// Optional RFC 7009 Token Revocation Endpoint URL (`/oauth2/revoke`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// Supported OAuth 2.0 grant types advertised by the server.
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    /// Supported OAuth 2.0 response types advertised by the server.
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// Supported client authentication methods at the token endpoint.
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// RFC 8693 OAuth 2.0 Token Exchange request parameters (`draft-klrc-aiagent-auth-03` §10.5 & §10.8).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    /// Security token representing the identity of the party on behalf of whom the request is being made (redacted in `Debug`).
    pub subject_token: String,
    /// URI identifying the type of `subject_token` (e.g. [`TOKEN_TYPE_ACCESS_TOKEN`]).
    pub subject_token_type: String,
    /// Optional security token representing the identity of the acting party (the AI Agent or Tool; redacted in `Debug`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_token: Option<String>,
    /// URI identifying the type of `actor_token` (required when `actor_token` is present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_token_type: Option<String>,
    /// Optional URI for the requested token type (e.g. [`TOKEN_TYPE_ACCESS_TOKEN`] or [`TOKEN_TYPE_TRANSACTION_TOKEN`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_token_type: Option<String>,
    /// Logical names of the target services (`audience`) where the client intends to use the requested token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    /// Space-delimited list of desired downscoped scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Optional RFC 8707 resource indicator URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

impl fmt::Debug for TokenExchangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenExchangeRequest")
            .field("subject_token", &"<redacted>")
            .field("subject_token_type", &self.subject_token_type)
            .field(
                "actor_token",
                &self.actor_token.as_ref().map(|_| "<redacted>"),
            )
            .field("actor_token_type", &self.actor_token_type)
            .field("requested_token_type", &self.requested_token_type)
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .finish()
    }
}

impl TokenExchangeRequest {
    /// Validates RFC 8693 Section 2.1 request invariants.
    pub fn validate(&self) -> Result<(), DcrValidationError> {
        if self.subject_token.trim().is_empty() {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidRequest,
                "subject_token is required for RFC 8693 token exchange",
            ));
        }
        if self.subject_token_type.trim().is_empty() {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidRequest,
                "subject_token_type is required for RFC 8693 token exchange",
            ));
        }
        if self.actor_token.is_some() && self.actor_token_type.as_deref().unwrap_or("").is_empty() {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidRequest,
                "actor_token_type MUST be provided when actor_token is present (RFC 8693 §2.1)",
            ));
        }
        if self.actor_token.is_none() && self.actor_token_type.is_some() {
            return Err(DcrValidationError::new(
                Rfc7591ErrorCode::InvalidRequest,
                "actor_token_type MUST NOT be provided when actor_token is absent (RFC 8693 §2.1)",
            ));
        }
        Ok(())
    }

    /// Lowers the validated request into ordered `(key, value)` form parameters for `POST /oauth2/token`.
    pub fn to_form_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = vec![
            (
                "grant_type".to_string(),
                GRANT_TYPE_TOKEN_EXCHANGE.to_string(),
            ),
            ("subject_token".to_string(), self.subject_token.clone()),
            (
                "subject_token_type".to_string(),
                self.subject_token_type.clone(),
            ),
        ];
        if let Some(ref act) = self.actor_token {
            pairs.push(("actor_token".to_string(), act.clone()));
        }
        if let Some(ref act_type) = self.actor_token_type {
            pairs.push(("actor_token_type".to_string(), act_type.clone()));
        }
        if let Some(ref req_type) = self.requested_token_type {
            pairs.push(("requested_token_type".to_string(), req_type.clone()));
        }
        for aud in &self.audience {
            pairs.push(("audience".to_string(), aud.clone()));
        }
        if let Some(ref scope) = self.scope {
            pairs.push(("scope".to_string(), scope.clone()));
        }
        if let Some(ref res) = self.resource {
            pairs.push(("resource".to_string(), res.clone()));
        }
        pairs
    }
}

/// OAuth 2.0 Token Response (`POST /oauth2/token`, RFC 6749 §5.1 & RFC 8693 §2.2.1).
///
/// Redacts `access_token` and `refresh_token` in `Debug` output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuth2TokenResponse {
    /// Minted access or transaction token (redacted in `Debug`).
    pub access_token: String,
    /// Token type (typically `"bearer"` or `"N_A"`).
    pub token_type: String,
    /// Lifetime in seconds of the access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Optional refresh token (redacted in `Debug`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Granted space-delimited scope string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// RFC 8693 `issued_token_type` URI when returned by Token Exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
}

impl fmt::Debug for OAuth2TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2TokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .field("issued_token_type", &self.issued_token_type)
            .finish()
    }
}

impl OAuth2TokenResponse {
    /// Returns a redacted copy with `access_token` and `refresh_token` scrubbed.
    pub fn redacted(&self) -> Self {
        Self {
            access_token: "<redacted>".to_string(),
            token_type: self.token_type.clone(),
            expires_in: self.expires_in,
            refresh_token: self
                .refresh_token
                .as_ref()
                .map(|_| "<redacted>".to_string()),
            scope: self.scope.clone(),
            issued_token_type: self.issued_token_type.clone(),
        }
    }
}

/// Nested RFC 8693 Section 4.1 `act` (Actor) claim representing a delegation chain
/// (`User -> Parent Agent -> Subagent`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorClaim {
    /// Subject or WIMSE identifier of the acting party (`sub`).
    pub sub: String,
    /// Optional OAuth 2.0 `client_id` of the acting party.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Optional issuer (`iss`) of the actor token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Prior actor in the delegation chain, if nested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActorClaim>>,
}

impl ActorClaim {
    /// Flattens the nested `act` chain into an ordered list of actor `sub` identifiers
    /// from the immediate actor to the outermost prior actor.
    pub fn chain_subjects(&self) -> Vec<String> {
        let mut out = vec![self.sub.clone()];
        let mut cursor = self.act.as_deref();
        while let Some(next) = cursor {
            out.push(next.sub.clone());
            cursor = next.act.as_deref();
        }
        out
    }
}

/// Ory Hydra `introspected_o_auth2_token` / RFC 7662 OAuth 2.0 Token Introspection response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IntrospectedOAuth2Token {
    /// Boolean indicator of whether the token is currently active.
    pub active: bool,
    /// OAuth 2.0 `client_id` for which the token was issued (`draft-klrc-aiagent-auth-03` §10.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Subject (`sub`) of the token (human user, system, or agent workload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Space-separated list of scopes associated with this token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Audience (`aud`) list for which this token is valid.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aud: Vec<String>,
    /// Issuer (`iss`) URL of the authorization server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Expiration timestamp (seconds since Unix epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Issued-at timestamp (seconds since Unix epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Not-before timestamp (seconds since Unix epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Token type (`"Bearer"` or `"access_token"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Ory Hydra `token_use` field (`"access_token"` or `"refresh_token"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_use: Option<String>,
    /// RFC 8693 `act` actor claim when present at top level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    /// Extra claims map (`ext` in Ory Hydra introspection responses).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: BTreeMap<String, serde_json::Value>,
}

impl IntrospectedOAuth2Token {
    /// Evaluates the introspected token into the 4-tier [`Principal`] authorization lattice at `now_epoch`.
    ///
    /// # Lattice Rules
    /// 1. Inactive tokens (`!active`), expired tokens (`exp <= now_epoch`), or not-yet-valid tokens
    ///    (`nbf > now_epoch`) evaluate to [`Principal::Denied`].
    /// 2. Any token carrying the `"estate:superuser"` scope whose `sub` is NOT a Sovereign Root
    ///    ([`crate::principal::SOVEREIGN_ROOT_EMAILS`]) is rejected as [`Principal::Denied`]
    ///    (Sovereign Root invariant).
    /// 3. When `sub` is a Sovereign Root and scopes contain `"estate:superuser"`,
    ///    evaluates to [`Principal::Superuser`].
    /// 4. Active tokens with zero scopes evaluate to [`Principal::Unscoped`]; active tokens with
    ///    non-empty scopes evaluate to [`Principal::Scoped`].
    pub fn to_principal(&self, now_epoch: u64) -> Principal {
        if !self.active {
            return Principal::Denied;
        }
        if self.exp.is_some_and(|exp| exp <= now_epoch) {
            return Principal::Denied;
        }
        if self.nbf.is_some_and(|nbf| nbf > now_epoch) {
            return Principal::Denied;
        }

        let scopes: BTreeSet<String> = self
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        if scopes.contains(ESTATE_SUPERUSER_SCOPE) {
            if self.sub.as_deref().is_some_and(is_sovereign_root_email) {
                return Principal::Superuser;
            }
            return Principal::Denied;
        }

        if scopes.is_empty() {
            Principal::Unscoped
        } else {
            Principal::Scoped { scopes }
        }
    }

    /// Extracts the RFC 8693 `act` delegation chain from either top-level `act` or Ory Hydra `ext["act"]`.
    pub fn resolved_actor(&self) -> Option<ActorClaim> {
        if let Some(ref act) = self.act {
            return Some(act.clone());
        }
        self.ext
            .get("act")
            .and_then(|v| serde_json::from_value::<ActorClaim>(v.clone()).ok())
    }
}

/// Encodes `(key, value)` pairs as `application/x-www-form-urlencoded` (RFC 3986 unreserved characters).
pub fn encode_form_urlencoded(pairs: &[(impl AsRef<str>, impl AsRef<str>)]) -> String {
    let mut out = String::new();
    for (idx, (k, v)) in pairs.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        percent_encode_into(k.as_ref(), &mut out);
        out.push('=');
        percent_encode_into(v.as_ref(), &mut out);
    }
    out
}

/// Decodes an `application/x-www-form-urlencoded` body into ordered `(key, value)` pairs.
pub fn decode_form_urlencoded(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(part), String::new()),
        })
        .collect()
}

fn percent_encode_into(input: &str, out: &mut String) {
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0F));
        }
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex_upper(nibble: u8) -> char {
    match nibble & 0x0F {
        0..=9 => (b'0' + (nibble & 0x0F)) as char,
        10..=15 => (b'A' + ((nibble & 0x0F) - 10)) as char,
        _ => '0',
    }
}

const fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_wimse_agent_id_parse_and_conclave_builder() {
        let id = WimseAgentId::for_conclave_elf(
            "cerebral.work",
            "sindri",
            SubjectMatterMesh::PlatformControl,
        )
        .unwrap();
        assert_eq!(
            id.to_uri(),
            "spiffe://cerebral.work/elf/platform-control/sindri"
        );

        let parsed = WimseAgentId::parse(&id.to_uri()).unwrap();
        assert_eq!(parsed, id);

        let wimse = WimseAgentId::parse("wimse://unsigned.gg/agent/hermes-01").unwrap();
        assert_eq!(wimse.scheme, WimseScheme::Wimse);
        assert_eq!(wimse.trust_domain, "unsigned.gg");
        assert_eq!(wimse.path, "agent/hermes-01");

        // Reject traversal, query strings, and non-WIMSE schemes
        assert!(WimseAgentId::parse("https://cerebral.work/elf/sindri").is_err());
        assert!(WimseAgentId::parse("spiffe://cerebral.work/elf/../root").is_err());
        assert!(WimseAgentId::parse("spiffe://cerebral.work/elf/sindri?foo=bar").is_err());
        assert!(WimseAgentId::parse("spiffe://UPPERCASE.work/elf/sindri").is_err());
    }

    #[test]
    fn test_rfc7591_validation_clauses_and_secret_redaction() {
        let agent_id = WimseAgentId::for_conclave_elf(
            "cerebral.work",
            "vidar",
            SubjectMatterMesh::IdentityGovernance,
        )
        .unwrap();
        let scopes = BTreeSet::from(["idp:read".to_string(), "mesh:attest".to_string()]);
        let mut meta = OAuth2ClientMetadata::for_agent(
            &agent_id,
            Some("vidar"),
            Some(SubjectMatterMesh::IdentityGovernance),
            &scopes,
            vec!["https://api.cerebral.work".to_string()],
            Some("https://idp.cerebral.work/.well-known/jwks.json".to_string()),
        );
        meta.client_secret = Some("top-secret-hydra-value".to_string());
        meta.registration_access_token = Some("ory_at_secret_reg_token".to_string());

        // Strict cryptographic mode passes because jwks_uri sets private_key_jwt
        assert!(meta.validate_rfc7591(true).is_ok());

        // Debug and .redacted() must never leak secrets
        let dbg_str = format!("{meta:?}");
        assert!(!dbg_str.contains("top-secret-hydra-value"));
        assert!(!dbg_str.contains("ory_at_secret_reg_token"));
        assert!(dbg_str.contains("<redacted>"));

        let redacted = meta.redacted();
        assert_eq!(redacted.client_secret.as_deref(), Some("<redacted>"));
        assert_eq!(
            redacted.registration_access_token.as_deref(),
            Some("<redacted>")
        );

        // Downgrading to client_secret_basic fails strict cryptographic agent mode
        let mut basic_agent = meta.clone();
        basic_agent.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretBasic;
        assert!(basic_agent.validate_rfc7591(false).is_ok());
        assert!(basic_agent.validate_rfc7591(true).is_err());

        // Requesting estate:superuser via DCR must be rejected
        let mut superuser_attempt = meta.clone();
        superuser_attempt.scope = Some("idp:read estate:superuser".to_string());
        assert_eq!(
            superuser_attempt.validate_rfc7591(false).unwrap_err().code,
            Rfc7591ErrorCode::InvalidScope
        );

        // authorization_code without redirect_uris or with non-HTTPS/non-loopback URI must fail
        let mut auth_code_client = meta.clone();
        auth_code_client
            .grant_types
            .push(OAuth2GrantType::AuthorizationCode);
        assert_eq!(
            auth_code_client.validate_rfc7591(false).unwrap_err().code,
            Rfc7591ErrorCode::InvalidRedirectUri
        );
        auth_code_client.redirect_uris = vec!["http://evil.example.com/cb".to_string()];
        assert_eq!(
            auth_code_client.validate_rfc7591(false).unwrap_err().code,
            Rfc7591ErrorCode::InvalidRedirectUri
        );
        auth_code_client.redirect_uris = vec!["https://auth.cerebral.work/callback".to_string()];
        assert!(auth_code_client.validate_rfc7591(false).is_ok());
    }

    #[test]
    fn test_introspected_token_to_principal_and_sovereign_root_guard() {
        let now = 1_800_000_000;

        // Active scoped agent token
        let token = IntrospectedOAuth2Token {
            active: true,
            client_id: Some("vidar-client".to_string()),
            sub: Some("spiffe://cerebral.work/elf/identity-governance/vidar".to_string()),
            scope: Some("idp:read mesh:attest".to_string()),
            exp: Some(now + 300),
            act: Some(ActorClaim {
                sub: "spiffe://cerebral.work/elf/platform-control/sindri".to_string(),
                client_id: Some("sindri-client".to_string()),
                iss: Some("https://auth.cerebral.work".to_string()),
                act: Some(Box::new(ActorClaim {
                    sub: SOLE_SUPERADMIN_EMAIL.to_string(),
                    client_id: None,
                    iss: None,
                    act: None,
                })),
            }),
            ..Default::default()
        };
        assert_eq!(
            token.to_principal(now),
            Principal::Scoped {
                scopes: BTreeSet::from(["idp:read".to_string(), "mesh:attest".to_string()])
            }
        );
        assert_eq!(
            token.resolved_actor().unwrap().chain_subjects(),
            vec![
                "spiffe://cerebral.work/elf/platform-control/sindri".to_string(),
                SOLE_SUPERADMIN_EMAIL.to_string()
            ]
        );

        // Expired token -> Denied
        assert_eq!(token.to_principal(now + 301), Principal::Denied);

        // Non-superadmin claiming estate:superuser -> Denied
        let mut rogue = token.clone();
        rogue.scope = Some("idp:read estate:superuser".to_string());
        assert_eq!(rogue.to_principal(now), Principal::Denied);

        // Sole superadmin claiming estate:superuser -> Superuser
        let mut root_token = rogue;
        root_token.sub = Some(SOLE_SUPERADMIN_EMAIL.to_string());
        assert_eq!(root_token.to_principal(now), Principal::Superuser);
    }

    #[test]
    fn test_token_exchange_request_and_form_urlencoded_roundtrip() {
        let req = TokenExchangeRequest {
            subject_token: "eyJhbGciOiJSUzI1NiJ9.user_token".to_string(),
            subject_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
            actor_token: Some("eyJhbGciOiJSUzI1NiJ9.agent_wit".to_string()),
            actor_token_type: Some(TOKEN_TYPE_JWT.to_string()),
            requested_token_type: Some(TOKEN_TYPE_TRANSACTION_TOKEN.to_string()),
            audience: vec![
                "https://llm.unsigned.gg/v1".to_string(),
                "https://xerj.tail769bd2.ts.net:9200".to_string(),
            ],
            scope: Some("llm:chat xerj:search".to_string()),
            resource: None,
        };
        assert!(req.validate().is_ok());

        let dbg_str = format!("{req:?}");
        assert!(!dbg_str.contains("user_token"));
        assert!(!dbg_str.contains("agent_wit"));

        let pairs = req.to_form_pairs();
        let encoded = encode_form_urlencoded(&pairs);
        let decoded = decode_form_urlencoded(&encoded);
        assert_eq!(decoded, pairs);
    }
}
