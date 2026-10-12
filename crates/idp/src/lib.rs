// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Identity Provider (idp) library for unsigned-gg and Clockwork Conclave bots.
//!
//! Provides GitHub App Manifest generation, conversion code exchange,
//! RS256 JWT minting, and installation access token brokering.

pub mod error;
pub mod manifest;
pub mod registry;
pub mod token;

pub use error::IdpError;
pub use manifest::{AppManifest, ConversionResponse, HookAttributes};
pub use registry::{CONCLAVE_ELVES, ElfPersona, KeyStore};
pub use token::{InstallationToken, TokenBroker};
