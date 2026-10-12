# idp

Identity provider and Conclave bot manager for unsigned-gg.

## Overview

The `idp` workspace provides identity management and bot provisioning for the unsigned-gg organization.
It implements the GitHub App Manifest flow to register dedicated bot identities for Clockwork Conclave personas.
It manages RS256 token signing and brokers GitHub App installation access tokens.

Host throttling rule: ceres runs multiple active agent sessions.
All cargo invocations must specify `-j 2` to prevent memory exhaustion and CPU starvation.

## Architecture

The workspace contains two crates:

- `crates/idp`: Core library providing:
  - GitHub App manifest models (`AppManifest`, `HookAttributes`).
  - Conversion payload parsers (`ConversionResponse`).
  - RS256 JWT minting (`TokenBroker::mint_jwt`).
  - GitHub App installation token exchange (`TokenBroker::create_installation_token`).
  - Local keystore management with 0600 file permission enforcement (`KeyStore`).
  - Clockwork Conclave persona catalog (`CONCLAVE_ELVES`).

- `crates/idp-cli`: Administrative command-line tool `idp` providing:
  - `idp manifest generate`: Emits GitHub App manifest JSON for any Conclave elf.
  - `idp manifest serve`: Runs the local Axum web server to mint bot identities via browser forms.
  - `idp token get`: Mints an RS256 JWT or exchanges for a scoped installation access token.
  - `idp bot list`: Displays local registration status and private key file paths for all 16 bots.

## Security and Invariants

1. Private keys are stored in `~/.config/revenant/keys/` with mode `0600`.
2. Directory permissions enforce mode `0700`.
3. Installation tokens are short-lived bearer tokens scoped to the unsigned-gg organization.
4. RS256 JWT expiration is bounded to 9 minutes with a 60-second backward drift window.
5. All source files and documentation adhere to 7-bit ASCII and ASD-STE100 controlled language.

## Quick Start

### Build

```bash
cargo build --workspace -j 2
```

### Run Tests

```bash
cargo test --workspace -j 2
```

### Inspect Conclave Bots

```bash
cargo run --package idp-cli -j 2 -- bot list
```

### Generate Manifest

```bash
cargo run --package idp-cli -j 2 -- manifest generate --bot sindri
```

### Run Minting Server

```bash
cargo run --package idp-cli -j 2 -- manifest serve --port 8787
```

## License

This project is licensed under Apache-2.0 OR MIT OR CC0-1.0.
See `LICENSE-CC0`, `LICENSE-MIT`, and `LICENSE-APACHE` for details.
