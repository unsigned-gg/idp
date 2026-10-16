# Makefile for idp (Identity Provider, Conclave Bot Manager & Directory Reconciler)
# Host Throttling: Physical host ceres runs multiple active agent sessions.
# Shared workstations keep JOBS=2 to prevent CPU starvation and OOM.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

JOBS ?= 2
export JOBS

.PHONY: help default xwork check graph-audit zero-io-domain projectfile-check \
        stages-check spec-check toolchain-check branch-hygiene build install \
        fmt fmt-check clippy test doc-test ci deny audit smoke

##@ General

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

default: help

##@ Verification & CI Gates (cargo xtask)

xwork: ## Execute the full compiled projectfile.yaml CI DAG (cargo xwork)
	cargo xwork

check: ## Run DBR-admitted verification pipeline with CAS receipts
	cargo xtask check --enforce-dbr

ci: ## Run full CI verification gates
	cargo xwork
	cargo xtask graph-audit --break-check
	cargo xtask check --break-check

graph-audit: ## Verify workspace crate DAG and Wave-0 idp-domain purity
	cargo xtask graph-audit --break-check

zero-io-domain: ## Verify Wave-0 idp-domain has zero I/O or runtime dependencies
	cargo xtask zero-io-domain

projectfile-check: ## Validate projectfile.yaml schema and CI nodes
	cargo xtask projectfile-check

stages-check: ## Verify stages.rs matches projectfile.yaml
	cargo xtask stages-check

spec-check: ## Validate markdown specs in specs/*.md
	cargo xtask spec-check

toolchain-check: ## Verify active rustc matches rust-toolchain.toml
	cargo xtask toolchain-check

branch-hygiene: ## Audit merged local git branches
	cargo xtask branch-hygiene --dry-run

##@ Build & Install

build: ## Compile the workspace with host throttling (-j 2)
	cargo build --workspace -j $(JOBS)

install: ## Install idp CLI to ~/.cargo/bin/idp
	cargo xtask install

smoke: ## Build CLI and run smoke tests
	cargo build --package idp-cli -j $(JOBS)
	cargo run --package idp-cli -j $(JOBS) -- bot list

##@ Code Quality & Supply Chain

fmt: ## Format all Rust code
	cargo fmt --all

fmt-check: ## Check code formatting without modifying
	cargo fmt --all -- --check

clippy: ## Lint workspace with clippy (-D warnings)
	cargo clippy --workspace --all-targets -j $(JOBS) -- -D warnings

test: ## Run unit and integration tests with bounded threads
	cargo test --workspace -j $(JOBS)

doc-test: ## Run documentation tests
	cargo test --doc --workspace -j $(JOBS)

deny: ## Audit licenses, bans, and advisories via cargo-deny
	cargo deny check

audit: ## Check dependencies for known security advisories
	cargo audit
