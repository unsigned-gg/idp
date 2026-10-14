// Copyright 2026 Christian M. Todie <chris@todie.io>
// SPDX-License-Identifier: Apache-2.0 OR MIT OR CC0-1.0

//! Registry definitions for Clockwork Conclave bots and host key management.

use crate::error::IdpError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Static persona definition for an agentic bot in the Conclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfPersona {
    /// Identity tag (lowercase alphanumeric, e.g. "sindri").
    pub id: &'static str,
    /// Human-readable title.
    pub name: &'static str,
    /// Associated repository or component.
    pub repo: &'static str,
    /// Architectural role.
    pub role: &'static str,
    /// Functional description.
    pub desc: &'static str,
}

/// The 16 canonical Clockwork Conclave personas.
pub const CONCLAVE_ELVES: &[ElfPersona] = &[
    ElfPersona {
        id: "sindri",
        name: "Sindri",
        repo: "revenant",
        role: "coordinator / sensing",
        desc: "Audit coordinator, system sensing, and health watchdog",
    },
    ElfPersona {
        id: "idunn",
        name: "Idunn",
        repo: "sbx",
        role: "containment / custody",
        desc: "Linux sandbox isolation, packaging custody, and verification",
    },
    ElfPersona {
        id: "brokkr",
        name: "Brokkr",
        repo: "kd",
        role: "process supervisor",
        desc: "Kernel daemon, pidfd lifecycle, and epoll supervisor",
    },
    ElfPersona {
        id: "mimir",
        name: "Mimir",
        repo: "revenant",
        role: "formal architect",
        desc: "Operational semantics, protocol invariants, and LeanSpec models",
    },
    ElfPersona {
        id: "loki",
        name: "Loki",
        repo: "revenant",
        role: "concurrency / fuzzing",
        desc: "Concurrency stress testing, race detection, and adversarial review",
    },
    ElfPersona {
        id: "thjalfi",
        name: "Thjalfi",
        repo: "revenant",
        role: "profiling / efficiency",
        desc: "Instruction profiling, memory footprint optimization, and benchmarks",
    },
    ElfPersona {
        id: "volva",
        name: "Volva",
        repo: "dgr",
        role: "workflow orchestration",
        desc: "DAG runtime engine, state graphs, and trajectory tracking",
    },
    ElfPersona {
        id: "kratos",
        name: "Kratos",
        repo: "gs",
        role: "cluster control",
        desc: "Godseat cluster operator, invariant verification, and gate policy",
    },
    ElfPersona {
        id: "sigyn",
        name: "Sigyn",
        repo: "ls",
        role: "specification parser",
        desc: "LeanSpec parser, AST validator, and CAS verification",
    },
    ElfPersona {
        id: "alrisha",
        name: "Alrisha",
        repo: "awesome",
        role: "ecosystem catalog",
        desc: "Documentation integrity, link validation, and catalog curation",
    },
    ElfPersona {
        id: "thuban",
        name: "Thuban",
        repo: "autoresearcher",
        role: "autonomous research",
        desc: "eBPF telemetry verification, iterative ratchets, and experimentation",
    },
    ElfPersona {
        id: "gullveig",
        name: "Gullveig",
        repo: "ep",
        role: "deterministic dispatch",
        desc: "Escapement discrete time loopback proxy and egress regulation",
    },
    ElfPersona {
        id: "heimdall",
        name: "Heimdall",
        repo: "wak",
        role: "traffic gate",
        desc: "Accept-and-hold wake gateway and TCP ingress management",
    },
    ElfPersona {
        id: "forseti",
        name: "Forseti",
        repo: "k8",
        role: "fleet reconciler",
        desc: "Kubernetes reconciler, CRD controllers, and fleet gates",
    },
    ElfPersona {
        id: "bragi",
        name: "Bragi",
        repo: ".github",
        role: "constitutional charter",
        desc: "Constitutional governance, CC0 licensing, and ASCII compliance",
    },
    ElfPersona {
        id: "vali",
        name: "Vali",
        repo: "kl",
        role: "kernel security",
        desc: "Linux Landlock LSM, seccomp filters, and kernel link primitives",
    },
];

/// Extended estate Clockwork Elves (22 total: 16 core Conclave + 6 platform/memory/auth elves).
pub const ALL_ESTATE_ELVES: &[ElfPersona] = &[
    ElfPersona {
        id: "sindri",
        name: "Sindri",
        repo: "revenant",
        role: "coordinator / sensing",
        desc: "Audit coordinator, system sensing, and health watchdog",
    },
    ElfPersona {
        id: "idunn",
        name: "Idunn",
        repo: "sbx",
        role: "containment / custody",
        desc: "Linux sandbox isolation, packaging custody, and verification",
    },
    ElfPersona {
        id: "brokkr",
        name: "Brokkr",
        repo: "kd",
        role: "process supervisor",
        desc: "Kernel daemon, pidfd lifecycle, and epoll supervisor",
    },
    ElfPersona {
        id: "mimir",
        name: "Mimir",
        repo: "revenant",
        role: "formal architect",
        desc: "Operational semantics, protocol invariants, and LeanSpec models",
    },
    ElfPersona {
        id: "loki",
        name: "Loki",
        repo: "revenant",
        role: "concurrency / fuzzing",
        desc: "Concurrency stress testing, race detection, and adversarial review",
    },
    ElfPersona {
        id: "thjalfi",
        name: "Thjalfi",
        repo: "revenant",
        role: "profiling / efficiency",
        desc: "Instruction profiling, memory footprint optimization, and benchmarks",
    },
    ElfPersona {
        id: "volva",
        name: "Volva",
        repo: "dgr",
        role: "workflow orchestration",
        desc: "DAG runtime engine, state graphs, and trajectory tracking",
    },
    ElfPersona {
        id: "kratos",
        name: "Kratos",
        repo: "gs",
        role: "cluster control",
        desc: "Godseat cluster operator, invariant verification, and gate policy",
    },
    ElfPersona {
        id: "sigyn",
        name: "Sigyn",
        repo: "ls",
        role: "specification parser",
        desc: "LeanSpec parser, AST validator, and CAS verification",
    },
    ElfPersona {
        id: "alrisha",
        name: "Alrisha",
        repo: "awesome",
        role: "ecosystem catalog",
        desc: "Documentation integrity, link validation, and catalog curation",
    },
    ElfPersona {
        id: "thuban",
        name: "Thuban",
        repo: "autoresearcher",
        role: "autonomous research",
        desc: "eBPF telemetry verification, iterative ratchets, and experimentation",
    },
    ElfPersona {
        id: "gullveig",
        name: "Gullveig",
        repo: "ep",
        role: "deterministic dispatch",
        desc: "Escapement discrete time loopback proxy and egress regulation",
    },
    ElfPersona {
        id: "heimdall",
        name: "Heimdall",
        repo: "wak",
        role: "traffic gate",
        desc: "Accept-and-hold wake gateway and TCP ingress management",
    },
    ElfPersona {
        id: "forseti",
        name: "Forseti",
        repo: "k8",
        role: "fleet reconciler",
        desc: "Kubernetes reconciler, CRD controllers, and fleet gates",
    },
    ElfPersona {
        id: "bragi",
        name: "Bragi",
        repo: ".github",
        role: "constitutional charter",
        desc: "Constitutional governance, CC0 licensing, and ASCII compliance",
    },
    ElfPersona {
        id: "vali",
        name: "Vali",
        repo: "kl",
        role: "kernel security",
        desc: "Linux Landlock LSM, seccomp filters, and kernel link primitives",
    },
    ElfPersona {
        id: "njord",
        name: "Njord",
        repo: "ch",
        role: "cache store",
        desc: "Distributed artifact cache and CAS storage broker",
    },
    ElfPersona {
        id: "norns",
        name: "Norns",
        repo: "mem",
        role: "memory continuity",
        desc: "Long-term observation graph and session handoff weaver",
    },
    ElfPersona {
        id: "sol",
        name: "Sol",
        repo: "search",
        role: "index & retrieval",
        desc: "Hybrid lexical/vector search and corpus indexing",
    },
    ElfPersona {
        id: "vidar",
        name: "Vidar",
        repo: "auth",
        role: "identity & attestation",
        desc: "Identity reconciliation, token brokering, and attestation verification",
    },
    ElfPersona {
        id: "ratatoskr",
        name: "Ratatoskr",
        repo: "bus",
        role: "mesh courier",
        desc: "Inter-agent message routing and event transport",
    },
    ElfPersona {
        id: "tyr",
        name: "Tyr",
        repo: "gate",
        role: "policy enforcement",
        desc: "Capability envelope enforcement and admission control",
    },
];

/// Looks up an elf persona by id across all 22 estate elves.
pub fn find_elf(id: &str) -> Option<&'static ElfPersona> {
    let needle = id.trim().to_ascii_lowercase();
    let needle = needle.strip_suffix("-bot[bot]").unwrap_or(&needle);
    let needle = needle.strip_suffix("-bot").unwrap_or(needle);
    ALL_ESTATE_ELVES.iter().find(|e| e.id == needle)
}

/// Returns true if the given GitHub login or actor handle belongs to a registered Clockwork Elf or runner bot.
pub fn is_automation_login(login: &str) -> bool {
    let lower = login.trim().to_ascii_lowercase();
    if lower == "runner-bot" || lower == "runner-bot[bot]" {
        return true;
    }
    find_elf(&lower).is_some()
}

/// Host storage manager for bot private keys and registration metadata.
pub struct KeyStore {
    base_dir: PathBuf,
}

impl Default for KeyStore {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Self::new(Path::new(&home).join(".config/revenant/keys"))
    }
}

impl KeyStore {
    /// Creates a key store backed by the specified directory path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: path.into(),
        }
    }

    /// Returns the directory path for key storage.
    pub fn dir(&self) -> &Path {
        &self.base_dir
    }

    /// Ensures the keys directory exists with restrictive 0700 permissions.
    pub fn ensure_dir(&self) -> Result<(), IdpError> {
        fs::create_dir_all(&self.base_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.base_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    /// Returns the path to the PEM private key for the given bot identifier.
    pub fn key_path(&self, bot_id: &str) -> PathBuf {
        let candidate_bot = self.base_dir.join(format!("{bot_id}-bot.pem"));
        if candidate_bot.exists() {
            return candidate_bot;
        }
        self.base_dir.join(format!("{bot_id}.pem"))
    }

    /// Checks if a private key exists for the given bot identifier.
    pub fn has_key(&self, bot_id: &str) -> bool {
        self.key_path(bot_id).exists()
    }

    /// Reads the PEM private key for the given bot identifier.
    pub fn read_key(&self, bot_id: &str) -> Result<String, IdpError> {
        let path = self.key_path(bot_id);
        if !path.exists() {
            return Err(IdpError::KeyMissing(path.display().to_string()));
        }
        Ok(fs::read_to_string(path)?)
    }

    /// Writes a private key to disk with strict 0600 file permissions.
    pub fn write_key(&self, bot_name: &str, pem: &str) -> Result<PathBuf, IdpError> {
        self.ensure_dir()?;
        let target = self.base_dir.join(format!("{bot_name}.pem"));
        fs::write(&target, pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        }
        Ok(target)
    }

    /// Writes registration metadata JSON to disk with strict 0600 file permissions.
    pub fn write_metadata(&self, bot_name: &str, json_data: &str) -> Result<PathBuf, IdpError> {
        self.ensure_dir()?;
        let target = self.base_dir.join(format!("{bot_name}.json"));
        fs::write(&target, json_data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        }
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conclave_elves_count_and_uniqueness() {
        assert_eq!(CONCLAVE_ELVES.len(), 16);
        let mut ids = std::collections::HashSet::new();
        for elf in CONCLAVE_ELVES {
            assert!(ids.insert(elf.id), "duplicate elf id: {}", elf.id);
            assert!(!elf.name.is_empty());
            assert!(!elf.repo.is_empty());
        }
    }

    #[test]
    fn test_keystore_permissions() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = KeyStore::new(temp_dir.path());
        store.ensure_dir().expect("ensure dir");

        let key_path = store
            .write_key("test-bot", "TEST_KEY_PEM")
            .expect("write key");
        assert!(key_path.exists());
        assert_eq!(store.read_key("test-bot").unwrap(), "TEST_KEY_PEM");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&key_path).expect("get metadata");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }
}
