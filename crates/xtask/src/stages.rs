//! Compiled DAG stage definitions for `cargo xwork`, lowered from `projectfile.yaml`.

/// A single stage in the `xwork` execution DAG.
#[derive(Debug, Clone, Copy)]
pub struct Stage {
    /// Unique stage identifier lowered from `org.projectfile.ci.nodes`.
    pub name: &'static str,
    /// Upstream stage dependencies that must complete before this stage runs.
    pub deps: &'static [&'static str],
    /// Executable command.
    pub command: &'static str,
    /// Command arguments.
    pub args: &'static [&'static str],
}

/// Topologically ordered `xwork` stages lowered from `projectfile.yaml`.
pub const XWORK_STAGES: &[Stage] = &[
    Stage {
        name: "toolchain-check",
        deps: &[],
        command: "cargo",
        args: &["xtask", "toolchain-check"],
    },
    Stage {
        name: "projectfile-check",
        deps: &["toolchain-check"],
        command: "cargo",
        args: &["xtask", "projectfile-check"],
    },
    Stage {
        name: "spec-check",
        deps: &["projectfile-check"],
        command: "cargo",
        args: &["xtask", "spec-check"],
    },
    Stage {
        name: "stages-check",
        deps: &["projectfile-check"],
        command: "cargo",
        args: &["xtask", "stages-check"],
    },
    Stage {
        name: "zero-io-domain",
        deps: &["projectfile-check"],
        command: "cargo",
        args: &["xtask", "zero-io-domain"],
    },
    Stage {
        name: "cargo-fmt",
        deps: &[
            "projectfile-check",
            "spec-check",
            "stages-check",
            "zero-io-domain",
        ],
        command: "cargo",
        args: &["fmt", "--all", "--", "--check"],
    },
    Stage {
        name: "cargo-clippy",
        deps: &["cargo-fmt"],
        command: "cargo",
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "-j",
            "2",
            "--",
            "-D",
            "warnings",
        ],
    },
    Stage {
        name: "cargo-test",
        deps: &["cargo-clippy"],
        command: "cargo",
        args: &["test", "--workspace", "-j", "2"],
    },
    Stage {
        name: "cargo-doc-test",
        deps: &["cargo-test"],
        command: "cargo",
        args: &["test", "--workspace", "--doc", "-j", "2"],
    },
];
