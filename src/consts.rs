//! Centralized names: directories, files, env vars, and markers. Anything path-like or
//! shared across modules lives here instead of inline, so there's one place to change it.
//! (Feature-local constants — e.g. a feature's regex patterns — stay with their feature.)

/// keel's private directory under `$HOME` (holds the PATH shims, etc.).
pub const KEEL_DIR: &str = ".keel";
/// Subdirectory of [`KEEL_DIR`] holding the busybox shim symlinks.
pub const SHIM_BIN_SUBDIR: &str = "bin";
/// Decision-log file name (under `~/<KEEL_DIR>/`): one JSONL line per hook call.
pub const DECISION_LOG_NAME: &str = "decisions.jsonl";
/// Per-project config file, looked up under the project root.
pub const CONFIG_FILE: &str = ".keel.json";
/// Git directory name, used for project-root discovery.
pub const GIT_DIR: &str = ".git";

/// Marker key tagging every hook entry keel adds — enables idempotent `apply` and a
/// clean `uninstall` (only keel-tagged entries are removed).
pub const KEEL_MARKER: &str = "__keel";

/// Environment overrides.
pub const ENV_HOME: &str = "KEEL_HOME"; // override $HOME for install/shim paths
pub const ENV_ROOT: &str = "KEEL_ROOT"; // force the project root
pub const ENV_CONFIG: &str = "KEEL_CONFIG"; // path to the config file

/// The command a registered hook invokes: `keel run <platform> <stage>`.
pub fn hook_command(platform: &str, stage: &str) -> String {
    format!("keel run {platform} {stage}")
}

/// The command a carryover hook invokes: `keel carryover-hook <platform> <stage>`.
pub fn carryover_command(platform: &str, stage: &str) -> String {
    format!("keel carryover-hook {platform} {stage}")
}
