//! Busybox shim + transparent install lifecycle (tas-style).
//!
//! Invoked as `claude`/`codex`/`antigravity` (via the symlinks `keel init` drops on
//! PATH), keel re-applies the hooks and then `exec`s the real agent.

use std::path::{Path, PathBuf};

use crate::agent::{self, Agent, AGENTS};
use crate::consts;
use crate::registry;

pub fn keel_bin_dir() -> PathBuf {
    agent::home()
        .join(consts::KEEL_DIR)
        .join(consts::SHIM_BIN_SUBDIR)
}

/// Shim mode. Re-apply hooks (best-effort, never block), then exec the real agent.
pub fn run_shim(name: &str) -> ! {
    // Apply is best-effort and panic-isolated: nothing here may stop the real agent.
    if let Some(a) = agent::agent_by_bin(name) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| agent::apply(a)));
    }
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    match find_real(name, &keel_bin_dir(), self_exe.as_deref()) {
        Some(real) => {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(&real)
                .args(std::env::args_os().skip(1))
                .exec();
            eprintln!("keel: failed to exec {}: {err}", real.display());
            std::process::exit(127);
        }
        None => {
            eprintln!("keel: real '{name}' not found on PATH (only the keel shim)");
            std::process::exit(127);
        }
    }
}

/// Resolve the real agent binary. Skips the shim dir AND any candidate that canonicalizes
/// to keel itself — a fork-bomb guard that holds even if the shim dir is listed oddly in PATH.
fn find_real(name: &str, shim_dir: &Path, self_exe: Option<&Path>) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    find_real_in(std::env::split_paths(&path), name, shim_dir, self_exe)
}

fn find_real_in<I: Iterator<Item = PathBuf>>(
    dirs: I,
    name: &str,
    shim_dir: &Path,
    self_exe: Option<&Path>,
) -> Option<PathBuf> {
    for dir in dirs {
        if dir == shim_dir {
            continue;
        }
        let cand = dir.join(name);
        if !agent::is_executable(&cand) {
            continue;
        }
        if self_exe.is_some() && std::fs::canonicalize(&cand).ok().as_deref() == self_exe {
            continue; // resolves to the keel binary — would re-invoke the shim (fork-bomb)
        }
        return Some(cand);
    }
    None
}

fn symlink_shim(a: &Agent, target: &Path) -> std::io::Result<()> {
    let link = keel_bin_dir().join(a.bin);
    if std::fs::symlink_metadata(&link).is_ok() {
        std::fs::remove_file(&link).ok();
    }
    std::os::unix::fs::symlink(target, &link)
}

fn path_has_bin_dir() -> bool {
    let dir = keel_bin_dir();
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d == dir))
        .unwrap_or(false)
}

/// The shell rc to write the PATH line into, from `$SHELL`. None if unsupported (fish etc.).
fn shell_rc() -> Option<PathBuf> {
    let shell = std::env::var("SHELL").ok()?;
    let rc = match Path::new(&shell).file_name()?.to_str()? {
        "zsh" => ".zshrc",
        "bash" => ".bashrc",
        _ => return None,
    };
    Some(agent::home().join(rc))
}

fn path_block(bin_dir: &Path) -> String {
    format!(
        "{}\nexport PATH=\"{}:$PATH\"\n{}\n",
        consts::PATH_BLOCK_BEGIN,
        bin_dir.display(),
        consts::PATH_BLOCK_END,
    )
}

/// Append keel's marked PATH block to `rc` if not already present. Returns whether it added.
fn write_path_block(rc: &Path, bin_dir: &Path) -> bool {
    let existing = std::fs::read_to_string(rc).unwrap_or_default();
    if existing.contains(consts::PATH_BLOCK_BEGIN) {
        return false; // idempotent
    }
    use std::io::Write;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(rc)
    else {
        return false;
    };
    let sep = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    write!(f, "{sep}\n{}", path_block(bin_dir)).is_ok()
}

/// Remove keel's marked PATH block from `rc` (for uninstall).
fn strip_path_block(rc: &Path) {
    let Ok(text) = std::fs::read_to_string(rc) else {
        return;
    };
    if !text.contains(consts::PATH_BLOCK_BEGIN) {
        return;
    }
    let mut out = String::new();
    let mut skipping = false;
    for line in text.lines() {
        if line.trim() == consts::PATH_BLOCK_BEGIN {
            skipping = true;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
        if skipping && line.trim() == consts::PATH_BLOCK_END {
            skipping = false;
        }
    }
    let out = out.trim_end_matches('\n');
    let _ = std::fs::write(
        rc,
        if out.is_empty() {
            String::new()
        } else {
            format!("{out}\n")
        },
    );
}

/// Add the shim dir to the shell PATH (idempotent). Returns `(rc, newly_added)`.
fn ensure_path_on_shell(bin_dir: &Path) -> Option<(PathBuf, bool)> {
    let rc = shell_rc()?;
    let added = write_path_block(&rc, bin_dir);
    Some((rc, added))
}

pub fn init() -> i32 {
    let bin_dir = keel_bin_dir();
    if let Err(e) = std::fs::create_dir_all(&bin_dir) {
        eprintln!("keel: cannot create {}: {e}", bin_dir.display());
        return 1;
    }
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("keel"));
    let mut attached: Vec<String> = Vec::new();
    for a in AGENTS {
        if !agent::detect(a) {
            continue;
        }
        if let Err(e) = symlink_shim(a, &exe) {
            eprintln!("keel: shim for {} failed: {e}", a.bin);
            continue;
        }
        let _ = agent::apply(a);
        attached.push(agent::label(a));
    }
    if attached.is_empty() {
        println!("keel init: no agents detected (looked for claude / codex / antigravity).");
    } else {
        println!("keel init: attached to {}.", attached.join(", "));
    }
    if !path_has_bin_dir() {
        match ensure_path_on_shell(&bin_dir) {
            Some((rc, true)) => println!(
                "  added the shim dir to PATH in {} — restart your shell (or `source {}`).",
                rc.display(),
                rc.display()
            ),
            Some((rc, false)) => println!(
                "  shim PATH already set in {} — restart your shell if it isn't active yet.",
                rc.display()
            ),
            None => println!(
                "  add the shim dir to PATH (then restart your shell):\n    export PATH=\"{}:$PATH\"",
                bin_dir.display()
            ),
        }
    }
    0
}

pub fn apply_all() -> i32 {
    let mut n = 0;
    for a in AGENTS {
        if agent::detect(a) {
            let _ = agent::apply(a);
            n += 1;
        }
    }
    println!("keel apply: refreshed hooks for {n} agent(s).");
    0
}

pub fn uninstall() -> i32 {
    for a in AGENTS {
        let _ = agent::clean(a);
        std::fs::remove_file(keel_bin_dir().join(a.bin)).ok();
    }
    if let Some(rc) = shell_rc() {
        strip_path_block(&rc);
    }
    std::fs::remove_dir_all(agent::home().join(consts::KEEL_DIR)).ok();
    println!("keel uninstall: removed shims, keel-tagged hooks, and the PATH block.");
    0
}

pub fn doctor() -> i32 {
    println!("keel {} ok", env!("CARGO_PKG_VERSION"));
    let active: Vec<&str> = registry::load(&serde_json::Value::Null)
        .iter()
        .map(|f| f.name())
        .collect();
    println!("  features active (default): {}", active.join(", "));
    let bin_dir = keel_bin_dir();
    println!(
        "  shim dir {}: {}",
        bin_dir.display(),
        if path_has_bin_dir() {
            "on PATH"
        } else {
            "NOT on PATH"
        }
    );
    for a in AGENTS {
        if !agent::detect(a) {
            println!("  {:<18} not detected", agent::label(a));
            continue;
        }
        let shimmed = std::fs::symlink_metadata(bin_dir.join(a.bin)).is_ok();
        println!(
            "  {:<18} detected · shim {} · {} hooks applied",
            agent::label(a),
            if shimmed { "✓" } else { "✗" },
            agent::applied_count(a)
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_exec(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn find_real_skips_shim_dir() {
        let base = std::env::temp_dir().join(format!("keel-fr-{}", std::process::id()));
        let shim = base.join("shimbin");
        let real = base.join("realbin");
        mk_exec(&shim, "claude"); // the shim symlink stand-in
        let real_claude = mk_exec(&real, "claude");
        let dirs = vec![shim.clone(), real.clone()].into_iter();
        // shim dir is skipped → resolves to the real one
        assert_eq!(find_real_in(dirs, "claude", &shim, None), Some(real_claude));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn path_block_write_idempotent_and_strip() {
        let dir = std::env::temp_dir().join(format!("keel-rc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rc = dir.join(".zshrc");
        std::fs::write(&rc, "# user's own line\n").unwrap();
        let bin = dir.join(".keel/bin");

        assert!(write_path_block(&rc, &bin)); // first write adds
        let txt = std::fs::read_to_string(&rc).unwrap();
        assert!(txt.contains(consts::PATH_BLOCK_BEGIN));
        assert!(txt.contains(&bin.display().to_string()));
        assert!(txt.contains("# user's own line")); // user's content preserved

        assert!(!write_path_block(&rc, &bin)); // idempotent — no second block
        assert_eq!(
            std::fs::read_to_string(&rc)
                .unwrap()
                .matches(consts::PATH_BLOCK_BEGIN)
                .count(),
            1
        );

        strip_path_block(&rc);
        let after = std::fs::read_to_string(&rc).unwrap();
        assert!(!after.contains(consts::PATH_BLOCK_BEGIN));
        assert!(after.contains("# user's own line")); // only keel's block removed
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_real_self_exclusion_prevents_forkbomb() {
        let base = std::env::temp_dir().join(format!("keel-fr2-{}", std::process::id()));
        let real = base.join("realbin");
        let claude = mk_exec(&real, "claude");
        let canon = std::fs::canonicalize(&claude).unwrap();
        // even though shim_dir doesn't match, the candidate IS keel itself → skipped → None
        let dirs = vec![real.clone()].into_iter();
        assert_eq!(
            find_real_in(dirs, "claude", Path::new("/nonexistent"), Some(&canon)),
            None
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
