//! Busybox shim + transparent install lifecycle (tas-style).
//!
//! Invoked as `claude`/`codex`/`antigravity` (via the symlinks `keel init` drops on
//! PATH), keel re-applies the hooks and then `exec`s the real agent.

use std::path::{Path, PathBuf};

use crate::agent::{self, Agent, AGENTS};

pub fn keel_bin_dir() -> PathBuf {
    agent::home().join(".keel").join("bin")
}

/// Shim mode. Re-apply hooks (best-effort, never block), then exec the real agent.
/// Fork-bomb avoided by excluding the shim dir from PATH when resolving the binary.
pub fn run_shim(name: &str) -> ! {
    if let Some(a) = agent::agent_by_bin(name) {
        let _ = agent::apply(a);
    }
    let exclude = keel_bin_dir();
    match agent::find_on_path(name, Some(exclude.as_path())) {
        Some(real) => {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(&real)
                .args(std::env::args_os().skip(1))
                .exec();
            eprintln!("keel: failed to exec {}: {err}", real.display());
            std::process::exit(127);
        }
        None => {
            eprintln!("keel: real '{name}' not found on PATH (excluding the keel shim dir)");
            std::process::exit(127);
        }
    }
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

pub fn init() -> i32 {
    let bin_dir = keel_bin_dir();
    if let Err(e) = std::fs::create_dir_all(&bin_dir) {
        eprintln!("keel: cannot create {}: {e}", bin_dir.display());
        return 1;
    }
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("keel"));
    let mut attached = Vec::new();
    for a in AGENTS {
        if !agent::detect(a) {
            continue;
        }
        if let Err(e) = symlink_shim(a, &exe) {
            eprintln!("keel: shim for {} failed: {e}", a.bin);
            continue;
        }
        let _ = agent::apply(a);
        attached.push(a.name);
    }
    if attached.is_empty() {
        println!("keel init: no agents detected (looked for claude / codex / antigravity).");
    } else {
        println!("keel init: attached to {}.", attached.join(", "));
    }
    if !path_has_bin_dir() {
        println!(
            "\n  Add the shim dir to PATH (then restart your shell):\n    export PATH=\"{}:$PATH\"",
            bin_dir.display()
        );
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
    std::fs::remove_dir_all(agent::home().join(".keel")).ok();
    println!("keel uninstall: removed shims and keel-tagged hooks.");
    0
}

pub fn doctor() -> i32 {
    println!("keel {} ok", env!("CARGO_PKG_VERSION"));
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
            println!("  {:<11} not detected", a.name);
            continue;
        }
        let shimmed = std::fs::symlink_metadata(bin_dir.join(a.bin)).is_ok();
        println!(
            "  {:<11} detected · shim {} · {} hooks applied",
            a.name,
            if shimmed { "✓" } else { "✗" },
            agent::applied_count(a)
        );
    }
    0
}
