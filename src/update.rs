//! `keel update [--check]` — check for and install a newer keel.
//!
//! keel is zero-runtime-dep, so this shells out to the system `curl` (to hit the GitHub
//! releases API) and, for Homebrew installs, delegates to `brew upgrade` — never a bundled
//! HTTP client. For a Homebrew-managed binary, replacing it out-of-band would break brew's
//! bookkeeping, so we always defer to brew there; standalone installs get download guidance.

use std::process::Command;

use crate::consts;

/// Parse `v0.1.5` / `0.1.5` → `(major, minor, patch)`.
fn parse_ver(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// Is `latest` a newer version than `current`? (numeric compare — 0.1.10 > 0.1.9)
fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_ver(current), parse_ver(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Latest release tag from GitHub, via the system `curl`. None on any failure (offline,
/// no curl, rate-limited) — the caller reports gracefully.
fn latest_tag() -> Option<String> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        consts::REPO
    );
    let out = Command::new("curl")
        .args(["-fsSL", "-H", "Accept: application/vnd.github+json", &url])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v.get("tag_name").and_then(|t| t.as_str()).map(String::from)
}

/// Is the running keel a Homebrew install? (the exe lives under `brew --prefix`)
fn brew_managed() -> bool {
    let prefix = Command::new("brew")
        .arg("--prefix")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|p| !p.is_empty());
    match (prefix, std::env::current_exe().ok()) {
        (Some(p), Some(exe)) => exe.starts_with(&p),
        _ => false,
    }
}

pub fn run(args: &[String]) -> i32 {
    let current = env!("CARGO_PKG_VERSION");
    let check_only = args.iter().any(|a| a == "--check");

    let Some(tag) = latest_tag() else {
        eprintln!(
            "keel update: couldn't reach GitHub (needs `curl` + network). You're on {current}."
        );
        return 1;
    };
    if !is_newer(current, &tag) {
        println!("keel {current} is up to date (latest release: {tag}).");
        return 0;
    }
    println!("keel {current} → {tag} is available.");
    if check_only {
        return 0;
    }
    if brew_managed() {
        println!("Updating via Homebrew…");
        let ok = Command::new("brew")
            .args(["upgrade", &format!("{}/keel", consts::REPO)])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        return i32::from(!ok);
    }
    println!(
        "Not a Homebrew install — download {tag} from:\n  https://github.com/{}/releases/tag/{tag}",
        consts::REPO
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare_is_numeric_not_lexical() {
        assert!(is_newer("0.1.3", "v0.1.4"));
        assert!(is_newer("0.1.9", "0.1.10")); // numeric, not string compare
        assert!(is_newer("0.1.4", "0.2.0"));
        assert!(!is_newer("0.1.4", "0.1.4"));
        assert!(!is_newer("0.2.0", "0.1.9"));
        assert!(!is_newer("0.1.4", "not-a-version"));
    }

    #[test]
    fn parses_tag_forms() {
        assert_eq!(parse_ver("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_ver("1.2"), Some((1, 2, 0)));
        assert_eq!(parse_ver("nope"), None);
    }
}
