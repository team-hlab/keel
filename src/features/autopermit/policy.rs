//! Pure file-tool decisions. No I/O.

use std::sync::LazyLock;

use regex::Regex;

use crate::model::Decision;

/// An unexpanded brace *expansion* (`{a,b}`, `{1..9}`) still present in an operand — means brace
/// expansion couldn't resolve it. A literal `{}` (find's placeholder) or `{single}` is NOT this.
static UNEXPANDED_BRACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{[^{}]*(,|\.\.)[^{}]*\}").unwrap());

pub const READ_TOOLS: &[&str] = &["Read", "Glob", "Grep", "NotebookRead"];
pub const WRITE_TOOLS: &[&str] = &["Edit", "MultiEdit", "Write", "NotebookEdit"];
// Basename globs for confidential files. Location-agnostic on purpose: `.env` under a
// worktree is as sensitive as one under $HOME, and shell reads have no reliable dir context.
// Distinctive key/credential basenames (id_rsa, .npmrc, …) also cover the common
// `cat ~/.ssh/id_rsa` / `cat ~/.aws/credentials` exfil paths without path-prefix matching.
pub const DEFAULT_SENSITIVE: &[&str] = &[
    // secrets / env / generic
    ".env*",
    "credentials*",
    "*secret*",
    ".netrc",
    ".npmrc",
    ".pgpass",
    ".htpasswd",
    // private keys / SSH
    "*.key",
    "*.pem",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "id_dsa*",
    "*.ppk",
    // certs / keystores / vaults
    "*.pfx",
    "*.p12",
    "*.keystore",
    "*.jks",
    "*.kdbx",
    // cloud / cluster / vpn
    "kubeconfig",
    "*.ovpn",
];

/// Compile a basename glob (`*`, `?`) into a case-insensitive anchored regex.
pub fn glob_to_regex(glob: &str) -> Regex {
    let mut re = String::from("(?i)^");
    for ch in glob.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c if r".+^${}()|[]\".contains(c) => {
                re.push('\\');
                re.push(c);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    Regex::new(&re).expect("glob regex")
}

pub fn basename(p: &str) -> &str {
    let t = p.trim_end_matches(['/', '\\']);
    t.rsplit(['/', '\\']).next().unwrap_or(t)
}

pub fn is_sensitive(file_path: Option<&str>, patterns: &[Regex]) -> bool {
    match file_path {
        Some(p) if !p.is_empty() => {
            let b = basename(p);
            patterns.iter().any(|r| r.is_match(b))
        }
        _ => false,
    }
}

/// A concrete filename a sensitive glob would match (`id_rsa*` → `id_rsa`, `*.pem` → `.pem`).
/// Lets us test whether a *glob operand* could expand onto a sensitive file.
pub fn glob_witness(glob: &str) -> String {
    let mut out = String::new();
    let mut chars = glob.chars();
    while let Some(c) = chars.next() {
        match c {
            '*' => {} // zero characters
            '?' => out.push('a'),
            '[' => {
                for n in chars.by_ref() {
                    if n == ']' {
                        break;
                    }
                }
                out.push('a');
            }
            c => out.push(c),
        }
    }
    out
}

/// Like [`is_sensitive`], but a glob operand counts as sensitive when it *could* expand onto a
/// sensitive file. The shell expands `cat ~/.ssh/id_*` / `cat .en?` at runtime; matching the
/// literal glob against the patterns would miss it. Ordinary globs (`cat *.log`) don't overlap
/// any sensitive witness, so they stay allowed — no added prompt fatigue.
pub fn is_sensitive_operand(operand: &str, patterns: &[Regex], witnesses: &[String]) -> bool {
    // An unresolved brace expansion (nested/huge/malformed) could still hide a secret variant —
    // fail closed. A literal `{}` (find placeholder) or `{single}` is not an expansion.
    if UNEXPANDED_BRACE.is_match(operand) {
        return true;
    }
    if is_sensitive(Some(operand), patterns) {
        return true;
    }
    let b = basename(operand);
    // A glob with at least one literal char could target a specific secret family (`id_*`,
    // `.en?`). A bare `*`/`?` matches everything — treating it as sensitive would ask on every
    // `cat *`, so require a literal anchor before consulting the witnesses.
    if b.contains(['*', '?', '[']) && b.chars().any(|c| !matches!(c, '*' | '?' | '[' | ']')) {
        let re = glob_to_regex(b);
        return witnesses.iter().any(|w| re.is_match(w));
    }
    false
}

pub fn is_inside(abs: &str, root: &str) -> bool {
    if abs.is_empty() || root.is_empty() {
        return false;
    }
    abs == root || abs.starts_with(&format!("{root}{}", std::path::MAIN_SEPARATOR))
}

pub fn write_allow_regexes(worktrees: &str, projects: &str) -> Vec<Regex> {
    let wt = regex::escape(worktrees.trim_matches('/'));
    let proj = regex::escape(projects.trim_matches('/'));
    vec![
        Regex::new(&format!(r"^{wt}/")).unwrap(),
        Regex::new(&format!(r"^{proj}/[^/]+/{wt}/")).unwrap(),
        Regex::new(&format!(r"^{proj}/[^/]+/[^/]+/{wt}/")).unwrap(),
        Regex::new(r"^\.lens/").unwrap(),
        Regex::new(r"^\.slack-digest/").unwrap(),
    ]
}

pub fn is_write_allowed(abs: &str, root: &str, regexes: &[Regex]) -> bool {
    let prefix = format!("{root}{}", std::path::MAIN_SEPARATOR);
    let rel = match abs.strip_prefix(&prefix) {
        Some(r) => r.replace(std::path::MAIN_SEPARATOR, "/"),
        None => return false,
    };
    regexes.iter().any(|r| r.is_match(&rel))
}

/// Pure file-tool verdict.
pub fn decide(
    tool: Option<&str>,
    file_path: Option<&str>,
    abs_path: Option<&str>,
    root: &str,
    patterns: &[Regex],
    regexes: &[Regex],
    protected: Decision, // verdict for an in-repo write outside the worktree areas
) -> Decision {
    let tool = tool.unwrap_or("");
    if READ_TOOLS.contains(&tool) {
        if is_sensitive(file_path, patterns) {
            return Decision::Ask;
        }
        return Decision::Allow;
    }
    if WRITE_TOOLS.contains(&tool) {
        let fp = match file_path {
            Some(p) if !p.is_empty() => p,
            _ => return Decision::Deny,
        };
        if is_sensitive(Some(fp), patterns) {
            return Decision::Ask;
        }
        let abs = abs_path.unwrap_or("");
        if is_write_allowed(abs, root, regexes) {
            return Decision::Allow;
        }
        if is_inside(abs, root) {
            return protected;
        }
        return Decision::Pass;
    }
    Decision::Pass
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/repo";

    fn pats() -> Vec<Regex> {
        DEFAULT_SENSITIVE.iter().map(|g| glob_to_regex(g)).collect()
    }

    fn dec(tool: &str, rel: Option<&str>) -> Decision {
        dec_p(tool, rel, Decision::Ask) // default: in-repo writes ask, not deny
    }
    fn dec_p(tool: &str, rel: Option<&str>, protected: Decision) -> Decision {
        let p = pats();
        let r = write_allow_regexes("worktrees", "projects");
        let abs = rel.map(|x| {
            if x.starts_with('/') {
                x.to_string()
            } else {
                format!("{ROOT}/{x}")
            }
        });
        decide(Some(tool), rel, abs.as_deref(), ROOT, &p, &r, protected)
    }

    #[test]
    fn reads() {
        assert_eq!(dec("Read", Some("wiki/README.md")), Decision::Allow);
        assert_eq!(dec("Read", Some("x/.env")), Decision::Ask);
        assert_eq!(dec("Glob", None), Decision::Allow);
    }

    #[test]
    fn writes() {
        assert_eq!(dec("Write", Some("worktrees/x/a")), Decision::Allow);
        assert_eq!(dec("Edit", Some("projects/foo/main/A")), Decision::Ask); // in-repo → ask (default)
        assert_eq!(dec("Write", Some("/tmp/x")), Decision::Pass); // outside repo → defer
        assert_eq!(dec("Write", Some("worktrees/x/.env")), Decision::Ask); // secret → ask
        assert_eq!(dec("Write", None), Decision::Deny); // malformed (no path) → deny
    }

    #[test]
    fn protected_writes_configurable() {
        // strict mode: in-repo writes outside a worktree are denied
        assert_eq!(
            dec_p("Edit", Some("projects/foo/main/A"), Decision::Deny),
            Decision::Deny
        );
        // worktree + outside-repo are unaffected by the knob
        assert_eq!(
            dec_p("Write", Some("worktrees/x/a"), Decision::Deny),
            Decision::Allow
        );
        assert_eq!(
            dec_p("Write", Some("/tmp/x"), Decision::Deny),
            Decision::Pass
        );
    }

    #[test]
    fn other_tools_pass() {
        assert_eq!(dec("WebFetch", None), Decision::Pass);
        assert_eq!(dec("Bash", Some("anything.sh")), Decision::Pass);
    }

    #[test]
    fn sensitive_and_allow_helpers() {
        let p = pats();
        assert!(is_sensitive(Some("a/.env"), &p));
        assert!(!is_sensitive(Some("a/README.md"), &p));
        let r = write_allow_regexes("worktrees", "projects");
        assert!(is_write_allowed("/repo/worktrees/f/a", ROOT, &r));
        assert!(!is_write_allowed("/repo/projects/foo/main/a", ROOT, &r));
    }

    #[test]
    fn sensitive_matrix() {
        let p = pats();
        for f in [
            "id.key",
            "server.pem",
            "credentials.json",
            "app-secrets.yaml",
            "MY_SECRET.txt", // case-insensitive
            "a/.env",
            // expanded set: SSH keys, keystores, cred/vpn/cluster configs
            "/home/u/.ssh/id_rsa",
            "id_ed25519",
            "vault.kdbx",
            "cert.p12",
            "site.pfx",
            ".npmrc",
            ".netrc",
            "kubeconfig",
            "client.ovpn",
        ] {
            assert!(is_sensitive(Some(f), &p), "{f} should be sensitive");
        }
        for f in ["README.md", "App.kt", "config.json", "env.example.md"] {
            assert!(!is_sensitive(Some(f), &p), "{f} should not be sensitive");
        }
        // basename-only: a "secret" directory must not match; a basename match must
        assert!(!is_sensitive(Some("secret-stuff/notes.md"), &p));
        assert!(is_sensitive(Some("any/dir/.env"), &p));
    }

    #[test]
    fn write_allowed_nested_and_outside() {
        let r = write_allow_regexes("worktrees", "projects");
        for ok in [
            "worktrees/x/a.md",
            "projects/foo/worktrees/f/A.kt",
            "projects/g/foo/worktrees/f/A.kt",
            ".lens/s.md",
        ] {
            assert!(
                is_write_allowed(&format!("/repo/{ok}"), ROOT, &r),
                "{ok} should be allowed"
            );
        }
        assert!(!is_write_allowed("/repo/projects/foo/main/A.kt", ROOT, &r));
        assert!(!is_write_allowed("/repo/CLAUDE.md", ROOT, &r)); // root file
        assert!(!is_write_allowed("/tmp/x.txt", ROOT, &r)); // outside root
    }
}
