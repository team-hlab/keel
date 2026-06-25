//! Port of the Python `no_external_deps` guard: keel's runtime stays lean. Instead of
//! Python's stdlib-only check, the Rust equivalent pins the `[dependencies]` allowlist —
//! a new runtime crate must be a deliberate, reviewed change, not an accident.

use std::collections::BTreeSet;

#[test]
fn only_allowed_runtime_dependencies() {
    let toml = include_str!("../Cargo.toml");
    let mut in_deps = false;
    let mut deps = BTreeSet::new();

    for line in toml.lines() {
        let t = line.trim();
        // `[dependencies.foo]` table form → the dep is named after the dot
        if let Some(rest) = t.strip_prefix("[dependencies.") {
            in_deps = false;
            if let Some(name) = rest.strip_suffix(']') {
                deps.insert(name.trim().to_string());
            }
            continue;
        }
        if t.starts_with('[') {
            in_deps = t == "[dependencies]";
            continue;
        }
        if in_deps && !t.is_empty() && !t.starts_with('#') {
            if let Some((name, _)) = t.split_once('=') {
                deps.insert(name.trim().to_string());
            }
        }
    }

    let allowed: BTreeSet<String> = ["regex", "serde_json"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        deps, allowed,
        "unexpected runtime dependencies — keep keel lean (got {deps:?})"
    );
}
