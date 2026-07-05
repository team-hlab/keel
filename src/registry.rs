//! Feature registry: build the enabled features from config.

use serde_json::Value;

use crate::features::autopermit::AutoPermit;
use crate::features::branch_guard::BranchGuard;
use crate::features::secret_scan::SecretScan;
use crate::features::session_banner::SessionBanner;
use crate::features::Feature;

/// All feature names, in registration order.
pub const NAMES: &[&str] = &[
    "autopermit",
    "branch-guard",
    "secret-scan",
    "session-banner",
];

fn enabled(config: &Value, name: &str) -> bool {
    config
        .get("features")
        .and_then(|f| f.get(name))
        .and_then(|s| s.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(true) // all features default on
}

fn feature_config(config: &Value, name: &str) -> Value {
    config
        .get("features")
        .and_then(|f| f.get(name))
        .cloned()
        .unwrap_or(Value::Null)
}

pub fn load(config: &Value) -> Vec<Box<dyn Feature>> {
    let active: Vec<String> = NAMES
        .iter()
        .filter(|n| enabled(config, n))
        .map(|s| s.to_string())
        .collect();

    let mut features: Vec<Box<dyn Feature>> = Vec::new();
    if enabled(config, "autopermit") {
        features.push(Box::new(AutoPermit::new(&feature_config(
            config,
            "autopermit",
        ))));
    }
    if enabled(config, "branch-guard") {
        features.push(Box::new(BranchGuard::new(&feature_config(
            config,
            "branch-guard",
        ))));
    }
    if enabled(config, "secret-scan") {
        features.push(Box::new(SecretScan::new(&feature_config(
            config,
            "secret-scan",
        ))));
    }
    if enabled(config, "session-banner") {
        features.push(Box::new(SessionBanner::new(active)));
    }
    features
}
