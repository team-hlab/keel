//! Feature registry: build the enabled features from config.
//!
//! Phase 1 registers `autopermit` (the flagship). Phase 2 adds branch-guard,
//! secret-scan, audit-log, session-banner.

use serde_json::Value;

use crate::features::autopermit::AutoPermit;
use crate::features::Feature;

fn enabled(config: &Value, name: &str) -> bool {
    config
        .get("features")
        .and_then(|f| f.get(name))
        .and_then(|s| s.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn feature_config(config: &Value, name: &str) -> Value {
    config
        .get("features")
        .and_then(|f| f.get(name))
        .cloned()
        .unwrap_or(Value::Null)
}

pub fn load(config: &Value) -> Vec<Box<dyn Feature>> {
    let mut features: Vec<Box<dyn Feature>> = Vec::new();
    if enabled(config, "autopermit") {
        features.push(Box::new(AutoPermit::new(&feature_config(
            config,
            "autopermit",
        ))));
    }
    features
}
