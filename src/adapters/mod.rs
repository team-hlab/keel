//! Per-platform adapters: parse hook JSON → Event, render Verdict → hook JSON.

pub mod antigravity;
pub mod claude;
pub mod codex;

use serde_json::Value;

use crate::model::{Event, Verdict};

pub fn is_known(platform: &str) -> bool {
    matches!(platform, "claude" | "claude-code" | "codex" | "antigravity")
}

pub fn parse(platform: &str, raw: &Value, stage: &str) -> Event {
    match platform {
        "codex" => codex::parse(raw, stage),
        "antigravity" => antigravity::parse(raw, stage),
        _ => claude::parse(raw, stage),
    }
}

pub fn render(platform: &str, verdict: &Verdict, stage: &str) -> String {
    match platform {
        "codex" => codex::render(verdict, stage),
        "antigravity" => antigravity::render(verdict, stage),
        _ => claude::render(verdict, stage),
    }
}
