//! session-banner — SessionStart observer: announce active features (to stderr).

use crate::features::Feature;
use crate::model::{Event, Verdict};

const STAGES: &[&str] = &["SessionStart"];

pub struct SessionBanner {
    active: Vec<String>,
}

impl SessionBanner {
    pub fn new(active: Vec<String>) -> Self {
        SessionBanner { active }
    }

    fn line(&self) -> String {
        let others: Vec<&str> = self
            .active
            .iter()
            .map(String::as_str)
            .filter(|n| *n != "session-banner")
            .collect();
        let list = if others.is_empty() {
            "(none)".to_string()
        } else {
            others.join(", ")
        };
        format!("🛡  keel active — features: {list}")
    }
}

impl Feature for SessionBanner {
    fn name(&self) -> &'static str {
        "session-banner"
    }

    fn stages(&self) -> &'static [&'static str] {
        STAGES
    }

    fn evaluate(&self, _event: &Event) -> Option<Verdict> {
        eprintln!("{}", self.line()); // stderr: never corrupts a stdout JSON contract
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_lists_other_features() {
        let b = SessionBanner::new(vec!["autopermit".into(), "session-banner".into()]);
        let line = b.line();
        assert!(line.contains("autopermit"));
        assert!(!line.contains("session-banner")); // excludes itself
    }
}
