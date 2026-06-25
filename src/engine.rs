//! The router: feed an `Event` to subscribed features, aggregate the verdicts.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::features::Feature;
use crate::model::{Decision, Event, Verdict};

/// Most-restrictive-wins: deny > ask > pass > allow. Empty → Pass. Ties keep the first.
pub fn aggregate(verdicts: Vec<Verdict>) -> Verdict {
    let mut chosen: Option<Verdict> = None;
    for v in verdicts {
        let replace = match &chosen {
            Some(c) => v.decision.rank() > c.decision.rank(),
            None => true,
        };
        if replace {
            chosen = Some(v);
        }
    }
    chosen.unwrap_or_else(|| Verdict::new(Decision::Pass, "no feature opined", ""))
}

/// Run every feature subscribed to `event.stage`; return the aggregated verdict.
/// A panicking feature is swallowed (per-feature fail-open).
pub fn run(event: &Event, features: &[Box<dyn Feature>]) -> Verdict {
    let mut out = Vec::new();
    for f in features {
        if !f.stages().contains(&event.stage.as_str()) {
            continue;
        }
        if let Ok(Some(v)) = catch_unwind(AssertUnwindSafe(|| f.evaluate(event))) {
            out.push(v);
        }
    }
    aggregate(out)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::features::Feature;
    use crate::model::Event;

    struct Fixed(Decision, &'static [&'static str]);
    impl Feature for Fixed {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn stages(&self) -> &'static [&'static str] {
            self.1
        }
        fn evaluate(&self, _e: &Event) -> Option<Verdict> {
            Some(Verdict::new(self.0, "", "fixed"))
        }
    }

    struct Boom;
    impl Feature for Boom {
        fn name(&self) -> &'static str {
            "boom"
        }
        fn stages(&self) -> &'static [&'static str] {
            &["PreToolUse"]
        }
        fn evaluate(&self, _e: &Event) -> Option<Verdict> {
            panic!("feature blew up")
        }
    }

    fn ev() -> Event {
        Event {
            stage: "PreToolUse".into(),
            tool: None,
            tool_input: Value::Null,
            cwd: None,
            root: String::new(),
            config: Value::Null,
        }
    }

    #[test]
    fn most_restrictive_wins() {
        let v = aggregate(vec![
            Verdict::new(Decision::Allow, "", ""),
            Verdict::new(Decision::Deny, "", ""),
            Verdict::new(Decision::Ask, "", ""),
        ]);
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(aggregate(vec![]).decision, Decision::Pass);
    }

    #[test]
    fn only_subscribed_features_run() {
        let feats: Vec<Box<dyn Feature>> = vec![
            Box::new(Fixed(Decision::Allow, &["PreToolUse"])),
            Box::new(Fixed(Decision::Deny, &["SessionStart"])),
        ];
        assert_eq!(run(&ev(), &feats).decision, Decision::Allow);
    }

    #[test]
    fn panicking_feature_is_swallowed() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence the expected panic
        let feats: Vec<Box<dyn Feature>> = vec![
            Box::new(Boom),
            Box::new(Fixed(Decision::Allow, &["PreToolUse"])),
        ];
        let v = run(&ev(), &feats);
        std::panic::set_hook(prev);
        assert_eq!(v.decision, Decision::Allow);
    }
}
