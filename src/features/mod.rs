//! The Feature contract: a self-contained policy or observer plugin.

pub mod autopermit;

use crate::model::{Event, Verdict};

pub trait Feature {
    fn name(&self) -> &'static str;

    /// Hook stages this feature subscribes to (e.g. `["PreToolUse"]`).
    fn stages(&self) -> &'static [&'static str];

    /// Return a `Verdict`, or `None` to abstain. Observer features act and return `None`.
    fn evaluate(&self, event: &Event) -> Option<Verdict>;
}
