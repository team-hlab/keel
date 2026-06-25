//! keel — a lean hook harness for AI coding agents.
//!
//! Busybox-style multi-call binary: when invoked as `claude`/`codex`/`antigravity`
//! (via the shim symlinks) it enters shim mode (Phase 2); otherwise it's the `keel` CLI.

mod adapters;
mod agent;
mod engine;
mod features;
mod model;
mod registry;
mod runtime;
mod shim;

use std::panic::catch_unwind;
use std::path::Path;

use serde_json::{Map, Value};

const USAGE: &str = "\
keel — a permission/policy harness for AI coding agents.
Every tool call passes through keel, which auto-permits, auto-denies, or asks you.

usage:
  keel init                                     # attach keel to your installed agents
  keel apply | uninstall | doctor | status      # manage the install
  keel run <claude|codex|antigravity> <stage>   # hook entrypoint (used by the hooks)
  keel features
";

fn main() {
    let arg0 = std::env::args().next().unwrap_or_default();
    let base = Path::new(&arg0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    // busybox: invoked as an agent name → shim mode (apply + exec the real agent)
    if matches!(base, "claude" | "codex" | "antigravity") {
        shim::run_shim(base);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(cli(&args));
}

fn cli(args: &[String]) -> i32 {
    let cmd = match args.first() {
        Some(c) => c.as_str(),
        None => {
            eprint!("{USAGE}");
            return 0;
        }
    };
    match cmd {
        // the hook path must never break the agent → fail open
        "run" if args.len() >= 3 && adapters::is_known(&args[1]) => {
            let (platform, stage) = (args[1].clone(), args[2].clone());
            let _ = catch_unwind(move || run(&platform, &stage));
            0
        }
        "features" => {
            for n in registry::NAMES {
                println!("{n}");
            }
            0
        }
        "init" => shim::init(),
        "apply" => shim::apply_all(),
        "uninstall" => shim::uninstall(),
        "doctor" | "status" => shim::doctor(),
        _ => {
            eprint!("{USAGE}");
            2
        }
    }
}

fn run(platform: &str, stage: &str) {
    let raw = runtime::read_input().unwrap_or_else(|| Value::Object(Map::new()));
    let raw = if raw.is_object() {
        raw
    } else {
        Value::Object(Map::new())
    };
    let mut event = adapters::parse(platform, &raw, stage);
    event.config = runtime::load_config(&event.root);
    let features = registry::load(&event.config);
    let verdict = engine::run(&event, &features);
    print!("{}", adapters::render(platform, &verdict, stage));
}
