# Contributing to keel

Thanks for helping! keel stays small on purpose.

## Ground rules

1. **No external runtime dependencies.** The core and features import only the
   Python standard library. `tests/test_no_external_deps.py` enforces this — keep it green.
2. **Pure core, side effects at the edges.** Decision logic (`policy`, `shell`,
   feature `evaluate`) stays pure where possible; I/O lives in `core/runtime.py`
   and adapters. This keeps everything unit-testable without a filesystem.
3. **Fail open.** A hook must never break the agent. Wrap risky work; on error, abstain.
4. **Most-restrictive-wins.** Verdicts aggregate `deny > ask > pass > allow`.

## Adding a feature

Implement `keel.features.base.Feature` (`name`, `stages()`, `evaluate(event) -> Verdict | None`),
register it in `keel/core/registry.py`, and add tests. Permission features return a
`Verdict`; observer features act and return `None`.

## Adding / fixing an adapter

Adapters parse a platform's hook JSON into an `Event` and render a `Verdict` back to
that platform's output schema. Cite the doc you verified against in the module docstring.

## Dev setup

```sh
pip install -e ".[dev]"    # editable install + dev-only tools (ruff). No runtime deps.
```

## Lint & format

```sh
ruff check .               # lint
ruff format .              # auto-format
ruff format --check .      # what CI enforces
```

## Tests

The tests are plain stdlib `unittest` files — run them directly (no test-runner dependency):

```sh
for t in policy shell engine features e2e no_external_deps; do python tests/test_$t.py; done
```

CI runs both `lint` and `test` (Python 3.8 / 3.10 / 3.12 / 3.13) on every push and PR.
