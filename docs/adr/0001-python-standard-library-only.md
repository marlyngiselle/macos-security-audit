# ADR 0001: Python standard library only

- Status: accepted
- Date: 2026-10-26

## Context

The tool must run on any Mac, including a freshly installed one, a GitHub-hosted runner and a colleague's laptop where nobody wants to install packages. macOS ships `/usr/bin/python3` (3.9 at the time of writing) with the Command Line Tools, and every runner image has it.

Three options were considered.

| Option | For | Against |
| --- | --- | --- |
| Bash | Present everywhere, close to the commands it wraps | Fragile parsing, no structured output, hard to unit test, SARIF and JSON schema by hand |
| Python with dependencies (PyYAML, Click, Rich) | Nicer CLI and YAML catalogue | A `pip install` before the first run, a supply chain to keep current, breaks on locked-down machines |
| Python standard library only | Runs with what is already there, testable, structured output | Plainer terminal output, JSON instead of YAML for the catalogue |

## Decision

The tool uses the Python standard library only and supports Python 3.9 and later. Test tooling (`jsonschema`, `ruff`, `mypy`) is allowed in development and CI, never at runtime.

## Consequences

- `git clone` followed by `bin/macaudit run` is the whole installation.
- CI runs the unit tests on 3.9 and 3.13, and the macOS job deliberately uses `/usr/bin/python3`.
- Schema validation of the report happens in tests, not at runtime. The runtime validates the catalogue with hand-written checks instead.
- A security tool with zero runtime dependencies has no dependency to compromise.
