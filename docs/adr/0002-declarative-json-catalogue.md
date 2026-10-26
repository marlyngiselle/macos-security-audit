# ADR 0002: Checks are data, evaluated by ordered rules

- Status: accepted
- Date: 2026-10-26

## Context

A posture audit lives or dies by how cheaply its checks can be reviewed, added and kept current as macOS changes its output. The mSCP project shows the value of describing each rule as data with a check, a fix and references. Hand-written Python per check would hide the expected state inside code and make review harder.

## Decision

Each check is a JSON object in `macaudit/data/catalogue.json` with an id, title, area, severity, rationale, expected state, probe, ordered evaluation rules, remediation text and references. A probe is either an argv executed without a shell or the name of a small built-in function for the few checks that need to walk files.

Rules are evaluated in order and the first match decides the status. When no rule matches, the status is `unknown`.

JSON was chosen over YAML because the standard library parses it (see ADR 0001) and because a JSON Schema validates it in CI.

## Consequences

- 29 of 35 checks are pure data. Reviewing one means reading one object.
- A new or changed macOS output format produces `unknown`, never a false pass.
- The SARIF rules, the Markdown catalogue in `docs/checks.md` and the `explain` command are all rendered from the same object, so they cannot drift. A test fails if `docs/checks.md` is stale.
- SARIF results point at the exact catalogue line of the check, which gives code scanning alerts a meaningful location even though the finding is about a machine, not a file.
- References are generic section labels and public NIST SP 800-53 control identifiers. No copyrighted benchmark text is reproduced.
