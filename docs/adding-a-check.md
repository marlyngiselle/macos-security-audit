# Adding a check

A check is a JSON object in [`macaudit/data/catalogue.json`](../macaudit/data/catalogue.json). Most checks need no Python at all: a command, a few ordered rules, and the text a person reads when it fails.

## 1. Find a read-only probe

The probe must not change anything and must not need a password. Good candidates are `defaults read`, `--get*` or `status` subcommands, and `launchctl print*`. Run it on a Mac in each state you care about and keep the exact output.

If the probe genuinely needs root, set `"requires_root": true`. macaudit then skips it without sudo and reports it as `skipped`, which is never counted as a pass.

## 2. Declare the check

```json
{
  "id": "MA-SHR-06",
  "title": "Content Caching is off",
  "area": "sharing",
  "severity": "low",
  "rationale": "Why an attacker cares, in one or two sentences.",
  "expected": "The state a compliant machine reports.",
  "probe": {"type": "command", "argv": ["AssetCacheManagerUtil", "status"]},
  "evaluate": [
    {"when": "regex", "pattern": "Activated: false", "status": "pass", "reason": "Content Caching is off."},
    {"when": "regex", "pattern": "Activated: true", "status": "fail", "reason": "Content Caching is on."}
  ],
  "remediation": ["Open System Settings, General, Sharing, and turn off Content Caching."],
  "references": ["CIS-style section: Sharing, content caching", "NIST SP 800-53 CM-7"]
}
```

| Field | Rule |
| --- | --- |
| `id` | `MA-<AREA>-NN`, unique, never reused |
| `area` | One of the keys under `areas` |
| `severity` | `info`, `low`, `medium`, `high` or `critical`. `info` is never scored |
| `probe.argv` | Executed without a shell. No pipes, no globbing, no variables |
| `probe.env` | Extra environment, for example `HOMEBREW_NO_AUTO_UPDATE` |
| `sensitive` | `true` when the raw output could contain personal data. Evidence is then dropped |
| `remediation` | Plain steps. macaudit prints them, it never runs them |
| `references` | Generic section labels and public control identifiers only. Never paste benchmark text |

### Rule kinds

Rules are evaluated in order and the first match wins. When nothing matches, the result is `unknown`, so a new macOS output format can never silently pass.

| `when` | Matches when | Extra fields |
| --- | --- | --- |
| `regex` | `pattern` is found in stdout or stderr (multiline) | `pattern` |
| `exit` | the exit code is in `codes`, or not in it with `negate` | `codes`, `negate` |
| `int_range` | `pattern` captures an integer. Inside `min`..`max` gives `status`, outside gives `otherwise` | `pattern`, `min`, `max`, `otherwise`, `otherwise_reason` |
| `line_count` | always, once reached. At most `max` non-empty lines gives `status`, more gives `otherwise` | `max`, `otherwise`, `otherwise_reason` |

`reason` and `otherwise_reason` may contain `{value}`, replaced by the measured number.

## 3. When a regex is not enough

Write a function in [`macaudit/probes.py`](../macaudit/probes.py) that takes a `Context` and returns an `Outcome`, register it in `BUILTINS`, and reference it with `{"type": "builtin", "name": "..."}`. Read files and run commands only through `ctx.fs` and `ctx.runner`, so the probe works against fixtures. Never return file contents, network names or key material as evidence.

## 4. Record fixtures

Add cases to `tests/fixtures/cases/<area>.json`, at least one each for `pass`, `fail` and `unknown`. The coverage test fails otherwise.

```json
{"check": "MA-SHR-06", "expect": "pass", "commands": {"AssetCacheManagerUtil status": {"stdout": "Activated: false\n"}}}
```

Command keys are the argv joined the way `shlex.join` would. File-based probes take a `files` map instead, keyed by path with `~` for the home directory, and `content_b64` for anything that looks like a secret so that secret scanners stay quiet.

## 5. Regenerate the docs and run the suite

```bash
python3 -m macaudit list --format markdown > docs/checks.md
python3 -m unittest discover -s tests -t .
```

The suite fails when `docs/checks.md` is stale, when a check lacks a fixture path, or when the catalogue no longer matches its schema.
