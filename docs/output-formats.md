# Output formats and exit codes

One run produces one canonical JSON document. Every other format is rendered from it, so they can never disagree. `macaudit render` re-renders a saved report later, for example to post a job summary from a report produced elsewhere.

| Format | Flag | Audience |
| --- | --- | --- |
| Table | default stdout, `--format table` | A person at a terminal. Colour when attached to a TTY, off with `--no-color` or `NO_COLOR` |
| JSON | `--format json` or `--json-out FILE` | Fleet collectors, `jq`, dashboards. Versioned schema |
| Markdown | `--format markdown` or `--markdown-out FILE` | Pull requests, GitHub job summaries, tickets |
| SARIF 2.1.0 | `--format sarif` or `--sarif-out FILE` | GitHub code scanning and any SARIF viewer |

## Statuses

| Status | Meaning | Counts against the exit code |
| --- | --- | --- |
| `pass` | The probe read the state and it matches the expectation | No |
| `fail` | The probe read the state and it does not match | Yes, when the severity reaches `--fail-on` |
| `unknown` | The probe ran but its output was not readable or not recognised | No, and never shown as a pass |
| `skipped` | Not applicable, tool missing, or root required | No |

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | No failed check at or above the `--fail-on` threshold (default `high`) |
| 2 | Usage error, unknown area or check, unreadable replay file |
| 3 | The check catalogue failed validation |
| 11 | Worst failure at or above the threshold is `low` |
| 12 | Worst failure at or above the threshold is `medium` |
| 13 | Worst failure at or above the threshold is `high` |
| 14 | Worst failure at or above the threshold is `critical` |

`info` checks are never scored and never change the exit code. `--fail-on none` always exits 0 after a successful run.

```bash
macaudit run --fail-on medium; rc=$?
[ "$rc" -ge 13 ] && echo "high or critical finding"
```

## JSON report

Described by [`macaudit/data/report.schema.json`](../macaudit/data/report.schema.json) (JSON Schema 2020-12, `schema_version` 1.0). Top-level keys are `tool`, `generated_at`, `host`, `policy`, `summary`, `areas` and `results`.

The `host` block holds the macOS version, build and architecture only. There is no hostname, serial number or user name, and evidence strings are redacted before they reach the report. See the [threat model](threat-model.md#threats-against-the-tool-itself).

## SARIF

Every check in the catalogue becomes a SARIF rule with a `security-severity` score that GitHub uses to rank alerts.

| Severity | `security-severity` | SARIF level |
| --- | ---: | --- |
| critical | 9.5 | error |
| high | 8.0 | error |
| medium | 5.5 | warning |
| low | 3.0 | note |
| info | 0.0 | note, never emitted as a result |

Only failed checks become results. Each result points at the line in `macaudit/data/catalogue.json` where its check is declared, so an alert in code scanning opens on the definition, rationale and remediation of the control. The fingerprint is the check id, so the same finding on the next run updates the existing alert instead of opening a new one.
