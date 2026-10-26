# ADR 0003: Read-only, no privilege escalation, never remediate

- Status: accepted
- Date: 2026-10-26

## Context

Audit tools that also fix are tempting: one command and the machine is compliant. They are also how audits break laptops, reset settings a user chose on purpose, and become something security teams cannot run on a machine they do not own. A tool that can write needs root, and a tool that asks for root is a tool people stop running.

## Decision

macaudit never changes the machine it inspects.

- The probe layer exposes no write operation. Commands come only from the reviewed catalogue, run without a shell, with stdin closed and a timeout.
- macaudit never calls `sudo`. Checks that need root declare `requires_root` and are reported as `skipped` unless the whole run was started as root by the operator.
- Remediation is text. `macaudit explain <ID>` prints the steps, and the operator decides.
- The only files macaudit writes are the reports the operator asks for with `--output`, `--json-out`, `--markdown-out` and `--sarif-out`.

## Consequences

- It is safe to run on any machine, including someone else's, and in CI.
- Some useful checks (for example remote management settings that only `systemsetup` exposes) are skipped by default. The report says so instead of guessing.
- Teams that want enforcement pair macaudit with configuration profiles from an MDM. macaudit then becomes the independent verification that the profile actually landed.
