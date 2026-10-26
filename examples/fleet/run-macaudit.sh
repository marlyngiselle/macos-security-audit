#!/usr/bin/env bash
# Scheduled macaudit run for fleets without an MDM.
#
# Runs as the logged-in user (no root), keeps the last reports locally and,
# when an upload URL is configured, ships the JSON report to it over HTTPS.
# The device is identified by a salted hash of its hardware UUID, never by
# hostname, serial number or user name.
#
# Configuration, all optional, through the environment or the LaunchAgent:
#   MACAUDIT_HOME        checkout or install location (default: /usr/local/share/macaudit)
#   MACAUDIT_REPORT_DIR  where reports are kept (default: ~/Library/Application Support/macaudit)
#   MACAUDIT_KEEP        how many reports to keep (default: 14)
#   MACAUDIT_UPLOAD_URL  HTTPS endpoint that accepts a JSON POST (default: none, local only)
#   MACAUDIT_FLEET_SALT  salt for the device id, shared across the fleet (default: macaudit)
# The upload token, if any, is read from the login keychain item "macaudit-upload".

set -euo pipefail

macaudit_home="${MACAUDIT_HOME:-/usr/local/share/macaudit}"
report_dir="${MACAUDIT_REPORT_DIR:-${HOME}/Library/Application Support/macaudit}"
keep="${MACAUDIT_KEEP:-14}"
upload_url="${MACAUDIT_UPLOAD_URL:-}"
salt="${MACAUDIT_FLEET_SALT:-macaudit}"

log() { logger -t macaudit "$*"; printf '%s\n' "$*" >&2; }

mkdir -p "${report_dir}"
chmod 700 "${report_dir}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
report="${report_dir}/macaudit-${stamp}.json"

# --fail-on none: a scheduled run records findings, it does not signal failure.
if ! PYTHONPATH="${macaudit_home}" /usr/bin/python3 -m macaudit run \
  --format json --output "${report}" --fail-on none; then
  log "audit did not complete"
  exit 1
fi
chmod 600 "${report}"
log "report written to ${report}"

# Keep the newest reports only.
find "${report_dir}" -maxdepth 1 -name 'macaudit-*.json' -type f -print0 \
  | xargs -0 ls -1t \
  | tail -n "+$((keep + 1))" \
  | while IFS= read -r old; do rm -f -- "${old}"; done

[ -n "${upload_url}" ] || exit 0

case "${upload_url}" in
  https://*) ;;
  *) log "refusing to upload over a non-HTTPS URL"; exit 1 ;;
esac

hw_uuid="$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/ {print $4}')"
device_id="$(printf '%s:%s' "${salt}" "${hw_uuid}" | shasum -a 256 | cut -c1-16)"

# The token goes to curl through a config on stdin, so it never shows up in `ps`.
curl_config=""
if token="$(security find-generic-password -s macaudit-upload -w 2>/dev/null)"; then
  curl_config="header = \"Authorization: Bearer ${token}\""
fi

if printf '%s\n' "${curl_config}" | curl --config - --fail --silent --show-error --max-time 30 --proto '=https' \
  -H 'Content-Type: application/json' \
  -H "X-Macaudit-Device: ${device_id}" \
  --data-binary "@${report}" \
  "${upload_url}" >/dev/null; then
  log "report uploaded for device ${device_id}"
else
  log "upload failed, the report stays in ${report_dir}"
  exit 1
fi
