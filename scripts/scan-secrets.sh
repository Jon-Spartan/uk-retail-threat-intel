#!/usr/bin/env bash
set -euo pipefail

scanner="$(mktemp -d)"
trap 'rm -rf -- "$scanner"' EXIT
archive="$scanner/gitleaks.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --max-time 45 \
  --output "$archive" 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_x64.tar.gz'
printf '%s  %s\n' '79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e' "$archive" \
  | sha256sum --check --status
tar -xzf "$archive" -C "$scanner" gitleaks
if [[ "$1" == git ]]; then
  "$scanner/gitleaks" git --redact=100 --no-banner --log-opts='--all' "$2"
else
  "$scanner/gitleaks" dir --redact=100 --no-banner "$2"
fi
