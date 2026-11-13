#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
first_run=0
if [ "$#" -eq 0 ]; then first_run=1; set -- --rotate-admin --apply; fi
if [ "${1:-}" = --audit-only ] && [ "$#" -eq 1 ]; then set --; fi
EXPECTED_HOST=cai-db01 EXPECTED_ID=ubuntu EXPECTED_VERSION=26.04 \
  bash ./boilerstorm-baseline.sh "$@"
if [ "$first_run" -eq 1 ]; then
  EXPECTED_HOST=cai-db01 EXPECTED_ID=ubuntu EXPECTED_VERSION=26.04 \
    bash ./boilerstorm-baseline.sh --hunt --backup-services
fi
