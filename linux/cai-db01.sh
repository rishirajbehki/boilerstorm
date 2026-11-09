#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
EXPECTED_HOST=cai-db01 EXPECTED_ID=ubuntu EXPECTED_VERSION=26.04 \
  bash ./boilerstorm-baseline.sh "$@"
