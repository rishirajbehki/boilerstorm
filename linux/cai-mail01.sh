#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
EXPECTED_HOST=cai-mail01 EXPECTED_ID=rocky EXPECTED_VERSION=10 \
  bash ./boilerstorm-baseline.sh "$@"
