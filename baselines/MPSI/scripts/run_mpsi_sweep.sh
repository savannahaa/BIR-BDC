#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./mpsi_benchmark}"
shift || true

PARTIES_LIST="${PARTIES_LIST:-3 5 10 20}"
SET_SIZES="${SET_SIZES:-4096 16384 65536}"
INTERSECTION="${INTERSECTION:-100}"
SEED="${SEED:-1}"

echo "parties_n,set_size_m,intersection,compute_seconds,total_communication_MB,total_seconds_1Gbps,total_seconds_100Mbps,total_seconds_10Mbps,peak_RSS_MB"
for parties in ${PARTIES_LIST}; do
  for set_size in ${SET_SIZES}; do
    "${BIN}" -nu "${parties}" -m "${set_size}" -ts "${INTERSECTION}" -seed "${SEED}" \
      | awk -F': ' '/^csv: / { print $2 }'
  done
done
