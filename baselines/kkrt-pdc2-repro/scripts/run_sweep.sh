#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./build/kkrt_pdc2_bench}"
OUT="${OUT:-results_kkrt_pdc2.csv}"

make >/dev/null

header="n,label_bits,m,matches_expected,matches_found,ok,compute_time_ms,comm_bytes_formula,comm_mb_formula,comm_mib_formula,total_time_1gbps_s,total_time_100mbps_s,total_time_10mbps_s,comm_bytes_explicit"
echo "$header" | tee "$OUT"

for n in 65536 262144 1048576; do
  for l in 1 4 10 20; do
    "$BIN" --n "$n" --label-bits "$l" --csv --trials 1 | tee -a "$OUT"
  done
done

echo "wrote $OUT"
