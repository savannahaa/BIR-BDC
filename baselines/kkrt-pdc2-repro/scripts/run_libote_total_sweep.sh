#!/usr/bin/env bash
set -euo pipefail

PDC2_BIN="${PDC2_BIN:-./build/kkrt_pdc2_bench}"
KKRT_BIN="${KKRT_BIN:-./build-libote/libote_kkrt_cost}"
OUT="${OUT:-results_kkrt_pdc2_libote_total.csv}"
LIBOTE_LIB="${LIBOTE_LIB:-/jty/xyx1/libOTe/out/install/linux/lib}"
MAX_OTS_PER_BATCH="${MAX_OTS_PER_BATCH:-4000000}"

make >/dev/null

header="n,label_bits,m,matches_found,ok,pdc2_logic_ms,libote_kkrt_ms,compute_total_ms,comm_mb,total_1gbps_s,total_100mbps_s,total_10mbps_s"
echo "$header" | tee "$OUT"

for n in 65536 262144 1048576; do
  for l in 1 4 10 20; do
    pdc2_line="$("$PDC2_BIN" --n "$n" --label-bits "$l" --csv --trials 1)"
    if [[ "$n" == "1048576" && "$l" == "20" ]]; then
      kkrt_line="$(LD_LIBRARY_PATH="$LIBOTE_LIB" "$KKRT_BIN" --n "$n" --label-bits "$l" --max-ots-per-batch "$MAX_OTS_PER_BATCH" --csv)"
    else
      kkrt_line="$(LD_LIBRARY_PATH="$LIBOTE_LIB" "$KKRT_BIN" --n "$n" --label-bits "$l" --csv)"
    fi

    python3 - "$pdc2_line" "$kkrt_line" <<'PY' | tee -a "$OUT"
import sys

p = sys.argv[1].strip().split(",")
k = sys.argv[2].strip().split(",")

n = p[0]
label_bits = p[1]
m = p[2]
matches_found = p[4]
ok = p[5]
pdc2_logic_ms = float(p[6])
comm_bytes = int(p[7])
libote_kkrt_ms = float(k[4])
compute_total_ms = pdc2_logic_ms + libote_kkrt_ms

def total_s(bandwidth_mbps):
    network_ms = comm_bytes * 8.0 / (bandwidth_mbps * 1_000_000.0) * 1000.0
    return (compute_total_ms + network_ms) / 1000.0

print(
    f"{n},{label_bits},{m},{matches_found},{ok},"
    f"{pdc2_logic_ms:.3f},{libote_kkrt_ms:.3f},{compute_total_ms:.3f},"
    f"{comm_bytes / 1_000_000.0:.3f},"
    f"{total_s(1000):.3f},{total_s(100):.3f},{total_s(10):.3f}"
)
PY
  done
done

echo "wrote $OUT"
