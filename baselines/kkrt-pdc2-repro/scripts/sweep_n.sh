#!/usr/bin/env bash
set -euo pipefail

LABEL_BITS=10
FROM_EXP=11
TO_EXP=19
BACKEND="ideal"
MAX_OTS_PER_BATCH=4000000

PDC2_BIN="${PDC2_BIN:-./build/kkrt_pdc2_bench}"
KKRT_BIN="${KKRT_BIN:-./build-libote/libote_kkrt_cost}"
LIBOTE_LIB="${LIBOTE_LIB:-/jty/xyx1/libOTe/out/install/linux/lib}"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/sweep_n.sh [options]

Options:
  --label-bits L          fixed label length l, default 10
  --from-exp E            start n=2^E, default 11
  --to-exp E              end n=2^E, default 19
  --backend ideal|libote  ideal uses protocol logic only; libote adds real libOTe-KKRT cost, default ideal
  --max-ots-per-batch N   chunk size for large libOTe KKRT runs, default 4000000

Examples:
  ./scripts/sweep_n.sh --label-bits 10 --from-exp 11 --to-exp 19
  ./scripts/sweep_n.sh --label-bits 20 --from-exp 11 --to-exp 19 --backend libote
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label-bits|-l)
      LABEL_BITS="$2"; shift 2 ;;
    --from-exp)
      FROM_EXP="$2"; shift 2 ;;
    --to-exp)
      TO_EXP="$2"; shift 2 ;;
    --backend)
      BACKEND="$2"; shift 2 ;;
    --max-ots-per-batch)
      MAX_OTS_PER_BATCH="$2"; shift 2 ;;
    --help|-h)
      usage; exit 0 ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1 ;;
  esac
done

if [[ "$BACKEND" != "ideal" && "$BACKEND" != "libote" ]]; then
  echo "--backend must be ideal or libote" >&2
  exit 1
fi

make >/dev/null

printf "%-10s %-10s %-12s %-15s %-17s %-15s\n" \
  "n" "l" "comm_mb" "total_1gbps_s" "total_100mbps_s" "total_10mbps_s"

for ((e = FROM_EXP; e <= TO_EXP; e++)); do
  n=$((2 ** e))
  pdc2_line="$("$PDC2_BIN" --n "$n" --label-bits "$LABEL_BITS" --csv)"

  if [[ "$BACKEND" == "libote" ]]; then
    kkrt_line="$(LD_LIBRARY_PATH="$LIBOTE_LIB" "$KKRT_BIN" --n "$n" --label-bits "$LABEL_BITS" --max-ots-per-batch "$MAX_OTS_PER_BATCH" --csv)"
    python3 - "$pdc2_line" "$kkrt_line" <<'PY'
import sys
p = sys.argv[1].strip().split(",")
k = sys.argv[2].strip().split(",")
n, l = p[0], p[1]
pdc2_ms = float(p[6])
comm_bytes = int(p[7])
kkrt_ms = float(k[4])
compute_ms = pdc2_ms + kkrt_ms
def total_s(mbps):
    return (compute_ms + comm_bytes * 8.0 / (mbps * 1_000_000.0) * 1000.0) / 1000.0
print(f"{n:<10} {l:<10} {comm_bytes/1_000_000.0:<12.3f} {total_s(1000):<15.3f} {total_s(100):<17.3f} {total_s(10):<15.3f}")
PY
  else
    python3 - "$pdc2_line" <<'PY'
import sys
p = sys.argv[1].strip().split(",")
n, l = p[0], p[1]
comm_mb = float(p[8])
t1 = float(p[10])
t100 = float(p[11])
t10 = float(p[12])
print(f"{n:<10} {l:<10} {comm_mb:<12.3f} {t1:<15.3f} {t100:<17.3f} {t10:<15.3f}")
PY
  fi
done
