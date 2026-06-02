# KKRT-PDC2 Reproduction Harness

This repository contains a standalone C++17 harness for reproducing the full
execution flow of the paper's `KKRT-PDC2` protocol, i.e. `Vector-PDC2` from
Figure 6 instantiated with KKRT-style vector OPRF semantics.

The current backend implements the ideal `FVector-OPRF` functionality locally
and accounts communication with the paper's KKRT-PDC2 formula:

```text
(5m + 3n) * l * lambda bits, where m = ceil(1.27n), lambda = 128
```

This makes the complete PDC2 protocol path runnable without libOTe first. The
OPRF layer is isolated so it can be replaced by libOTe's KKRT implementation.

## Build

```bash
make
```

## Run

```bash
./build/kkrt_pdc2_bench --n 65536 --label-bits 10 --trials 1
```

Sweep several dataset sizes and label lengths:

```bash
./scripts/run_sweep.sh
```

Output columns:

- `n`: dataset size per party
- `label_bits`: label length `l`
- `m`: Cuckoo table size
- `matches_expected`: generated overlapping records with mismatching labels
- `matches_found`: protocol output count
- `ok`: correctness flag
- `compute_time_ms`: local compute/protocol time without bandwidth delay
- `comm_bytes_formula`: KKRT-PDC2 communication from the paper
- `comm_mb_formula`: same communication in decimal MB
- `comm_mib_formula`: same communication in MiB
- `total_time_1gbps_s`: estimated end-to-end time at 1 Gbps
- `total_time_100mbps_s`: estimated end-to-end time at 100 Mbps
- `total_time_10mbps_s`: estimated end-to-end time at 10 Mbps
- `comm_bytes_explicit`: explicit Figure 6 messages after ideal OPRF
