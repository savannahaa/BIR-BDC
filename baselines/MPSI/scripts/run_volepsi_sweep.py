#!/usr/bin/env python3
import argparse
import csv
import re
import subprocess
import time
from pathlib import Path


def parse_list(text):
    return [int(x.strip()) for x in text.split(",") if x.strip()]


def parse_output(text):
    time_ms = None
    bytes_total = None
    intersection = None
    rss_mb = None

    end = re.search(r"^end\s+([0-9.]+)", text, re.MULTILINE)
    if end:
        time_ms = float(end.group(1))

    comm = re.search(r"bytesSent receiver=(\d+) sender=(\d+) total=(\d+)", text)
    if comm:
        bytes_total = int(comm.group(3))

    inter = re.search(r"intersection\s+(\d+)", text)
    if inter:
        intersection = int(inter.group(1))

    rss = re.search(r"peakRSS_MB\s+([0-9.]+)", text)
    if rss:
        rss_mb = float(rss.group(1))

    if time_ms is None or bytes_total is None or intersection is None:
        raise RuntimeError(f"failed to parse frontend output:\n{text}")

    return {
        "time_s": time_ms / 1000.0,
        "comm_mb": bytes_total / (1024.0 * 1024.0),
        "intersection": intersection,
        "rss_mb": rss_mb,
    }


def run_one(frontend, m, intersection, seed, args):
    cmd = [
        str(frontend),
        "-perf",
        "-psi",
        "-m",
        str(m),
        "-ts",
        str(intersection),
        "-seed",
        str(seed),
        "-slowRounds",
        str(args.slow_rounds),
        "-nt",
        str(args.threads),
        "-v",
    ]
    if args.malicious:
        cmd.append("-malicious")
    if args.no_compress:
        cmd.append("-nc")
    if args.fake_base:
        cmd.append("-fakeBase")

    started = time.perf_counter()
    proc = subprocess.run(cmd, cwd=args.repo, text=True, capture_output=True)
    wall_s = time.perf_counter() - started
    if proc.returncode != 0:
        raise RuntimeError(
            "frontend failed\n"
            + "cmd: "
            + " ".join(cmd)
            + "\nstdout:\n"
            + proc.stdout
            + "\nstderr:\n"
            + proc.stderr
        )
    parsed = parse_output(proc.stdout)
    parsed["wall_s"] = wall_s
    return parsed


def main():
    parser = argparse.ArgumentParser(
        description="Sweep volepsi pairwise PSI as a sequential star n-party baseline."
    )
    parser.add_argument("--repo", type=Path, default=Path("~/New_project_2/volepsi").expanduser())
    parser.add_argument("--frontend", type=Path, default=None)
    parser.add_argument("--m-values", required=True, help="comma-separated set sizes, e.g. 4096,65536")
    parser.add_argument("--n-values", required=True, help="comma-separated party counts, e.g. 3,5,10")
    parser.add_argument("--intersection", type=int, default=1000)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--slow-rounds", type=int, default=0)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--malicious", action="store_true")
    parser.add_argument("--no-compress", action="store_true")
    parser.add_argument("--fake-base", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("volepsi_sweep.csv"))
    args = parser.parse_args()

    frontend = args.frontend or args.repo / "out/build/linux/frontend/frontend"
    m_values = parse_list(args.m_values)
    n_values = parse_list(args.n_values)

    rows = []
    for m in m_values:
        if args.intersection > m:
            raise ValueError(f"intersection={args.intersection} exceeds m={m}")
        for parties in n_values:
            if parties < 2:
                raise ValueError("n-values must be >= 2")
            for rep in range(args.repeat):
                total_time_s = 0.0
                total_wall_s = 0.0
                total_comm_mb = 0.0
                max_rss_mb = 0.0
                pair_count = parties - 1

                for pair in range(pair_count):
                    seed = args.seed + rep * 100000 + parties * 1000 + pair
                    result = run_one(frontend, m, args.intersection, seed, args)
                    total_time_s += result["time_s"]
                    total_wall_s += result["wall_s"]
                    total_comm_mb += result["comm_mb"]
                    max_rss_mb = max(max_rss_mb, result["rss_mb"] or 0.0)

                row = {
                    "m": m,
                    "n_parties": parties,
                    "pairwise_runs": pair_count,
                    "repeat": rep,
                    "intersection": args.intersection,
                    "total_protocol_time_s": total_time_s,
                    "total_wall_time_s": total_wall_s,
                    "total_comm_MB": total_comm_mb,
                    "max_peak_RSS_MB": max_rss_mb,
                    "avg_pair_time_s": total_time_s / pair_count,
                    "avg_pair_comm_MB": total_comm_mb / pair_count,
                    "slow_rounds": args.slow_rounds,
                    "threads": args.threads,
                    "malicious": int(args.malicious),
                    "no_compress": int(args.no_compress),
                    "fake_base": int(args.fake_base),
                }
                rows.append(row)
                print(
                    f"m={m} n={parties} rep={rep}: "
                    f"time={total_time_s:.3f}s comm={total_comm_mb:.3f}MB rss={max_rss_mb:.3f}MB",
                    flush=True,
                )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
