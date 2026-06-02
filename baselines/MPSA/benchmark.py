#!/usr/bin/env python3
"""
MPSI Protocol Benchmark
=======================
用法示例：
  python3 benchmark.py                                            # 默认参数
  python3 benchmark.py --m 1000 5000 --n 4 8                    # 指定大小和参与方
  python3 benchmark.py --m 2048 4096 8192 16384 32768 --n 4     # 2^11~2^15

参数说明：
  --m  <int...>   数据集大小列表       默认: 100 500 1000 2000 3000 5000
  --n  <int...>   参与方数量列表       默认: 2 3 4 6 8
  --lam <int>     安全参数 λ           默认: 64
  --l  <int>      LWE 秘密向量维度     默认: 10
  --overlap <f>   交集比例             默认: 0.3
"""

import argparse
import math
import random
import secrets
import sys
import time
from typing import Dict, List, Tuple

sys.path.insert(0, ".")
from mpsi import (
    ShamirSSS,
    decode_g_prime,
    next_prime,
    reliable_vector_aggregation,
    sample_index_generation,
    sample_to_bucket,
)

# ──────────────────────────────────────────────────────────
#  网络带宽（Bytes/s）
# ──────────────────────────────────────────────────────────
BANDWIDTHS = {
    "1 Gbps ": 1_000_000_000 / 8,   # 125.0 MB/s
    "100 Mbps":  100_000_000 / 8,   #  12.5 MB/s
    "10 Mbps ":   10_000_000 / 8,   #   1.25 MB/s
}

# ──────────────────────────────────────────────────────────
#  公共矩阵缓存（避免重复生成）
# ──────────────────────────────────────────────────────────
_A_CACHE: Dict[Tuple[int, int, int], List[List[int]]] = {}

def get_public_matrix(m: int, l: int, q: int) -> List[List[int]]:
    key = (m, l, q)
    if key not in _A_CACHE:
        _A_CACHE[key] = [
            [secrets.randbelow(q) for _ in range(l)] for _ in range(m)
        ]
    return _A_CACHE[key]


# ──────────────────────────────────────────────────────────
#  合成数据生成
# ──────────────────────────────────────────────────────────
def generate_datasets(N: int, n: int, overlap: float = 0.3) -> List[List[str]]:
    n_common   = max(1, int(n * overlap))
    n_personal = n - n_common
    total      = n_common + N * n_personal
    pool       = [f"u{i:08d}" for i in range(total)]
    common     = pool[:n_common]
    datasets   = []
    for i in range(N):
        start = n_common + i * n_personal
        datasets.append(common + pool[start: start + n_personal])
    return datasets


# ──────────────────────────────────────────────────────────
#  单次协议运行（内部计时单位：秒）
# ──────────────────────────────────────────────────────────
def run_once(datasets: List[List[str]], n: int, lam: int, l: int) -> Dict:
    N   = len(datasets)
    tau = N
    m   = n

    log2_lam    = math.log2(lam)
    log2_N_ceil = (N - 1).bit_length()
    lam_prime   = lam - int(log2_lam ** 2) - log2_N_ceil
    if lam_prime <= 0:
        raise ValueError(f"λ'={lam_prime}≤0: 请增大 λ 或减小 N")

    q   = next_prime(N * (1 << lam) + 1)
    bpe = (q.bit_length() + 7) // 8       # bytes per F_q element
    sss = ShamirSSS(tau=tau, N=N, p=q)
    A   = get_public_matrix(m, l, q)

    timings: Dict[str, float] = {}        # 单位：秒

    # Phase 1 : 样本索引生成 (Algorithm 1)
    t0 = time.perf_counter()
    b_list, d_list = [], []
    for samples in datasets:
        b, d = sample_index_generation(samples, m, lam, lam_prime)
        b_list.append(b)
        d_list.append(d)
    timings["ph1"] = time.perf_counter() - t0

    # Phase 2 : LWE 加密  c_i = A·s_i + d_i  (Eq.10)
    t0 = time.perf_counter()
    s_list, c_list = [], []
    for i in range(N):
        s_i = [secrets.randbelow(q) for _ in range(l)]
        c_i = [
            (sum(A[j][k] * s_i[k] for k in range(l)) + d_list[i][j]) % q
            for j in range(m)
        ]
        s_list.append(s_i)
        c_list.append(c_i)
    timings["ph2"] = time.perf_counter() - t0

    # Phase 3 : SSS 可靠向量聚合 (Algorithm 2)
    t0 = time.perf_counter()
    s_sum = reliable_vector_aggregation(s_list, sss, q)
    timings["ph3"] = time.perf_counter() - t0

    # Phase 4 : Server 计算 d_sum  (Eq.11)
    t0 = time.perf_counter()
    c_sum  = [sum(c_list[i][j] for i in range(N)) % q for j in range(m)]
    As_sum = [sum(A[j][k] * s_sum[k] for k in range(l)) % q for j in range(m)]
    d_sum  = [(c_sum[j] - As_sum[j]) % q for j in range(m)]
    timings["ph4"] = time.perf_counter() - t0

    # Phase 5 : 客户端解码  g'(d_sum,j, N)  (Eq.5)
    t0 = time.perf_counter()
    inter_buckets = {j for j in range(m) if decode_g_prime(d_sum[j], N, lam_prime)}
    result = [s for s in datasets[0] if sample_to_bucket(s, m) in inter_buckets]
    timings["ph5"] = time.perf_counter() - t0

    compute_s = sum(timings.values())

    # 通信量（字节数）
    comm_bytes = {
        "ph2_up": N * m * bpe,           # N 客户端上传密文
        "ph3_sh": 2 * N * N * l * bpe,  # 份额双向分发
        "ph3_om": N * l * bpe,           # ω_k 上传
        "ph4_dn": N * m * bpe,           # d_sum 下发
    }
    total_bytes = sum(comm_bytes.values())
    total_mb    = total_bytes / 1_048_576

    return {
        "N": N, "m": m, "lam_prime": lam_prime,
        "q_bits": q.bit_length(), "bpe": bpe,
        "timings":    timings,
        "comm_bytes": comm_bytes,
        "compute_s":  compute_s,
        "total_bytes": total_bytes,
        "total_mb":   total_mb,
        "inter_size": len(result),
    }


# ──────────────────────────────────────────────────────────
#  总时间（含传输）= 计算时间 + 通信字节 / 带宽，单位秒
# ──────────────────────────────────────────────────────────
def total_with_bw(r: Dict, bw_bps: float) -> float:
    return r["compute_s"] + r["total_bytes"] / bw_bps


# ──────────────────────────────────────────────────────────
#  通用表格打印
# ──────────────────────────────────────────────────────────
def print_grid(title: str, N_vals, m_vals, data: Dict, fmt: str) -> None:
    cw, rw = 11, 6
    print(f"\n{'━'*70}")
    print(f"  {title}")
    print(f"{'━'*70}")
    hdr = "N\\m"
    print(f"  {hdr:<{rw}}" + "".join(f"{v:>{cw}}" for v in m_vals))
    print("  " + "─" * (rw + cw * len(m_vals)))
    for N in N_vals:
        row = f"  {N:<{rw}}"
        for m in m_vals:
            v = data.get((N, m))
            row += f"{v:>{cw}{fmt}}" if v is not None else f"{'–':>{cw}}"
        print(row)


# ──────────────────────────────────────────────────────────
#  主函数
# ──────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="MPSI 协议基准测试",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--m", type=int, nargs="+",
        default=[100, 500, 1000, 2000, 3000, 5000],
        metavar="M",
        help="数据集大小列表，例如 --m 1000 5000",
    )
    parser.add_argument(
        "--n", type=int, nargs="+",
        default=[2, 3, 4, 6, 8],
        metavar="N",
        help="参与方数量列表，例如 --n 2 4 8",
    )
    parser.add_argument("--lam",     type=int,   default=64,  help="安全参数 λ（默认 64）")
    parser.add_argument("--l",       type=int,   default=10,  help="LWE 向量维度（默认 10）")
    parser.add_argument("--overlap", type=float, default=0.3, help="交集比例（默认 0.3）")
    args = parser.parse_args()

    M_VALS = sorted(set(args.m))
    N_VALS = sorted(set(args.n))
    LAM    = args.lam
    L      = args.l
    OVL    = args.overlap

    random.seed(2024)

    print(f"\n{'═'*70}")
    print(f"  MPSI 协议基准测试  （Algorithm 1 + 2 + 3，完整实现）")
    print(f"  λ={LAM}  l={L}  τ=N  交集比例={OVL*100:.0f}%  时间单位:s  通信单位:MB")
    print(f"  m 列表 : {M_VALS}")
    print(f"  N 列表 : {N_VALS}")
    print(f"{'═'*70}\n")

    all_results: Dict[Tuple[int, int], Dict] = {}

    for N in N_VALS:
        for m in M_VALS:
            datasets = generate_datasets(N, m, overlap=OVL)
            print(f"  N={N}, m={m:>7} ...", end="", flush=True)
            try:
                r = run_once(datasets, n=m, lam=LAM, l=L)
                all_results[(N, m)] = r
                print(f"  compute={r['compute_s']:.4f}s  "
                      f"comm={r['total_mb']:.4f}MB  "
                      f"q={r['q_bits']}b  λ'={r['lam_prime']}  |∩|={r['inter_size']}")
            except Exception as e:
                print(f"  ERROR: {e}")

    if not all_results:
        print("无结果，请检查参数。")
        return

    # ── 1. 各阶段时间细分表 ───────────────────────────────────
    phase_defs = [
        ("ph1",         "Phase 1 : 样本索引生成 (s)"),
        ("ph2",         "Phase 2 : LWE 加密 (s)"),
        ("ph3",         "Phase 3 : SSS 聚合 (s)"),
        ("ph4_ph5",     "Phase 4+5 : Server计算d_sum + 解码 (s)"),
    ]
    for ph_key, ph_title in phase_defs:
        if ph_key == "ph4_ph5":
            ph_data = {k: v["timings"]["ph4"] + v["timings"]["ph5"]
                       for k, v in all_results.items()}
        else:
            ph_data = {k: v["timings"][ph_key] for k, v in all_results.items()}
        print_grid(ph_title, N_VALS, M_VALS, ph_data, ".4f")

    # ── 2. 纯计算时间汇总 (s) ─────────────────────────────────
    compute_data = {k: v["compute_s"] for k, v in all_results.items()}
    print_grid("纯计算时间汇总 (s)  [Ph1+Ph2+Ph3+Ph4+Ph5]", N_VALS, M_VALS, compute_data, ".4f")

    # ── 3. 总通信量 (MB) ──────────────────────────────────────
    mb_data = {k: v["total_mb"] for k, v in all_results.items()}
    print_grid("总通信量 (MB)", N_VALS, M_VALS, mb_data, ".4f")

    # ── 4~6. 三种带宽下总时间 (s) ────────────────────────────
    for bw_label, bw_bps in BANDWIDTHS.items():
        bw_data = {k: total_with_bw(v, bw_bps) for k, v in all_results.items()}
        print_grid(
            f"总时间 @ {bw_label} (s)  [计算 + 传输]",
            N_VALS, M_VALS, bw_data, ".4f",
        )

    # ── 6. 单组详细分解 ───────────────────────────────────────
    demo_N = N_VALS[len(N_VALS) // 2] if len(N_VALS) > 1 else N_VALS[0]
    demo_m = M_VALS[len(M_VALS) // 2] if len(M_VALS) > 1 else M_VALS[0]
    r = all_results.get((demo_N, demo_m))
    if r:
        bpe = r["bpe"]
        print(f"\n{'━'*70}")
        print(f"  详细分解  N={demo_N}, m={demo_m}"
              f"  (λ'={r['lam_prime']}, q={r['q_bits']}b, {bpe}B/elem)")
        print(f"{'━'*70}")

        ph_labels = {
            "ph1": "Phase 1 : 样本索引生成 (Alg.1)",
            "ph2": "Phase 2 : LWE 加密 (Eq.10)",
            "ph3": "Phase 3 : SSS 聚合 (Alg.2)",
            "ph4": "Phase 4 : Server d_sum (Eq.11)",
            "ph5": "Phase 5 : 客户端解码 (Eq.5)",
        }
        print(f"\n  ▌计算时间细分")
        print(f"  {'阶段':<36}  {'时间 (s)':>12}")
        print(f"  {'─'*50}")
        for key, label in ph_labels.items():
            print(f"  {label:<36}  {r['timings'][key]:>12.6f}")
        print(f"  {'─'*50}")
        print(f"  {'合计':<36}  {r['compute_s']:>12.6f}")

        comm_labels = {
            "ph2_up": ("Phase 2 : 客户端上传密文",    "客户端 → Server"),
            "ph3_sh": ("Phase 3 : 份额分发 (双向)",    "双向"),
            "ph3_om": ("Phase 3 : ω_k 上传",           "客户端 → Server"),
            "ph4_dn": ("Phase 4 : d_sum 下发",         "Server → 客户端"),
        }
        print(f"\n  ▌通信量细分")
        print(f"  {'阶段':<36}  {'MB':>10}  方向")
        print(f"  {'─'*60}")
        for key, (label, direction) in comm_labels.items():
            mb = r["comm_bytes"][key] / 1_048_576
            print(f"  {label:<36}  {mb:>10.6f}  {direction}")
        print(f"  {'─'*60}")
        print(f"  {'合计':<36}  {r['total_mb']:>10.6f}")

        print(f"\n  ▌不同带宽下总时间")
        print(f"  {'带宽':<12}  {'传输时间 (s)':>14}  "
              f"{'计算时间 (s)':>14}  {'总时间 (s)':>12}")
        print(f"  {'─'*56}")
        for bw_label, bw_bps in BANDWIDTHS.items():
            comm_s = r["total_bytes"] / bw_bps
            total  = r["compute_s"] + comm_s
            print(f"  {bw_label:<12}  {comm_s:>14.6f}  "
                  f"{r['compute_s']:>14.6f}  {total:>12.6f}")

    print(f"\n{'═'*70}")
    print(f"  完成。  协议说明：所有 5 个阶段均已完整实现，当前基准在单机")
    print(f"  上模拟多参与方，传输时间按实际通信量 ÷ 带宽估算（无网络延迟）。")
    print(f"  生产环境建议 λ≥128。")
    print(f"{'═'*70}\n")


if __name__ == "__main__":
    main()
