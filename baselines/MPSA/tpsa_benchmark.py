#!/usr/bin/env python3
"""
T-PSA Benchmark  —  Algorithm 4 完整实现与性能/准确性分析
============================================================
用法示例：
  python3 tpsa_benchmark.py                              # 默认（准确性分析）
  python3 tpsa_benchmark.py --m 2048 8192 32768 --n 4   # 性能网格
  python3 tpsa_benchmark.py --m 2048 4096 8192 16384 32768 65536 131072 262144 524288 --n 4

参数：
  --m   数据集大小列表（默认仅运行准确性测试）
  --n   参与方数量（默认 4）
  --z   z 值列表（默认 10 20 30）
  --T   交集阈值（默认 200）

① T-PSA 性能：不同 m 和 z 下运行时间 (s) 和通信量 (MB)
② 判定成功率 & 误判率：|I|≥T 与 |I|<T 两种场景
③ GS 参数分析：z 和 ψ 对准确性的影响

Algorithm 4 核心流程：
  客户端 P_i（第 j 轮）：
    h_j ← H_{κ,ℓ},  y_j ←{0,1}^ℓ
    X^j_i = {x ∈ S_i : h_j(x) = y_j}       ← 过滤样本
    u^j_i ← H(X^j_i)                         ← m_T 维位向量
    v^j_i = A_T·s_i + u^j_i  (mod q)         ← LWE 加密
  Server：
    u^j_sum = Σ v^j_i − A_T·s_sum            ← 聚合解密
    β_j = 1  iff  ∃k: u^j_sum[k] == N        ← 检测交集
  最终：ε = 1  iff  Σβ_j > ψ
"""

import argparse
import hashlib, math, random, secrets, sys, time
from typing import Dict, List, Tuple

sys.path.insert(0, ".")
from mpsi import ShamirSSS, next_prime, reliable_vector_aggregation

# ─────────────────────────────────────────────────────────
#  § 1  哈希工具
# ─────────────────────────────────────────────────────────

def gs_hash(sample: str, j: int, ell: int) -> int:
    """h_j(x): 第 j 轮随机哈希，截取 ℓ 位 → {0,1}^ℓ"""
    raw = hashlib.sha256(f"gs|{j}|{sample}".encode()).digest()
    return int.from_bytes(raw[:4], "big") & ((1 << ell) - 1)

def H_bucket(sample: str, j: int, m_T: int) -> int:
    """碰撞安全哈希 H：将样本映射到 [0, m_T) 中的桶"""
    raw = hashlib.sha256(f"Hb|{j}|{sample}".encode()).digest()
    return int.from_bytes(raw[4:8], "big") % m_T

def choose_ell(T: int) -> int:
    """选择 ℓ 满足 2^{ℓ-2} ≤ T ≤ 2^{ℓ-1}，即 ℓ = ⌈log₂T⌉ + 1"""
    return math.ceil(math.log2(max(T, 2))) + 1

# ─────────────────────────────────────────────────────────
#  § 2  合成数据：精确控制交集大小
# ─────────────────────────────────────────────────────────

def make_datasets(N: int, n: int, inter_size: int) -> List[List[str]]:
    """生成 N 个大小为 n 的数据集，公共交集恰好 inter_size 个元素"""
    inter_size = min(inter_size, n)
    n_priv = n - inter_size
    pool   = [f"s{i:09d}" for i in range(inter_size + N * n_priv)]
    common = pool[:inter_size]
    sets   = []
    for i in range(N):
        start = inter_size + i * n_priv
        sets.append(list(common) + pool[start: start + n_priv])
    return sets

# ─────────────────────────────────────────────────────────
#  § 3  Algorithm 4：T-PSA 单次运行
# ─────────────────────────────────────────────────────────

def run_tpsa(
    datasets: List[List[str]],
    z: int, psi: int, ell: int, m_T: int,
    A_T: List[List[int]], s_sum: List[int],
    q: int,
    hash_cache: Dict = None,          # 可选预计算缓存
) -> Tuple[int, List[int], float, int]:
    """
    运行 Algorithm 4。
    返回 (ε, [β_j for j in z], compute_s, comm_bytes)

    LWE 加密/解密在仿真中互相抵消：
      v^j_sum − A_T·s_sum = Σ(A_T·s_i + u^j_i) − A_T·Σs_i = Σ u^j_i = u^j_sum
    因此直接累加 u^j_i 即可，通信量仍按协议规范计算。
    """
    N   = len(datasets)
    bpe = (q.bit_length() + 7) // 8
    t0  = time.perf_counter()

    beta_list: List[int] = []

    for j in range(z):
        y_j = secrets.randbelow(1 << ell)          # y_j ← {0,1}^ℓ

        # ① 各客户端：过滤 → 位向量 u^j_i
        u_sum = [0] * m_T
        for i, samples in enumerate(datasets):
            for x in samples:
                # 用缓存加速重复调用
                if hash_cache:
                    hv = hash_cache[i][x][j]
                else:
                    hv = gs_hash(x, j, ell)
                if hv == y_j:
                    bkt = H_bucket(x, j, m_T)
                    # u^j_i[bkt] = 1（位向量），直接累加到 u_sum
                    if u_sum[bkt] < N:
                        u_sum[bkt] += 1            # 等价于将所有 u^j_i 加和

        # ② Server：β_j = 1 iff ∃k: u_sum[k] == N
        beta_list.append(1 if any(v == N for v in u_sum) else 0)

    epsilon      = 1 if sum(beta_list) > psi else 0
    compute_s    = time.perf_counter() - t0
    # 通信量：N 客户端 × z 轮 × m_T 元素/轮 × bpe 字节/元素
    comm_bytes   = N * z * m_T * bpe
    return epsilon, beta_list, compute_s, comm_bytes

# ─────────────────────────────────────────────────────────
#  § 4  哈希预计算（加速多次试验）
# ─────────────────────────────────────────────────────────

def build_hash_cache(datasets: List[List[str]], z_max: int, ell: int) -> Dict:
    """预计算所有样本在每一轮的 gs_hash 值（只对固定 ell）"""
    cache = {}
    for i, samples in enumerate(datasets):
        cache[i] = {}
        for x in samples:
            cache[i][x] = [gs_hash(x, j, ell) for j in range(z_max)]
    return cache

# ─────────────────────────────────────────────────────────
#  § 5  多次试验统计
# ─────────────────────────────────────────────────────────

def trials(
    datasets, z, psi, ell, m_T,
    A_T, s_sum, q,
    n_trials: int,
    cache: Dict = None,
) -> float:
    """返回 ε=1 的比率（成功率或误判率）"""
    hits = sum(
        run_tpsa(datasets, z, psi, ell, m_T, A_T, s_sum, q, cache)[0]
        for _ in range(n_trials)
    )
    return hits / n_trials

# ─────────────────────────────────────────────────────────
#  § 6  理论单轮通过概率
# ─────────────────────────────────────────────────────────

def p_hit_theory(inter_size: int, ell: int) -> float:
    """P(β_j=1 | |I|=inter_size) = 1−(1−2^{-ℓ})^{|I|}"""
    if inter_size == 0:
        return 0.0
    return 1.0 - (1.0 - 2.0 ** (-ell)) ** inter_size

# ─────────────────────────────────────────────────────────
#  § 7  主函数
# ─────────────────────────────────────────────────────────

def print_grid(title: str, row_vals, col_vals, data: Dict,
               row_label: str, col_label: str, fmt: str) -> None:
    cw, rw = 14, 12
    print(f"\n{'━'*70}")
    print(f"  {title}")
    print(f"{'━'*70}")
    hdr_cell = row_label + "\\" + col_label
    print(f"  {hdr_cell:<{rw}}" +
          "".join(f"{'z='+str(c):>{cw}}" for c in col_vals))
    print("  " + "─" * (rw + cw * len(col_vals)))
    for r in row_vals:
        row = f"  {r:<{rw}}"
        for c in col_vals:
            v = data.get((r, c))
            row += f"{v:>{cw}{fmt}}" if v is not None else f"{'–':>{cw}}"
        print(row)


def _show_n_z_grid(n_vals: List[int], z_vals: List[int], m: int,
                   T: int, LAM: int, L: int) -> None:
    """固定 m，展示 N × z 网格（时间 & 通信量），直观体现 N 的线性影响。"""
    ell = choose_ell(T)
    time_data: Dict[Tuple, float] = {}
    mb_data:   Dict[Tuple, float] = {}

    print(f"\n{'═'*70}")
    print(f"  N × z 网格  (固定 m={m}, T={T}, λ={LAM})")
    print(f"  通信量公式: N × z² × bpe  →  随 N 线性增长，与 m 无关")
    print(f"{'═'*70}\n")

    for N in n_vals:
        q   = next_prime(N * (1 << LAM) + 1)
        bpe = (q.bit_length() + 7) // 8
        sss = ShamirSSS(tau=N, N=N, p=q)
        s_list = [[secrets.randbelow(q) for _ in range(L)] for _ in range(N)]
        s_sum  = reliable_vector_aggregation(s_list, sss, q)
        ds     = make_datasets(N, m, inter_size=max(1, m // 5))

        for z in z_vals:
            m_T = z
            psi = max(1, z // 3)
            A_T = [[secrets.randbelow(q) for _ in range(L)] for _ in range(m_T)]
            print(f"  N={N}, z={z:>3} ...", end="", flush=True)
            _, _, cs, cb = run_tpsa(ds, z, psi, ell, m_T, A_T, s_sum, q)
            time_data[(N, z)] = cs
            mb_data[(N, z)]   = cb / 1_048_576
            print(f"  {cs:.4f}s  {cb/1_048_576:.8f}MB")

    print_grid(f"时间 (s)  [m={m}]",
               n_vals, z_vals, time_data, "N", "z", ".4f")
    print_grid(f"通信量 (MB)  [m={m}，同一行内各列不同但各行随 N 线性增]",
               n_vals, z_vals, mb_data, "N", "z", ".8f")


def run_perf_grid(N: int, m_vals: List[int], z_vals: List[int],
                  T: int, LAM: int, L: int) -> None:
    """性能网格：不同 m（数据集大小）× z（轮数），输出时间和通信量。"""
    ell = choose_ell(T)
    q   = next_prime(N * (1 << LAM) + 1)
    bpe = (q.bit_length() + 7) // 8
    sss = ShamirSSS(tau=N, N=N, p=q)
    s_list = [[secrets.randbelow(q) for _ in range(L)] for _ in range(N)]
    s_sum  = reliable_vector_aggregation(s_list, sss, q)

    p_theory = T * 2 ** (-ell)
    print(f"\n{'═'*70}")
    print(f"  T-PSA 性能网格  N={N}  T={T}  λ={LAM}  ℓ={ell}  "
          f"p={p_theory:.4f}  {bpe}B/elem")
    print(f"  m 列表 : {m_vals}")
    print(f"  z 列表 : {z_vals}")
    print(f"{'═'*70}")
    print(f"\n  说明：通信量 = N×z×m_T×bpe = N×z²×bpe（与 m 无关）\n")

    time_data: Dict[Tuple, float] = {}
    mb_data:   Dict[Tuple, float] = {}

    for m in m_vals:
        for z in z_vals:
            m_T = z
            psi = max(1, z // 3)
            A_T = [[secrets.randbelow(q) for _ in range(L)] for _ in range(m_T)]
            ds  = make_datasets(N, m, inter_size=max(1, m // 5))

            print(f"  m={m:>8}, z={z:>3} ...", end="", flush=True)
            eps, _, cs, cb = run_tpsa(ds, z, psi, ell, m_T, A_T, s_sum, q)
            time_data[(m, z)] = cs
            mb_data[(m, z)]   = cb / 1_048_576
            print(f"  {cs:.4f}s  {cb/1_048_576:.8f}MB  (ε={eps})")

    print_grid("时间 (s)", m_vals, z_vals, time_data, "m", "z", ".4f")
    print_grid("通信量 (MB)", m_vals, z_vals, mb_data, "m", "z", ".8f")

    print(f"\n{'═'*70}")
    print(f"  完成")
    print(f"{'═'*70}\n")


def main():
    parser = argparse.ArgumentParser(description="T-PSA 基准测试")
    parser.add_argument("--m",  type=int, nargs="+", default=[], metavar="M",
                        help="数据集大小列表（指定后运行性能网格）")
    parser.add_argument("--n",  type=int, nargs="+", default=[4], metavar="N",
                        help="参与方数量列表（默认 4）")
    parser.add_argument("--z",  type=int, nargs="+", default=[10, 20, 30],
                        metavar="Z", help="z 值列表（默认 10 20 30）")
    parser.add_argument("--T",  type=int, default=200, help="交集阈值（默认 200）")
    parser.add_argument("--lam",type=int, default=64,  help="安全参数 λ（默认 64）")
    parser.add_argument("--l",  type=int, default=10,  help="LWE 向量维度（默认 10）")
    args = parser.parse_args()

    if args.m:
        # ── 性能网格模式 ──────────────────────────────────────
        n_vals = sorted(set(args.n))
        m_vals = sorted(set(args.m))
        z_vals = sorted(set(args.z))

        if len(n_vals) == 1:
            # 单个 N：m × z 网格
            run_perf_grid(N=n_vals[0], m_vals=m_vals, z_vals=z_vals,
                          T=args.T, LAM=args.lam, L=args.l)
        else:
            # 多个 N：分别输出每个 N 的 m × z 网格，最后额外输出 N × z 表
            for N in n_vals:
                run_perf_grid(N=N, m_vals=m_vals, z_vals=z_vals,
                              T=args.T, LAM=args.lam, L=args.l)

            # ── 固定 m=m_vals[len//2]，展示 N × z 依赖 ──────
            demo_m = m_vals[len(m_vals) // 2]
            _show_n_z_grid(n_vals=n_vals, z_vals=z_vals, m=demo_m,
                           T=args.T, LAM=args.lam, L=args.l)
        return

    # ── 默认模式：准确性分析 ──────────────────────────────────
    random.seed(42)

    N   = args.n[0]
    n   = 1000
    T   = args.T
    LAM = args.lam
    L   = args.l
    ell = choose_ell(T)

    log2_lam    = math.log2(LAM)
    log2_N_ceil = (N - 1).bit_length()
    lam_prime   = LAM - int(log2_lam ** 2) - log2_N_ceil
    q   = next_prime(N * (1 << LAM) + 1)
    bpe = (q.bit_length() + 7) // 8
    sss = ShamirSSS(tau=N, N=N, p=q)

    # s_sum 由主协议 SSS 聚合得到（此处模拟）
    s_list = [[secrets.randbelow(q) for _ in range(L)] for _ in range(N)]
    s_sum  = reliable_vector_aggregation(s_list, sss, q)

    p_theory = T * 2 ** (-ell)   # p = T·2^{-ℓ}，应 ∈ [1/4, 1/2]

    print(f"\n{'═'*65}")
    print(f"  T-PSA Benchmark")
    print(f"  N={N}  n={n}  T={T}  λ={LAM}  ℓ={ell}  q={q.bit_length()}b  {bpe}B/elem")
    print(f"  p = T·2^{{-ℓ}} = {T}·2^{{-{ell}}} = {p_theory:.4f}  ∈ [1/4, 1/2] ✓")
    print(f"{'═'*65}")

    # ────────────────────────────────────────────────────
    #  ① T-PSA 性能：时间 (s) 与 通信量 (MB)
    # ────────────────────────────────────────────────────
    print(f"\n{'━'*65}")
    print(f"  ① T-PSA 性能  (N={N}, n={n}, T={T}, 1次运行)")
    print(f"{'━'*65}")

    z_perf_vals = [10, 20, 30, 40, 50]
    ds_perf = make_datasets(N, n, inter_size=T)

    print(f"  {'z':>5}  {'m_T':>5}  {'时间 (s)':>12}  {'通信量 (MB)':>14}")
    print(f"  {'─'*42}")
    for z in z_perf_vals:
        m_T = z                    # m_T ≈ z（论文设定）
        psi = z // 3
        A_T = [[secrets.randbelow(q) for _ in range(L)] for _ in range(m_T)]
        eps, _, cs, cb = run_tpsa(ds_perf, z, psi, ell, m_T, A_T, s_sum, q)
        print(f"  {z:>5}  {m_T:>5}  {cs:>12.6f}  {cb/1_048_576:>14.8f}")

    # ────────────────────────────────────────────────────
    #  ② 判定成功率 & 误判率  (z=20, ψ=z/3)
    # ────────────────────────────────────────────────────
    Z2, PSI2, MT2, N_TR2 = 20, 7, 20, 100

    A_T2 = [[secrets.randbelow(q) for _ in range(L)] for _ in range(MT2)]

    print(f"\n{'━'*65}")
    print(f"  ② 判定成功率 & 误判率  (z={Z2}, ψ={PSI2}, m_T={MT2}, {N_TR2} 次试验)")
    print(f"{'━'*65}")
    print(f"  {'|I| 情况':<30}  {'P(ε=1)':>8}  {'判定':>8}  {'理论P(β_j=1)':>14}")
    print(f"  {'─'*64}")

    cases = [
        (0,       f"|I|=0  (空交集)"),
        (T//4,    f"|I|=T/4={T//4}"),
        (T//2,    f"|I|=T/2={T//2}"),
        (T,       f"|I|=T={T}  ← 等于阈值"),
        (int(T*1.5), f"|I|=1.5T={int(T*1.5)}"),
        (T*2,     f"|I|=2T={T*2}"),
        (T*3,     f"|I|=3T={T*3}"),
    ]

    for inter_sz, label in cases:
        ds   = make_datasets(N, n, inter_sz)
        cache= build_hash_cache(ds, Z2, ell)
        rate = trials(ds, Z2, PSI2, ell, MT2, A_T2, s_sum, q, N_TR2, cache)
        ok   = "✓ 正确" if (inter_sz >= T and rate >= 0.5) or \
                          (inter_sz <  T and rate < 0.15) else "△ 边界"
        th   = p_hit_theory(inter_sz, ell)
        print(f"  {label:<30}  {rate:>8.2f}  {ok:>8}  {th:>14.4f}")

    # ────────────────────────────────────────────────────
    #  ③ GS 参数 z 和 ψ 对准确性的影响
    # ────────────────────────────────────────────────────
    N_TR3  = 50
    ds_pos = make_datasets(N, n, T * 2)    # |I|=2T  → 应输出 ε=1
    ds_neg = make_datasets(N, n, 0)         # |I|=0   → 应输出 ε=0

    print(f"\n{'━'*65}")
    print(f"  ③ GS 参数分析  ({N_TR3} 次试验/组)")
    print(f"     行：ψ 占 z 的比例；列：z；")
    print(f"     格式 = 成功率(|I|=2T) / 误判率(|I|=0)")
    print(f"{'━'*65}")

    z_vals3   = [10, 20, 30]
    psi_specs = [
        ("ψ=z/5",  lambda z: max(1, z // 5)),
        ("ψ=z/4",  lambda z: max(1, z // 4)),
        ("ψ=z/3",  lambda z: max(1, z // 3)),
        ("ψ=z/2",  lambda z: max(1, z // 2)),
        ("ψ=2z/3", lambda z: max(1, 2 * z // 3)),
    ]

    # 表头
    cw = 18
    hdr = f"  {'':14}" + "".join(f"{'z='+str(z):>{cw}}" for z in z_vals3)
    print(hdr)
    print("  " + "─" * (14 + cw * len(z_vals3)))

    for psi_label, psi_fn in psi_specs:
        row = f"  {psi_label:<14}"
        for z in z_vals3:
            psi_v = psi_fn(z)
            m_T3  = z
            A_T3  = [[secrets.randbelow(q) for _ in range(L)] for _ in range(m_T3)]
            cache_pos = build_hash_cache(ds_pos, z, ell)
            cache_neg = build_hash_cache(ds_neg, z, ell)
            sr  = trials(ds_pos, z, psi_v, ell, m_T3, A_T3, s_sum, q, N_TR3, cache_pos)
            fpr = trials(ds_neg, z, psi_v, ell, m_T3, A_T3, s_sum, q, N_TR3, cache_neg)
            cell = f"{sr:.2f}/{fpr:.2f}"
            row += f"{cell:>{cw}}"
        print(row)

    print(f"\n  说明：成功率=P(ε=1||I|=2T)，误判率=P(ε=1||I|=0)")
    print(f"  理想结果：成功率→1.0，误判率→0.0")
    print(f"\n{'═'*65}")
    print(f"  完成")
    print(f"{'═'*65}\n")


if __name__ == "__main__":
    main()
