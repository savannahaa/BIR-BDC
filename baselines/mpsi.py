#!/usr/bin/env python3
"""
MPSI Protocol: Delegated Multi-Party Private Set Intersection
============================================================
Source paper:
  "Private Sample Alignment for Vertical Federated Learning:
   An Efficient and Reliable Realization"  (Xi et al.)

Implements:
  · Algorithm 1 – Sample Index Generation
  · Algorithm 2 – Reliable Vector Aggregation (Shamir SSS)
  · Algorithm 3 – Private Sample Alignment (LWE + outsourced server)

Excluded:  T-PSA (Algorithm 4, Goldwasser-Sipser threshold variant).

Protocol overview
-----------------
N clients each hold a private set of sample IDs.  They want the server
to compute the intersection without learning individual sets.

Step 1 (clients) – Each client P_i:
  • Hashes its samples into an m-bit vector  b_i  (presence/absence).
  • Encodes b_i into an m-int vector  d_i  via function g (Eq. 4):
      b_{i,j} = 1  →  d_{i,j} ∈ Z_{2^λ'}  (small domain)
      b_{i,j} = 0  →  d_{i,j} ∈ Z_{2^λ}   (large domain)
  • Generates a random secret  s_i ∈ F_q^l  and computes (Eq. 10):
      c_i = A · s_i + d_i   (mod q)
  • Uploads  c_i  to the server.

Step 2 (server + clients) – Reliable Vector Aggregation (Alg. 2):
  • Each P_i splits s_i into N Shamir shares and distributes them.
  • Each P_k sums the k-th shares from all clients → ω_k  (Eq. 8).
    (By SSS additivity:  ω_k evaluates the aggregate polynomial at k.)
  • Server uses τ ω-values and Lagrange interpolation → s_sum = Σ s_i.

Step 3 (server) – Compute d_sum (Eq. 11):
  • c_sum = Σ c_i  (mod q)
  • d_sum = c_sum − A · s_sum  (mod q)   ≡  Σ d_i  (mod q)

Step 4 (clients) – Decode (Eq. 5):
  • g'(d_sum,j , N) = 1   if  d_sum,j < 2^(⌈log₂N⌉ + λ')
                     = 0   otherwise
  Each client checks its own samples against the intersection buckets.

Correctness argument
--------------------
Intersection bucket j (all clients have it):
  Σ d_{i,j}  ≤  N · (2^λ' − 1)  <  N · 2^λ'  ≤  2^(⌈log₂N⌉ + λ')
  → g' returns 1  ✓

Non-intersection bucket j (some client has b_{i,j} = 0):
  That client's d_{i,j} ∈ Z_{2^λ}, so the sum contains a term drawn from
  the large domain.  Probability of falling below the decode threshold:
    ≈ 2^(log₂N + λ') / 2^λ  =  2^{−(log₂λ)²}  (negligible)  ✓
"""

import hashlib
import math
import secrets
from typing import List, Tuple

# ─────────────────────────────────────────────────────────
#  § 1  Number-theory helpers
# ─────────────────────────────────────────────────────────

def _is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin (correct for n < 3.3 × 10²⁴)."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for a in small_primes:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int) -> int:
    """Smallest prime ≥ n."""
    n = max(2, n)
    if n == 2:
        return 2
    n |= 1  # make odd
    while not _is_prime(n):
        n += 2
    return n


def modinv(a: int, p: int) -> int:
    """a⁻¹ mod p  (p prime, a ≢ 0)."""
    return pow(a, p - 2, p)


# ─────────────────────────────────────────────────────────
#  § 2  Shamir's Secret Sharing  (Section III-B, Eqs. 2–3)
# ─────────────────────────────────────────────────────────

class ShamirSSS:
    """(τ, N)-threshold Secret Sharing over the prime field F_p."""

    def __init__(self, tau: int, N: int, p: int) -> None:
        assert 1 <= tau <= N, "Need 1 ≤ τ ≤ N"
        self.tau = tau
        self.N   = N
        self.p   = p

    # --- distribution phase ---

    def share(self, secret: int) -> List[Tuple[int, int]]:
        """
        Polynomial f of degree τ−1 with f(0) = secret.
        Returns  [(k, f(k))  for  k = 1..N].
        """
        p      = self.p
        coeffs = [secret % p] + [secrets.randbelow(p) for _ in range(self.tau - 1)]

        def poly(x: int) -> int:
            return sum(c * pow(x, i, p) for i, c in enumerate(coeffs)) % p

        return [(k, poly(k)) for k in range(1, self.N + 1)]

    # --- reconstruction phase  (Eq. 3) ---

    def reconstruct(self, shares: List[Tuple[int, int]]) -> int:
        """
        Lagrange interpolation at x = 0 from (at least) τ shares.
        Uses only the first τ pairs provided.
        """
        pts = shares[: self.tau]
        p   = self.p
        acc = 0
        for i, (xi, yi) in enumerate(pts):
            num = den = 1
            for j, (xj, _) in enumerate(pts):
                if i == j:
                    continue
                num = num * (p - xj) % p   # multiply by (−xj) mod p
                den = den * (xi - xj) % p
            acc = (acc + yi * num * modinv(den, p)) % p
        return acc


# ─────────────────────────────────────────────────────────
#  § 3  Encoding / Decoding  (Eqs. 4–5)
# ─────────────────────────────────────────────────────────

def encode_g(bit: int, lam: int, lam_prime: int) -> int:
    """
    Encoding function g  (Eq. 4).
      bit = 1  →  r ←$ Z_{2^λ'}     (small domain; signals *presence*)
      bit = 0  →  r ←$ Z_{2^λ}      (large domain; signals *absence*)
    """
    n_bits = lam_prime if bit == 1 else lam
    return secrets.randbelow(1 << n_bits)


def decode_g_prime(val: int, N: int, lam_prime: int) -> int:
    """
    Decoding function g'  (Eq. 5).
      Returns 1 if  val < 2^(⌈log₂N⌉ + λ')  (intersection),  else 0.
    """
    log2_N_ceil = (N - 1).bit_length()          # ⌈log₂N⌉
    threshold   = 1 << (log2_N_ceil + lam_prime)
    return 1 if val < threshold else 0


# ─────────────────────────────────────────────────────────
#  § 4  Sample → bucket hashing  (hash function H in paper)
# ─────────────────────────────────────────────────────────

def sample_to_bucket(sample: str, m: int) -> int:
    """Collision-resistant hash of a sample ID to a bucket in [0, m)."""
    raw = hashlib.sha256(sample.encode()).digest()
    return int.from_bytes(raw, "big") % m


# ─────────────────────────────────────────────────────────
#  § 5  Algorithm 1 – Sample Index Generation
# ─────────────────────────────────────────────────────────

def sample_index_generation(
    samples:   List[str],
    m:         int,
    lam:       int,
    lam_prime: int,
) -> Tuple[List[int], List[int]]:
    """
    Algorithm 1.

    Phase A  – Sample mapping vectorization
        Build m-bit vector  b  where  b[j] = 1  iff some sample in
        `samples` hashes to bucket j.

    Phase B  – Index summation encoding
        d[j] = g(b[j])   (Eq. 4)

    Returns (b, d).
    """
    # Phase A: bit-vector
    b = [0] * m
    for s in samples:
        b[sample_to_bucket(s, m)] = 1

    # Phase B: encode
    d = [encode_g(b[j], lam, lam_prime) for j in range(m)]
    return b, d


# ─────────────────────────────────────────────────────────
#  § 6  Algorithm 2 – Reliable Vector Aggregation
# ─────────────────────────────────────────────────────────

def reliable_vector_aggregation(
    secret_vecs: List[List[int]],   # [s_i  for i in range(N)]
    sss:         ShamirSSS,
    q:           int,
) -> List[int]:
    """
    Algorithm 2.  Securely computes  s_sum = Σ_i s_i  (mod q).

    Full distributed simulation (honest-but-curious model):

    ① P_i  splits each element  s_{i,j}  into N shares via SSS.
    ② Server routes the k-th share of every P_i to client P_k.
    ③ P_k  sums all received shares element-wise → ω_{k,j}.
       (SSS additive homomorphism:  ω_{k,j} = Σ_i f_{i,j}(k)
        evaluates the *aggregate* polynomial at k.)
    ④ Server reconstructs  s_sum,j  via Lagrange interpolation on
       τ point-value pairs  {(k, ω_{k,j})}.

    Returns  s_sum  as a list of l integers in F_q.
    """
    N = len(secret_vecs)
    l = len(secret_vecs[0])

    # Step ① – generate all shares
    # shares[j][i] = list of N (x_k, f_{i,j}(k)) tuples
    shares: List[List[List[Tuple[int, int]]]] = []
    for j in range(l):
        col = [sss.share(secret_vecs[i][j]) for i in range(N)]
        shares.append(col)

    # Step ③ – each client k computes ω_k  (intermediate result)
    # omega[k][j] = ω_{k+1, j}   (0-indexed k)
    omega: List[List[int]] = []
    for k in range(N):
        omega_k = [
            sum(shares[j][i][k][1] for i in range(N)) % sss.p
            for j in range(l)
        ]
        omega.append(omega_k)

    # Step ④ – server reconstructs s_sum via Lagrange interpolation
    # Uses only the first τ clients' omega values
    s_sum: List[int] = []
    for j in range(l):
        pt_vals = [(k + 1, omega[k][j]) for k in range(sss.tau)]
        s_sum.append(sss.reconstruct(pt_vals))
    return s_sum


# ─────────────────────────────────────────────────────────
#  § 7  Algorithm 3 – Private Sample Alignment
# ─────────────────────────────────────────────────────────

def private_sample_alignment(
    client_sample_sets: List[List[str]],
    m:         int  = None,
    l:         int  = 20,
    lam:       int  = 64,
    tau:       int  = None,
    verbose:   bool = True,
) -> List[str]:
    """
    Algorithm 3: Full delegated MPSI for Private Sample Alignment.

    Parameters
    ----------
    client_sample_sets : one list of sample-ID strings per client.
    m                  : hash-table size  (default: 4 × max |S_i|).
    l                  : LWE secret-vector dimension.
    lam                : security parameter λ  (≥ 64 recommended).
    tau                : SSS threshold τ  (default: N, require all clients).
    verbose            : print protocol trace.

    Returns
    -------
    Sorted list of intersection sample IDs visible to client 1.
    """
    N = len(client_sample_sets)
    if m is None:
        m = 4 * max(len(s) for s in client_sample_sets)
    if tau is None:
        tau = N

    # ── Derive security parameters ──────────────────────────────────
    log2_lam      = math.log2(lam)
    log2_N_ceil   = (N - 1).bit_length()             # ⌈log₂N⌉
    lam_prime     = lam - int(log2_lam ** 2) - log2_N_ceil
    if lam_prime <= 0:
        raise ValueError(
            f"λ'={lam_prime} ≤ 0.  Increase λ (currently {lam}) "
            f"or reduce N ({N})."
        )
    decode_thresh = 1 << (log2_N_ceil + lam_prime)

    # Prime field F_q used for both LWE and SSS.
    # Must satisfy q > N · 2^λ so encoded sums never wrap around.
    q   = next_prime(N * (1 << lam) + 1)
    sss = ShamirSSS(tau=tau, N=N, p=q)

    # Shared public matrix A ∈ F_q^{m × l}  (all parties know A)
    A: List[List[int]] = [
        [secrets.randbelow(q) for _ in range(l)]
        for _ in range(m)
    ]

    if verbose:
        print(f"\n{'═'*55}")
        print(f"  Private Sample Alignment  –  Protocol Trace")
        print(f"{'═'*55}")
        print(f"  N={N}  τ={tau}  m={m}  l={l}  λ={lam}  λ'={lam_prime}")
        print(f"  q  ({q.bit_length()} bits)")
        print(f"  decode threshold = 2^{log2_N_ceil + lam_prime}")

    # ── Phase 1 : Sample Index Generation  (Algorithm 1) ────────────
    if verbose:
        print(f"\n[Phase 1]  Sample Index Generation (Alg. 1)")
    b_list: List[List[int]] = []
    d_list: List[List[int]] = []
    for i, samples in enumerate(client_sample_sets):
        b, d = sample_index_generation(samples, m, lam, lam_prime)
        b_list.append(b)
        d_list.append(d)
        if verbose:
            print(f"    P{i+1}: {len(samples)} samples → "
                  f"{sum(b)} active buckets in b_{i+1}")

    # ── Phase 2 : LWE Encryption  c_i = A·s_i + d_i  (Eq. 10) ──────
    if verbose:
        print(f"\n[Phase 2]  LWE Encryption   c_i = A·s_i + d_i  (mod q)")
    s_list: List[List[int]] = []
    c_list: List[List[int]] = []
    for i in range(N):
        s_i: List[int] = [secrets.randbelow(q) for _ in range(l)]
        c_i: List[int] = [
            (sum(A[j][k] * s_i[k] for k in range(l)) + d_list[i][j]) % q
            for j in range(m)
        ]
        s_list.append(s_i)
        c_list.append(c_i)
    if verbose:
        print(f"    Each P_i uploads a {m}-dim encrypted vector to server.")

    # ── Phase 3 : Reliable Vector Aggregation  (Algorithm 2) ────────
    if verbose:
        print(f"\n[Phase 3]  Reliable Vector Aggregation (Alg. 2, τ={tau})")
    s_sum = reliable_vector_aggregation(s_list, sss, q)
    if verbose:
        print(f"    s_sum reconstructed via Lagrange interpolation ✓")

    # ── Phase 4 : Server computes d_sum  (Eq. 11) ───────────────────
    if verbose:
        print(f"\n[Phase 4]  Server:  d_sum = c_sum − A·s_sum  (mod q)")

    # c_sum = Σ c_i  (mod q)
    c_sum = [sum(c_list[i][j] for i in range(N)) % q for j in range(m)]

    # A · s_sum  (mod q)
    As_sum = [
        sum(A[j][k] * s_sum[k] for k in range(l)) % q
        for j in range(m)
    ]

    # d_sum = c_sum − A·s_sum  (mod q)
    d_sum = [(c_sum[j] - As_sum[j]) % q for j in range(m)]

    # Internal correctness check (simulation only; not part of real protocol)
    d_sum_ref = [
        sum(d_list[i][j] for i in range(N)) % q for j in range(m)
    ]
    assert d_sum == d_sum_ref, "BUG: d_sum mismatch"
    if verbose:
        print(f"    d_sum verified  ✓")

    # ── Phase 5 : Client-side Decoding  (Eq. 5) ─────────────────────
    if verbose:
        print(f"\n[Phase 5]  Clients decode  g'(d_sum[j], N, λ')")

    intersection_buckets = {
        j for j in range(m)
        if decode_g_prime(d_sum[j], N, lam_prime)
    }

    # Each client independently identifies its own samples in intersection.
    # Here we show all clients' results.
    all_client_results: List[List[str]] = []
    for i, samples in enumerate(client_sample_sets):
        found = sorted(
            s for s in samples
            if sample_to_bucket(s, m) in intersection_buckets
        )
        all_client_results.append(found)

    if verbose:
        print(f"    Intersection buckets: {len(intersection_buckets)}")
        for i, res in enumerate(all_client_results):
            print(f"    P{i+1} decoded intersection: {res}")

    # Return client 1's result (representative; all agree on common samples)
    return all_client_results[0]


# ─────────────────────────────────────────────────────────
#  § 8  Test / Demo
# ─────────────────────────────────────────────────────────

def _true_intersection(sample_sets: List[List[str]]) -> List[str]:
    return sorted(set.intersection(*[set(s) for s in sample_sets]))


def _run_test(
    name:    str,
    sets:    List[List[str]],
    m:       int,
    l:       int   = 10,
    lam:     int   = 64,
    tau:     int   = None,
) -> None:
    print(f"\n{'━'*55}")
    print(f"  TEST: {name}")
    print(f"{'━'*55}")
    for i, s in enumerate(sets):
        print(f"  P{i+1}: {sorted(s)}")

    true = _true_intersection(sets)
    print(f"  True intersection: {true}")

    result = private_sample_alignment(sets, m=m, l=l, lam=lam, tau=tau)
    ok = set(result) == set(true)
    print(f"\n  ▶  Protocol result  : {result}")
    print(f"  ▶  Correct          : {'✓ YES' if ok else '✗ NO'}")


if __name__ == "__main__":
    import random

    # ── Test 1: 3 clients, small overlapping sets ────────────────────
    _run_test(
        name="3 clients – small sets",
        sets=[
            ["user_001", "user_002", "user_003", "user_004", "user_005"],
            ["user_002", "user_003", "user_005", "user_006", "user_007"],
            ["user_001", "user_003", "user_005", "user_008", "user_009"],
        ],
        m=200,
        l=10,
        lam=64,
        tau=3,
    )

    # ── Test 2: 4 clients, 15 samples each ──────────────────────────
    print(f"\n{'━'*55}")
    print(f"  TEST: 4 clients – 15 samples each, τ=3 (fault-tolerant)")
    print(f"{'━'*55}")
    random.seed(42)
    pool   = [f"id_{i:04d}" for i in range(80)]
    common = random.sample(pool, 6)
    sets4  = []
    for _ in range(4):
        personal = random.sample([x for x in pool if x not in common], 9)
        sets4.append(common + personal)
    for i, s in enumerate(sets4):
        print(f"  P{i+1}: {sorted(s)}")
    true4 = _true_intersection(sets4)
    print(f"  True intersection: {true4}")

    result4 = private_sample_alignment(sets4, m=500, l=15, lam=64, tau=3)
    ok4 = set(result4) == set(true4)
    print(f"\n  ▶  Protocol result  : {result4}")
    print(f"  ▶  Correct (τ=3<N=4): {'✓ YES' if ok4 else '✗ NO'}")

    # ── Test 3: Disjoint sets (empty intersection) ───────────────────
    _run_test(
        name="2 clients – disjoint sets (empty intersection)",
        sets=[["a", "b", "c"], ["d", "e", "f"]],
        m=50,
        l=5,
        lam=64,
        tau=2,
    )

    # ── Test 4: Full intersection ────────────────────────────────────
    _run_test(
        name="3 clients – identical sets",
        sets=[["x", "y", "z"]] * 3,
        m=50,
        l=5,
        lam=64,
        tau=3,
    )
