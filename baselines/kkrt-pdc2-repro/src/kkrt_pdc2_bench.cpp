#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

struct Block {
    uint64_t lo;
    uint64_t hi;

    bool operator==(const Block& other) const {
        return lo == other.lo && hi == other.hi;
    }
};

struct BlockHash {
    size_t operator()(const Block& b) const {
        return static_cast<size_t>(b.lo ^ (b.hi + 0x9e3779b97f4a7c15ULL + (b.lo << 6) + (b.lo >> 2)));
    }
};

Block operator^(const Block& a, const Block& b) {
    return {a.lo ^ b.lo, a.hi ^ b.hi};
}

uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

uint64_t mix_many(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    uint64_t x = splitmix64(a);
    x ^= splitmix64(b + 0x517cc1b727220a95ULL);
    x = splitmix64(x ^ c);
    x ^= splitmix64(d + 0x6c8e9cf570932bd5ULL);
    return splitmix64(x);
}

Block hash_block(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    uint64_t lo = mix_many(a, b, c, d);
    uint64_t hi = mix_many(a ^ 0xa24baed4963ee407ULL, b, c ^ 0x9fb21c651e98df25ULL, d);
    return {lo, hi};
}

Block prf(const Block& key, const Block& input) {
    return hash_block(input.lo ^ key.lo, input.hi ^ key.hi, key.lo + input.hi, key.hi + input.lo);
}

uint64_t prefix_value(uint64_t label, uint32_t label_bits, uint32_t prefix_len, bool flip_last) {
    if (prefix_len == 0 || prefix_len > label_bits || prefix_len > 63) {
        throw std::runtime_error("invalid prefix length");
    }
    const uint32_t shift = label_bits - prefix_len;
    uint64_t prefix = label >> shift;
    if (flip_last) {
        prefix ^= 1ULL;
    }
    return prefix;
}

Block protocol_hash(uint64_t item, uint64_t label, uint32_t label_bits, uint32_t prefix_len, bool flip_last) {
    uint64_t prefix = prefix_value(label, label_bits, prefix_len, flip_last);
    return hash_block(item, prefix, prefix_len, 0);
}

struct Record {
    uint64_t item;
    uint64_t label;
};

struct Bucket {
    bool occupied = false;
    uint64_t item = 0;
    uint64_t label = 0;
    uint8_t choice = 0;
};

struct CuckooTable {
    std::vector<Bucket> buckets;
    uint64_t seed = 0;
};

std::array<size_t, 3> choices(uint64_t item, size_t m, uint64_t seed) {
    std::array<size_t, 3> out{};
    size_t count = 0;
    uint64_t ctr = 0;
    while (count < 3) {
        size_t h = static_cast<size_t>(mix_many(item, seed, ctr, 0) % m);
        bool duplicate = false;
        for (size_t i = 0; i < count; ++i) {
            duplicate = duplicate || out[i] == h;
        }
        if (!duplicate) {
            out[count++] = h;
        }
        ++ctr;
    }
    return out;
}

bool cuckoo_insert(CuckooTable& table, const Record& rec, uint64_t seed) {
    const size_t m = table.buckets.size();
    uint64_t cur_item = rec.item;
    uint64_t cur_label = rec.label;
    uint8_t cur_choice = 0;
    size_t pos = choices(cur_item, m, seed)[cur_choice];
    const size_t max_kicks = 500;

    for (size_t kick = 0; kick < max_kicks; ++kick) {
        Bucket& b = table.buckets[pos];
        if (!b.occupied) {
            b.occupied = true;
            b.item = cur_item;
            b.label = cur_label;
            b.choice = cur_choice;
            return true;
        }

        std::swap(cur_item, b.item);
        std::swap(cur_label, b.label);
        std::swap(cur_choice, b.choice);

        auto ch = choices(cur_item, m, seed);
        cur_choice = static_cast<uint8_t>((cur_choice + 1) % 3);
        pos = ch[cur_choice];
    }
    return false;
}

std::pair<CuckooTable, CuckooTable> build_shared_cuckoo(
    const std::vector<Record>& sender,
    const std::vector<Record>& receiver,
    size_t m,
    uint64_t seed_base) {
    for (uint64_t attempt = 0; attempt < 100; ++attempt) {
        uint64_t seed = seed_base + attempt * 0x9e3779b97f4a7c15ULL;
        CuckooTable ts;
        CuckooTable tr;
        ts.buckets.resize(m);
        tr.buckets.resize(m);
        ts.seed = seed;
        tr.seed = seed;
        bool ok = true;
        for (const auto& rec : sender) {
            if (!cuckoo_insert(ts, rec, seed)) {
                ok = false;
                break;
            }
        }
        if (!ok) {
            continue;
        }
        for (const auto& rec : receiver) {
            if (!cuckoo_insert(tr, rec, seed)) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return {std::move(ts), std::move(tr)};
        }
    }
    throw std::runtime_error("failed to build shared stash-less cuckoo tables");
}

struct Args {
    size_t n = 1ULL << 16;
    uint32_t label_bits = 10;
    uint64_t seed = 1;
    double overlap = 0.5;
    double mismatch = 0.5;
    int trials = 1;
    bool csv = false;
    bool debug = false;
};

Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need_value = [&](const std::string& name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error("missing value for " + name);
            }
            return argv[++i];
        };
        if (a == "--n") args.n = std::stoull(need_value(a));
        else if (a == "--label-bits" || a == "-l") args.label_bits = static_cast<uint32_t>(std::stoul(need_value(a)));
        else if (a == "--seed") args.seed = std::stoull(need_value(a));
        else if (a == "--overlap") args.overlap = std::stod(need_value(a));
        else if (a == "--mismatch") args.mismatch = std::stod(need_value(a));
        else if (a == "--trials") args.trials = std::stoi(need_value(a));
        else if (a == "--csv") args.csv = true;
        else if (a == "--debug") args.debug = true;
        else if (a == "--help") {
            std::cout << "Usage: kkrt_pdc2_bench --n N --label-bits L [--csv]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + a);
        }
    }
    if (args.label_bits == 0 || args.label_bits > 63) {
        throw std::runtime_error("label bits must be in [1,63]");
    }
    if (args.overlap < 0 || args.overlap > 1 || args.mismatch < 0 || args.mismatch > 1) {
        throw std::runtime_error("overlap and mismatch must be in [0,1]");
    }
    return args;
}

struct Dataset {
    std::vector<Record> sender;
    std::vector<Record> receiver;
    size_t expected_misclassified = 0;
};

Dataset make_dataset(const Args& args, uint64_t trial_seed) {
    std::mt19937_64 rng(trial_seed);
    const uint64_t label_mask = args.label_bits == 64 ? std::numeric_limits<uint64_t>::max() : ((1ULL << args.label_bits) - 1);
    const size_t overlap_count = static_cast<size_t>(args.n * args.overlap);
    const size_t mismatch_count = static_cast<size_t>(overlap_count * args.mismatch);

    Dataset d;
    d.sender.reserve(args.n);
    d.receiver.reserve(args.n);

    for (size_t i = 0; i < args.n; ++i) {
        d.sender.push_back({1000000000ULL + i, rng() & label_mask});
    }

    for (size_t i = 0; i < overlap_count; ++i) {
        uint64_t label = d.sender[i].label;
        if (i < mismatch_count) {
            uint32_t bit = static_cast<uint32_t>(i % args.label_bits);
            label ^= (1ULL << bit);
        }
        d.receiver.push_back({d.sender[i].item, label & label_mask});
    }
    for (size_t i = overlap_count; i < args.n; ++i) {
        d.receiver.push_back({2000000000ULL + i, rng() & label_mask});
    }
    d.expected_misclassified = mismatch_count;
    return d;
}

struct TrialResult {
    size_t n;
    uint32_t label_bits;
    size_t m;
    size_t expected;
    size_t found;
    bool ok;
    double time_ms;
    uint64_t comm_bytes_formula;
    uint64_t comm_bytes_explicit;
};

TrialResult run_trial(const Args& args, uint64_t trial_seed) {
    const auto start = std::chrono::steady_clock::now();
    Dataset data = make_dataset(args, trial_seed);
    const size_t n = args.n;
    const uint32_t ell = args.label_bits;
    const size_t m = static_cast<size_t>((127 * n + 99) / 100);
    const uint64_t cuckoo_seed = splitmix64(trial_seed);

    auto tables = build_shared_cuckoo(data.sender, data.receiver, m, cuckoo_seed);
    CuckooTable ts = std::move(tables.first);
    CuckooTable tr = std::move(tables.second);
    const uint64_t hash_seed = ts.seed;

    const size_t ml = m * static_cast<size_t>(ell);
    std::vector<Block> kr(ml), ks(ml), z_sr(ml), z_rs(ml), tstar(ml * 3);

    for (size_t j = 0; j < m; ++j) {
        for (uint32_t k = 1; k <= ell; ++k) {
            size_t idx = j * ell + (k - 1);
            kr[idx] = hash_block(0x1111, j, k, trial_seed);
            ks[idx] = hash_block(0x2222, j, k, trial_seed);

            Block hs = ts.buckets[j].occupied
                ? protocol_hash(ts.buckets[j].item, ts.buckets[j].label, ell, k, false)
                : hash_block(0x3333, j, k, trial_seed);
            Block hr = tr.buckets[j].occupied
                ? protocol_hash(tr.buckets[j].item, tr.buckets[j].label, ell, k, true)
                : hash_block(0x4444, j, k, trial_seed);

            z_sr[idx] = prf(kr[idx], hs);
            z_rs[idx] = prf(ks[idx], hr);
        }
    }

    const Block kr_star = hash_block(0x5555, n, ell, trial_seed);

    for (size_t j = 0; j < m; ++j) {
        for (uint32_t k = 1; k <= ell; ++k) {
            size_t idx = j * ell + (k - 1);
            if (!tr.buckets[j].occupied) {
                tstar[idx * 3 + 0] = hash_block(0x6666, j, k, trial_seed);
                tstar[idx * 3 + 1] = hash_block(0x7777, j, k, trial_seed);
                tstar[idx * 3 + 2] = hash_block(0x8888, j, k, trial_seed);
                continue;
            }
            const auto& b = tr.buckets[j];
            auto ch = choices(b.item, m, hash_seed);
            Block hr = protocol_hash(b.item, b.label, ell, k, true);
            Block id = prf(kr_star, hash_block(b.item, 0, 0, 0));
            for (size_t c = 0; c < 3; ++c) {
                size_t pos = ch[c];
                size_t key_idx = pos * ell + (k - 1);
                tstar[idx * 3 + c] = z_rs[idx] ^ prf(kr[key_idx], hr) ^ id;
            }
        }
    }

    std::vector<Block> response;
    response.reserve(n * static_cast<size_t>(ell) * 3);
    for (const auto& rec : data.sender) {
        auto ch = choices(rec.item, m, hash_seed);
        size_t used = 0;
        const Bucket& placed = ts.buckets[ch[0]].occupied && ts.buckets[ch[0]].item == rec.item ? ts.buckets[ch[0]]
            : (ts.buckets[ch[1]].occupied && ts.buckets[ch[1]].item == rec.item ? ts.buckets[ch[1]] : ts.buckets[ch[2]]);
        used = placed.choice;
        size_t used_bucket = ch[used];
        for (uint32_t k = 1; k <= ell; ++k) {
            size_t used_idx = used_bucket * ell + (k - 1);
            Block hs = protocol_hash(rec.item, rec.label, ell, k, false);
            for (size_t c = 0; c < 3; ++c) {
                size_t r_bucket = ch[c];
                size_t t_idx = r_bucket * ell + (k - 1);
                Block cut = tstar[t_idx * 3 + used];
                Block d = z_sr[used_idx] ^ prf(ks[t_idx], hs) ^ cut;
                response.push_back(d);
            }
        }
    }
    std::shuffle(response.begin(), response.end(), std::mt19937_64(trial_seed ^ 0x9999));

    std::unordered_set<Block, BlockHash> response_set;
    response_set.reserve(response.size() * 2);
    for (const auto& b : response) {
        response_set.insert(b);
    }

    size_t found = 0;
    for (const auto& rec : data.receiver) {
        Block id = prf(kr_star, hash_block(rec.item, 0, 0, 0));
        if (response_set.find(id) != response_set.end()) {
            ++found;
        }
    }

    if (args.debug) {
        const auto& s0 = data.sender[0];
        const auto& r0 = data.receiver[0];
        auto sch = choices(s0.item, m, hash_seed);
        auto rch = choices(r0.item, m, hash_seed);
        std::cerr << "debug item " << s0.item << " labels " << s0.label << " " << r0.label
                  << " s_choices " << sch[0] << ' ' << sch[1] << ' ' << sch[2]
                  << " r_choices " << rch[0] << ' ' << rch[1] << ' ' << rch[2] << '\n';
        for (uint32_t k = 1; k <= ell; ++k) {
            Block hs = protocol_hash(s0.item, s0.label, ell, k, false);
            Block hr = protocol_hash(r0.item, r0.label, ell, k, true);
            std::cerr << " k=" << k << " h_equal=" << (hs == hr) << '\n';
        }
    }

    const auto end = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    constexpr uint64_t lambda_bytes = 16;
    uint64_t comm_formula = static_cast<uint64_t>((5 * m + 3 * n) * static_cast<size_t>(ell) * lambda_bytes);
    uint64_t comm_explicit = static_cast<uint64_t>((3 * m + 3 * n) * static_cast<size_t>(ell) * lambda_bytes);

    return {n, ell, m, data.expected_misclassified, found, found == data.expected_misclassified, ms, comm_formula, comm_explicit};
}

void print_result(const TrialResult& r, bool csv) {
    double mb = static_cast<double>(r.comm_bytes_formula) / 1000000.0;
    double mib = static_cast<double>(r.comm_bytes_formula) / (1024.0 * 1024.0);
    auto total_seconds = [&](double bandwidth_mbps) {
        double network_ms = static_cast<double>(r.comm_bytes_formula) * 8.0 / (bandwidth_mbps * 1000000.0) * 1000.0;
        return (r.time_ms + network_ms) / 1000.0;
    };
    if (csv) {
        std::cout << r.n << ',' << r.label_bits << ',' << r.m << ','
                  << r.expected << ',' << r.found << ',' << (r.ok ? 1 : 0) << ','
                  << std::fixed << std::setprecision(3) << r.time_ms << ','
                  << r.comm_bytes_formula << ',' << mb << ',' << mib << ','
                  << total_seconds(1000.0) << ','
                  << total_seconds(100.0) << ','
                  << total_seconds(10.0) << ','
                  << r.comm_bytes_explicit << '\n';
    } else {
        std::cout << "n=" << r.n
                  << " label_bits=" << r.label_bits
                  << " m=" << r.m
                  << " expected=" << r.expected
                  << " found=" << r.found
                  << " ok=" << (r.ok ? "yes" : "no")
                  << " compute_time_ms=" << std::fixed << std::setprecision(3) << r.time_ms
                  << " kkrt_comm_mb=" << mb
                  << " kkrt_comm_mib=" << mib
                  << " total_1gbps_s=" << total_seconds(1000.0)
                  << " total_100mbps_s=" << total_seconds(100.0)
                  << " total_10mbps_s=" << total_seconds(10.0)
                  << " explicit_msg_mib=" << static_cast<double>(r.comm_bytes_explicit) / (1024.0 * 1024.0)
                  << '\n';
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        Args args = parse_args(argc, argv);
        for (int t = 0; t < args.trials; ++t) {
            TrialResult r = run_trial(args, args.seed + static_cast<uint64_t>(t));
            print_result(r, args.csv);
            if (!r.ok) {
                return 2;
            }
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
