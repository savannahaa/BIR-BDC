#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <queue>
#include <random>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <unordered_set>
#include <vector>

struct Block {
    uint64_t lo = 0;
    uint64_t hi = 0;

    bool operator==(const Block& other) const {
        return lo == other.lo && hi == other.hi;
    }
};

struct BlockHash {
    size_t operator()(const Block& b) const {
        uint64_t x = b.lo ^ (b.hi + 0x9e3779b97f4a7c15ULL + (b.lo << 6) + (b.lo >> 2));
        x ^= x >> 30;
        x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27;
        x *= 0x94d049bb133111ebULL;
        x ^= x >> 31;
        return static_cast<size_t>(x);
    }
};

static inline Block bxor(Block a, Block b) {
    return {a.lo ^ b.lo, a.hi ^ b.hi};
}

static uint64_t splitmix64(uint64_t& x) {
    uint64_t z = (x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static Block random_block(uint64_t& state) {
    return {splitmix64(state), splitmix64(state)};
}

static Block prf(Block key, Block x) {
    uint64_t s0 = key.lo ^ x.lo ^ 0x243f6a8885a308d3ULL;
    uint64_t s1 = key.hi ^ x.hi ^ 0x13198a2e03707344ULL;
    return {splitmix64(s0), splitmix64(s1)};
}

struct XorOkvs {
    static constexpr size_t kHash = 3;
    size_t m = 0;
    std::vector<Block> table;

    static std::array<size_t, kHash> positions(const Block& key, size_t table_size) {
        uint64_t s = key.lo ^ (key.hi << 1) ^ 0x9e3779b97f4a7c15ULL;
        std::array<size_t, kHash> p{};
        for (size_t i = 0; i < kHash; ++i) {
            p[i] = static_cast<size_t>(splitmix64(s) % table_size);
            for (size_t j = 0; j < i; ++j) {
                if (p[i] == p[j]) {
                    p[i] = (p[i] + i + 1) % table_size;
                    j = static_cast<size_t>(-1);
                }
            }
        }
        return p;
    }

    static XorOkvs encode(const std::vector<std::pair<Block, Block>>& items, uint64_t seed) {
        if (items.empty()) {
            return {};
        }

        double factor = 1.35;
        for (int attempt = 0; attempt < 8; ++attempt, factor += 0.10) {
            XorOkvs okvs;
            okvs.m = static_cast<size_t>(std::ceil(items.size() * factor)) + 16;
            okvs.table.resize(okvs.m);

            std::vector<std::array<size_t, kHash>> pos(items.size());
            std::vector<std::vector<size_t>> buckets(okvs.m);
            std::vector<uint8_t> degree(okvs.m, 0);
            for (size_t i = 0; i < items.size(); ++i) {
                pos[i] = positions(items[i].first, okvs.m);
                for (size_t p : pos[i]) {
                    buckets[p].push_back(i);
                    ++degree[p];
                }
            }

            std::queue<size_t> q;
            for (size_t i = 0; i < okvs.m; ++i) {
                if (degree[i] == 1) q.push(i);
            }

            std::vector<char> removed(items.size(), 0);
            std::vector<std::pair<size_t, size_t>> stack;
            while (!q.empty()) {
                size_t p = q.front();
                q.pop();
                if (degree[p] != 1) continue;

                size_t edge = items.size();
                for (size_t e : buckets[p]) {
                    if (!removed[e]) {
                        edge = e;
                        break;
                    }
                }
                if (edge == items.size()) continue;
                removed[edge] = 1;
                stack.push_back({edge, p});
                for (size_t pp : pos[edge]) {
                    if (degree[pp] > 0 && --degree[pp] == 1) q.push(pp);
                }
            }

            if (stack.size() != items.size()) {
                continue;
            }

            uint64_t rng = seed ^ (static_cast<uint64_t>(attempt) << 32);
            for (Block& b : okvs.table) b = random_block(rng);

            std::vector<char> assigned(okvs.m, 0);
            for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
                size_t edge = it->first;
                size_t pivot = it->second;
                Block value = items[edge].second;
                for (size_t p : pos[edge]) {
                    if (p != pivot) value = bxor(value, okvs.table[p]);
                }
                okvs.table[pivot] = value;
                assigned[pivot] = 1;
            }
            (void)assigned;
            return okvs;
        }
        throw std::runtime_error("OKVS encode failed; increase table factor or change seed");
    }

    Block decode(const Block& key) const {
        if (table.empty()) return {};
        auto p = positions(key, m);
        Block out = table[p[0]];
        for (size_t i = 1; i < kHash; ++i) out = bxor(out, table[p[i]]);
        return out;
    }
};

struct Args {
    size_t parties = 5;
    size_t log_n = 12;
    size_t set_size = 0;
    size_t intersection = 100;
    uint64_t seed = 1;
};

static Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        auto need_value = [&](const char* name) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + name);
            return argv[++i];
        };
        if (s == "-nu") a.parties = std::stoull(need_value("-nu"));
        else if (s == "-m") a.set_size = std::stoull(need_value("-m"));
        else if (s == "-nn") a.log_n = std::stoull(need_value("-nn"));
        else if (s == "-ts") a.intersection = std::stoull(need_value("-ts"));
        else if (s == "-seed") a.seed = std::stoull(need_value("-seed"));
        else if (s == "-h" || s == "--help") {
            std::cout << "Usage: mpsi_benchmark [-nu parties] [-m set_size | -nn log2_set_size] [-ts intersection] [-seed n]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + s);
        }
    }
    if (a.parties < 3) throw std::runtime_error("-nu must be at least 3");
    if (a.log_n >= 31) throw std::runtime_error("-nn too large for this standalone benchmark");
    size_t n = a.set_size ? a.set_size : (size_t{1} << a.log_n);
    if (a.intersection > n) throw std::runtime_error("-ts cannot exceed set size");
    return a;
}

static std::vector<std::vector<Block>> make_sets(const Args& args) {
    size_t n = args.set_size ? args.set_size : (size_t{1} << args.log_n);
    std::vector<std::vector<Block>> sets(args.parties, std::vector<Block>(n));

    uint64_t common_rng = args.seed ^ 0xabcdef;
    std::vector<Block> common(args.intersection);
    for (Block& x : common) x = random_block(common_rng);

    for (size_t p = 0; p < args.parties; ++p) {
        std::copy(common.begin(), common.end(), sets[p].begin());
        uint64_t rng = args.seed + 0x100000001b3ULL * (p + 1);
        for (size_t i = args.intersection; i < n; ++i) {
            Block x = random_block(rng);
            x.hi ^= (p + 1) << 48;
            sets[p][i] = x;
        }
        std::shuffle(sets[p].begin(), sets[p].end(), std::mt19937_64(args.seed + p));
    }
    return sets;
}

static double rss_mb() {
    rusage r{};
    getrusage(RUSAGE_SELF, &r);
#ifdef __APPLE__
    return static_cast<double>(r.ru_maxrss) / (1024.0 * 1024.0);
#else
    return static_cast<double>(r.ru_maxrss) / 1024.0;
#endif
}

int main(int argc, char** argv) {
    try {
        Args args = parse_args(argc, argv);
        size_t n = args.set_size ? args.set_size : (size_t{1} << args.log_n);
        size_t leader_id = args.parties - 1;
        size_t pivot_id = args.parties - 2;
        size_t clients = args.parties - 2;

        auto t0 = std::chrono::steady_clock::now();
        auto sets = make_sets(args);
        auto t_data = std::chrono::steady_clock::now();

        Block key{args.seed ^ 0x1111222233334444ULL, args.seed ^ 0x5555666677778888ULL};
        std::vector<std::pair<Block, Block>> leader_pairs;
        leader_pairs.reserve(n);
        for (const Block& x : sets[leader_id]) leader_pairs.push_back({x, prf(key, x)});
        XorOkvs leader_okvs = XorOkvs::encode(leader_pairs, args.seed ^ 0x1234);

        std::vector<XorOkvs> client_shares;
        client_shares.reserve(clients);
        XorOkvs pivot_share = leader_okvs;
        uint64_t share_seed = args.seed ^ 0xfeedfaceULL;
        for (size_t c = 0; c < clients; ++c) {
            XorOkvs share;
            share.m = leader_okvs.m;
            share.table.resize(leader_okvs.m);
            for (Block& b : share.table) b = random_block(share_seed);
            for (size_t i = 0; i < pivot_share.table.size(); ++i) {
                pivot_share.table[i] = bxor(pivot_share.table[i], share.table[i]);
            }
            client_shares.push_back(std::move(share));
        }
        auto t_share = std::chrono::steady_clock::now();

        std::vector<XorOkvs> client_okvs;
        client_okvs.reserve(clients);
        for (size_t c = 0; c < clients; ++c) {
            std::vector<std::pair<Block, Block>> pairs;
            pairs.reserve(n);
            for (const Block& x : sets[c]) {
                pairs.push_back({x, client_shares[c].decode(x)});
            }
            client_okvs.push_back(XorOkvs::encode(pairs, args.seed ^ (0x9000 + c)));
        }
        auto t_client = std::chrono::steady_clock::now();

        std::vector<Block> pivot_values;
        pivot_values.reserve(n);
        for (const Block& x : sets[pivot_id]) {
            Block y = pivot_share.decode(x);
            for (const XorOkvs& okvs : client_okvs) y = bxor(y, okvs.decode(x));
            pivot_values.push_back(y);
        }
        auto t_pivot = std::chrono::steady_clock::now();

        std::unordered_set<Block, BlockHash> pivot_index;
        pivot_index.reserve(pivot_values.size() * 2);
        for (Block v : pivot_values) pivot_index.insert(v);

        size_t found = 0;
        for (const Block& x : sets[leader_id]) {
            if (pivot_index.find(prf(key, x)) != pivot_index.end()) ++found;
        }
        auto t_psi = std::chrono::steady_clock::now();

        auto seconds = [](auto a, auto b) {
            return std::chrono::duration<double>(b - a).count();
        };

        double leader_sent_mb = (clients * 16.0 + pivot_share.table.size() * sizeof(Block)) / (1024.0 * 1024.0);
        double client_sent_mb = client_okvs.empty() ? 0.0 : client_okvs.back().table.size() * sizeof(Block) / (1024.0 * 1024.0);
        double pivot_psi_sent_mb = pivot_values.size() * sizeof(Block) / (1024.0 * 1024.0);
        double leader_psi_sent_mb = n * sizeof(Block) / (1024.0 * 1024.0);
        double total_sent_mb = leader_sent_mb + clients * client_sent_mb + pivot_psi_sent_mb + leader_psi_sent_mb;
        double total_seconds = seconds(t0, t_psi);

        std::cout << std::fixed << std::setprecision(3);
        std::cout << "MPSI standalone benchmark (BZS + local hash PSI)\n";
        std::cout << "participants_n=" << args.parties << ", set_size_m=" << n
                  << ", expected_intersection=" << args.intersection << "\n";
        std::cout << "intersection_found=" << found << "\n\n";

        std::cout << "time_seconds:\n";
        std::cout << "  data_generation: " << seconds(t0, t_data) << "\n";
        std::cout << "  leader_okvs_sharing: " << seconds(t_data, t_share) << "\n";
        std::cout << "  clients_reconstruct_encode: " << seconds(t_share, t_client) << "\n";
        std::cout << "  pivot_reconstruct: " << seconds(t_client, t_pivot) << "\n";
        std::cout << "  leader_pivot_psi: " << seconds(t_pivot, t_psi) << "\n";
        std::cout << "  total: " << total_seconds << "\n\n";

        std::cout << "modeled_sent_MB:\n";
        std::cout << "  leader_bzs: " << leader_sent_mb << "\n";
        std::cout << "  one_client_bzs: " << client_sent_mb << "\n";
        std::cout << "  pivot_psi: " << pivot_psi_sent_mb << "\n";
        std::cout << "  leader_psi: " << leader_psi_sent_mb << "\n\n";

        std::cout << "summary:\n";
        std::cout << "  total_seconds: " << total_seconds << "\n";
        std::cout << "  total_communication_MB: " << total_sent_mb << "\n";
        std::cout << "  peak_RSS_MB: " << rss_mb() << "\n\n";

        std::cout << "csv_header: parties_n,set_size_m,intersection,total_seconds,total_communication_MB,peak_RSS_MB\n";
        std::cout << "csv: " << args.parties << "," << n << "," << args.intersection << ","
                  << total_seconds << "," << total_sent_mb << "," << rss_mb() << "\n";

        std::cout << "peak_RSS_MB: " << rss_mb() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
