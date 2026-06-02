#include "volePSI/RsOprf.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace cp = coproto;
namespace oc = osuCrypto;
using volePSI::RsOprfReceiver;
using volePSI::RsOprfSender;

namespace {

struct Args {
    uint64_t n = 1024;
    uint64_t labelBits = 8;
    uint64_t trials = 1;
    uint64_t threads = 1;
    bool fakeBase = false;
};

struct Bucket {
    int64_t item = -1;
    uint8_t choice = 0;
};

struct BlockHash {
    size_t operator()(const oc::block& b) const
    {
        return static_cast<size_t>(b.get<uint64_t>(0) ^ (b.get<uint64_t>(1) * 0x9e3779b97f4a7c15ull));
    }
};

uint64_t splitmix64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    return x ^ (x >> 31);
}

oc::block makeBlock(uint64_t a, uint64_t b)
{
    return oc::block(a, b);
}

uint64_t labelPrefix(uint64_t label, uint64_t len, uint64_t k, bool flipLast)
{
    uint64_t prefix = len == k ? label : (label >> (len - k));
    return flipLast ? (prefix ^ 1ull) : prefix;
}

oc::block pdcInput(uint64_t item, uint64_t label, uint64_t labelBits, uint64_t k, bool flipLast)
{
    auto prefix = labelPrefix(label, labelBits, k, flipLast);
    auto a = splitmix64(item ^ (k * 0x100000001b3ull) ^ (prefix * 0xd6e8feb86659fd93ull));
    auto b = splitmix64(a ^ item ^ (prefix << 1));
    return makeBlock(a, b);
}

std::array<uint64_t, 3> positions(uint64_t item, uint64_t m, uint64_t seed)
{
    for (uint64_t round = 0;; ++round) {
        std::array<uint64_t, 3> p{
            splitmix64(item ^ seed ^ (round * 7 + 1)) % m,
            splitmix64(item ^ seed ^ (round * 7 + 2)) % m,
            splitmix64(item ^ seed ^ (round * 7 + 3)) % m
        };
        if (p[0] != p[1] && p[0] != p[2] && p[1] != p[2])
            return p;
    }
}

bool buildCuckoo(const std::vector<uint64_t>& items, uint64_t m, uint64_t seed, std::vector<Bucket>& table)
{
    table.assign(m, {});
    std::vector<std::array<uint64_t, 3>> pos(items.size());
    for (uint64_t i = 0; i < items.size(); ++i)
        pos[i] = positions(items[i], m, seed);

    std::mt19937_64 rng(seed);
    for (uint64_t i = 0; i < items.size(); ++i) {
        uint64_t cur = i;
        uint8_t choice = 0;
        for (uint64_t kick = 0; kick < 500; ++kick) {
            uint64_t b = pos[cur][choice];
            if (table[b].item < 0) {
                table[b] = {static_cast<int64_t>(cur), choice};
                break;
            }
            uint64_t evicted = static_cast<uint64_t>(table[b].item);
            uint8_t evictedChoice = table[b].choice;
            table[b] = {static_cast<int64_t>(cur), choice};
            cur = evicted;
            choice = static_cast<uint8_t>((evictedChoice + 1 + (rng() % 2)) % 3);
            if (kick == 499)
                return false;
        }
    }
    return true;
}

void fakeBase(RsOprfSender& sender, RsOprfReceiver& receiver, oc::PRNG& prng)
{
    std::vector<std::array<oc::block, 2>> sendBase(128);
    std::vector<oc::block> recvBase(128);
    oc::BitVector recvChoice(128);
    recvChoice.randomize(prng);
    prng.get(sendBase.data(), sendBase.size());
    for (uint64_t i = 0; i < 128; ++i)
        recvBase[i] = sendBase[i][recvChoice[i]];
    receiver.mVoleRecver.mOtExtSender.emplace();
    sender.mVoleSender.mOtExtRecver.emplace();
    receiver.mVoleRecver.mOtExtSender->setBaseOts(recvBase, recvChoice);
    sender.mVoleSender.mOtExtRecver->setBaseOts(sendBase);
}

Args parseArgs(int argc, char** argv)
{
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s(argv[i]);
        auto need = [&](const char* name) -> uint64_t {
            if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + name);
            return std::stoull(argv[++i]);
        };
        if (s == "--n") a.n = need("--n");
        else if (s == "--l") a.labelBits = need("--l");
        else if (s == "--trials") a.trials = need("--trials");
        else if (s == "--threads") a.threads = need("--threads");
        else if (s == "--fake-base") a.fakeBase = true;
        else if (s == "--help") {
            std::cout << "usage: pdc2_bench --n N --l LABEL_BITS [--trials T] [--threads T] [--fake-base]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + s);
        }
    }
    if (a.labelBits == 0 || a.labelBits > 63)
        throw std::runtime_error("--l must be in [1,63]");
    return a;
}

} // namespace

int main(int argc, char** argv)
{
    auto args = parseArgs(argc, argv);
    uint64_t m = static_cast<uint64_t>((args.n * 127 + 99) / 100);
    uint64_t batch = m * args.labelBits;

    std::cout << "trial,n,l,m,total_ms,oprf_ms,post_ms,sender_bytes,receiver_bytes,total_bytes,expected_errors,found_errors\n";

    for (uint64_t trial = 0; trial < args.trials; ++trial) {
        oc::PRNG prng(makeBlock(0x1234, trial + 1));
        uint64_t labelMask = (1ull << args.labelBits) - 1;

        std::vector<uint64_t> sItems(args.n), rItems(args.n), sLabels(args.n), rLabels(args.n);
        for (uint64_t i = 0; i < args.n; ++i) {
            sItems[i] = splitmix64(i + 1);
            sLabels[i] = splitmix64(i * 3 + 11) & labelMask;
            if (i < args.n / 2) {
                rItems[i] = sItems[i];
                rLabels[i] = (i % 2 == 0) ? sLabels[i] : ((sLabels[i] + 1) & labelMask);
            } else {
                rItems[i] = splitmix64(args.n + i + 1);
                rLabels[i] = splitmix64(i * 5 + 17) & labelMask;
            }
        }
        uint64_t expected = args.n / 4;

        std::vector<Bucket> ts, tr;
        uint64_t seed = 0xfeed0000 + trial;
        for (uint64_t attempt = 0; attempt < 200; ++attempt) {
            if (buildCuckoo(sItems, m, seed + attempt, ts) && buildCuckoo(rItems, m, seed + attempt, tr)) {
                seed += attempt;
                break;
            }
            if (attempt == 199) throw std::runtime_error("cuckoo insertion failed");
        }

        std::vector<oc::block> sRecvIn(batch), sRecvOut(batch), rRecvIn(batch), rRecvOut(batch);
        for (uint64_t j = 0; j < m; ++j) {
            for (uint64_t k = 1; k <= args.labelBits; ++k) {
                uint64_t off = j * args.labelBits + (k - 1);
                if (ts[j].item >= 0) {
                    uint64_t idx = static_cast<uint64_t>(ts[j].item);
                    sRecvIn[off] = pdcInput(sItems[idx], sLabels[idx], args.labelBits, k, false);
                } else {
                    sRecvIn[off] = makeBlock(splitmix64(off), splitmix64(off + 1));
                }
                if (tr[j].item >= 0) {
                    uint64_t idx = static_cast<uint64_t>(tr[j].item);
                    rRecvIn[off] = pdcInput(rItems[idx], rLabels[idx], args.labelBits, k, true);
                } else {
                    rRecvIn[off] = makeBlock(splitmix64(off + 2), splitmix64(off + 3));
                }
            }
        }

        RsOprfSender rAsSender, sAsSender;
        RsOprfReceiver sAsReceiver, rAsReceiver;
        if (args.fakeBase) {
            fakeBase(rAsSender, sAsReceiver, prng);
            fakeBase(sAsSender, rAsReceiver, prng);
        }

        auto socketsA = cp::LocalAsyncSocket::makePair();
        auto socketsB = cp::LocalAsyncSocket::makePair();

        auto totalStart = std::chrono::steady_clock::now();
        auto oprfStart = std::chrono::steady_clock::now();
        auto p0 = rAsSender.send(batch, prng, socketsA[0], args.threads);
        auto p1 = sAsReceiver.receive(sRecvIn, sRecvOut, prng, socketsA[1], args.threads);
        auto bothA = macoro::sync_wait(macoro::when_all_ready(std::move(p0), std::move(p1)));
        std::get<0>(bothA).result();
        std::get<1>(bothA).result();

        auto p2 = sAsSender.send(batch, prng, socketsB[0], args.threads);
        auto p3 = rAsReceiver.receive(rRecvIn, rRecvOut, prng, socketsB[1], args.threads);
        auto bothB = macoro::sync_wait(macoro::when_all_ready(std::move(p2), std::move(p3)));
        std::get<0>(bothB).result();
        std::get<1>(bothB).result();
        auto oprfEnd = std::chrono::steady_clock::now();

        std::vector<std::array<oc::block, 3>> tStar(batch);
        std::vector<oc::block> ids(args.n);
        for (uint64_t i = 0; i < args.n; ++i)
            ids[i] = makeBlock(splitmix64(rItems[i] ^ 0xabc), splitmix64(rItems[i] ^ 0xdef));

        for (uint64_t j = 0; j < m; ++j) {
            for (uint64_t k = 1; k <= args.labelBits; ++k) {
                uint64_t off = j * args.labelBits + (k - 1);
                if (tr[j].item < 0) {
                    tStar[off] = {makeBlock(splitmix64(off + 4), splitmix64(off + 5)),
                                  makeBlock(splitmix64(off + 6), splitmix64(off + 7)),
                                  makeBlock(splitmix64(off + 8), splitmix64(off + 9))};
                    continue;
                }
                uint64_t idx = static_cast<uint64_t>(tr[j].item);
                auto prfR = rAsSender.eval(rRecvIn[off]);
                auto c = rRecvOut[off] ^ prfR ^ ids[idx];
                tStar[off] = {c, c, c};
            }
        }

        std::vector<oc::block> candidates;
        candidates.reserve(args.n * args.labelBits * 3);
        for (uint64_t i = 0; i < args.n; ++i) {
            auto pos = positions(sItems[i], m, seed);
            uint8_t idxChoice = 0;
            for (uint8_t c = 0; c < 3; ++c) {
                if (ts[pos[c]].item == static_cast<int64_t>(i)) {
                    idxChoice = c;
                    break;
                }
            }
            auto mappedBucket = pos[idxChoice];
            for (uint64_t k = 1; k <= args.labelBits; ++k) {
                uint64_t sourceOff = mappedBucket * args.labelBits + (k - 1);
                auto prfS = sAsSender.eval(sRecvIn[sourceOff]);
                for (uint8_t c = 0; c < 3; ++c) {
                    uint64_t off = pos[c] * args.labelBits + (k - 1);
                    candidates.push_back(sRecvOut[sourceOff] ^ prfS ^ tStar[off][idxChoice]);
                }
            }
        }
        std::shuffle(candidates.begin(), candidates.end(), std::mt19937_64(trial + 99));

        std::unordered_set<oc::block, BlockHash> candSet;
        candSet.reserve(candidates.size() * 2);
        for (auto& c : candidates)
            candSet.insert(c);
        uint64_t found = 0;
        for (auto& id : ids) {
            if (candSet.find(id) != candSet.end())
                ++found;
        }
        auto totalEnd = std::chrono::steady_clock::now();

        auto ms = [](auto a, auto b) {
            return std::chrono::duration<double, std::milli>(b - a).count();
        };

        uint64_t senderBytes = socketsA[0].bytesSent() + socketsB[0].bytesSent()
            + candidates.size() * sizeof(oc::block);
        uint64_t receiverBytes = socketsA[1].bytesSent() + socketsB[1].bytesSent()
            + tStar.size() * 3 * sizeof(oc::block);

        std::cout << trial << "," << args.n << "," << args.labelBits << "," << m << ","
                  << ms(totalStart, totalEnd) << "," << ms(oprfStart, oprfEnd) << ","
                  << ms(oprfEnd, totalEnd) << "," << senderBytes << "," << receiverBytes << ","
                  << (senderBytes + receiverBytes) << "," << expected << "," << found << "\n";
    }
}
