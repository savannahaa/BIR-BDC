#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/Tools/Coproto.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

struct Args {
    uint64_t n = 1ULL << 16;
    uint64_t label_bits = 10;
    uint64_t trials = 1;
    uint64_t max_ots_per_batch = 0;
    bool csv = false;
};

Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + a);
            return argv[++i];
        };
        if (a == "--n") args.n = std::stoull(value());
        else if (a == "--label-bits" || a == "-l") args.label_bits = std::stoull(value());
        else if (a == "--trials") args.trials = std::stoull(value());
        else if (a == "--max-ots-per-batch") args.max_ots_per_batch = std::stoull(value());
        else if (a == "--csv") args.csv = true;
        else if (a == "--help") {
            std::cout << "Usage: libote_kkrt_cost --n N --label-bits L [--csv]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + a);
        }
    }
    return args;
}

osuCrypto::block make_block(uint64_t i, uint64_t domain) {
    return osuCrypto::toBlock(0x9e3779b97f4a7c15ULL ^ domain, i * 0xbf58476d1ce4e5b9ULL + domain);
}

double run_one_kkrt_batch(uint64_t num_ots, uint64_t seed_domain) {
    using namespace osuCrypto;
    namespace cp = coproto;

    constexpr uint64_t step = 1024;
    auto sockets = cp::LocalAsyncSocket::makePair();
    PRNG recv_prng(toBlock(seed_domain, 1));
    PRNG send_prng(toBlock(seed_domain, 2));

    KkrtNcoOtReceiver receiver;
    KkrtNcoOtSender sender;
    receiver.configure(false, 40, 128);
    sender.configure(false, 40, 128);

    auto recv_routine = [&]() -> macoro::task<> {
        co_await receiver.init(num_ots, recv_prng, sockets[0]);
        for (uint64_t i = 0; i < num_ots;) {
            uint64_t count = std::min<uint64_t>(step, num_ots - i);
            for (uint64_t j = 0; j < count; ++j, ++i) {
                block choice = make_block(i, seed_domain ^ 0x1234);
                block out;
                receiver.encode(i, &choice, &out, sizeof(out));
            }
            co_await receiver.sendCorrection(sockets[0], count);
        }
        co_await receiver.check(sockets[0], recv_prng.get());
        co_await sockets[0].flush();
    };

    auto send_routine = [&]() -> macoro::task<> {
        co_await sender.init(num_ots, send_prng, sockets[1]);
        for (uint64_t i = 0; i < num_ots;) {
            uint64_t count = std::min<uint64_t>(step, num_ots - i);
            co_await sender.recvCorrection(sockets[1], count);
            for (uint64_t j = 0; j < count; ++j, ++i) {
                block c0 = make_block(i, seed_domain ^ 0x2000);
                block c1 = make_block(i, seed_domain ^ 0x3000);
                block c2 = make_block(i, seed_domain ^ 0x4000);
                block o0, o1, o2;
                sender.encode(i, &c0, &o0, sizeof(o0));
                sender.encode(i, &c1, &o1, sizeof(o1));
                sender.encode(i, &c2, &o2, sizeof(o2));
            }
        }
        co_await sender.check(sockets[1], ZeroBlock);
        co_await sockets[1].flush();
    };

    auto start = std::chrono::steady_clock::now();
    auto both = macoro::when_all_ready(recv_routine(), send_routine());
    macoro::sync_wait(std::move(both));
    auto end = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

double run_chunked_kkrt(uint64_t num_ots, uint64_t seed_domain, uint64_t max_ots_per_batch) {
    if (max_ots_per_batch == 0 || num_ots <= max_ots_per_batch) {
        return run_one_kkrt_batch(num_ots, seed_domain);
    }
    double ms = 0.0;
    uint64_t done = 0;
    uint64_t chunk = 0;
    while (done < num_ots) {
        uint64_t count = std::min<uint64_t>(max_ots_per_batch, num_ots - done);
        ms += run_one_kkrt_batch(count, seed_domain + chunk * 0x10000);
        done += count;
        ++chunk;
    }
    return ms;
}

} // namespace

int main(int argc, char** argv) {
    try {
        Args args = parse_args(argc, argv);
        uint64_t m = (127 * args.n + 99) / 100;
        uint64_t num_ots = m * args.label_bits;
        double total_ms = 0.0;
        for (uint64_t t = 0; t < args.trials; ++t) {
            total_ms += run_chunked_kkrt(num_ots, 0xA000 + t * 2, args.max_ots_per_batch);
            total_ms += run_chunked_kkrt(num_ots, 0xB000 + t * 2, args.max_ots_per_batch);
        }
        double avg_ms = total_ms / static_cast<double>(args.trials);
        if (args.csv) {
            std::cout << args.n << ',' << args.label_bits << ',' << m << ','
                      << num_ots << ',' << std::fixed << std::setprecision(3)
                      << avg_ms << '\n';
        } else {
            std::cout << "n=" << args.n
                      << " label_bits=" << args.label_bits
                      << " m=" << m
                      << " kkrt_ots_per_direction=" << num_ots
                      << " kkrt_two_direction_ms=" << std::fixed << std::setprecision(3) << avg_ms
                      << '\n';
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
