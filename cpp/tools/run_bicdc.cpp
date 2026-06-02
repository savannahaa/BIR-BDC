#include "bicdc/baselines.hpp"
#include "bicdc/bytes.hpp"
#include "bicdc/data.hpp"
#include "bicdc/protocol.hpp"

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct BandwidthCase {
    const char* name;
    double bits_per_second;
};

constexpr BandwidthCase kBandwidths[] = {
    {"1gbps", 1'000'000'000.0},
    {"100mbps", 100'000'000.0},
    {"10mbps", 10'000'000.0},
};

double network_seconds(std::uint64_t bytes, double bits_per_second) {
    return static_cast<double>(bytes) * 8.0 / bits_per_second;
}

std::vector<int> parse_int_list(int argc, char** argv, int& i) {
    std::vector<int> out;
    while (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
        out.push_back(std::atoi(argv[++i]));
    }
    return out;
}

std::vector<std::size_t> parse_size_list(int argc, char** argv, int& i) {
    std::vector<std::size_t> out;
    while (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
        out.push_back(static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10)));
    }
    return out;
}

void usage() {
    std::cerr << "Usage: bicdc_cpp --parties 4 6 8 --records 1024 4096 --label-bits 128 --label-domain-bits 20 "
                 "--conflict-rate 0.1 --overlap 0.75 --okvs simulated|shallmate [--json]\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
    std::vector<int> parties = {5};
    std::vector<std::size_t> records = {1024};
    int label_bits = 128;
    int label_domain_bits = 20;
    double conflict_rate = 0.1;
    double overlap = 0.75;
    std::uint64_t seed = 7;
    bool json = false;
    bicdc::OkvsConfig okvs_config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--parties") {
            parties = parse_int_list(argc, argv, i);
        } else if (arg == "--records") {
            records = parse_size_list(argc, argv, i);
        } else if (arg == "--label-bits" && i + 1 < argc) {
            label_bits = std::atoi(argv[++i]);
        } else if (arg == "--label-domain-bits" && i + 1 < argc) {
            label_domain_bits = std::atoi(argv[++i]);
        } else if (arg == "--conflict-rate" && i + 1 < argc) {
            conflict_rate = std::atof(argv[++i]);
        } else if (arg == "--overlap" && i + 1 < argc) {
            overlap = std::atof(argv[++i]);
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = std::strtoull(argv[++i], nullptr, 10);
        } else if (arg == "--json") {
            json = true;
        } else if (arg == "--okvs" && i + 1 < argc) {
            std::string name = argv[++i];
            if (name == "simulated") {
                okvs_config.kind = bicdc::OkvsKind::Simulated;
            } else if (name == "shallmate") {
                okvs_config.kind = bicdc::OkvsKind::ShallMatePaxos;
            } else {
                std::cerr << "unknown OKVS backend: " << name << "\n";
                return 1;
            }
        } else if (arg == "--okvs-weight" && i + 1 < argc) {
            okvs_config.weight = static_cast<std::uint64_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (arg == "--okvs-ssp" && i + 1 < argc) {
            okvs_config.statistical_security = static_cast<std::uint64_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (arg == "--help") {
            usage();
            return 0;
        } else {
            usage();
            return 1;
        }
    }

    if (!json) {
        std::cout << "n\tm\tlabel_bits\ttruth\tfound\tcorrect\truntime_s\tcomm_MB"
                  << "\tokvs_encode_s\tokvs_decode_s"
                  << "\tnet_1gbps_s\ttotal_1gbps_s"
                  << "\tnet_100mbps_s\ttotal_100mbps_s"
                  << "\tnet_10mbps_s\ttotal_10mbps_s"
                  << "\tpairwise_x\tmpsi_x\n";
    }

    for (int n : parties) {
        for (std::size_t m : records) {
            bicdc::SyntheticConfig config;
            config.parties = n;
            config.records = m;
            config.label_bits = label_domain_bits;
            config.conflict_rate = conflict_rate;
            config.all_party_overlap = overlap;
            config.seed = seed;

            auto datasets = bicdc::generate_synthetic_datasets(config);
            auto truth = bicdc::truth_mislabeled_records(datasets);
            bicdc::BicDCProtocol protocol(n, label_bits, 16, "bic-dc-session", okvs_config);
            auto result = protocol.run(datasets);
            auto pairwise = bicdc::pairwise_cleaning_baseline(datasets, label_bits);
            auto mpsi = bicdc::mpsi_then_compare_baseline(datasets, label_bits);
            bool correct = result.mislabeled_records == truth;
            double okvs_encode_s = result.metrics.timings.count("okvs_encode") ? result.metrics.timings.at("okvs_encode") : 0.0;
            double okvs_decode_s = result.metrics.timings.count("okvs_decode") ? result.metrics.timings.at("okvs_decode") : 0.0;
            double pairwise_ratio = result.metrics.communication_bytes == 0 ? 0.0 : static_cast<double>(pairwise.communication_bytes) / static_cast<double>(result.metrics.communication_bytes);
            double mpsi_ratio = result.metrics.communication_bytes == 0 ? 0.0 : static_cast<double>(mpsi.communication_bytes) / static_cast<double>(result.metrics.communication_bytes);

            if (json) {
                std::cout << "{"
                          << "\"parties\":" << n
                          << ",\"records\":" << m
                          << ",\"label_bits\":" << label_bits
                          << ",\"truth_mislabeled\":" << truth.size()
                          << ",\"bicdc_mislabeled\":" << result.mislabeled_records.size()
                          << ",\"correct\":" << (correct ? "true" : "false")
                          << ",\"runtime_s\":" << result.metrics.runtime_s()
                          << ",\"okvs_encode_s\":" << okvs_encode_s
                          << ",\"okvs_decode_s\":" << okvs_decode_s
                          << ",\"communication_bytes\":" << result.metrics.communication_bytes
                          << ",\"okvs_bytes\":" << result.metrics.okvs_bytes
                          << ",\"bicentric_token_bytes\":" << result.metrics.bicentric_token_bytes
                          << ",\"pairwise_comm_bytes\":" << pairwise.communication_bytes
                          << ",\"mpsi_comm_bytes\":" << mpsi.communication_bytes;
                for (const auto& bw : kBandwidths) {
                    double net_s = network_seconds(result.metrics.communication_bytes, bw.bits_per_second);
                    std::cout << ",\"net_" << bw.name << "_s\":" << net_s
                              << ",\"total_" << bw.name << "_s\":" << (result.metrics.runtime_s() + net_s);
                }
                std::cout
                          << "}\n";
            } else {
                double net_1g = network_seconds(result.metrics.communication_bytes, kBandwidths[0].bits_per_second);
                double net_100m = network_seconds(result.metrics.communication_bytes, kBandwidths[1].bits_per_second);
                double net_10m = network_seconds(result.metrics.communication_bytes, kBandwidths[2].bits_per_second);
                std::cout << n << '\t'
                          << m << '\t'
                          << label_bits << '\t'
                          << truth.size() << '\t'
                          << result.mislabeled_records.size() << '\t'
                          << (correct ? "true" : "false") << '\t'
                          << result.metrics.runtime_s() << '\t'
                          << bicdc::human_mb(result.metrics.communication_bytes) << '\t'
                          << okvs_encode_s << '\t'
                          << okvs_decode_s << '\t'
                          << net_1g << '\t'
                          << result.metrics.runtime_s() + net_1g << '\t'
                          << net_100m << '\t'
                          << result.metrics.runtime_s() + net_100m << '\t'
                          << net_10m << '\t'
                          << result.metrics.runtime_s() + net_10m << '\t'
                          << pairwise_ratio << '\t'
                          << mpsi_ratio << '\n';
            }
        }
    }
    return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
