#include "bicdc/crypto.hpp"
#include "bicdc/data.hpp"
#include "bicdc/protocol.hpp"

#include <iostream>
#include <stdexcept>

int main() {
    {
        auto same = bicdc::Bytes{0xaa};
        auto other = bicdc::Bytes{0xba};
        auto complete = bicdc::complete_prefixes(same, 8);
        auto flipped_same = bicdc::flipped_prefixes(same, 8);
        auto flipped_other = bicdc::flipped_prefixes(other, 8);
        bool same_intersects = false;
        bool other_intersects = false;
        for (const auto& a : complete) {
            for (const auto& b : flipped_same) {
                same_intersects = same_intersects || (a == b);
            }
            for (const auto& b : flipped_other) {
                other_intersects = other_intersects || (a == b);
            }
        }
        if (same_intersects || !other_intersects) {
            throw std::runtime_error("prefix flipping invariant failed");
        }
    }

    bicdc::SyntheticConfig config;
    config.parties = 6;
    config.records = 256;
    config.label_bits = 20;
    config.conflict_rate = 0.2;
    config.seed = 42;
    auto datasets = bicdc::generate_synthetic_datasets(config);
    auto truth = bicdc::truth_mislabeled_records(datasets);
    bicdc::BicDCProtocol protocol(config.parties, config.label_bits);
    auto result = protocol.run(datasets);
    if (result.mislabeled_records != truth) {
        throw std::runtime_error("Bic-DC output differs from truth");
    }

    std::cout << "C++ Bic-DC tests passed\n";
    return 0;
}

