#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace bicdc {

struct RecordLabel {
    std::string record;
    std::uint64_t label;
};

struct PartyDataset {
    int party_id = 0;
    std::vector<RecordLabel> rows;
};

struct SyntheticConfig {
    int parties = 5;
    std::size_t records = 1024;
    int label_bits = 20;
    double all_party_overlap = 0.75;
    double conflict_rate = 0.1;
    std::uint64_t seed = 7;
};

std::vector<PartyDataset> generate_synthetic_datasets(const SyntheticConfig& config);
std::unordered_set<std::string> truth_mislabeled_records(const std::vector<PartyDataset>& datasets);

}  // namespace bicdc

