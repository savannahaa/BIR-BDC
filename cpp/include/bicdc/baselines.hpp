#pragma once

#include "bicdc/data.hpp"

#include <cstdint>
#include <string>
#include <unordered_set>

namespace bicdc {

struct BaselineMetrics {
    std::string name;
    std::unordered_set<std::string> mislabeled_records;
    std::uint64_t communication_bytes = 0;
    std::uint64_t comparisons = 0;
};

BaselineMetrics pairwise_cleaning_baseline(const std::vector<PartyDataset>& datasets, int label_bits, int tag_bytes = 16);
BaselineMetrics mpsi_then_compare_baseline(const std::vector<PartyDataset>& datasets, int label_bits, int tag_bytes = 16);

}  // namespace bicdc

