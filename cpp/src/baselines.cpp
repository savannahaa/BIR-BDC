#include "bicdc/baselines.hpp"

namespace bicdc {

BaselineMetrics pairwise_cleaning_baseline(const std::vector<PartyDataset>& datasets, int label_bits, int tag_bytes) {
    std::uint64_t n = datasets.size();
    std::uint64_t m = datasets.empty() ? 0 : datasets.front().rows.size();
    std::uint64_t pairs = n * (n - 1) / 2;
    std::uint64_t label_bytes = static_cast<std::uint64_t>((label_bits + 7) / 8);
    return {
        "pairwise-pdc-estimate",
        truth_mislabeled_records(datasets),
        pairs * m * static_cast<std::uint64_t>(tag_bytes + label_bytes) * 2,
        pairs * m,
    };
}

BaselineMetrics mpsi_then_compare_baseline(const std::vector<PartyDataset>& datasets, int label_bits, int tag_bytes) {
    std::uint64_t n = datasets.size();
    std::uint64_t m = datasets.empty() ? 0 : datasets.front().rows.size();
    std::uint64_t label_bytes = static_cast<std::uint64_t>((label_bits + 7) / 8);
    return {
        "mpsi-then-compare-estimate",
        truth_mislabeled_records(datasets),
        n * m * static_cast<std::uint64_t>(tag_bytes + label_bytes),
        n * m,
    };
}

}  // namespace bicdc

