#include "bicdc/data.hpp"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

namespace bicdc {

namespace {

std::string padded(const std::string& prefix, std::size_t value) {
    std::ostringstream os;
    os << prefix << std::setw(8) << std::setfill('0') << value;
    return os.str();
}

}  // namespace

std::vector<PartyDataset> generate_synthetic_datasets(const SyntheticConfig& config) {
    if (config.parties < 4) {
        throw std::runtime_error("Bic-DC requires at least four parties");
    }
    if (config.records == 0) {
        throw std::runtime_error("records must be positive");
    }
    if (config.label_bits <= 0 || config.label_bits > 62) {
        throw std::runtime_error("label_bits must be in [1, 62]");
    }
    if (config.all_party_overlap < 0.0 || config.all_party_overlap > 1.0 || config.conflict_rate < 0.0 || config.conflict_rate > 1.0) {
        throw std::runtime_error("rates must be in [0, 1]");
    }

    std::mt19937_64 rng(config.seed);
    std::uint64_t max_label = 1ULL << config.label_bits;
    std::uniform_int_distribution<std::uint64_t> label_dist(0, max_label - 1);
    std::size_t common_count = static_cast<std::size_t>(config.records * config.all_party_overlap);
    std::size_t conflict_count = static_cast<std::size_t>(common_count * config.conflict_rate);

    std::vector<std::string> common_records;
    common_records.reserve(common_count);
    std::unordered_map<std::string, std::uint64_t> base_labels;
    for (std::size_t i = 0; i < common_count; ++i) {
        auto record = padded("common-", i);
        common_records.push_back(record);
        base_labels[record] = label_dist(rng);
    }

    std::shuffle(common_records.begin(), common_records.end(), rng);
    std::unordered_set<std::string> conflict_records;
    for (std::size_t i = 0; i < conflict_count; ++i) {
        conflict_records.insert(common_records[i]);
    }

    std::vector<PartyDataset> datasets;
    datasets.reserve(static_cast<std::size_t>(config.parties));
    for (int party = 1; party <= config.parties; ++party) {
        PartyDataset dataset;
        dataset.party_id = party;
        dataset.rows.reserve(config.records);
        for (const auto& record : common_records) {
            std::uint64_t label = base_labels[record];
            if (party == config.parties && conflict_records.count(record) > 0) {
                label = (label + 1 + (label_dist(rng) % (max_label - 1))) % max_label;
            }
            dataset.rows.push_back({record, label});
        }
        for (std::size_t i = common_count; i < config.records; ++i) {
            std::ostringstream os;
            os << "party-" << std::setw(3) << std::setfill('0') << party << "-unique-" << std::setw(8) << i;
            dataset.rows.push_back({os.str(), label_dist(rng)});
        }
        std::shuffle(dataset.rows.begin(), dataset.rows.end(), rng);
        datasets.push_back(std::move(dataset));
    }
    return datasets;
}

std::unordered_set<std::string> truth_mislabeled_records(const std::vector<PartyDataset>& datasets) {
    if (datasets.empty()) {
        return {};
    }
    std::vector<std::unordered_map<std::string, std::uint64_t>> maps;
    maps.reserve(datasets.size());
    for (const auto& dataset : datasets) {
        std::unordered_map<std::string, std::uint64_t> map;
        for (const auto& row : dataset.rows) {
            map[row.record] = row.label;
        }
        maps.push_back(std::move(map));
    }

    std::unordered_set<std::string> out;
    for (const auto& item : maps.front()) {
        const auto& record = item.first;
        bool common = true;
        std::unordered_set<std::uint64_t> labels;
        labels.insert(item.second);
        for (std::size_t i = 1; i < maps.size(); ++i) {
            auto it = maps[i].find(record);
            if (it == maps[i].end()) {
                common = false;
                break;
            }
            labels.insert(it->second);
        }
        if (common && labels.size() > 1) {
            out.insert(record);
        }
    }
    return out;
}

}  // namespace bicdc

