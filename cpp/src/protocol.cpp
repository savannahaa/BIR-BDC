#include "bicdc/protocol.hpp"

#include <stdexcept>

namespace bicdc {

BicDCProtocol::BicDCProtocol(
    int parties,
    int label_bits,
    std::size_t security_bytes,
    std::string session_id,
    OkvsConfig okvs_config)
    : parties_(parties),
      label_bits_(label_bits),
      security_bytes_(security_bytes),
      session_id_(std::move(session_id)),
      okvs_config_(okvs_config),
      left_bicentric_(parties - 1),
      right_bicentric_(parties) {
    if (parties_ < 4) {
        throw std::runtime_error("Bic-DC requires at least four parties");
    }
    if (label_bits_ <= 0 || label_bits_ > static_cast<int>(security_bytes_ * 8)) {
        throw std::runtime_error("label_bits must fit in the PRF output");
    }
    for (int party = 2; party <= parties_ - 2; ++party) {
        keys_[party] = derive_key(session_id_, party, security_bytes_);
    }
}

BicDCResult BicDCProtocol::run(const std::vector<PartyDataset>& datasets) const {
    validate(datasets);
    RunMetrics metrics;
    BicDCRepresentation representation;
    {
        ScopedTimer timer(metrics, "representation");
        representation = represent(datasets, metrics);
    }
    std::unordered_set<std::string> mislabeled;
    {
        ScopedTimer timer(metrics, "resolution");
        mislabeled = resolve(datasets, representation, metrics);
    }
    metrics.communication_bytes = metrics.okvs_bytes + metrics.bicentric_token_bytes;
    return {std::move(mislabeled), std::move(metrics)};
}

BicDCRepresentation BicDCProtocol::represent(const std::vector<PartyDataset>& datasets, RunMetrics& metrics) const {
    BicDCRepresentation representation;
    std::vector<int> middle;
    for (int party = 2; party <= parties_ - 2; ++party) {
        middle.push_back(party);
    }

    std::vector<std::pair<Bytes, Bytes>> record_pairs;
    std::vector<std::pair<Bytes, Bytes>> label_pairs;
    for (const auto& row : datasets[0].rows) {
        std::vector<Bytes> record_values;
        std::vector<Bytes> label_values;
        for (int party : middle) {
            record_values.push_back(prf(keys_.at(party), string_bytes(row.record), security_bytes_));
            label_values.push_back(prf(keys_.at(party), uint64_bytes(row.label), security_bytes_));
        }
        record_pairs.push_back({string_bytes(row.record), xor_bytes(record_values, security_bytes_)});
        label_pairs.push_back({uint64_bytes(row.label), xor_bytes(label_values, security_bytes_)});
    }
    representation.to_right.emplace(1, encode_party(1, record_pairs, label_pairs, metrics));

    for (int party : middle) {
        record_pairs.clear();
        label_pairs.clear();
        for (const auto& row : datasets[static_cast<std::size_t>(party - 1)].rows) {
            record_pairs.push_back({string_bytes(row.record), prf(keys_.at(party), string_bytes(row.record), security_bytes_)});
            label_pairs.push_back({uint64_bytes(row.label), prf(keys_.at(party), uint64_bytes(row.label), security_bytes_)});
        }
        representation.to_left.emplace(party, encode_party(party, record_pairs, label_pairs, metrics));
    }

    for (const auto& item : representation.to_left) {
        metrics.okvs_bytes += item.second.record_okvs->encoded_bytes();
        metrics.okvs_bytes += item.second.label_okvs->encoded_bytes();
    }
    for (const auto& item : representation.to_right) {
        metrics.okvs_bytes += item.second.record_okvs->encoded_bytes();
        metrics.okvs_bytes += item.second.label_okvs->encoded_bytes();
    }
    return representation;
}

std::unordered_set<std::string> BicDCProtocol::resolve(
    const std::vector<PartyDataset>& datasets,
    const BicDCRepresentation& representation,
    RunMetrics& metrics) const {
    const auto& left_dataset = datasets[static_cast<std::size_t>(left_bicentric_ - 1)];
    const auto& right_dataset = datasets[static_cast<std::size_t>(right_bicentric_ - 1)];

    std::unordered_map<std::string, std::unordered_set<std::string>> left_tokens;
    for (const auto& row : left_dataset.rows) {
        std::vector<Bytes> record_values;
        std::vector<Bytes> label_values;
        for (int party = 2; party <= parties_ - 2; ++party) {
            const auto& encoded = representation.to_left.at(party);
            auto decode_start = std::chrono::steady_clock::now();
            record_values.push_back(encoded.record_okvs->decode(string_bytes(row.record)));
            label_values.push_back(encoded.label_okvs->decode(uint64_bytes(row.label)));
            auto decode_end = std::chrono::steady_clock::now();
            metrics.timings["okvs_decode"] += std::chrono::duration<double>(decode_end - decode_start).count();
        }
        Bytes record_tag = xor_bytes(record_values, security_bytes_);
        Bytes label_tag = xor_bytes(label_values, security_bytes_);
        for (const auto& prefix : complete_prefixes(label_tag, label_bits_)) {
            left_tokens[bytes_key(concat(record_tag, prefix))].insert(row.record);
        }
    }

    std::unordered_map<std::string, std::unordered_set<std::string>> right_tokens;
    const auto& right_encoded = representation.to_right.at(1);
    for (const auto& row : right_dataset.rows) {
        auto decode_start = std::chrono::steady_clock::now();
        Bytes record_tag = right_encoded.record_okvs->decode(string_bytes(row.record));
        Bytes label_tag = right_encoded.label_okvs->decode(uint64_bytes(row.label));
        auto decode_end = std::chrono::steady_clock::now();
        metrics.timings["okvs_decode"] += std::chrono::duration<double>(decode_end - decode_start).count();
        for (const auto& prefix : flipped_prefixes(label_tag, label_bits_)) {
            right_tokens[bytes_key(concat(record_tag, prefix))].insert(row.record);
        }
    }

    std::unordered_set<std::string> mislabeled;
    for (const auto& item : left_tokens) {
        auto it = right_tokens.find(item.first);
        if (it == right_tokens.end()) {
            continue;
        }
        for (const auto& record : item.second) {
            if (it->second.count(record) > 0) {
                mislabeled.insert(record);
            }
        }
    }

    metrics.token_count_left += static_cast<std::uint64_t>(left_dataset.rows.size()) * static_cast<std::uint64_t>(label_bits_);
    metrics.token_count_right += static_cast<std::uint64_t>(right_dataset.rows.size()) * static_cast<std::uint64_t>(label_bits_);
    std::uint64_t token_len = static_cast<std::uint64_t>(security_bytes_ + 2 + ((label_bits_ + 7) / 8));
    metrics.bicentric_token_bytes += (metrics.token_count_left + metrics.token_count_right) * token_len;
    return mislabeled;
}

void BicDCProtocol::validate(const std::vector<PartyDataset>& datasets) const {
    if (static_cast<int>(datasets.size()) != parties_) {
        throw std::runtime_error("unexpected number of datasets");
    }
    if (datasets.empty()) {
        throw std::runtime_error("empty dataset list");
    }
    std::size_t size = datasets.front().rows.size();
    for (int i = 0; i < parties_; ++i) {
        if (datasets[static_cast<std::size_t>(i)].party_id != i + 1) {
            throw std::runtime_error("datasets must be ordered by party id");
        }
        if (datasets[static_cast<std::size_t>(i)].rows.size() != size) {
            throw std::runtime_error("all datasets must have equal size");
        }
    }
}

EncodedParty BicDCProtocol::encode_party(
    int party_id,
    const std::vector<std::pair<Bytes, Bytes>>& record_pairs,
    const std::vector<std::pair<Bytes, Bytes>>& label_pairs,
    RunMetrics& metrics) const {
    Bytes seed_base = string_bytes(session_id_ + ":okvs:" + std::to_string(party_id));
    auto encode_start = std::chrono::steady_clock::now();
    auto record_okvs = make_okvs(record_pairs, security_bytes_, concat(seed_base, string_bytes(":record")), okvs_config_);
    auto label_okvs = make_okvs(label_pairs, security_bytes_, concat(seed_base, string_bytes(":label")), okvs_config_);
    auto encode_end = std::chrono::steady_clock::now();
    metrics.timings["okvs_encode"] += std::chrono::duration<double>(encode_end - encode_start).count();
    return {record_okvs, label_okvs};
}

}  // namespace bicdc
