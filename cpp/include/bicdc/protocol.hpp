#pragma once

#include "bicdc/data.hpp"
#include "bicdc/metrics.hpp"
#include "bicdc/okvs.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace bicdc {

struct EncodedParty {
    std::shared_ptr<OkvsBackend> record_okvs;
    std::shared_ptr<OkvsBackend> label_okvs;
};

struct BicDCRepresentation {
    std::unordered_map<int, EncodedParty> to_left;
    std::unordered_map<int, EncodedParty> to_right;
};

struct BicDCResult {
    std::unordered_set<std::string> mislabeled_records;
    RunMetrics metrics;
};

class BicDCProtocol {
public:
    BicDCProtocol(
        int parties,
        int label_bits,
        std::size_t security_bytes = 16,
        std::string session_id = "bic-dc-session",
        OkvsConfig okvs_config = {});

    BicDCResult run(const std::vector<PartyDataset>& datasets) const;
    BicDCRepresentation represent(const std::vector<PartyDataset>& datasets, RunMetrics& metrics) const;
    std::unordered_set<std::string> resolve(
        const std::vector<PartyDataset>& datasets,
        const BicDCRepresentation& representation,
        RunMetrics& metrics) const;

private:
    int parties_;
    int label_bits_;
    std::size_t security_bytes_;
    std::string session_id_;
    OkvsConfig okvs_config_;
    int left_bicentric_;
    int right_bicentric_;
    std::unordered_map<int, Bytes> keys_;

    void validate(const std::vector<PartyDataset>& datasets) const;
    EncodedParty encode_party(
        int party_id,
        const std::vector<std::pair<Bytes, Bytes>>& record_pairs,
        const std::vector<std::pair<Bytes, Bytes>>& label_pairs,
        RunMetrics& metrics) const;
};

}  // namespace bicdc
