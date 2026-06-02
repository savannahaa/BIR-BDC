#include "bicdc/okvs.hpp"

#include <cmath>
#include <cstring>
#include <stdexcept>

#ifdef BICDC_USE_SHALLMATE_OKVS
#include "Paxos.h"
#include "PaxosImpl.h"
#endif

namespace bicdc {

SimulatedOkvs::SimulatedOkvs(std::vector<std::pair<Bytes, Bytes>> pairs, std::size_t value_len, Bytes seed)
    : value_len_(value_len), seed_(std::move(seed)) {
    for (auto& pair : pairs) {
        table_[bytes_key(pair.first)] = std::move(pair.second);
    }
}

Bytes SimulatedOkvs::decode(const Bytes& key) const {
    auto it = table_.find(bytes_key(key));
    if (it != table_.end()) {
        return it->second;
    }
    Bytes missing = string_bytes("missing:");
    missing.insert(missing.end(), key.begin(), key.end());
    return prf(seed_, missing, value_len_);
}

std::uint64_t SimulatedOkvs::encoded_bytes() const {
    return static_cast<std::uint64_t>(std::ceil(static_cast<double>(table_.size()) * expansion_)) * value_len_;
}

#ifdef BICDC_USE_SHALLMATE_OKVS
namespace {

volePSI::block key_to_block(const Bytes& bytes) {
    Bytes digest = prf(string_bytes("bicdc-okvs-block"), bytes, 16);
    std::uint64_t lo = 0;
    std::uint64_t hi = 0;
    std::memcpy(&lo, digest.data(), 8);
    std::memcpy(&hi, digest.data() + 8, 8);
    return volePSI::block(lo, hi);
}

volePSI::block value_to_block(const Bytes& bytes) {
    std::uint64_t lo = 0;
    std::uint64_t hi = 0;
    std::memcpy(&lo, bytes.data(), 8);
    std::memcpy(&hi, bytes.data() + 8, 8);
    return volePSI::block(lo, hi);
}

Bytes block_to_bytes(const volePSI::block& block) {
    Bytes out(16);
    std::memcpy(out.data(), &block, 16);
    return out;
}

}  // namespace

struct ShallMatePaxosOkvs::Impl {
    volePSI::Paxos<volePSI::u64> paxos;
    std::vector<volePSI::block> pax;
};

ShallMatePaxosOkvs::ShallMatePaxosOkvs(
    std::vector<std::pair<Bytes, Bytes>> pairs,
    std::size_t value_len,
    Bytes seed,
    const OkvsConfig& config)
    : impl_(std::make_shared<Impl>()) {
    if (value_len != 16) {
        throw std::runtime_error("ShallMate Paxos OKVS currently expects 16-byte values");
    }

    std::vector<volePSI::block> keys;
    std::vector<volePSI::block> values;
    keys.reserve(pairs.size());
    values.reserve(pairs.size());
    for (const auto& pair : pairs) {
        if (pair.second.size() != 16) {
            throw std::runtime_error("ShallMate Paxos OKVS value length mismatch");
        }
        keys.push_back(key_to_block(pair.first));
        values.push_back(value_to_block(pair.second));
    }

    impl_->paxos.init(
        static_cast<volePSI::u64>(keys.size()),
        config.weight,
        config.statistical_security,
        volePSI::PaxosParam::GF128,
        key_to_block(seed));
    impl_->pax.resize(impl_->paxos.size());
    impl_->paxos.template solve<volePSI::block>(
        volePSI::span<const volePSI::block>(keys.data(), keys.size()),
        volePSI::span<const volePSI::block>(values.data(), values.size()),
        volePSI::span<volePSI::block>(impl_->pax.data(), impl_->pax.size()));
}

Bytes ShallMatePaxosOkvs::decode(const Bytes& key) const {
    auto input = key_to_block(key);
    volePSI::block value;
    impl_->paxos.template decode<volePSI::block>(
        volePSI::span<const volePSI::block>(&input, 1),
        volePSI::span<volePSI::block>(&value, 1),
        volePSI::span<const volePSI::block>(impl_->pax.data(), impl_->pax.size()));
    return block_to_bytes(value);
}

std::uint64_t ShallMatePaxosOkvs::encoded_bytes() const {
    return static_cast<std::uint64_t>(impl_->pax.size() * sizeof(volePSI::block));
}
#endif

std::shared_ptr<OkvsBackend> make_okvs(
    std::vector<std::pair<Bytes, Bytes>> pairs,
    std::size_t value_len,
    Bytes seed,
    const OkvsConfig& config) {
    std::unordered_map<std::string, std::size_t> seen;
    std::vector<std::pair<Bytes, Bytes>> deduped;
    deduped.reserve(pairs.size());
    for (auto& pair : pairs) {
        auto key = bytes_key(pair.first);
        if (seen.find(key) == seen.end()) {
            seen.emplace(std::move(key), deduped.size());
            deduped.push_back(std::move(pair));
        }
    }
    pairs = std::move(deduped);

    if (config.kind == OkvsKind::Simulated) {
        return std::make_shared<SimulatedOkvs>(std::move(pairs), value_len, std::move(seed));
    }
#ifdef BICDC_USE_SHALLMATE_OKVS
    if (config.kind == OkvsKind::ShallMatePaxos) {
        return std::make_shared<ShallMatePaxosOkvs>(std::move(pairs), value_len, std::move(seed), config);
    }
#else
    if (config.kind == OkvsKind::ShallMatePaxos) {
        throw std::runtime_error("ShallMate/OKVS backend is not compiled in; rebuild with USE_SHALLMATE_OKVS=1");
    }
#endif
    throw std::runtime_error("unknown OKVS backend");
}

}  // namespace bicdc
