#pragma once

#include "bicdc/bytes.hpp"
#include "bicdc/crypto.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace bicdc {

class OkvsBackend {
public:
    virtual ~OkvsBackend() = default;
    virtual Bytes decode(const Bytes& key) const = 0;
    virtual std::uint64_t encoded_bytes() const = 0;
};

enum class OkvsKind {
    Simulated,
    ShallMatePaxos,
};

struct OkvsConfig {
    OkvsKind kind = OkvsKind::Simulated;
    std::uint64_t weight = 3;
    std::uint64_t statistical_security = 40;
};

class SimulatedOkvs final : public OkvsBackend {
public:
    SimulatedOkvs() = default;
    SimulatedOkvs(std::vector<std::pair<Bytes, Bytes>> pairs, std::size_t value_len, Bytes seed);

    Bytes decode(const Bytes& key) const override;
    std::uint64_t encoded_bytes() const override;

private:
    std::unordered_map<std::string, Bytes> table_;
    std::size_t value_len_ = 16;
    Bytes seed_;
    double expansion_ = 1.23;
};

#ifdef BICDC_USE_SHALLMATE_OKVS
class ShallMatePaxosOkvs final : public OkvsBackend {
public:
    ShallMatePaxosOkvs(std::vector<std::pair<Bytes, Bytes>> pairs, std::size_t value_len, Bytes seed, const OkvsConfig& config);

    Bytes decode(const Bytes& key) const override;
    std::uint64_t encoded_bytes() const override;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};
#endif

std::shared_ptr<OkvsBackend> make_okvs(
    std::vector<std::pair<Bytes, Bytes>> pairs,
    std::size_t value_len,
    Bytes seed,
    const OkvsConfig& config);

}  // namespace bicdc
