#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace bicdc {

struct RunMetrics {
    std::unordered_map<std::string, double> timings;
    std::uint64_t okvs_bytes = 0;
    std::uint64_t bicentric_token_bytes = 0;
    std::uint64_t communication_bytes = 0;
    std::uint64_t token_count_left = 0;
    std::uint64_t token_count_right = 0;

    double runtime_s() const;
};

class ScopedTimer {
public:
    ScopedTimer(RunMetrics& metrics, std::string name);
    ~ScopedTimer();

private:
    RunMetrics& metrics_;
    std::string name_;
    std::chrono::steady_clock::time_point start_;
};

}  // namespace bicdc

