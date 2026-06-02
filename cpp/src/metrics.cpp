#include "bicdc/metrics.hpp"

#include <utility>

namespace bicdc {

double RunMetrics::runtime_s() const {
    double total = 0.0;
    for (const auto& item : timings) {
        total += item.second;
    }
    return total;
}

ScopedTimer::ScopedTimer(RunMetrics& metrics, std::string name)
    : metrics_(metrics), name_(std::move(name)), start_(std::chrono::steady_clock::now()) {}

ScopedTimer::~ScopedTimer() {
    auto end = std::chrono::steady_clock::now();
    double seconds = std::chrono::duration<double>(end - start_).count();
    metrics_.timings[name_] += seconds;
}

}  // namespace bicdc

