#pragma once

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace bicdc {

using Bytes = std::vector<std::uint8_t>;

inline Bytes xor_bytes(const std::vector<Bytes>& values, std::size_t len) {
    Bytes out(len, 0);
    for (const auto& value : values) {
        if (value.size() != len) {
            throw std::runtime_error("xor_bytes length mismatch");
        }
        for (std::size_t i = 0; i < len; ++i) {
            out[i] ^= value[i];
        }
    }
    return out;
}

inline std::string bytes_key(const Bytes& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

inline Bytes string_bytes(const std::string& value) {
    return Bytes(value.begin(), value.end());
}

inline Bytes uint64_bytes(std::uint64_t value) {
    Bytes out(8);
    for (int i = 7; i >= 0; --i) {
        out[static_cast<std::size_t>(7 - i)] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xff);
    }
    return out;
}

inline Bytes concat(const Bytes& a, const Bytes& b) {
    Bytes out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

inline std::string human_mb(std::uint64_t bytes) {
    std::ostringstream os;
    os.setf(std::ios::fixed);
    os.precision(3);
    os << static_cast<double>(bytes) / (1024.0 * 1024.0);
    return os.str();
}

}  // namespace bicdc

