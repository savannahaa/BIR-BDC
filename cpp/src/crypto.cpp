#include "bicdc/crypto.hpp"

#include <functional>
#include <stdexcept>

namespace bicdc {

Bytes prf(const Bytes& key, const Bytes& value, std::size_t out_len) {
    Bytes out;
    out.reserve(out_len);
    std::hash<std::string> hasher;
    std::string base = bytes_key(key) + ":" + bytes_key(value);
    std::uint64_t counter = 0;
    while (out.size() < out_len) {
        std::string block = base + ":" + std::to_string(counter++);
        std::uint64_t h = static_cast<std::uint64_t>(hasher(block));
        for (int i = 0; i < 8 && out.size() < out_len; ++i) {
            out.push_back(static_cast<std::uint8_t>((h >> (i * 8)) & 0xff));
        }
    }
    return out;
}

Bytes derive_key(const std::string& session_id, int party_id, std::size_t out_len) {
    Bytes seed = string_bytes(session_id + ":party:" + std::to_string(party_id));
    return prf(string_bytes("derive-key"), seed, out_len);
}

Bytes prefix_bits(const Bytes& data, int bit_len) {
    if (bit_len < 0 || bit_len > static_cast<int>(data.size() * 8)) {
        throw std::runtime_error("prefix length out of range");
    }
    std::size_t byte_len = static_cast<std::size_t>((bit_len + 7) / 8);
    Bytes out;
    out.reserve(byte_len + 2);
    out.push_back(static_cast<std::uint8_t>((bit_len >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(bit_len & 0xff));
    out.insert(out.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(byte_len));
    int unused = static_cast<int>(byte_len * 8) - bit_len;
    if (unused > 0 && out.size() > 2) {
        out.back() &= static_cast<std::uint8_t>((0xff << unused) & 0xff);
    }
    return out;
}

Bytes flip_last_prefix_bit(const Bytes& data, int bit_len) {
    if (bit_len <= 0 || bit_len > static_cast<int>(data.size() * 8)) {
        throw std::runtime_error("prefix length out of range");
    }
    std::size_t byte_len = static_cast<std::size_t>((bit_len + 7) / 8);
    Bytes tmp(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(byte_len));
    int last = bit_len - 1;
    std::size_t byte_idx = static_cast<std::size_t>(last / 8);
    int offset = last % 8;
    tmp[byte_idx] ^= static_cast<std::uint8_t>(1 << (7 - offset));
    int unused = static_cast<int>(byte_len * 8) - bit_len;
    if (unused > 0) {
        tmp.back() &= static_cast<std::uint8_t>((0xff << unused) & 0xff);
    }
    Bytes out;
    out.reserve(byte_len + 2);
    out.push_back(static_cast<std::uint8_t>((bit_len >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(bit_len & 0xff));
    out.insert(out.end(), tmp.begin(), tmp.end());
    return out;
}

std::vector<Bytes> complete_prefixes(const Bytes& data, int label_bits) {
    std::vector<Bytes> out;
    out.reserve(static_cast<std::size_t>(label_bits));
    for (int bits = 1; bits <= label_bits; ++bits) {
        out.push_back(prefix_bits(data, bits));
    }
    return out;
}

std::vector<Bytes> flipped_prefixes(const Bytes& data, int label_bits) {
    std::vector<Bytes> out;
    out.reserve(static_cast<std::size_t>(label_bits));
    for (int bits = 1; bits <= label_bits; ++bits) {
        out.push_back(flip_last_prefix_bit(data, bits));
    }
    return out;
}

}  // namespace bicdc

