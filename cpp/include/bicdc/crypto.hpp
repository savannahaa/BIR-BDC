#pragma once

#include "bicdc/bytes.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace bicdc {

Bytes prf(const Bytes& key, const Bytes& value, std::size_t out_len);
Bytes derive_key(const std::string& session_id, int party_id, std::size_t out_len);
Bytes prefix_bits(const Bytes& data, int bit_len);
Bytes flip_last_prefix_bit(const Bytes& data, int bit_len);
std::vector<Bytes> complete_prefixes(const Bytes& data, int label_bits);
std::vector<Bytes> flipped_prefixes(const Bytes& data, int label_bits);

}  // namespace bicdc

