/**
 * @file group_common.cpp
 * @brief Backend-agnostic helpers shared by the FF and EC `Group` backends:
 *        `TagHash` (H') and the fixed-width, domain-separated item encoders
 *        used by DGT12 PSI-CA (`EncodeRawItem`, `EncodeTaggedItem`).
 */

#include "baselines/group.h"

#include <openssl/sha.h>

namespace piccard {
namespace baselines {

namespace {

// Big-endian encoders for the fixed-width item layout.
void AppendBE64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

void AppendBE32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

}  // namespace

std::vector<uint8_t> TagHash(const std::vector<uint8_t>& serialized_element) {
    // Domain-separated: 0x03 || serialized_element, distinct from the group
    // backends' own hash-to-group domain tags (0x10 FF, 0x11 EC).
    std::vector<uint8_t> input;
    input.reserve(serialized_element.size() + 1);
    input.push_back(0x03);
    input.insert(input.end(), serialized_element.begin(), serialized_element.end());

    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(input.data(), input.size(), digest.data());
    return digest;
}

std::vector<uint8_t> EncodeRawItem(uint64_t value) {
    std::vector<uint8_t> out;
    out.reserve(9);
    out.push_back(0x01);
    AppendBE64(out, value);
    return out;
}

std::vector<uint8_t> EncodeTaggedItem(uint64_t value, uint32_t index) {
    std::vector<uint8_t> out;
    out.reserve(13);
    out.push_back(0x02);
    AppendBE64(out, value);
    AppendBE32(out, index);
    return out;
}

}  // namespace baselines
}  // namespace piccard
