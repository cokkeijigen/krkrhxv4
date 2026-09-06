#pragma once

#include "common.hpp"

#include <cstdint>
#include <span>

namespace krkr::dumpkey
{
    // Argon2i v1.3 (0x13) raw key derivation, mirroring the Rust `argon2` crate
    // (Algorithm::Argon2i, Version::V0x13) used by Cxdec_Tools. `m_cost` is in
    // kibibytes, `t_cost` is passes, `p_cost` is lanes.
    void argon2i_hash_raw(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t p_cost,
                          std::span<const std::uint8_t> pwd,
                          std::span<const std::uint8_t> salt,
                          std::span<std::uint8_t> out);
} // namespace krkr::dumpkey
