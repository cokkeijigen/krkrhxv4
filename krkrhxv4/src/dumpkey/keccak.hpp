#pragma once

#include "common.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace krkr::dumpkey
{
    // Runs one Keccak-f[1600] permutation on 25 little-endian 64-bit lanes.
    void keccak_f1600(std::array<std::uint64_t, 25>& state);

    // The game DLL's CxSponge (Keccak-based sponge with a byte-level rate and a
    // custom domain byte, mirroring E:\GitRepos\Cxdec_Tools bootstrap_alg.rs).
    class cx_sponge
    {
    public:
        // `rate` is in bytes, `domain` is the domain-separation byte.
        cx_sponge(std::size_t rate, std::uint8_t domain);

        auto absorb(std::span<const std::uint8_t> input) -> void;

        // Finalizes with the domain + 0x80 padding and squeezes `output`.
        auto squeeze(std::span<std::uint8_t> output) -> void;

    private:
        std::size_t                   m_rate{};
        std::size_t                   m_position{};
        std::uint8_t                  m_domain{};
        std::array<std::uint64_t, 25> m_state{};
    };

    // Standard SHA3-384 (rate 104 bytes, domain 0x06).
    [[nodiscard]] auto sha3_384(std::span<const std::uint8_t> data) -> std::array<std::uint8_t, 48>;
} // namespace krkr::dumpkey
