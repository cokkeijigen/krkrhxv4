#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include "common.hpp"

namespace krkr::cx
{
    // CX/HX content cipher scheme (the values dumped from a running game).
    struct scheme
    {
        std::uint32_t          mask{};
        std::uint32_t          offset{};
        std::array<int, 3> prolog_order{ 0, 1, 2 };
        std::array<int, 6> odd_branch_order{ 0, 1, 2, 3, 4, 5 };
        std::array<int, 8> even_branch_order{ 0, 1, 2, 3, 4, 5, 6, 7 };
        // 1024 words as produced by the dumped control block (already ~-inverted
        // by the caller, exactly what MOV_EAX_INDIRECT expects).
        std::vector<std::uint32_t> control_block;
        // 8-byte filter key, interpreted as little-endian std::uint64_t.
        std::uint64_t              filter_key{};
        // 0 = splittable-old RNG, otherwise splittable-new RNG.
        int              random_type{};
    };

    // Per-file keystream material derived from an index entry (id, key).
    struct filter_key
    {
        std::array<std::uint64_t, 2>   span;
        std::uint32_t                  split_pos{};
        std::array<std::uint8_t, 16>   header{};
    };

    class cipher
    {
    public:
        explicit cipher(scheme sch);
        ~cipher();

        // Derives the per-file material for an index entry.
        [[nodiscard]] auto derive(std::uint64_t entry_key, std::uint64_t entry_id) -> filter_key;

        // Encodes/decodes a single decompressed segment in place (XOR-symmetric).
        // `hash` is the adlr hash of the entry.
        auto crypt(std::uint64_t hash, std::uint64_t offset, std::span<std::uint8_t> data) -> void;

        // Applies the full per-file content transform (header key + span split).
        // Skipped-bytes symetry makes this usable for both pack and unpack.
        auto content_crypt(const filter_key& key, std::span<std::uint8_t> data) -> void;

        [[nodiscard]] auto state() const noexcept -> const scheme& { return m_scheme; }

    private:
        class program;

        scheme                                  m_scheme;
        std::array<std::unique_ptr<program>, 0x80> m_programs;

        auto get_base_offset(std::uint32_t hash) const -> std::uint32_t { return (hash & m_scheme.mask) + m_scheme.offset; }

        auto execute_xcode(std::uint32_t hash) -> std::pair<std::uint32_t, std::uint32_t>;
        auto decode(std::uint32_t key, std::uint64_t offset, std::span<std::uint8_t> data) -> void;
        auto generate_program(std::uint32_t seed) -> std::unique_ptr<program>;
        auto emit_code(program& p, int stage) const -> bool;
        auto emit_body(program& p, int stage) const -> bool;
        auto emit_body2(program& p, int stage) const -> bool;
        auto emit_prolog(program& p) const -> bool;
        auto emit_odd_branch(program& p) const -> bool;
        auto emit_even_branch(program& p) const -> bool;
    };
} // namespace krkr::cx