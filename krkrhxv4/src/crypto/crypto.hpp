#pragma once

#include "common.hpp"

#include <string_view>

namespace krkr::crypto
{
    // ChaCha20 with a 64-bit block counter and 64-bit nonce (original djb layout),
    // 20 rounds. Uses the same stream the KiriKiri HxV4 index calls for.
    class chacha20
    {
    public:
        chacha20(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 8> nonce, std::uint64_t counter = 0);

        // XORs the keystream over [data).
        void xor_stream(std::span<std::uint8_t> data);

        // Raw keystream block at `counter` (does not advance the stream).
        auto block(std::uint64_t counter) const -> std::array<std::uint8_t, 64>;

    private:
        std::array<std::uint32_t, 16> m_state{};
        std::uint64_t m_counter = 0;

        auto block() -> std::array<std::uint8_t, 64>;
    };

    // SipHash-2-4 with the all-zero 128-bit key (8-byte little-endian digest).
    [[nodiscard]] auto siphash24_empty(std::span<const std::uint8_t> data) -> std::uint64_t;

    // BLAKE2s-256, little-endian word output (32-byte digest).
    [[nodiscard]] auto blake2s_256(std::span<const std::uint8_t> data) -> std::array<std::uint8_t, 32>;

    // HxV4 index blob authentication tag (the 16-byte "blob prefix" the engine
    // verifies before decrypting, sub_1001F950).  Poly1305 keyed by the first
    // 32 bytes of the ChaCha20 (djb) block 0 of (key, nonce), over the
    // encrypted payload framed as pad16(payload) + le64(0) + le64(len(payload))
    // — every full 16-byte block contributes +2^128, matching the game DLL's
    // buffered stream (sub_10021410).
    [[nodiscard]] auto index_blob_tag(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 8> nonce, std::span<const std::uint8_t> encrypted_payload) -> std::array<std::uint8_t, 16>;

    // HxV4 hash domain ("xp3hnp") appended to every hashed name.
    inline constexpr std::string_view kHashDomain = "xp3hnp";

    // Directory hash: SipHash-2-4 over utf16le(dir path + trailing '/') + utf16le(domain).
    // `path` must already include the trailing slash for non-root directories.
    [[nodiscard]] auto dirhash(std::u16string_view path) -> std::array<std::uint8_t, 8>;

    // File name hash: BLAKE2s-256 over utf16le(leaf name) + utf16le(domain).
    [[nodiscard]] auto filehash(std::u16string_view name) -> std::array<std::uint8_t, 32>;
} // namespace krkr::crypto