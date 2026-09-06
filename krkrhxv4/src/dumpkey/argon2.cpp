#include "argon2.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace krkr::dumpkey
{
    namespace
    {
        constexpr int k_sync_points = 4;       // slices
        constexpr int k_addresses_in_block = 128;
        constexpr std::size_t k_block_words = 128; // 1024 bytes / 8

        constexpr std::uint64_t k_blake2b_iv[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
            0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
        };

        constexpr int k_sigma[10][16] = {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        };

        auto rotr64(std::uint64_t v, int n) -> std::uint64_t
        {
            return (n == 0) ? v : ((v >> n) | (v << (64 - n)));
        }

        struct block
        {
            std::array<std::uint64_t, k_block_words> v{};
        };

        auto block_from_bytes(std::span<const std::uint8_t, 1024> bytes) -> block
        {
            block b{};
            for (std::size_t i = 0; i < k_block_words; ++i)
            {
                std::uint64_t w = 0;
                for (int k = 0; k < 8; ++k)
                {
                    w |= static_cast<std::uint64_t>(bytes[i * 8 + k]) << (8 * k);
                }
                b.v[i] = w;
            }
            return b;
        }

        auto block_to_bytes(const block& b) -> std::array<std::uint8_t, 1024>
        {
            std::array<std::uint8_t, 1024> out{};
            for (std::size_t i = 0; i < k_block_words; ++i)
            {
                for (int k = 0; k < 8; ++k)
                {
                    out[i * 8 + k] = static_cast<std::uint8_t>(b.v[i] >> (8 * k));
                }
            }
            return out;
        }

        // One Argon2 permutation step (the G function on four u64 words).
        auto permute_step(std::uint64_t& a, std::uint64_t& b, std::uint64_t& c, std::uint64_t& d) -> void
        {
            a = a + b + 2u * ((a & 0xffffffffu) * (b & 0xffffffffu));
            d = rotr64(d ^ a, 32);
            c = c + d + 2u * ((c & 0xffffffffu) * (d & 0xffffffffu));
            b = rotr64(b ^ c, 24);
            a = a + b + 2u * ((a & 0xffffffffu) * (b & 0xffffffffu));
            d = rotr64(d ^ a, 16);
            c = c + d + 2u * ((c & 0xffffffffu) * (d & 0xffffffffu));
            b = rotr64(b ^ c, 63);
        }

        // Argon2 block compression: q = permute(rhs ^ lhs) ^ (rhs ^ lhs).
        auto compress(const block& rhs, const block& lhs) -> block
        {
            block r{};
            for (std::size_t i = 0; i < k_block_words; ++i)
            {
                r.v[i] = rhs.v[i] ^ lhs.v[i];
            }

            block q = r;
            // rowwise
            for (std::size_t chunk = 0; chunk < k_block_words; chunk += 16)
            {
                permute_step(q.v[chunk + 0], q.v[chunk + 4], q.v[chunk + 8], q.v[chunk + 12]);
                permute_step(q.v[chunk + 1], q.v[chunk + 5], q.v[chunk + 9], q.v[chunk + 13]);
                permute_step(q.v[chunk + 2], q.v[chunk + 6], q.v[chunk + 10], q.v[chunk + 14]);
                permute_step(q.v[chunk + 3], q.v[chunk + 7], q.v[chunk + 11], q.v[chunk + 15]);
                permute_step(q.v[chunk + 0], q.v[chunk + 5], q.v[chunk + 10], q.v[chunk + 15]);
                permute_step(q.v[chunk + 1], q.v[chunk + 6], q.v[chunk + 11], q.v[chunk + 12]);
                permute_step(q.v[chunk + 2], q.v[chunk + 7], q.v[chunk + 8], q.v[chunk + 13]);
                permute_step(q.v[chunk + 3], q.v[chunk + 4], q.v[chunk + 9], q.v[chunk + 14]);
            }
            // columnwise
            for (int i = 0; i < 8; ++i)
            {
                const std::size_t b = static_cast<std::size_t>(i) * 2;
                permute_step(q.v[b], q.v[b + 32], q.v[b + 64], q.v[b + 96]);
                permute_step(q.v[b + 1], q.v[b + 33], q.v[b + 65], q.v[b + 97]);
                permute_step(q.v[b + 16], q.v[b + 48], q.v[b + 80], q.v[b + 112]);
                permute_step(q.v[b + 17], q.v[b + 49], q.v[b + 81], q.v[b + 113]);
                permute_step(q.v[b], q.v[b + 33], q.v[b + 80], q.v[b + 113]);
                permute_step(q.v[b + 1], q.v[b + 48], q.v[b + 81], q.v[b + 96]);
                permute_step(q.v[b + 16], q.v[b + 49], q.v[b + 64], q.v[b + 97]);
                permute_step(q.v[b + 17], q.v[b + 32], q.v[b + 65], q.v[b + 112]);
            }

            for (std::size_t i = 0; i < k_block_words; ++i)
            {
                q.v[i] ^= r.v[i];
            }
            return q;
        }

        // Blake2b with variable digest length (1..64 bytes), no key.
        auto blake2b(std::size_t digest_len, std::span<const std::uint8_t> data) -> std::vector<std::uint8_t>
        {
            std::array<std::uint64_t, 8> h{};
            for (int i = 0; i < 8; ++i)
            {
                h[i] = k_blake2b_iv[i];
            }
            h[0] ^= 0x01010000u ^ static_cast<std::uint64_t>(digest_len);

            auto g = [](std::array<std::uint64_t, 16>& v, int a, int b, int c, int d, std::uint64_t x, std::uint64_t y)
            {
                v[a] = v[a] + v[b] + x;
                v[d] = rotr64(v[d] ^ v[a], 32);
                v[c] = v[c] + v[d];
                v[b] = rotr64(v[b] ^ v[c], 24);
                v[a] = v[a] + v[b] + y;
                v[d] = rotr64(v[d] ^ v[a], 16);
                v[c] = v[c] + v[d];
                v[b] = rotr64(v[b] ^ v[c], 63);
            };

            std::size_t offset = 0;
            while (data.size() - offset > 128)
            {
                std::array<std::uint64_t, 16> m{};
                for (std::size_t i = 0; i < 16; ++i)
                {
                    m[i] = krkr::read_u64_le(data, offset + i * 8);
                }
                std::array<std::uint64_t, 16> v{};
                for (int i = 0; i < 8; ++i)
                {
                    v[i] = h[i];
                }
                for (int i = 0; i < 8; ++i)
                {
                    v[8 + i] = k_blake2b_iv[i];
                }
                v[12] ^= static_cast<std::uint64_t>(offset) + 128; // byte counter includes this block
                for (int r = 0; r < 12; ++r)
                {
                    const auto* s = k_sigma[r % 10];
                    g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
                    g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
                    g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                    g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                    g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                    g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                    g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
                }
                for (int i = 0; i < 8; ++i)
                {
                    h[i] ^= v[i] ^ v[i + 8];
                }
                offset += 128;
            }

            // final block
            std::array<std::uint8_t, 128> block_bytes{};
            std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset), data.end(), block_bytes.begin());
            std::array<std::uint64_t, 16> m{};
            for (std::size_t i = 0; i < 16; ++i)
            {
                m[i] = krkr::read_u64_le(block_bytes, i * 8);
            }
            std::array<std::uint64_t, 16> v{};
            for (int i = 0; i < 8; ++i)
            {
                v[i] = h[i];
            }
            for (int i = 0; i < 8; ++i)
            {
                v[8 + i] = k_blake2b_iv[i];
            }
            v[12] ^= static_cast<std::uint64_t>(data.size()); // byte counter includes this block
            v[14] = ~v[14];
            for (int r = 0; r < 12; ++r)
            {
                const auto* s = k_sigma[r % 10];
                g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
                g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
                g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
            }
            for (int i = 0; i < 8; ++i)
            {
                h[i] ^= v[i] ^ v[i + 8];
            }

            std::vector<std::uint8_t> out(digest_len);
            for (std::size_t i = 0; i < digest_len; ++i)
            {
                out[i] = static_cast<std::uint8_t>(h[i / 8] >> (8 * (i % 8)));
            }
            return out;
        }

        // Argon2's variable-length hash over concatenated input chunks.
        auto blake2b_long(const std::vector<std::span<const std::uint8_t>>& inputs, std::span<std::uint8_t> out) -> void
        {
            const auto out_len = static_cast<std::uint32_t>(out.size());
            std::vector<std::uint8_t> len_bytes(4);
            krkr::write_u32_le(len_bytes, 0, out_len);

            std::vector<std::uint8_t> head = len_bytes;
            for (const auto& input : inputs)
            {
                head.insert(head.end(), input.begin(), input.end());
            }

            if (out.size() <= 64)
            {
                const auto digest = blake2b(out.size(), head);
                std::copy(digest.begin(), digest.end(), out.begin());
                return;
            }

            // Long output: first 32 bytes, then chained 32-byte full blocks.
            auto last_output = blake2b(64, head);
            constexpr std::size_t k_half = 32;
            std::copy_n(last_output.begin(), k_half, out.begin());

            std::size_t counter = 0;
            std::size_t pos = k_half;
            while (pos + k_half <= out.size())
            {
                counter += k_half;
                if (out_len - counter <= 64)
                {
                    break;
                }
                last_output = blake2b(64, last_output);
                std::copy_n(last_output.begin(), k_half, out.begin() + static_cast<std::ptrdiff_t>(pos));
                pos += k_half;
            }

            // Final variable-length block.
            const std::size_t last_block_size = out.size() - counter;
            const auto final_block = blake2b(last_block_size, last_output);
            std::copy(final_block.begin(), final_block.end(), out.begin() + static_cast<std::ptrdiff_t>(counter));
        }

        // Appends u32 LE to a byte vector.
        auto append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) -> void
        {
            for (int i = 0; i < 4; ++i)
            {
                out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
            }
        }
    } // namespace

    void argon2i_hash_raw(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t p_cost,
                          const std::span<const std::uint8_t> pwd,
                          const std::span<const std::uint8_t> salt,
                          const std::span<std::uint8_t> out)
    {
        const std::uint32_t algorithm = 1;   // Argon2i
        const std::uint32_t version = 0x13;  // v1.3

        const std::size_t lanes = p_cost;
        const std::size_t memory_blocks = (m_cost < 2u * k_sync_points * lanes) ? (2u * k_sync_points * lanes) : m_cost;
        const std::size_t segment_length = memory_blocks / (lanes * k_sync_points);
        const std::size_t lane_length = segment_length * k_sync_points;
        const std::size_t block_count = segment_length * lanes * k_sync_points;

        // H0 = Blake2b-512 of the parameter block.
        std::vector<std::uint8_t> h0_input;
        append_u32_le(h0_input, p_cost);
        append_u32_le(h0_input, static_cast<std::uint32_t>(out.size()));
        append_u32_le(h0_input, m_cost);
        append_u32_le(h0_input, t_cost);
        append_u32_le(h0_input, version);
        append_u32_le(h0_input, algorithm);
        append_u32_le(h0_input, static_cast<std::uint32_t>(pwd.size()));
        h0_input.insert(h0_input.end(), pwd.begin(), pwd.end());
        append_u32_le(h0_input, static_cast<std::uint32_t>(salt.size()));
        h0_input.insert(h0_input.end(), salt.begin(), salt.end());
        append_u32_le(h0_input, 0); // secret (None)
        append_u32_le(h0_input, 0); // associated data (empty)
        const auto initial_hash = blake2b(64, h0_input);

        std::vector<block> memory(block_count);

        // Fill first two blocks of each lane.
        for (std::size_t l = 0; l < lanes; ++l)
        {
            for (std::size_t i = 0; i < 2; ++i)
            {
                std::array<std::uint8_t, 4> i_le{};
                std::array<std::uint8_t, 4> l_le{};
                krkr::write_u32_le(i_le, 0, static_cast<std::uint32_t>(i));
                krkr::write_u32_le(l_le, 0, static_cast<std::uint32_t>(l));
                const std::span<const std::uint8_t> h0{ initial_hash.data(), initial_hash.size() };
                const std::vector<std::span<const std::uint8_t>> inputs{ h0, i_le, l_le };
                std::array<std::uint8_t, 1024> hash{};
                blake2b_long(inputs, hash);
                memory[l * lane_length + i] = block_from_bytes(hash);
            }
        }

        const block zero_block{};

        for (std::uint32_t pass = 0; pass < t_cost; ++pass)
        {
            for (int slice = 0; slice < k_sync_points; ++slice)
            {
                const bool data_independent = true; // Argon2i

                for (std::size_t lane = 0; lane < lanes; ++lane)
                {
                    block address_block{};
                    block input_block{};
                    if (data_independent)
                    {
                        input_block.v[0] = pass;
                        input_block.v[1] = lane;
                        input_block.v[2] = static_cast<std::uint64_t>(slice);
                        input_block.v[3] = memory.size();
                        input_block.v[4] = t_cost;
                        input_block.v[5] = algorithm;
                    }

                    const std::size_t first_block = (pass == 0 && slice == 0) ? 2 : 0;
                    if (pass == 0 && slice == 0 && data_independent)
                    {
                        input_block.v[6] += 1;
                        address_block = compress(zero_block, input_block);
                        address_block = compress(zero_block, address_block);
                    }

                    std::size_t cur_index = lane * lane_length + static_cast<std::size_t>(slice) * segment_length + first_block;
                    std::size_t prev_index = (slice == 0 && first_block == 0) ? (cur_index + lane_length - 1) : (cur_index - 1);

                    for (std::size_t block_i = first_block; block_i < segment_length; ++block_i)
                    {
                        std::uint64_t rand = 0;
                        if (data_independent)
                        {
                            const std::size_t address_index = block_i % k_addresses_in_block;
                            if (address_index == 0)
                            {
                                input_block.v[6] += 1;
                                address_block = compress(zero_block, input_block);
                                address_block = compress(zero_block, address_block);
                            }
                            rand = address_block.v[address_index];
                        }
                        else
                        {
                            rand = memory[prev_index].v[0];
                        }

                        const std::size_t ref_lane = (pass == 0 && slice == 0)
                            ? lane
                            : static_cast<std::size_t>((rand >> 32) % lanes);

                        std::size_t reference_area_size = 0;
                        if (pass == 0)
                        {
                            if (slice == 0)
                            {
                                reference_area_size = block_i - 1;
                            }
                            else if (ref_lane == lane)
                            {
                                reference_area_size = static_cast<std::size_t>(slice) * segment_length + block_i - 1;
                            }
                            else
                            {
                                reference_area_size = static_cast<std::size_t>(slice) * segment_length - (block_i == 0 ? 1 : 0);
                            }
                        }
                        else
                        {
                            if (ref_lane == lane)
                            {
                                reference_area_size = lane_length - segment_length + block_i - 1;
                            }
                            else
                            {
                                reference_area_size = lane_length - segment_length - (block_i == 0 ? 1 : 0);
                            }
                        }

                        std::uint64_t map = rand & 0xffffffffu;
                        map = (map * map) >> 32;
                        const std::size_t relative_position = reference_area_size - 1
                            - static_cast<std::size_t>((reference_area_size * map) >> 32);

                        const std::size_t start_position = (pass != 0 && slice != k_sync_points - 1)
                            ? (static_cast<std::size_t>(slice) + 1) * segment_length
                            : 0;

                        const std::size_t lane_index = (start_position + relative_position) % lane_length;
                        const std::size_t ref_index = ref_lane * lane_length + lane_index;

                        const block result = compress(memory[prev_index], memory[ref_index]);
                        if (version == 0x10 || pass == 0)
                        {
                            memory[cur_index] = result;
                        }
                        else
                        {
                            for (std::size_t w = 0; w < k_block_words; ++w)
                            {
                                memory[cur_index].v[w] ^= result.v[w];
                            }
                        }

                        prev_index = cur_index;
                        ++cur_index;
                    }
                }
            }
        }

        // Finalize: XOR last block of each lane, then hash.
        block blockhash = memory[lane_length - 1];
        for (std::size_t l = 1; l < lanes; ++l)
        {
            const block& last = memory[l * lane_length + (lane_length - 1)];
            for (std::size_t w = 0; w < k_block_words; ++w)
            {
                blockhash.v[w] ^= last.v[w];
            }
        }
        const auto blockhash_bytes = block_to_bytes(blockhash);
        const std::span<const std::uint8_t> bh{ blockhash_bytes.data(), blockhash_bytes.size() };
        const std::vector<std::span<const std::uint8_t>> inputs{ bh };
        blake2b_long(inputs, out);
    }
} // namespace krkr::dumpkey
