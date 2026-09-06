#include "keccak.hpp"

namespace krkr::dumpkey
{
    namespace
    {
        constexpr std::uint64_t k_round_constants[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
            0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
            0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
        };

        // Cycle-ordered rho offsets and pi permutation (Keccak reference).
        constexpr int k_rho[24] = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
        };
        constexpr int k_pi[24] = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
        };

        auto rotl64(std::uint64_t v, int n) -> std::uint64_t
        {
            return (n == 0) ? v : ((v << n) | (v >> (64 - n)));
        }
    } // namespace

    void keccak_f1600(std::array<std::uint64_t, 25>& state)
    {
        std::array<std::uint64_t, 5> bc{};
        for (const std::uint64_t rc : k_round_constants)
        {
            // theta
            bc.fill(0);
            for (int x = 0; x < 5; ++x)
            {
                for (int y = 0; y < 5; ++y)
                {
                    bc[x] ^= state[5 * y + x];
                }
            }
            for (int x = 0; x < 5; ++x)
            {
                const std::uint64_t t = bc[(x + 4) % 5] ^ rotl64(bc[(x + 1) % 5], 1);
                for (int y = 0; y < 5; ++y)
                {
                    state[5 * y + x] ^= t;
                }
            }

            // rho + pi
            std::uint64_t last = state[1];
            for (int x = 0; x < 24; ++x)
            {
                bc[0] = state[k_pi[x]];
                state[k_pi[x]] = rotl64(last, k_rho[x]);
                last = bc[0];
            }

            // chi
            for (int y_step = 0; y_step < 5; ++y_step)
            {
                const int y = 5 * y_step;
                for (int x = 0; x < 5; ++x)
                {
                    bc[x] = state[y + x];
                }
                for (int x = 0; x < 5; ++x)
                {
                    state[y + x] = bc[x] ^ ((~bc[(x + 1) % 5]) & bc[(x + 2) % 5]);
                }
            }

            // iota
            state[0] ^= rc;
        }
    }

    cx_sponge::cx_sponge(const std::size_t rate, const std::uint8_t domain)
        : m_rate{ rate }
        , m_domain{ domain }
    {
    }

    auto cx_sponge::absorb(const std::span<const std::uint8_t> input) -> void
    {
        for (const std::uint8_t byte : input)
        {
            m_state[m_position / 8] ^= static_cast<std::uint64_t>(byte) << (8 * (m_position % 8));
            ++m_position;
            if (m_position == m_rate)
            {
                keccak_f1600(m_state);
                m_position = 0;
            }
        }
    }

    auto cx_sponge::squeeze(const std::span<std::uint8_t> output) -> void
    {
        m_state[m_position / 8] ^= static_cast<std::uint64_t>(m_domain) << (8 * (m_position % 8));
        m_state[(m_rate - 1) / 8] ^= static_cast<std::uint64_t>(0x80) << (8 * ((m_rate - 1) % 8));
        keccak_f1600(m_state);

        std::size_t offset = 0;
        while (offset < output.size())
        {
            const std::size_t count = (m_rate < output.size() - offset) ? m_rate : (output.size() - offset);
            for (std::size_t i = 0; i < count; ++i)
            {
                output[offset + i] = static_cast<std::uint8_t>(m_state[i / 8] >> (8 * (i % 8)));
            }
            offset += count;
            if (offset < output.size())
            {
                keccak_f1600(m_state);
            }
        }
    }

    auto sha3_384(const std::span<const std::uint8_t> data) -> std::array<std::uint8_t, 48>
    {
        constexpr std::size_t k_rate = 104; // 200 - 2*48 bytes
        std::array<std::uint64_t, 25> state{};

        // Absorb full blocks.
        std::size_t offset = 0;
        while (data.size() - offset >= k_rate)
        {
            for (std::size_t i = 0; i < k_rate; ++i)
            {
                state[i / 8] ^= static_cast<std::uint64_t>(data[offset + i]) << (8 * (i % 8));
            }
            keccak_f1600(state);
            offset += k_rate;
        }

        // Final block with SHA3 padding (0x06 domain + 0x80 final bit).
        std::array<std::uint8_t, k_rate> block{};
        const std::size_t rem = data.size() - offset;
        for (std::size_t i = 0; i < rem; ++i)
        {
            block[i] = data[offset + i];
        }
        block[rem] = 0x06;
        block[k_rate - 1] |= 0x80;
        for (std::size_t i = 0; i < k_rate; ++i)
        {
            state[i / 8] ^= static_cast<std::uint64_t>(block[i]) << (8 * (i % 8));
        }
        keccak_f1600(state);

        std::array<std::uint8_t, 48> out{};
        for (std::size_t i = 0; i < out.size(); ++i)
        {
            out[i] = static_cast<std::uint8_t>(state[i / 8] >> (8 * (i % 8)));
        }
        return out;
    }
} // namespace krkr::dumpkey
