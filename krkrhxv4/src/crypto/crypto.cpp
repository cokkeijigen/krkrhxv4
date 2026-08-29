#include "crypto.hpp"

namespace krkr::crypto
{
    namespace
    {
        constexpr std::uint32_t k_chacha_rounds = 20;

        auto rotl(std::uint32_t x, int n) -> std::uint32_t
        {
            return (x << n) | (x >> (32 - n));
        }

        auto rotl(std::uint64_t x, int n) -> std::uint64_t
        {
            return (x << n) | (x >> (64 - n));
        }

        auto rotr(std::uint32_t x, int n) -> std::uint32_t
        {
            return (x >> n) | (x << (32 - n));
        }

        // One ChaCha quarter round.
        auto quarter(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) -> void
        {
            a += b; d ^= a; d = rotl(d, 16);
            c += d; b ^= c; b = rotl(b, 12);
            a += b; d ^= a; d = rotl(d, 8);
            c += d; b ^= c; b = rotl(b, 7);
        }

        auto utf16le_bytes(std::u16string_view text) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out;
            out.reserve(text.size() * 2);
            for (const auto c : text)
            {
                write_u16_le(out, c);
            }
            return out;
        }

        // Hash input = utf16le(value) + utf16le("xp3hnp").
        auto hash_input(std::u16string_view value) -> std::vector<std::uint8_t>
        {
            auto out = utf16le_bytes(value);
            const auto domain = to_utf16le(kHashDomain); // ASCII domain -> utf16le
            out.insert(out.end(), domain.begin(), domain.end());
            return out;
        }

        // Applies `rounds` double-rounds to the state words, returns transformed words.
        auto chacha_transform(std::array<std::uint32_t, 16> z, int cd = k_chacha_rounds) -> std::array<std::uint32_t, 16>
        {
            for (int r = 0; r < cd; r += 2)
            {
                // column rounds
                quarter(z[0], z[4], z[8],  z[12]);
                quarter(z[1], z[5], z[9],  z[13]);
                quarter(z[2], z[6], z[10], z[14]);
                quarter(z[3], z[7], z[11], z[15]);
                // diagonal rounds
                quarter(z[0], z[5], z[10], z[15]);
                quarter(z[1], z[6], z[11], z[12]);
                quarter(z[2], z[7], z[8],  z[13]);
                quarter(z[3], z[4], z[9],  z[14]);
            }
            return z;
        }

        // ---- SipHash helpers ----
        auto sip_round(std::uint64_t& v0, std::uint64_t& v1, std::uint64_t& v2, std::uint64_t& v3) -> void
        {
            v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
            v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
        }

        // ---- Poly1305 helpers (little-endian 32-bit limbs, p = 2^130 - 5) ----
        constexpr std::array<std::uint32_t, 5> k_poly_p = { 0xfffffffbu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 3u };

        auto poly_ge_p(const std::array<std::uint32_t, 5>& w) -> bool
        {
            for (std::size_t i = 5; i-- > 0;)
            {
                if (w[i] != k_poly_p[i])
                {
                    return w[i] > k_poly_p[i];
                }
            }
            return true;
        }

        auto poly_sub_p(std::array<std::uint32_t, 5>& w) -> void
        {
            std::uint64_t borrow = 0;
            for (std::size_t i = 0; i < 5; ++i)
            {
                const std::uint64_t cur = static_cast<std::uint64_t>(w[i]) - k_poly_p[i] - borrow;
                w[i]   = static_cast<std::uint32_t>(cur);
                borrow = (cur >> 63) & 1;
            }
        }
    } // namespace

    chacha20::chacha20(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 8> nonce, std::uint64_t counter)
        : m_counter{ counter }
    {
        constexpr std::uint32_t constants[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
        for (int i = 0; i < 4; ++i)
        {
            m_state[i] = constants[i];
        }
        for (int i = 0; i < 8; ++i)
        {
            m_state[4 + i] = read_u32_le(key, i * 4);
        }
        m_state[12] = static_cast<std::uint32_t>(m_counter);
        m_state[13] = static_cast<std::uint32_t>(m_counter >> 32);
        m_state[14] = read_u32_le(nonce, 0);
        m_state[15] = read_u32_le(nonce, 4);
    }

    auto chacha20::block(std::uint64_t counter) const -> std::array<std::uint8_t, 64>
    {
        std::array<std::uint32_t, 16> state = m_state;
        state[12] = static_cast<std::uint32_t>(counter);
        state[13] = static_cast<std::uint32_t>(counter >> 32);

        const auto transformed = chacha_transform(state);
        std::array<std::uint8_t, 64> out{};
        for (std::size_t i = 0; i < 16; ++i)
        {
            const auto v = state[i] + transformed[i];
            for (std::size_t k = 0; k < 4; ++k)
            {
                out[i * 4 + k] = static_cast<std::uint8_t>(v >> (k * 8));
            }
        }
        return out;
    }

    void chacha20::xor_stream(std::span<std::uint8_t> data)
    {
        std::size_t offset = 0;
        while (offset < data.size())
        {
            const auto ks        = block(m_counter);
            const auto count     = static_cast<std::size_t>((data.size() - offset) < (64) ? (data.size() - offset) : (64));
            for (std::size_t i = 0; i < count; ++i)
            {
                data[offset + i] ^= ks[i];
            }
            offset += count;
            ++m_counter;
        }
    }

    auto siphash24_empty(std::span<const std::uint8_t> data) -> std::uint64_t
    {
        std::uint64_t v0 = 0x736f6d6570736575ull;
        std::uint64_t v1 = 0x646f72616e646f6dull;
        std::uint64_t v2 = 0x6c7967656e657261ull;
        std::uint64_t v3 = 0x7465646279746573ull;

        std::size_t i = 0;
        while (data.size() - i >= 8)
        {
            const std::uint64_t m = read_u64_le(data, i);
            v3 ^= m;
            sip_round(v0, v1, v2, v3);
            sip_round(v0, v1, v2, v3);
            v0 ^= m;
            i += 8;
        }

        std::uint64_t tail = static_cast<std::uint64_t>(data.size() & 0xff) << 56;
        for (std::size_t k = 0; i + k < data.size(); ++k)
        {
            tail |= static_cast<std::uint64_t>(data[i + k]) << (8 * k);
        }

        v3 ^= tail;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= tail;

        v2 ^= 0xff;
        for (int k = 0; k < 4; ++k)
        {
            sip_round(v0, v1, v2, v3);
        }

        return v0 ^ v1 ^ v2 ^ v3;
    }

    auto blake2s_256(std::span<const std::uint8_t> data) -> std::array<std::uint8_t, 32>
    {
        constexpr std::uint32_t iv[8] = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
        };
        constexpr int sigma[10][16] = {
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

        auto g = [](std::array<std::uint32_t, 16>& v, int a, int b, int c, int d, std::uint32_t x, std::uint32_t y)
        {
            v[static_cast<std::size_t>(a)] = v[static_cast<std::size_t>(a)] + v[static_cast<std::size_t>(b)] + x;
            v[static_cast<std::size_t>(d)] = rotr(v[static_cast<std::size_t>(d)] ^ v[static_cast<std::size_t>(a)], 16);
            v[static_cast<std::size_t>(c)] += v[static_cast<std::size_t>(d)];
            v[static_cast<std::size_t>(b)] = rotr(v[static_cast<std::size_t>(b)] ^ v[static_cast<std::size_t>(c)], 12);
            v[static_cast<std::size_t>(a)] = v[static_cast<std::size_t>(a)] + v[static_cast<std::size_t>(b)] + y;
            v[static_cast<std::size_t>(d)] = rotr(v[static_cast<std::size_t>(d)] ^ v[static_cast<std::size_t>(a)], 8);
            v[static_cast<std::size_t>(c)] += v[static_cast<std::size_t>(d)];
            v[static_cast<std::size_t>(b)] = rotr(v[static_cast<std::size_t>(b)] ^ v[static_cast<std::size_t>(c)], 7);
        };

        std::array<std::uint32_t, 8> h{};
        std::copy(std::begin(iv), std::end(iv), h.begin());
        h[0] ^= 0x01010020u; // digest_size(32)=0x20 | key_length(0)<<8 | fanout(1)<<16 | depth(1)<<24

        std::size_t offset = 0;
        while (data.size() - offset > 64)
        {
            std::array<std::uint32_t, 16> m{};
            for (std::size_t i = 0; i < 16; ++i)
            {
                m[i] = read_u32_le(data, offset + i * 4);
            }
            std::array<std::uint32_t, 16> v{};
            std::copy(h.begin(), h.end(), v.begin());
            std::copy(std::begin(iv), std::end(iv), v.begin() + 8);
            v[12] ^= static_cast<std::uint32_t>((offset + 64) & 0xffffffffu);
            v[13] ^= static_cast<std::uint32_t>(((offset + 64) >> 32) & 0xffffffffu);
            for (const auto& s : sigma)
            {
                g(v, 0, 4, 8, 12, m[static_cast<std::size_t>(s[0])], m[static_cast<std::size_t>(s[1])]);
                g(v, 1, 5, 9, 13, m[static_cast<std::size_t>(s[2])], m[static_cast<std::size_t>(s[3])]);
                g(v, 2, 6, 10, 14, m[static_cast<std::size_t>(s[4])], m[static_cast<std::size_t>(s[5])]);
                g(v, 3, 7, 11, 15, m[static_cast<std::size_t>(s[6])], m[static_cast<std::size_t>(s[7])]);
                g(v, 0, 5, 10, 15, m[static_cast<std::size_t>(s[8])], m[static_cast<std::size_t>(s[9])]);
                g(v, 1, 6, 11, 12, m[static_cast<std::size_t>(s[10])], m[static_cast<std::size_t>(s[11])]);
                g(v, 2, 7, 8, 13, m[static_cast<std::size_t>(s[12])], m[static_cast<std::size_t>(s[13])]);
                g(v, 3, 4, 9, 14, m[static_cast<std::size_t>(s[14])], m[static_cast<std::size_t>(s[15])]);
            }
            for (std::size_t i = 0; i < 8; ++i)
            {
                h[i] ^= v[i] ^ v[i + 8];
            }
            offset += 64;
        }

        // final (padded) block
        std::array<std::uint8_t, 64> block{};
        std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset), data.end(), block.begin());
        const auto total = static_cast<std::uint64_t>(data.size());
        std::array<std::uint32_t, 16> m{};
        for (std::size_t i = 0; i < 16; ++i)
        {
            m[i] = read_u32_le(block, i * 4);
        }
        std::array<std::uint32_t, 16> v{};
        std::copy(h.begin(), h.end(), v.begin());
        std::copy(std::begin(iv), std::end(iv), v.begin() + 8);
        v[12] ^= static_cast<std::uint32_t>(total & 0xffffffffu);
        v[13] ^= static_cast<std::uint32_t>((total >> 32) & 0xffffffffu);
        v[14] = ~v[14]; // final block flag
        for (const auto& s : sigma)
        {
            g(v, 0, 4, 8, 12, m[static_cast<std::size_t>(s[0])], m[static_cast<std::size_t>(s[1])]);
            g(v, 1, 5, 9, 13, m[static_cast<std::size_t>(s[2])], m[static_cast<std::size_t>(s[3])]);
            g(v, 2, 6, 10, 14, m[static_cast<std::size_t>(s[4])], m[static_cast<std::size_t>(s[5])]);
            g(v, 3, 7, 11, 15, m[static_cast<std::size_t>(s[6])], m[static_cast<std::size_t>(s[7])]);
            g(v, 0, 5, 10, 15, m[static_cast<std::size_t>(s[8])], m[static_cast<std::size_t>(s[9])]);
            g(v, 1, 6, 11, 12, m[static_cast<std::size_t>(s[10])], m[static_cast<std::size_t>(s[11])]);
            g(v, 2, 7, 8, 13, m[static_cast<std::size_t>(s[12])], m[static_cast<std::size_t>(s[13])]);
            g(v, 3, 4, 9, 14, m[static_cast<std::size_t>(s[14])], m[static_cast<std::size_t>(s[15])]);
        }
        for (std::size_t i = 0; i < 8; ++i)
        {
            h[i] ^= v[i] ^ v[i + 8];
        }

        std::array<std::uint8_t, 32> out{};
        for (std::size_t i = 0; i < 8; ++i)
        {
            write_u32_le(out, i * 4, h[i]);
        }
        return out;
    }

    // ---------------------------------------------------------------------------
    // HxV4 index blob tag: Poly1305 over the encrypted payload (see crypto.hpp).
    // 32-bit limb arithmetic mirrors the verified Python reference
    // (test/verify_poly_tag.py, DLL sub_10021410 / sub_1001F510).
    // ---------------------------------------------------------------------------
    auto index_blob_tag(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 8> nonce, std::span<const std::uint8_t> encrypted_payload) -> std::array<std::uint8_t, 16>
    {
        // poly key = first 32 bytes of the chacha20 (djb) block 0.
        const chacha20 ch{ key, nonce, 0 };
        const auto block0 = ch.block(0);

        // DLL clamp (sub_1001F640): operate on 32-bit words first (matches the
        // Python reference exactly), then unpack into 5 x 26-bit limbs.
        std::uint32_t rw[4];
        rw[0] = read_u32_le(block0,  0) & 0x0fffffffu;
        rw[1] = read_u32_le(block0,  4) & 0x0ffffffcu;
        rw[2] = read_u32_le(block0,  8) & 0x0ffffffcu;
        rw[3] = read_u32_le(block0, 12) & 0x0ffffffcu;
        std::array<std::uint64_t, 5> r{};
        r[0] =  (rw[0]        ) & 0x03ffffffu;
        r[1] = ((rw[0] >> 26) | (static_cast<std::uint64_t>(rw[1]) <<  6)) & 0x03ffffffu;
        r[2] = ((rw[1] >> 20) | (static_cast<std::uint64_t>(rw[2]) << 12)) & 0x03ffffffu;
        r[3] = ((rw[2] >> 14) | (static_cast<std::uint64_t>(rw[3]) << 18)) & 0x03ffffffu;
        r[4] =  (rw[3] >>  8) & 0x00ffffffu;
        // s (poly pad) = block0[16:32], used as-is at the end (LE 128-bit add).
        const std::uint32_t s0 = read_u32_le(block0, 16);
        const std::uint32_t s1 = read_u32_le(block0, 20);
        const std::uint32_t s2 = read_u32_le(block0, 24);
        const std::uint32_t s3 = read_u32_le(block0, 28);

        // message stream = pad16(payload) || le64(0) || le64(len(payload)).
        // Every 16-byte window in this concatenated stream contributes +2^128
        // (see verify_poly_tag.py comment on the DLL's buffered update).
        std::vector<std::uint8_t> stream(encrypted_payload.begin(), encrypted_payload.end());
        stream.resize((stream.size() + 15) & ~static_cast<std::size_t>(15), 0);
        const auto plen = static_cast<std::uint64_t>(encrypted_payload.size());
        for (std::size_t i = 0; i < 8; ++i) stream.push_back(0);
        for (std::size_t i = 0; i < 8; ++i)
        {
            stream.push_back(static_cast<std::uint8_t>(plen >> (8 * i)));
        }

        std::array<std::uint64_t, 5> h{};
        std::uint64_t hr0 = r[0] * 5u, hr1 = r[1] * 5u, hr2 = r[2] * 5u, hr3 = r[3] * 5u, hr4 = r[4] * 5u;

        for (std::size_t off = 0; off < stream.size(); off += 16)
        {
            // Decode 16 LE bytes as 5 x 26-bit limbs, then OR the 2^128 bit.
            std::uint32_t w0 = read_u32_le(stream, off + 0);
            std::uint32_t w1 = read_u32_le(stream, off + 4);
            std::uint32_t w2 = read_u32_le(stream, off + 8);
            std::uint32_t w3 = read_u32_le(stream, off + 12);
            h[0] += (w0                        ) & 0x03ffffffu;
            h[1] += ((w0 >> 26) | (w1 <<  6))   & 0x03ffffffu;
            h[2] += ((w1 >> 20) | (w2 << 12))   & 0x03ffffffu;
            h[3] += ((w2 >> 14) | (w3 << 18))   & 0x03ffffffu;
            h[4] += ((w3 >>  8)                 & 0x03ffffffu) | (1u << 24); // +2^128

            // h = h * r   (schoolbook)
            std::uint64_t d0 = h[0]*r[0] + h[1]*hr4 + h[2]*hr3 + h[3]*hr2 + h[4]*hr1;
            std::uint64_t d1 = h[0]*r[1] + h[1]*r[0] + h[2]*hr4 + h[3]*hr3 + h[4]*hr2;
            std::uint64_t d2 = h[0]*r[2] + h[1]*r[1] + h[2]*r[0] + h[3]*hr4 + h[4]*hr3;
            std::uint64_t d3 = h[0]*r[3] + h[1]*r[2] + h[2]*r[1] + h[3]*r[0] + h[4]*hr4;
            std::uint64_t d4 = h[0]*r[4] + h[1]*r[3] + h[2]*r[2] + h[3]*r[1] + h[4]*r[0];
            // partial carry: each d[i] has extra bits, fold into i+1 via 26-bit slots.
            std::uint64_t c;
            c = (d0 >> 26); d0 &= 0x03ffffffu; d1 += c;
            c = (d1 >> 26); d1 &= 0x03ffffffu; d2 += c;
            c = (d2 >> 26); d2 &= 0x03ffffffu; d3 += c;
            c = (d3 >> 26); d3 &= 0x03ffffffu; d4 += c;
            c = (d4 >> 26); d4 &= 0x03ffffffu; d0 += c * 5u;
            c = (d0 >> 26); d0 &= 0x03ffffffu; d1 += c;
            h[0] = d0; h[1] = d1; h[2] = d2; h[3] = d3; h[4] = d4;
        }

        // Final full carry-reduce once, then compare + optional subtract.
        {
            std::uint64_t c = (h[0] >> 26); h[0] &= 0x03ffffffu; h[1] += c;
            c = (h[1] >> 26); h[1] &= 0x03ffffffu; h[2] += c;
            c = (h[2] >> 26); h[2] &= 0x03ffffffu; h[3] += c;
            c = (h[3] >> 26); h[3] &= 0x03ffffffu; h[4] += c;
            c = (h[4] >> 26); h[4] &= 0x03ffffffu; h[0] += c * 5u;
            c = (h[0] >> 26); h[0] &= 0x03ffffffu; h[1] += c;
        }

        // Subtract p = 2^130 - 5 if h >= p, producing a canonical < p.
        // p stored as 5 x 26-bit little-endian limbs; last limb holds the
        // two overflow bits (2^128, 2^129) minus the constant borrow.
        {
            constexpr std::uint64_t kP[5] = {
                0x03fffffbu, 0x03ffffffu, 0x03ffffffu, 0x03ffffffu, 0x04000000u
            };
            // Compare h vs kP lexicographically (ms limb first).  Equal also
            // triggers the subtract (h == p => 0 mod p).
            bool ge = true;
            for (int i = 4; i >= 0; --i)
            {
                if (h[i] != kP[i]) { ge = (h[i] > kP[i]); break; }
            }
            if (ge)
            {
                // h -= p with limb borrow propagation.
                std::uint64_t borrow = 0;
                for (int i = 0; i < 5; ++i)
                {
                    const std::uint64_t cur = h[i] - kP[i] - borrow;
                    h[i]   = cur & 0xFFFFFFFFFFFFFFFFu;            // keep full 64-bit
                    borrow = (h[i] >> 63) & 1u;                    // underflow => borrow 1
                    h[i]  &= 0x03ffffffu;                          // back to 26 bits
                }
            }
        }

        // Recombine 5x26 limbs back to 4x32 LE (bits 0..127, drop bit 128+).
        const std::uint32_t h0 = static_cast<std::uint32_t>((h[0] >>  0) | (h[1] << 26));
        const std::uint32_t h1 = static_cast<std::uint32_t>((h[1] >>  6) | (h[2] << 20));
        const std::uint32_t h2 = static_cast<std::uint32_t>((h[2] >> 12) | (h[3] << 14));
        const std::uint32_t h3 = static_cast<std::uint32_t>((h[3] >> 18) | (h[4] <<  8));

        // tag = (h + s) mod 2^128, LE.
        std::uint64_t carry;
        std::uint32_t o0, o1, o2, o3;
        carry = static_cast<std::uint64_t>(h0) + s0;                 o0 = static_cast<std::uint32_t>(carry); carry >>= 32;
        carry = carry + static_cast<std::uint64_t>(h1) + s1;         o1 = static_cast<std::uint32_t>(carry); carry >>= 32;
        carry = carry + static_cast<std::uint64_t>(h2) + s2;         o2 = static_cast<std::uint32_t>(carry); carry >>= 32;
        (void) (carry + static_cast<std::uint64_t>(h3) + s3);        o3 = static_cast<std::uint32_t>(carry + static_cast<std::uint64_t>(h3) + s3);

        std::array<std::uint8_t, 16> tag{};
        write_u32_le(tag, 0, o0);
        write_u32_le(tag, 4, o1);
        write_u32_le(tag, 8, o2);
        write_u32_le(tag, 12, o3);
        return tag;
    }

    auto dirhash(std::u16string_view path) -> std::array<std::uint8_t, 8>
    {
        const auto data = hash_input(path);
        const auto dh   = siphash24_empty(data);
        std::array<std::uint8_t, 8> out{};
        for (std::size_t i = 0; i < 8; ++i)
        {
            out[i] = static_cast<std::uint8_t>(dh >> (i * 8));
        }
        return out;
    }

    auto filehash(std::u16string_view name) -> std::array<std::uint8_t, 32>
    {
        return blake2s_256(hash_input(name));
    }
} // namespace krkr::crypto