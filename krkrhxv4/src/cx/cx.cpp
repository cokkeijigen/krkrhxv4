#include "cx.hpp"

#include <memory>
#include <stdexcept>

namespace krkr::cx
{
    namespace
    {
        constexpr std::size_t k_limit = 0x80;

        auto pack(std::uint32_t lo, std::uint32_t hi) -> std::uint64_t
        {
            return static_cast<std::uint64_t>(lo) | (static_cast<std::uint64_t>(hi) << 32);
        }

        enum opcode : std::uint8_t
        {
            op_nop          = 0,
            op_retn         = 1,
            op_mov_edi_arg  = 2,
            op_push_ebx     = 3,
            op_pop_ebx      = 4,
            op_push_ecx     = 5,
            op_pop_ecx      = 6,
            op_mov_eax_ebx  = 7,
            op_mov_ebx_eax  = 8,
            op_mov_ecx_ebx  = 9,
            op_mov_eax_edi  = 10,
            op_mov_eax_ind  = 11,
            op_add_eax_ebx  = 12,
            op_sub_eax_ebx  = 13,
            op_imul_eax_ebx = 14,
            op_and_ecx_0f   = 15,
            op_shr_ebx_1    = 16,
            op_shl_eax_1    = 17,
            op_shr_eax_cl   = 18,
            op_shl_eax_cl   = 19,
            op_or_eax_ebx   = 20,
            op_not_eax      = 21,
            op_neg_eax      = 22,
            op_dec_eax      = 23,
            op_inc_eax      = 24,
            op_mov_eax_imm  = 25,
            op_and_ebx_imm  = 26,
            op_and_eax_imm  = 27,
            op_xor_eax_imm  = 28,
            op_add_eax_imm  = 29,
            op_sub_eax_imm  = 30,
        };

        auto is_immed_op(opcode bc) -> bool
        {
            return bc == op_mov_eax_imm || bc == op_and_ebx_imm || bc == op_and_eax_imm ||
                   bc == op_xor_eax_imm || bc == op_add_eax_imm || bc == op_sub_eax_imm;
        }

        // Splittable random (the basis of the HX RNG).
        struct splittable_random
        {
            std::uint64_t seed{};
            auto next() -> std::uint64_t
            {
                seed = seed + 0x9e3779b97f4a7c15ull;
                std::uint64_t z = seed;
                z ^= z >> 30;
                z *= 0xbf58476d1ce4e5b9ull;
                z ^= z >> 27;
                z *= 0x94d049bb133111ebull;
                z ^= z >> 31;
                return z;
            }
        };

        auto lo32(std::uint64_t v) -> std::uint32_t { return static_cast<std::uint32_t>(v); }
        auto hi32(std::uint64_t v) -> std::uint32_t { return static_cast<std::uint32_t>(v >> 32); }

        auto hx_old_random(std::array<std::uint64_t, 2>& s) -> std::uint64_t
        {
            const std::uint64_t a = s[0];
            const std::uint64_t b = s[1];

            const std::uint64_t c = pack(hi32(a) ^ hi32(b), lo32(a) ^ lo32(b));
            const std::uint64_t e = pack(hi32(c), lo32(c));

            std::uint64_t t0 = (static_cast<std::uint64_t>(hi32(c))) << 21;
            t0 ^= a >> 15;
            t0 ^= hi32(c);
            const std::uint32_t seed0_lo = static_cast<std::uint32_t>(t0);

            t0  = static_cast<std::uint64_t>(hi32(a) >> 15);
            t0 |= static_cast<std::uint64_t>(lo32(a)) << 17;
            t0 ^= e >> 11;
            t0 ^= lo32(c);
            const std::uint32_t seed0_hi = static_cast<std::uint32_t>(t0);

            const std::uint32_t seed1_hi = static_cast<std::uint32_t>(e >> 4);
            const std::uint32_t seed1_lo = static_cast<std::uint32_t>(c >> 4);

            s[0] = pack(seed0_lo, seed0_hi);
            s[1] = pack(seed1_lo, seed1_hi);

            const std::uint64_t d = a + b;
            t0 = d << 17;
            t0 |= static_cast<std::uint64_t>(hi32(d) >> 15);
            return t0 + a;
        }

        auto hx_new_random(std::array<std::uint64_t, 2>& s) -> std::uint64_t
        {
            const std::uint64_t a = s[0];
            const std::uint64_t b = s[1];

            const std::uint64_t c = pack(lo32(a) ^ lo32(b), hi32(a) ^ hi32(b));

            std::uint64_t t0 = (static_cast<std::uint64_t>(lo32(a))) << 24;
            t0 |= static_cast<std::uint64_t>(hi32(a) >> 8);
            t0 ^= static_cast<std::uint64_t>(lo32(c)) << 16;
            t0 ^= lo32(c);
            const std::uint32_t seed0_lo = static_cast<std::uint32_t>(t0);

            t0  = c >> 16;
            t0 ^= a >> 8;
            t0 ^= hi32(c);
            const std::uint32_t seed0_hi = static_cast<std::uint32_t>(t0);

            t0  = static_cast<std::uint64_t>(hi32(c) >> 27);
            t0 |= static_cast<std::uint64_t>(lo32(c)) << 5;
            const std::uint32_t seed1_hi = static_cast<std::uint32_t>(t0);
            const std::uint32_t seed1_lo = static_cast<std::uint32_t>(c >> 27);

            s[0] = pack(seed0_lo, seed0_hi);
            s[1] = pack(seed1_lo, seed1_hi);

            const std::uint64_t d = static_cast<std::uint64_t>(5) * a;
            t0 = static_cast<std::uint64_t>(hi32(d) >> 25);
            t0 |= d << 7;
            return t0 * 9;
        }
    } // namespace

    // ---------------------------------------------------------------------------
    // HX bytecode program.
    // ---------------------------------------------------------------------------
    class cipher::program
    {
    public:
        program(std::uint32_t seed, int method, const std::vector<std::uint32_t>& cb)
            : m_cb{ cb }
        {
            m_method = method;
            const std::uint32_t split_hi = ~seed;
            const std::uint64_t split_seed = static_cast<std::uint64_t>(seed) | (static_cast<std::uint64_t>(split_hi) << 32);
            splittable_random rng{ split_seed };
            m_seeds[0] = rng.next();
            m_seeds[1] = rng.next();
        }

        auto execute(std::uint32_t hash) -> std::uint32_t
        {
            std::uint32_t eax = 0, ebx = 0, ecx = 0, edi = 0;
            std::vector<std::uint32_t> stack;
            stack.reserve(8);

            std::size_t i = 0;
            while (i < m_code.size())
            {
                if (m_code[i].is_immed)
                {
                    krkr::detail::fail("unexpected immediate bytecode");
                }
                const auto bc = static_cast<opcode>(m_code[i].code);
                ++i;

                std::uint32_t immed = 0;
                if (is_immed_op(bc))
                {
                    if (i >= m_code.size() || !m_code[i].is_immed)
                    {
                        krkr::detail::fail("incomplete immediate bytecode");
                    }
                    immed = m_code[i].immed;
                    ++i;
                }

                switch (bc)
                {
                case op_nop: break;
                case op_mov_edi_arg: edi = hash; break;
                case op_push_ebx: stack.push_back(ebx); break;
                case op_pop_ebx:
                {
                    if (stack.empty())
                    {
                        krkr::detail::fail("imbalanced stack");
                    }
                    ebx = stack.back();
                    stack.pop_back();
                    break;
                }
                case op_push_ecx: stack.push_back(ecx); break;
                case op_pop_ecx:
                {
                    if (stack.empty())
                    {
                        krkr::detail::fail("imbalanced stack");
                    }
                    ecx = stack.back();
                    stack.pop_back();
                    break;
                }
                case op_mov_ebx_eax: ebx = eax; break;
                case op_mov_eax_edi: eax = edi; break;
                case op_mov_ecx_ebx: ecx = ebx; break;
                case op_mov_eax_ebx: eax = ebx; break;
                case op_and_ecx_0f: ecx &= 0x0f; break;
                case op_shr_ebx_1: ebx >>= 1; break;
                case op_shl_eax_1: eax <<= 1; break;
                case op_shr_eax_cl: eax >>= (ecx & 31); break;
                case op_shl_eax_cl: eax <<= (ecx & 31); break;
                case op_or_eax_ebx: eax |= ebx; break;
                case op_not_eax: eax = ~eax; break;
                case op_neg_eax: eax = 0u - eax; break;
                case op_dec_eax: --eax; break;
                case op_inc_eax: ++eax; break;
                case op_mov_eax_ind:
                    if (eax >= m_cb.size())
                    {
                        krkr::detail::fail("control block index out of bounds");
                    }
                    eax = ~m_cb[eax];
                    break;
                case op_add_eax_ebx: eax += ebx; break;
                case op_sub_eax_ebx: eax -= ebx; break;
                case op_imul_eax_ebx: eax *= ebx; break;
                case op_add_eax_imm: eax += immed; break;
                case op_sub_eax_imm: eax -= immed; break;
                case op_and_ebx_imm: ebx &= immed; break;
                case op_and_eax_imm: eax &= immed; break;
                case op_xor_eax_imm: eax ^= immed; break;
                case op_mov_eax_imm: eax = immed; break;
                case op_retn:
                    if (!stack.empty())
                    {
                        krkr::detail::fail("imbalanced stack");
                    }
                    return eax;
                }
            }
            krkr::detail::fail("program without return");
        }

        auto get_random() -> std::uint32_t
        {
            if (m_method == 0)
            {
                return static_cast<std::uint32_t>(hx_old_random(m_seeds));
            }
            return static_cast<std::uint32_t>(hx_new_random(m_seeds));
        }

        auto emit(opcode bc, std::size_t length) -> bool
        {
            if (m_length + length > k_limit)
            {
                return false;
            }
            m_length += length;
            ins e{};
            e.code    = static_cast<std::uint8_t>(bc);
            e.is_immed = false;
            m_code.push_back(e);
            return true;
        }

        auto emit_nop(std::size_t count) -> bool
        {
            if (m_length + count > k_limit)
            {
                return false;
            }
            m_length += count;
            return true;
        }

        auto emit_u32(std::uint32_t value) -> bool
        {
            if (m_length + 4 > k_limit)
            {
                return false;
            }
            m_length += 4;
            ins e{};
            e.immed    = value;
            e.is_immed = true;
            m_code.push_back(e);
            return true;
        }

        auto emit_random() -> bool { return emit_u32(get_random()); }

        auto clear() -> void
        {
            m_length = 0;
            m_code.clear();
        }

    private:
        struct ins
        {
            std::uint8_t  code     = 0;
            std::uint32_t immed    = 0;
            bool is_immed = false;
        };

        const std::vector<std::uint32_t>& m_cb;
        std::vector<ins>         m_code;
        std::size_t              m_length = 0;
        int                      m_method = 0;
        std::array<std::uint64_t, 2>       m_seeds{};
    };

    // ---------------------------------------------------------------------------
    // cipher.
    // ---------------------------------------------------------------------------
    cipher::~cipher() = default;

    cipher::cipher(scheme sch)
        : m_scheme{ std::move(sch) }
    {
        if (m_scheme.control_block.size() < 0x400)
        {
            krkr::detail::fail("CX control block is too small");
        }
    }

    auto cipher::generate_program(std::uint32_t seed) -> std::unique_ptr<program>
    {
        // The random state must persist across stage retries (clear() only resets
        // the emitted code), otherwise the generated bytecode diverges from the
        // reference implementation and the CX key stream is wrong.
        auto p = std::make_unique<program>(seed, m_scheme.random_type, m_scheme.control_block);
        for (int stage = 5; stage >= 1; --stage)
        {
            p->clear();
            if (emit_code(*p, stage))
            {
                return p;
            }
        }
        krkr::detail::fail("overly large CX bytecode");
    }

    auto cipher::emit_code(program& p, int stage) const -> bool
    {
        return p.emit_nop(5) && p.emit(op_mov_edi_arg, 4) && emit_body(p, stage) &&
               p.emit_nop(5) && p.emit(op_retn, 1);
    }

    auto cipher::emit_body(program& p, int stage) const -> bool
    {
        if (stage == 1)
        {
            return emit_prolog(p);
        }
        if (!p.emit(op_push_ebx, 1))
        {
            return false;
        }
        if (p.get_random() & 1)
        {
            if (!emit_body(p, stage - 1))
            {
                return false;
            }
        }
        else if (!emit_body2(p, stage - 1))
        {
            return false;
        }
        if (!p.emit(op_mov_ebx_eax, 2))
        {
            return false;
        }
        if (p.get_random() & 1)
        {
            if (!emit_body(p, stage - 1))
            {
                return false;
            }
        }
        else if (!emit_body2(p, stage - 1))
        {
            return false;
        }
        return emit_odd_branch(p) && p.emit(op_pop_ebx, 1);
    }

    auto cipher::emit_body2(program& p, int stage) const -> bool
    {
        if (stage == 1)
        {
            return emit_prolog(p);
        }
        const bool rc = (p.get_random() & 1) ? emit_body(p, stage - 1) : emit_body2(p, stage - 1);
        return rc && emit_even_branch(p);
    }

    auto cipher::emit_prolog(program& p) const -> bool
    {
        const int choice = m_scheme.prolog_order[static_cast<std::size_t>(p.get_random() % 3)];
        switch (choice)
        {
        case 2:
            return p.emit_nop(5) && p.emit(op_mov_eax_imm, 2) && p.emit_u32(p.get_random() & 0x3ff) &&
                   p.emit(op_mov_eax_ind, 0);
        case 1:
            return p.emit(op_mov_eax_edi, 2);
        case 0:
            return p.emit(op_mov_eax_imm, 1) && p.emit_random();
        default:
            return false;
        }
    }

    auto cipher::emit_even_branch(program& p) const -> bool
    {
        const int choice = m_scheme.even_branch_order[static_cast<std::size_t>(p.get_random() & 7)];
        switch (choice)
        {
        case 0: return p.emit(op_not_eax, 2);
        case 1: return p.emit(op_dec_eax, 1);
        case 2: return p.emit(op_neg_eax, 2);
        case 3: return p.emit(op_inc_eax, 1);
        case 4:
            return p.emit_nop(5) && p.emit(op_and_eax_imm, 1) && p.emit_u32(0x3ff) &&
                   p.emit(op_mov_eax_ind, 3);
        case 5:
            return p.emit(op_push_ebx, 1) && p.emit(op_mov_ebx_eax, 2) && p.emit(op_and_ebx_imm, 2) &&
                   p.emit_u32(0xaaaaaaaau) && p.emit(op_and_eax_imm, 1) && p.emit_u32(0x55555555u) &&
                   p.emit(op_shr_ebx_1, 2) && p.emit(op_shl_eax_1, 2) && p.emit(op_or_eax_ebx, 2) &&
                   p.emit(op_pop_ebx, 1);
        case 6:
            return p.emit(op_xor_eax_imm, 1) && p.emit_random();
        case 7:
        {
            const bool ok = (p.get_random() & 1) ? p.emit(op_add_eax_imm, 1) : p.emit(op_sub_eax_imm, 1);
            return ok && p.emit_random();
        }
        default:
            return false;
        }
    }

    auto cipher::emit_odd_branch(program& p) const -> bool
    {
        const int choice = m_scheme.odd_branch_order[static_cast<std::size_t>(p.get_random() % 6)];
        switch (choice)
        {
        case 0:
            return p.emit(op_push_ecx, 1) && p.emit(op_mov_ecx_ebx, 2) && p.emit(op_and_ecx_0f, 3) &&
                   p.emit(op_shr_eax_cl, 2) && p.emit(op_pop_ecx, 1);
        case 1:
            return p.emit(op_push_ecx, 1) && p.emit(op_mov_ecx_ebx, 2) && p.emit(op_and_ecx_0f, 3) &&
                   p.emit(op_shl_eax_cl, 2) && p.emit(op_pop_ecx, 1);
        case 2: return p.emit(op_add_eax_ebx, 2);
        case 3: return p.emit(op_neg_eax, 2) && p.emit(op_add_eax_ebx, 2);
        case 4: return p.emit(op_imul_eax_ebx, 3);
        case 5: return p.emit(op_sub_eax_ebx, 2);
        default: return false;
        }
    }

    auto cipher::execute_xcode(std::uint32_t hash) -> std::pair<std::uint32_t, std::uint32_t>
    {
        const std::uint32_t seed = hash & 0x7f;
        if (!m_programs[seed])
        {
            m_programs[seed] = generate_program(seed);
        }
        const std::uint32_t h = hash >> 7;
        const std::uint32_t ret1 = m_programs[seed]->execute(h);
        const std::uint32_t ret2 = m_programs[seed]->execute(~h);
        return { ret1, ret2 };
    }

    auto cipher::decode(std::uint32_t key, std::uint64_t offset, std::span<std::uint8_t> data) -> void
    {
        const auto [r1, r2] = execute_xcode(key);
        std::uint64_t key1 = (r2 >> 16) & 0xffff;
        std::uint64_t key2 = r2 & 0xffff;
        std::uint8_t  key3 = static_cast<std::uint8_t>(r1 & 0xff);
        if (key1 == key2)
        {
            key2 = (key2 + 1) & 0xffff;
        }
        if (key3 == 0)
        {
            key3 = 1;
        }

        const std::uint64_t end = offset + data.size();
        if (key2 >= offset && key2 < end)
        {
            data[static_cast<std::size_t>(key2 - offset)] ^= static_cast<std::uint8_t>((r1 >> 16) & 0xff);
        }
        if (key1 >= offset && key1 < end)
        {
            data[static_cast<std::size_t>(key1 - offset)] ^= static_cast<std::uint8_t>((r1 >> 8) & 0xff);
        }
        for (auto& b : data)
        {
            b ^= key3;
        }
    }

    auto cipher::crypt(std::uint64_t hash, std::uint64_t offset, std::span<std::uint8_t> data) -> void
    {
        const std::uint64_t base = get_base_offset(static_cast<std::uint32_t>(hash));
        std::uint64_t       off  = offset;
        std::uint64_t       buffer_off = 0;

        if (off < base)
        {
            const auto count = static_cast<std::size_t>((base - off) < data.size() ? (base - off) : data.size());
            decode(static_cast<std::uint32_t>(hash), off, data.subspan(0, count));
            off += count;
            buffer_off += count;
        }
        if (buffer_off < data.size())
        {
            const std::uint32_t key2 = (static_cast<std::uint32_t>(hash) >> 16) ^ static_cast<std::uint32_t>(hash);
            decode(key2, off, data.subspan(buffer_off));
        }
    }

    auto cipher::derive(std::uint64_t entry_key, std::uint64_t entry_id) -> filter_key
    {
        filter_key out{};

        std::uint64_t k = entry_key;
        if ((entry_id & 0x100000000ull) == 0)
        {
            k ^= m_scheme.filter_key;
        }
        const std::uint64_t seed = ~k;

        const auto [k0lo, k0hi] = execute_xcode(static_cast<std::uint32_t>(k & 0xffffffff));
        out.span[0]             = pack(k0lo, k0hi);
        const auto [k1lo, k1hi] = execute_xcode(static_cast<std::uint32_t>((k >> 32) & 0xffffffff));
        out.span[1]             = pack(k1lo, k1hi);

        out.split_pos = m_scheme.offset + ((static_cast<std::uint32_t>(k >> 16)) & m_scheme.mask);

        auto [k3lo, k3hi] = execute_xcode(static_cast<std::uint32_t>(seed & 0xffffffff));
        std::uint64_t v             = ~pack(k3lo, k3hi);
        for (int i = 0; i < 8; ++i)
        {
            out.header[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (56 - i * 8));
        }

        const auto [k4lo, k4hi] = execute_xcode(static_cast<std::uint32_t>(v & 0xffffffff));
        v                       = ~pack(k4lo, k4hi);
        for (int i = 0; i < 8; ++i)
        {
            out.header[static_cast<std::size_t>(i + 8)] = static_cast<std::uint8_t>(v >> (56 - i * 8));
        }

        return out;
    }

    auto cipher::content_crypt(const filter_key& key, std::span<std::uint8_t> data) -> void
    {
        const auto n     = data.size();
        const auto hdr   = n < 16 ? n : 16;
        for (std::size_t i = 0; i < hdr; ++i)
        {
            data[i] ^= key.header[i];
        }

        const std::size_t split = key.split_pos;
        auto span_crypt = [](std::uint64_t span_key, std::span<std::uint8_t> dst, std::uint64_t offset) -> void
        {
            std::uint32_t deckey  = static_cast<std::uint32_t>(((span_key >> 8) & 0xff) | ((span_key >> 8) & 0xff00));
            std::uint64_t p0      = (span_key >> 48) & 0xffff;
            std::uint64_t p1      = (span_key >> 32) & 0xffff;
            std::uint32_t first   = static_cast<std::uint32_t>(span_key & 0xff);
            if (p0 == p1)
            {
                p1 = p1 + 1;
            }
            if (first == 0)
            {
                first = 0xa5;
            }
            first *= 0x01010101;

            const std::uint8_t first_bytes[4] = { static_cast<std::uint8_t>(first), static_cast<std::uint8_t>(first >> 8), static_cast<std::uint8_t>(first >> 16), static_cast<std::uint8_t>(first >> 24) };
            for (std::size_t i = 0; i < dst.size(); ++i)
            {
                dst[i] ^= first_bytes[i & 3];
            }

            const std::uint64_t positions[2] = { p0, p1 };
            const std::uint8_t  keys[2]      = { static_cast<std::uint8_t>(deckey & 0xff), static_cast<std::uint8_t>((deckey >> 8) & 0xff) };
            for (int i = 0; i < 2; ++i)
            {
                const std::uint64_t pos = positions[static_cast<std::size_t>(i)];
                if (pos >= offset && pos - offset < dst.size())
                {
                    dst[static_cast<std::size_t>(pos - offset)] ^= keys[static_cast<std::size_t>(i)];
                }
            }
        };

        if (split < n)
        {
            span_crypt(key.span[0], data.first(split), 0);
            span_crypt(key.span[1], data.subspan(split), split);
        }
        else
        {
            span_crypt(key.span[0], data, 0);
        }
    }
} // namespace krkr::cx