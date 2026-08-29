#pragma once

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include <windows.h>

namespace krkr
{
    namespace detail
    {
        class exception
        {
        public:
            explicit exception(std::string message) :
                m_message{ std::move(message) }
            {
            }

            explicit exception(std::wstring message) :
                m_message{ std::move(message) }
            {
            }

            template<class T>
            requires std::same_as<T, std::string> || std::same_as<T, std::wstring>
            auto message() const -> const T*
            {
                return std::get_if<T>(&m_message);
            }

        private:
            std::variant<std::string, std::wstring> m_message;
        };

        [[noreturn]] inline void fail(const std::string_view message)
        {
            throw exception{ std::string{ message } };
        }

        [[noreturn]] inline void fail(const std::wstring_view message)
        {
            throw exception{ std::wstring{ message } };
        }
    } // namespace detail

    // ---- little-endian / big-endian readers -------------------------------------

    inline auto read_u16_le(std::span<const std::uint8_t> s, std::size_t off) -> std::uint16_t
    {
        return static_cast<std::uint16_t>(s[off] | (static_cast<std::uint32_t>(s[off + 1]) << 8));
    }

    inline auto read_u32_le(std::span<const std::uint8_t> s, std::size_t off) -> std::uint32_t
    {
        return static_cast<std::uint32_t>(s[off]) | (static_cast<std::uint32_t>(s[off + 1]) << 8) |
               (static_cast<std::uint32_t>(s[off + 2]) << 16) | (static_cast<std::uint32_t>(s[off + 3]) << 24);
    }

    inline auto read_u64_le(std::span<const std::uint8_t> s, std::size_t off) -> std::uint64_t
    {
        std::uint64_t v{};
        for (std::size_t i = 0; i < 8; ++i)
        {
            v |= static_cast<std::uint64_t>(s[off + i]) << (i * 8);
        }
        return v;
    }

    inline auto write_u16_le(std::span<std::uint8_t> dst, std::size_t off, std::uint16_t v) -> void
    {
        dst[off]     = static_cast<std::uint8_t>(v);
        dst[off + 1] = static_cast<std::uint8_t>(v >> 8);
    }

    inline auto write_u32_le(std::span<std::uint8_t> dst, std::size_t off, std::uint32_t v) -> void
    {
        for (std::size_t i = 0; i < 4; ++i)
        {
            dst[off + i] = static_cast<std::uint8_t>(v >> (i * 8));
        }
    }

    inline auto write_u64_le(std::span<std::uint8_t> dst, std::size_t off, std::uint64_t v) -> void
    {
        for (std::size_t i = 0; i < 8; ++i)
        {
            dst[off + i] = static_cast<std::uint8_t>(v >> (i * 8));
        }
    }

    inline auto write_u16_le(std::vector<std::uint8_t>& v, std::uint16_t x) -> void
    {
        v.push_back(static_cast<std::uint8_t>(x));
        v.push_back(static_cast<std::uint8_t>(x >> 8));
    }

    inline auto write_u32_le(std::vector<std::uint8_t>& v, std::uint32_t x) -> void
    {
        for (std::size_t i = 0; i < 4; ++i)
        {
            v.push_back(static_cast<std::uint8_t>(x >> (i * 8)));
        }
    }

    inline auto write_u64_le(std::vector<std::uint8_t>& v, std::uint64_t x) -> void
    {
        for (std::size_t i = 0; i < 8; ++i)
        {
            v.push_back(static_cast<std::uint8_t>(x >> (i * 8)));
        }
    }

    inline auto write_u64_be(std::vector<std::uint8_t>& v, std::uint64_t x) -> void
    {
        for (int i = 7; i >= 0; --i)
        {
            v.push_back(static_cast<std::uint8_t>(x >> (i * 8)));
        }
    }

    inline auto write_i32_be(std::vector<std::uint8_t>& v, std::int32_t x) -> void
    {
        v.push_back(static_cast<std::uint8_t>((static_cast<std::uint32_t>(x) >> 24) & 0xff));
        v.push_back(static_cast<std::uint8_t>((static_cast<std::uint32_t>(x) >> 16) & 0xff));
        v.push_back(static_cast<std::uint8_t>((static_cast<std::uint32_t>(x) >> 8) & 0xff));
        v.push_back(static_cast<std::uint8_t>(static_cast<std::uint32_t>(x) & 0xff));
    }

    inline auto write_i64_be(std::vector<std::uint8_t>& v, std::int64_t x) -> void
    {
        for (int i = 7; i >= 0; --i)
        {
            v.push_back(static_cast<std::uint8_t>((static_cast<std::uint64_t>(x) >> (i * 8)) & 0xff));
        }
    }

    // ---- UTF-16LE helpers --------------------------------------------------------

    inline auto to_utf16le(std::string_view text) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        for (char c : text)
        {
            const auto byte = static_cast<std::uint8_t>(c);
            out.push_back(byte);
            out.push_back(0);
        }
        return out;
    }

    inline auto from_utf16le(std::span<const std::uint8_t> s) -> std::string
    {
        std::string out;
        for (std::size_t i = 0; i + 1 < s.size() && i < s.size(); i += 2)
        {
            out.push_back(static_cast<char>(s[i]));
        }
        return out;
    }

    // ---- hex ---------------------------------------------------------------------

    inline auto to_hex(std::span<const std::uint8_t> s) -> std::string
    {
        constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(s.size() * 2);
        for (const auto byte : s)
        {
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0x0f]);
        }
        return out;
    }

    // Decodes hex into out; returns false on malformed input.
    inline auto from_hex(std::string_view hex, std::vector<std::uint8_t>& out) -> bool
    {
        auto value = [](char c) -> int
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }
            return -1;
        };
        out.clear();
        out.reserve(hex.size() / 2);
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            const int hi = value(hex[i]);
            const int lo = value(hex[i + 1]);
            if (hi < 0 || lo < 0)
            {
                return false;
            }
            out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        }
        return true;
    }

    inline auto parse_u64(std::string_view s, std::uint64_t& out) -> bool
    {
        if (s.empty())
        {
            return false;
        }
        const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), out, 0);
        return ec == std::errc{} && ptr == s.data() + s.size();
    }
} // namespace krkr