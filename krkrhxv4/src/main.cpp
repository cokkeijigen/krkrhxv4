#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

#include <common.hpp>
#include <console.hpp>
#include <cx/cx.hpp>
#include <crypto/crypto.hpp>
#include <xp3/xp3.hpp>

// Global singleton backing console.hpp's `extern helper_t helper;`.
// Must live at namespace scope exactly once (mirrors MesTextTool_V3 layout).
console::helper_t console::helper{ L"krkrhxv4 - KiriKiri HxV4 xp3 pack/unpack tool" };

namespace krkrhxv4
{
    inline constexpr std::string_view k_usage
    {
        "krkrhxv4 - KiriKiri HxV4 xp3 pack/unpack tool\n"
        "\n"
        "USAGE:\n"
        "  krkrhxv4 unpack <in.xp3> --parampath key.ini --blockpath control_block.bin \\\n"
        "                          -o <outdir> [--namestyle name|hash]\n"
        "  krkrhxv4 pack <manifest> -o <outdir> --out out.xp3\n"
        "  krkrhxv4 packdir <indir> --parampath key.ini --blockpath control_block.bin \\\n"
        "                          --out out.xp3\n"
        "\n"
        "key.ini format (key=value lines, #/; comments ignored):\n"
        "  key       = <32 bytes hex>   ChaCha20 index key (frida derived_key)\n"
        "  nonce     = <16 bytes hex>   nonce buffer (first 8 bytes = nonce8)\n"
        "  filterkey = <8 bytes hex>    CX content cipher filter key\n"
        "  mask      = 0xNNN            HxFilter base offset mask (hash&mask)\n"
        "  offset    = 0xNNN            HxFilter base offset addend\n"
        "  randtype  = 0|1              CX RNG variant (0 = old, 1 = new)\n"
        "  order     = 17 space-separated hex bytes: CX VM execution order\n"
        "  verify    = <32 bytes hex>   (optional, external tools only)\n"
        "\n"
        "control_block.bin is the 4096-byte CX VM bytecode table (per-game static\n"
        "blob, bitwise-not inverted on load).  It cannot be derived from key.ini.\n"
    };

    // Return a trimmed sub-view of `s` with leading / trailing ASCII whitespace
    // (spaces / tabs / CR / LF) dropped.  Byte-offset view so it keeps working
    // on raw UTF-8 / ASCII INI content without allocation.
    static auto trim_ascii_ws(std::string_view s) -> std::string_view
    {
        std::size_t l = 0;
        std::size_t r = s.size();
        while (l < r && (s[l] == ' ' || s[l] == '\t' || s[l] == '\r' || s[l] == '\n'))
        {
            ++l;
        }
        while (r > l && (s[r - 1] == ' ' || s[r - 1] == '\t' || s[r - 1] == '\r' || s[r - 1] == '\n'))
        {
            --r;
        }
        return s.substr(l, r - l);
    }

    // ASCII case-insensitive equality on two byte strings.  INI section / key
    // names are guaranteed ASCII by the tool's schema; this avoids any
    // wide/UTF conversion and is free of C locale side effects.
    static auto ascii_iequals(std::string_view a, std::string_view b) -> bool
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            const unsigned char ca = static_cast<unsigned char>(a[i]);
            const unsigned char cb = static_cast<unsigned char>(b[i]);
            const unsigned char la = (ca >= 'A' && ca <= 'Z') ? static_cast<unsigned char>(ca + ('a' - 'A')) : ca;
            const unsigned char lb = (cb >= 'A' && cb <= 'Z') ? static_cast<unsigned char>(cb + ('a' - 'A')) : cb;
            if (la != lb)
            {
                return false;
            }
        }
        return true;
    }

    // Truncate an ASCII-only wchar_t literal (section / key identifiers used
    // by this tool) to a stack-allocated narrow string_view for byte-level
    // matching.  Non-ASCII code units in the input are rejected via fail.
    static auto ascii_wlit(const wchar_t* s) -> std::string
    {
        std::string out{};
        for (; *s; ++s)
        {
            const unsigned int c = static_cast<unsigned int>(*s);
            if (c > 0x7F)
            {
                krkr::detail::fail("internal: ini identifier contains non-ASCII character");
            }
            out.push_back(static_cast<char>(c));
        }
        return out;
    }

    static auto get_ini_string(const std::filesystem::path& ini, const wchar_t* section, const wchar_t* key, bool required) -> std::optional<std::string>
    {
        const auto raw = krkr::xp3::read_file(ini);
        std::string_view bytes{ reinterpret_cast<const char*>(raw.data()), raw.size() };

        // Optional UTF-8 BOM (EF BB BF).  Matches the tolerant behaviour of
        // most INI readers and editors that save files as UTF-8 with BOM.
        if (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xEF &&
            static_cast<unsigned char>(bytes[1]) == 0xBB && static_cast<unsigned char>(bytes[2]) == 0xBF)
        {
            bytes.remove_prefix(3);
        }

        // Lookup identifiers narrowed once at the top: they are schema-defined
        // ASCII literals, so converting them is safe and cheap.  The actual
        // file content (values, line bytes) stays in the original encoding
        // end-to-end -- no widening round-trips are performed on the data.
        const std::string sec_name = ascii_wlit(section);
        const std::string key_name = ascii_wlit(key);

        std::optional<std::string> found{};
        bool in_target_section = (sec_name.empty());

        std::size_t pos = 0;
        while (pos < bytes.size())
        {
            std::size_t end = pos;
            while (end < bytes.size() && bytes[end] != '\r' && bytes[end] != '\n')
            {
                ++end;
            }
            const std::string_view raw_line = bytes.substr(pos, end - pos);
            if (end < bytes.size() && bytes[end] == '\r')
            {
                ++end;
            }
            if (end < bytes.size() && bytes[end] == '\n')
            {
                ++end;
            }
            pos = end;

            const std::string_view line = trim_ascii_ws(raw_line);
            if (line.empty())
            {
                continue;
            }
            if (line.front() == ';' || line.front() == '#')
            {
                continue;
            }

            if (line.front() == '[')
            {
                const auto close = line.find(']');
                if (close != std::string_view::npos)
                {
                    const std::string_view name = trim_ascii_ws(line.substr(1, close - 1));
                    in_target_section = ascii_iequals(name, std::string_view{ sec_name });
                }
                continue;
            }

            if (!in_target_section)
            {
                continue;
            }

            const auto eq = line.find('=');
            if (eq == std::string_view::npos)
            {
                continue;
            }
            const std::string_view k = trim_ascii_ws(line.substr(0, eq));
            if (!ascii_iequals(k, std::string_view{ key_name }))
            {
                continue;
            }
            const std::string_view v = trim_ascii_ws(line.substr(eq + 1));
            found = std::string{ v };
            // Later duplicates override earlier ones, matching the
            // documented precedence of GetPrivateProfileStringW for reads.
        }

        if (!found.has_value())
        {
            if (required)
            {
                krkr::detail::fail(std::wstring{ L"ini missing required key: [" } + section + L"]." + key);
            }
            return std::nullopt;
        }
        if (found->size() >= 4093)
        {
            krkr::detail::fail(std::wstring{ L"ini value too long: [" } + section + L"]." + key);
        }
        return found;
    }

    static constexpr const wchar_t* k_section_hxv4 = L"hxv4";

    auto load_params_ini(krkr::xp3::params& params, const std::filesystem::path& path) -> void
    {
        if (!std::filesystem::exists(path))
        {
            krkr::detail::fail("cannot open param file: " + path.generic_string());
        }

        // ---- required hex blobs ----
        const auto key_str = get_ini_string(path, k_section_hxv4, L"key", true).value();
        {
            std::vector<std::uint8_t> hex{};
            if (!krkr::from_hex(key_str, hex) || hex.size() != 32)
            {
                krkr::detail::fail("ini [hxv4].key must be 32 bytes hexadecimal");
            }
            std::copy_n(hex.begin(), 32, params.index_key.begin());
        }

        const auto nonce_str = get_ini_string(path, k_section_hxv4, L"nonce", true).value();
        {
            std::vector<std::uint8_t> hex{};
            if (!krkr::from_hex(nonce_str, hex) || hex.size() != 16)
            {
                krkr::detail::fail("ini [hxv4].nonce must be 16 bytes hexadecimal");
            }
            std::copy_n(hex.begin(), 16, params.index_nonce.begin());
        }

        const auto fk_str = get_ini_string(path, k_section_hxv4, L"filterkey", true).value();
        {
            std::vector<std::uint8_t> hex{};
            if (!krkr::from_hex(fk_str, hex) || hex.size() != 8)
            {
                krkr::detail::fail("ini [hxv4].filterkey must be 8 bytes hexadecimal");
            }
            std::uint64_t value{};
            for (std::size_t i = 0; i < 8; ++i)
            {
                value |= static_cast<std::uint64_t>(hex[i]) << (i * 8);
            }
            params.cx.filter_key = value;
        }

        // ---- required numeric fields (stoul base-0: supports 0x.. and decimal) ----
        const auto mask_str = get_ini_string(path, k_section_hxv4, L"mask", true).value();
        params.cx.mask = static_cast<std::uint32_t>(std::stoul(mask_str, nullptr, 0));

        const auto off_str = get_ini_string(path, k_section_hxv4, L"offset", true).value();
        params.cx.offset = static_cast<std::uint32_t>(std::stoul(off_str, nullptr, 0));

        const auto rt_str = get_ini_string(path, k_section_hxv4, L"randtype", true).value();
        params.cx.random_type = std::stoi(rt_str);

        // ---- required 17-byte execution order ----
        const auto order_str = get_ini_string(path, k_section_hxv4, L"order", true).value();
        std::array<std::uint8_t, 17> order{};
        {
            std::vector<std::string> tokens;
            std::stringstream       ss{ order_str };
            for (std::string token; ss >> token;)
            {
                tokens.push_back(token);
            }
            if (tokens.size() != 17)
            {
                krkr::detail::fail("ini [hxv4].order must contain 17 space-separated hex bytes");
            }
            for (std::size_t i = 0; i < 17; ++i)
            {
                order[i] = static_cast<std::uint8_t>(std::stoul(tokens[i], nullptr, 16));
            }
        }

        // Derive GARbro-compatible branch orders from the raw 17-byte
        // execution order (mirrors krkr_hxv4_dumpkey.js).
        constexpr std::uint8_t k_s3[3] = { 0, 1, 2 };
        constexpr std::uint8_t k_s6[6] = { 2, 5, 3, 4, 1, 0 };
        constexpr std::uint8_t k_s8[8] = { 0, 2, 3, 1, 5, 6, 7, 4 };

        std::array<int, 3> o3{ 0, 1, 2 };
        std::array<int, 6> o6{ 0, 1, 2, 3, 4, 5 };
        std::array<int, 8> o8{ 0, 1, 2, 3, 4, 5, 6, 7 };

        for (int i = 0; i < 3; ++i)
        {
            o3[order[static_cast<std::size_t>(14 + i)]] = k_s3[static_cast<std::size_t>(i)];
        }
        for (int i = 0; i < 6; ++i)
        {
            o6[order[static_cast<std::size_t>(8 + i)]] = k_s6[static_cast<std::size_t>(i)];
        }
        for (int i = 0; i < 8; ++i)
        {
            o8[order[static_cast<std::size_t>(i)]] = k_s8[static_cast<std::size_t>(i)];
        }

        std::copy_n(o3.begin(), 3, params.cx.prolog_order.begin());
        std::copy_n(o6.begin(), 6, params.cx.odd_branch_order.begin());
        std::copy_n(o8.begin(), 8, params.cx.even_branch_order.begin());
    }

    auto load_control_block(std::vector<std::uint32_t>& block, const std::filesystem::path& path) -> void
    {
        const auto bytes{ krkr::xp3::read_file(path) };
        if (bytes.size() != 4096)
        {
            krkr::detail::fail("control block must be exactly 4096 bytes");
        }

        block.resize(1024);
        for (std::size_t i = 0; i < 1024; ++i)
        {
            block[i] = ~krkr::read_u32_le(bytes, i * 4);
        }
    }

    auto run_unpack(const int argc, const wchar_t* const argv[]) -> int
    {
        if (argc < 3)
        {
            console::helper.writeline(k_usage);
            return 1;
        }
        const std::filesystem::path inpath{ argv[1] };

        std::filesystem::path outdir{ L"out" };
        std::filesystem::path parampath{};
        std::filesystem::path blockpath{};
        bool hash_names{ false };

        for (int i = 2; i < argc; ++i)
        {
            const std::wstring_view arg{ argv[i] };
            const auto value = [&]() -> std::wstring_view
            {
                return (i + 1 < argc) ? std::wstring_view{ argv[++i] } : std::wstring_view{};
            };

            if (arg == L"-o")
            {
                outdir = std::filesystem::path{ value() };
            }
            else if (arg == L"--parampath")
            {
                parampath = std::filesystem::path{ value() };
            }
            else if (arg == L"--blockpath")
            {
                blockpath = std::filesystem::path{ value() };
            }
            else if (arg == L"--namestyle")
            {
                hash_names = (value() == L"hash");
            }
        }

        krkr::xp3::params params{};
        if (!parampath.empty())
        {
            load_params_ini(params, parampath);
        }
        if (!blockpath.empty())
        {
            load_control_block(params.cx.control_block, blockpath);
        }
        if (params.cx.control_block.empty())
        {
            krkr::detail::fail("control block required");
        }

        const auto unpack_in_line{ std::string{ "[unpack] " } + inpath.generic_string() };
        console::helper.writeline(unpack_in_line);
        const auto manifest{ krkr::xp3::unpack(inpath, outdir, params, hash_names) };

        auto manifest_path{ outdir };
        manifest_path /= ".manifest";
        krkr::xp3::save_manifest(manifest, manifest_path);

        const auto unpack_tail_line
        {
            std::string{ "[unpack] " } + std::to_string(manifest.files.size()) + " file(s) -> " + outdir.generic_string() +
            "\n[unpack] manifest -> " + manifest_path.generic_string()
        };
        console::helper.writeline(unpack_tail_line);
        return 0;
    }

    auto run_pack(const int argc, const wchar_t* const argv[]) -> int
    {
        if (argc < 3)
        {
            console::helper.writeline(k_usage);
            return 1;
        }
        const std::filesystem::path manifest_path{ argv[1] };

        std::filesystem::path outdir{ L"out" };
        std::filesystem::path outpath{};

        for (int i = 2; i < argc; ++i)
        {
            const std::wstring_view arg{ argv[i] };
            const auto value = [&]() -> std::wstring_view
            {
                return (i + 1 < argc) ? std::wstring_view{ argv[++i] } : std::wstring_view{};
            };

            if (arg == L"-o")
            {
                outdir = std::filesystem::path{ value() };
            }
            else if (arg == L"--out")
            {
                outpath = std::filesystem::path{ value() };
            }
        }

        if (outpath.empty())
        {
            krkr::detail::fail("--out required");
        }

        
        const auto pack_start_line{ std::string{ "[pack] manifest=" } + manifest_path.generic_string() + " outdir=" + outdir.generic_string() };
        console::helper.writeline(pack_start_line);
        krkr::xp3::pack(manifest_path, outdir, outpath);
        const auto pack_done_line{ std::string{ "[pack] done -> " } + outpath.generic_string() };
        console::helper.writeline(pack_done_line);
        return 0;
    }

    auto run_packdir(const int argc, const wchar_t* const argv[]) -> int
    {
        if (argc < 3)
        {
            console::helper.writeline(k_usage);
            return 1;
        }
        const std::filesystem::path indir{ argv[1] };

        std::filesystem::path parampath{};
        std::filesystem::path blockpath{};
        std::filesystem::path outpath{};

        for (int i = 2; i < argc; ++i)
        {
            const std::wstring_view arg{ argv[i] };
            const auto value = [&]() -> std::wstring_view
            {
                return (i + 1 < argc) ? std::wstring_view{ argv[++i] } : std::wstring_view{};
            };

            if (arg == L"--parampath")
            {
                parampath = std::filesystem::path{ value() };
            }
            else if (arg == L"--blockpath")
            {
                blockpath = std::filesystem::path{ value() };
            }
            else if (arg == L"--out")
            {
                outpath = std::filesystem::path{ value() };
            }
        }

        if (outpath.empty())
        {
            krkr::detail::fail("--out required");
        }

        krkr::xp3::params params{};
        if (!parampath.empty())
        {
            load_params_ini(params, parampath);
        }
        if (!blockpath.empty())
        {
            load_control_block(params.cx.control_block, blockpath);
        }
        if (params.cx.control_block.empty())
        {
            krkr::detail::fail("control block required");
        }

        const auto packdir_start_line{ std::string{ "[packdir] " } + indir.generic_string() };
        console::helper.writeline(packdir_start_line);

        krkr::xp3::pack_dir(indir, params, outpath);
        
        const auto packdir_done_line{ std::string{ "[packdir] done -> " } + outpath.generic_string() };
        console::helper.writeline(packdir_done_line);
        return 0;
    }

    static auto main(const int argc, const wchar_t* const argv[]) -> int
    {
        if (argc < 2)
        {
            console::helper.writeline(k_usage);
            return 1;
        }

        const std::wstring_view command{ argv[1] };
        if (command == L"unpack")
        {
            return run_unpack(argc - 1, argv + 1);
        }
        if (command == L"pack")
        {
            return run_pack(argc - 1, argv + 1);
        }
        if (command == L"packdir")
        {
            return run_packdir(argc - 1, argv + 1);
        }

        console::helper.writeline(k_usage);
        return 1;
    }

    extern "C" auto main(void) -> int
    {
        int argc{};
        const LPWSTR  cmds{ ::GetCommandLineW() };
        const LPWSTR* argv{ ::CommandLineToArgvW(cmds, &argc) };
        try
        {
            return krkrhxv4::main(argc, argv);
        }
        catch (const krkr::detail::exception& error)
        {
            console::helper.set_attrs(console::attrs::color::text_red);
            if (const auto* narrow = error.message<std::string>())
            {
                const auto err_line{ std::string{ "error: " } + *narrow };
                console::helper.writeline(err_line).reset_attrs();
            }
            else if (const auto* wide = error.message<std::wstring>())
            {
                const auto err_line{ std::wstring{ L"error: " } + *wide };
               console::helper.writeline(err_line).reset_attrs();
            }
            return 1;
        }
        catch (const std::exception& error)
        {
            const auto err_line{ std::string{ "error: " } + error.what() };
            console::helper.set_attrs(console::attrs::color::text_red);
            console::helper.writeline(err_line).reset_attrs();
            return 1;
        }
    }
}