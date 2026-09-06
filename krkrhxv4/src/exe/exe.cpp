#include "exe.hpp"

#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>

namespace krkr::exe
{
    namespace
    {
        constexpr std::size_t k_salt_size = 0x2000;  // 8192 bytes

        // ChaCha8 constants (obfuscated)
        constexpr std::array<std::uint8_t, 16> k_obfuscated_chacha_const = {
            0x9a, 0x87, 0x8f, 0x9e, 0x91, 0x9b, 0xdf, 0xcc,
            0xcd, 0xd2, 0x9d, 0x86, 0x8b, 0x9a, 0xdf, 0x94,
        };

        auto rotl_u32(std::uint32_t v, int n) -> std::uint32_t
        {
            return (v << n) | (v >> (32 - n));
        }

        auto chacha_quarter(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) -> void
        {
            a += b; d ^= a; d = rotl_u32(d, 16);
            c += d; b ^= c; b = rotl_u32(b, 12);
            a += b; d ^= a; d = rotl_u32(d, 8);
            c += d; b ^= c; b = rotl_u32(b, 7);
        }

        // Simple SHA3-384 placeholder - in real impl use dumpkey::cx_sponge
        auto derive_key_material(const std::string& filter_path, const std::vector<std::uint8_t>& salt)
            -> std::array<std::uint8_t, 48>
        {
            std::array<std::uint8_t, 48> result{};
            std::vector<std::uint8_t> input;

            // filter_path as UTF-16LE
            for (const char ch : filter_path)
            {
                input.push_back(static_cast<std::uint8_t>(ch));
                input.push_back(0);
            }
            input.insert(input.end(), salt.begin(), salt.end());

            // TODO: Replace with actual SHA3-384
            // For now, use a simple hash placeholder
            for (std::size_t i = 0; i < 48 && i < input.size(); ++i)
            {
                result[i] = input[i];
            }
            return result;
        }

        class ExeChaCha8
        {
        public:
            ExeChaCha8(const std::string& filter_path, const std::vector<std::uint8_t>& salt)
            {
                const auto material = derive_key_material(filter_path, salt);

                // Initialize ChaCha state with obfuscated constant
                m_state[0] = static_cast<std::uint32_t>(k_obfuscated_chacha_const[0]) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[1]) << 8) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[2]) << 16) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[3]) << 24);
                m_state[1] = static_cast<std::uint32_t>(k_obfuscated_chacha_const[4]) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[5]) << 8) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[6]) << 16) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[7]) << 24);
                m_state[2] = static_cast<std::uint32_t>(k_obfuscated_chacha_const[8]) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[9]) << 8) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[10]) << 16) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[11]) << 24);
                m_state[3] = static_cast<std::uint32_t>(k_obfuscated_chacha_const[12]) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[13]) << 8) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[14]) << 16) |
                            (static_cast<std::uint32_t>(k_obfuscated_chacha_const[15]) << 24);

                // Key (material[0..31], inverted)
                for (int i = 0; i < 8; ++i)
                {
                    m_state[4 + i] = ~krkr::read_u32_le(std::span<const std::uint8_t>(material.data() + i * 4, 4), 0);
                }

                m_state[12] = 0xFFFFFFFF;
                m_state[13] = 0xFFFFFFFF;
                m_state[14] = ~krkr::read_u32_le(std::span<const std::uint8_t>(material.data() + 32, 4), 0);
                m_state[15] = ~krkr::read_u32_le(std::span<const std::uint8_t>(material.data() + 36, 4), 0);

                m_counter_low = krkr::read_u32_le(std::span<const std::uint8_t>(material.data() + 40, 4), 0);
                m_counter_high = krkr::read_u32_le(std::span<const std::uint8_t>(material.data() + 44, 4), 0);
            }

            auto decrypt(std::uint64_t counter, std::span<std::uint8_t> data) -> void
            {
                std::size_t offset = 0;
                while (offset < data.size())
                {
                    const auto block = generate_block(counter);
                    counter++;

                    for (int i = 0; i < 64 && offset < data.size(); ++i)
                    {
                        data[offset++] ^= block[static_cast<std::size_t>(i)];
                    }
                }
            }

        private:
            std::array<std::uint32_t, 16> m_state{};
            std::uint32_t m_counter_low{};
            std::uint32_t m_counter_high{};

            auto generate_block(std::uint64_t counter) -> std::array<std::uint8_t, 64>
            {
                std::array<std::uint32_t, 16> state = m_state;
                state[12] += static_cast<std::uint32_t>(counter & 0xFFFFFFFF);
                state[13] += static_cast<std::uint32_t>((counter >> 32) & 0xFFFFFFFF) + m_counter_high;

                // 8 rounds (4 double rounds)
                for (int r = 0; r < 4; ++r)
                {
                    // Column rounds
                    chacha_quarter(state[0], state[4], state[8], state[12]);
                    chacha_quarter(state[1], state[5], state[9], state[13]);
                    chacha_quarter(state[2], state[6], state[10], state[14]);
                    chacha_quarter(state[3], state[7], state[11], state[15]);
                    // Diagonal rounds
                    chacha_quarter(state[0], state[5], state[10], state[15]);
                    chacha_quarter(state[1], state[6], state[11], state[12]);
                    chacha_quarter(state[2], state[7], state[8], state[13]);
                    chacha_quarter(state[3], state[4], state[9], state[14]);
                }

                std::array<std::uint8_t, 64> result{};
                for (int i = 0; i < 16; ++i)
                {
                    const auto v = state[i] + m_state[i];  // Add initial state
                    for (int j = 0; j < 4; ++j)
                    {
                        result[static_cast<std::size_t>(i * 4 + j)] = static_cast<std::uint8_t>(v >> (j * 8));
                    }
                }
                return result;
            }
        };

        // Extract bootstrap path from TJS bytecode by scanning for "bres://./<token>/bootstrap"
        auto extract_bootstrap_path_from_tjs(const std::vector<std::uint8_t>& tjs_data) -> std::optional<std::string>
        {
            if (tjs_data.size() < 20)
                return std::nullopt;

            // Scan for "bres://./" pattern in UTF-16LE
            const std::string target = "bres://./";
            for (std::size_t i = 0; i + target.size() * 2 <= tjs_data.size(); ++i)
            {
                bool match = true;
                for (std::size_t j = 0; j < target.size() && match; ++j)
                {
                    if (tjs_data[i + j * 2] != static_cast<std::uint8_t>(target[j]) ||
                        tjs_data[i + j * 2 + 1] != 0)
                    {
                        match = false;
                    }
                }

                if (match)
                {
                    // Found "bres://./" - extract the token
                    std::string token;
                    for (std::size_t j = i + target.size() * 2; j + 1 < tjs_data.size(); j += 2)
                    {
                        const auto ch = static_cast<char>(tjs_data[j]);
                        if (ch == '/')
                        {
                            // Check for "/bootstrap"
                            const std::string suffix = "/bootstrap";
                            bool suffix_match = true;
                            for (std::size_t k = 0; k < suffix.size() && suffix_match; ++k)
                            {
                                if (j + k * 2 + 1 >= tjs_data.size() ||
                                    tjs_data[j + k * 2] != static_cast<std::uint8_t>(suffix[k]))
                                {
                                    suffix_match = false;
                                }
                            }
                            if (suffix_match)
                                return token;
                            break;
                        }
                        if (ch == 0 || ch < 0x20 || ch > 0x7E)
                            break;
                        token.push_back(ch);
                    }
                }
            }

            return std::nullopt;
        }

        auto zlib_decompress(const std::vector<std::uint8_t>& compressed) -> std::optional<std::vector<std::uint8_t>>
        {
            z_stream stream{};
            stream.next_in = const_cast<Bytef*>(compressed.data());
            stream.avail_in = static_cast<uInt>(compressed.size());

            if (inflateInit(&stream) != Z_OK)
                return std::nullopt;

            std::vector<std::uint8_t> result;
            std::array<std::uint8_t, 4096> buffer{};

            while (true)
            {
                stream.next_out = buffer.data();
                stream.avail_out = static_cast<uInt>(buffer.size());

                const auto ret = inflate(&stream, Z_NO_FLUSH);
                if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
                {
                    inflateEnd(&stream);
                    return std::nullopt;
                }

                result.insert(result.end(), buffer.begin(), buffer.begin() + buffer.size() - stream.avail_out);

                if (ret == Z_STREAM_END)
                    break;
            }

            inflateEnd(&stream);
            return result;
        }

    } // namespace

    // --- Public API ---

    auto is_pe_file(const std::filesystem::path& path) -> bool
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
            return false;

        // Check DOS stub
        std::array<char, 2> dos_sig{};
        file.read(dos_sig.data(), 2);
        if (dos_sig[0] != 'M' || dos_sig[1] != 'Z')
            return false;

        // Check PE signature
        std::uint32_t pe_off{};
        file.seekg(0x3c);
        file.read(reinterpret_cast<char*>(&pe_off), 4);

        std::array<char, 4> pe_sig{};
        file.seekg(pe_off);
        file.read(pe_sig.data(), 4);

        return pe_sig[0] == 'P' && pe_sig[1] == 'E' && pe_sig[2] == 0 && pe_sig[3] == 0;
    }

    auto dump_exe_resources(const std::filesystem::path& exe_path) -> std::optional<ExeDumpResult>
    {
        // Use Win32 API to load resources
        const auto mod = ::LoadLibraryExW(exe_path.c_str(), nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (!mod)
        {
            // Debug output
            std::cout << "[debug] LoadLibraryExW failed" << std::endl;
            return std::nullopt;
        }

        std::cout << "[debug] Module loaded at " << mod << std::endl;

        // Find TEXT/127 resource (startup filter path)
        const auto h_text = ::FindResourceW(mod, MAKEINTRESOURCEW(127), L"TEXT");
        std::string startup_filter_path;
        std::cout << "[debug] TEXT/127 handle: " << h_text << std::endl;
        if (h_text)
        {
            const auto h_data = ::LoadResource(mod, h_text);
            const auto ptr = static_cast<const std::uint8_t*>(::LockResource(h_data));
            const auto size = ::SizeofResource(mod, h_text);
            std::cout << "[debug] TEXT/127 size: " << size << std::endl;

            // UTF-16LE to UTF-8
            const auto bytes = static_cast<const std::uint8_t*>(ptr);
            std::u16string u16str;
            for (std::size_t i = 0; i + 1 < size; i += 2)
            {
                const auto ch = static_cast<char16_t>(bytes[i] | (bytes[i + 1] << 8));
                if (ch == 0)
                    break;
                u16str.push_back(ch);
            }

            std::string str;
            for (const auto ch : u16str)
                str.push_back(static_cast<char>(ch));
            std::cout << "[debug] TEXT/127 content: " << str << std::endl;

            // Extract token: "bres://./<token>/" -> "<token>"
            if (str.starts_with("bres://./"))
            {
                str.erase(0, 10);  // "bres://./" is 10 chars
                const auto slash_pos = str.find('/');
                if (slash_pos != std::string::npos)
                    str.erase(slash_pos);
                startup_filter_path = str;
                std::cout << "[debug] Extracted startup_filter_path: " << startup_filter_path << std::endl;
            }
        }

        // Find RCDATA/STARTUP.TJS
        const auto h_startup = ::FindResourceW(mod, L"STARTUP.TJS", MAKEINTRESOURCEW(10));
        std::vector<std::uint8_t> startup_tjs;
        std::cout << "[debug] RCDATA/STARTUP.TJS handle: " << h_startup << std::endl;
        if (h_startup)
        {
            const auto h_data = ::LoadResource(mod, h_startup);
            const auto ptr = static_cast<const std::uint8_t*>(::LockResource(h_data));
            const auto size = ::SizeofResource(mod, h_startup);
            std::cout << "[debug] RCDATA/STARTUP.TJS size: " << size << std::endl;
            startup_tjs.assign(ptr, ptr + size);
        }

        // Find RCDATA/BOOTSTRAP
        const auto h_bootstrap = ::FindResourceW(mod, L"BOOTSTRAP", MAKEINTRESOURCEW(10));
        std::vector<std::uint8_t> bootstrap_raw;
        std::cout << "[debug] RCDATA/BOOTSTRAP handle: " << h_bootstrap << std::endl;
        if (h_bootstrap)
        {
            const auto h_data = ::LoadResource(mod, h_bootstrap);
            const auto ptr = static_cast<const std::uint8_t*>(::LockResource(h_data));
            const auto size = ::SizeofResource(mod, h_bootstrap);
            std::cout << "[debug] RCDATA/BOOTSTRAP size: " << size << std::endl;
            bootstrap_raw.assign(ptr, ptr + size);
        }

        ::FreeLibrary(mod);

        // Check if this is a HxV4 game
        if (startup_filter_path.empty() || startup_tjs.empty() || bootstrap_raw.empty())
        {
            std::cout << "[debug] Missing resources: startup_filter_path=" << !startup_filter_path.empty()
                      << ", startup_tjs=" << !startup_tjs.empty()
                      << ", bootstrap_raw=" << !bootstrap_raw.empty() << std::endl;
            return std::nullopt;
        }

        std::cout << "[debug] startup_filter_path: " << startup_filter_path << std::endl;

        // Extract salt from PE (placeholder - real impl needs pattern scan)
        std::vector<std::uint8_t> salt(k_salt_size, 0);

        // Decrypt STARTUP.TJS
        std::cout << "[debug] Decrypting STARTUP.TJS with ChaCha8..." << std::endl;
        ExeChaCha8 chacha_startup(startup_filter_path, salt);
        chacha_startup.decrypt(0, std::span<std::uint8_t>(startup_tjs));

        // Check decryption result
        std::cout << "[debug] STARTUP.TJS first 16 bytes after decrypt: ";
        for (int i = 0; i < 16 && i < startup_tjs.size(); ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(startup_tjs[i]) << " ";
        std::cout << std::dec << std::endl;

        // Extract bootstrap path from STARTUP.TJS
        const auto bootstrap_path = extract_bootstrap_path_from_tjs(startup_tjs);
        if (!bootstrap_path)
        {
            std::cout << "[debug] Failed to extract bootstrap path from STARTUP.TJS" << std::endl;
            return std::nullopt;
        }
        std::cout << "[debug] bootstrap_filter_path: " << *bootstrap_path << std::endl;

        // Decrypt BOOTSTRAP
        ExeChaCha8 chacha_bootstrap(*bootstrap_path, salt);
        chacha_bootstrap.decrypt(0, std::span<std::uint8_t>(bootstrap_raw));

        // Decompress BOOTSTRAP (format: [packed:4][unpacked:4][zlib_data])
        if (bootstrap_raw.size() < 8)
            return std::nullopt;

        const auto packed_size = krkr::read_u32_le(std::span<const std::uint8_t>(bootstrap_raw.data(), 4), 0);

        std::vector<std::uint8_t> compressed(bootstrap_raw.begin() + 8,
                                              bootstrap_raw.begin() + 8 + packed_size);
        auto decompressed = zlib_decompress(compressed);
        if (!decompressed)
            return std::nullopt;

        return ExeDumpResult{
            .startup_tjs = std::move(startup_tjs),
            .bootstrap = std::move(*decompressed),
            .salt = std::move(salt),
            .startup_filter_path = std::move(startup_filter_path),
            .bootstrap_filter_path = std::move(*bootstrap_path),
        };
    }

    auto write_dump_result(const ExeDumpResult& result, const std::filesystem::path& outdir) -> void
    {
        std::filesystem::create_directories(outdir);

        // Write STARTUP.TJS
        {
            const auto path = outdir / "STARTUP.TJS";
            std::ofstream file(path, std::ios::binary);
            file.write(reinterpret_cast<const char*>(result.startup_tjs.data()),
                       static_cast<std::streamsize>(result.startup_tjs.size()));
        }

        // Write BOOTSTRAP
        {
            const auto path = outdir / "BOOTSTRAP";
            std::ofstream file(path, std::ios::binary);
            file.write(reinterpret_cast<const char*>(result.bootstrap.data()),
                       static_cast<std::streamsize>(result.bootstrap.size()));
        }

        // Write salt.bin
        {
            const auto path = outdir / "salt.bin";
            std::ofstream file(path, std::ios::binary);
            file.write(reinterpret_cast<const char*>(result.salt.data()),
                       static_cast<std::streamsize>(result.salt.size()));
        }

        // Write filter_paths.txt
        {
            const auto path = outdir / "filter_paths.txt";
            std::ofstream file(path);
            file << "startup_filter_path=" << result.startup_filter_path << "\n";
            file << "bootstrap_filter_path=" << result.bootstrap_filter_path << "\n";
        }
    }

} // namespace krkr::exe