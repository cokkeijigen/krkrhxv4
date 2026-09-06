#pragma once

#include "common.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace krkr::exe
{
    // Bootstrap CX parameters extracted from BOOTSTRAP DLL.
    struct BootstrapParams
    {
        std::array<std::uint8_t, 17> raw_order{};
        std::uint8_t mode{};
        std::uint8_t flags{};
        std::uint32_t mask{};
        std::uint32_t offset{};
        std::int32_t hx_random_type{};
    };

    // Key material extracted from game EXE.
    struct ExeDumpResult
    {
        std::vector<std::uint8_t> startup_tjs;        // Decrypted TJS2100 bytecode
        std::vector<std::uint8_t> bootstrap;          // Decrypted and decompressed DLL
        std::vector<std::uint8_t> salt;               // 8192 bytes from .data
        std::string startup_filter_path;              // e.g. "udpatkczbyqvm8r8z6p84vhxdn"
        std::string bootstrap_filter_path;            // Extracted from STARTUP.TJS

        // Optional: extracted from BOOTSTRAP if present
        std::optional<BootstrapParams> bootstrap_params;
        std::optional<std::string> warning_string;
        std::optional<std::array<std::uint8_t, 8>> archive_unique_key;
    };

    // Checks if a file is a valid PE executable.
    [[nodiscard]] auto is_pe_file(const std::filesystem::path& path) -> bool;

    // Dumps embedded resources from a game EXE.
    // Returns nullopt if the file is not a game EXE with HxV4 resources.
    [[nodiscard]] auto dump_exe_resources(const std::filesystem::path& exe_path)
        -> std::optional<ExeDumpResult>;

    // Writes dump results to output directory.
    // Creates: STARTUP.TJS, BOOTSTRAP, key.ini (if params available)
    auto write_dump_result(const ExeDumpResult& result, const std::filesystem::path& outdir) -> void;
} // namespace krkr::exe