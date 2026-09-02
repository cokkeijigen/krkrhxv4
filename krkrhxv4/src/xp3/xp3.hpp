#pragma once

#include <filesystem>
#include <string>

#include "common.hpp"
#include "cx/cx.hpp"
#include "crypto/crypto.hpp"

namespace krkr::xp3
{
    extern const std::array<std::uint8_t, 11> kXp3Sig;

    // One GTK "segment" descriptor inside a File entry.
    struct segm_t
    {
        std::uint32_t flags{};
        std::uint64_t offset{};
        std::uint64_t fsize{};
        std::uint64_t zsize{};
    };

    // One parsed xp3 index entry. `File` entries carry content metadata, `Hxv4`
    // entries carry the raw 14-byte payload.
    struct index_entry
    {
        std::string           sig;      // "File" or "Hxv4"
        std::vector<std::uint8_t>       raw;      // entry payload (for Hxv4: the 14-byte descriptor)
        std::u16string        name;     // File entry name (fakename), decoded from UTF-16LE
        std::uint32_t                   info_flags{};
        std::int64_t                   fsize{};
        std::int64_t                   zsize{};
        std::vector<segm_t>   segms;
        std::uint32_t                   adlr{};
    };

    // One file described by the decrypted HxV4 index.
    struct hvx_entry
    {
        std::uint64_t                   id{};
        std::uint64_t                   key{};
        std::u16string        fakename;
        std::array<std::uint8_t, 8>     dirhash{};
        std::array<std::uint8_t, 32>    filehash{};
    };

    // Scheme + archive level parameters needed both for unpack and pack.
    struct params
    {
        std::array<std::uint8_t, 32> index_key{};
        std::array<std::uint8_t, 16> index_nonce{};
        cx::scheme         cx;
        // First 16 bytes of the encrypted index blob (left untouched by the cipher).
        std::array<std::uint8_t, 16> blob_prefix{};
        // First 4 bytes of the decrypted index blob (before the zlib payload).
        std::array<std::uint8_t, 4>  blob_header{};
        std::int16_t                blob_flags{};
        bool               index_compressed = true;
    };

    struct file_entry
    {
        std::string        path;      // relative path on disk
        std::u16string     fakename;
        std::array<std::uint8_t, 8>  dirhash{};
        std::array<std::uint8_t, 32> filehash{};
        std::uint64_t                id        = 0;
        std::uint64_t                key       = 0;
        int                enc_type  = -1; // -1 = binary, 0/1/2 = text enc type
        // Plaintext-named entry (on-disk name starts with '.'): the xp3 index
        // carries the real name and the payload is NOT cx-encrypted.
        bool               plain_name = false;
        std::uint32_t                info_flags{};
        std::uint32_t                seg_flags{};
        std::uint32_t                adlr{};
    };

    struct manifest
    {
        params                  c;
        std::vector<file_entry> files;
    };

    // ---- file helpers ---------------------------------------------------------
    [[nodiscard]] auto read_file(const std::filesystem::path& path) -> std::vector<std::uint8_t>;
    auto write_file(const std::filesystem::path& path, std::span<const std::uint8_t> data) -> void;
    auto make_dirs(const std::filesystem::path& path) -> void;
    [[nodiscard]] auto utf16_to_utf8(std::u16string_view text) -> std::string;
    [[nodiscard]] auto utf8_to_utf16(std::string_view text) -> std::u16string;

    // zlib helpers.
    [[nodiscard]] auto inflate(std::span<const std::uint8_t> data) -> std::vector<std::uint8_t>;
    [[nodiscard]] auto deflate(std::span<const std::uint8_t> data) -> std::vector<std::uint8_t>;

    // ---- xp3 archive ------------------------------------------------------------
    [[nodiscard]] auto parse_index(std::span<const std::uint8_t> data) -> std::vector<index_entry>;

    inline auto convert_fakename(std::uint64_t id) -> std::u16string
    {
        std::u16string s;
        while (true)
        {
            const std::uint16_t u = static_cast<std::uint16_t>(((id & 0x3fff) + 0x5000) & 0xffff);
            s.push_back(u);
            id >>= 14;
            if (id == 0)
            {
                break;
            }
        }
        return s;
    }

    // Read + decrypt the HxV4 index blob, resolving per-file entries in order.
    // Also fills `p.blob_prefix` / `p.blob_header` / `p.blob_flags` from the blob.
    [[nodiscard]] auto parse_hxv4_index(std::span<const std::uint8_t> archive, const index_entry& hxv4, params& p) -> std::vector<hvx_entry>;

    // ---- unpack / pack ------------------------------------------------------------
    // Unpacks the source xp3 into `outdir` (plus an embedded `.manifest`) and returns it.
    auto unpack(const std::filesystem::path& inpath, const std::filesystem::path& outdir, const params& p, bool hash_names) -> manifest;
    // Repacks `outdir` per the manifest at `manifest_path` into `outpath`.
    auto pack(const std::filesystem::path& manifest_path, const std::filesystem::path& outdir, const std::filesystem::path& outpath) -> void;

    // Options controlling hash-literal detection in pack_dir.
    struct pack_dir_options
    {
        // When true, the leaf-most directory component (exactly 16 hex digits)
        // is used directly as the dirhash, and a leaf name of exactly 64 hex
        // digits is used directly as the filehash, instead of hashing the
        // on-disk name.
        bool hash_literal = false;
        // Exception entries (raw, un-normalized) that must keep being hashed as
        // ordinary names even when they match the hash-literal shape.  A bare
        // token matches the leaf name or a single directory component; a token
        // containing '/' matches the full relative path.  Normalization is
        // applied inside pack_dir (lowercase, '/' separators, trimmed, no
        // trailing '/').
        std::vector<std::u16string> hash_keep{};
    };

    // Packs `indir` directly into `outpath`, computing each file's dirhash/filehash
    // from its lowercased relative path and assigning sequential ids/keys.
    auto pack_dir(const std::filesystem::path& indir, const params& p, const std::filesystem::path& outpath, const pack_dir_options& opts = {}) -> void;

    // Persist / reload the unpack manifest.
    auto save_manifest(const manifest& m, const std::filesystem::path& path) -> void;
    [[nodiscard]] auto load_manifest(const std::filesystem::path& path) -> manifest;
} // namespace krkr::xp3