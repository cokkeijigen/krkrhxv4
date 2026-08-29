#include "xp3/xp3.hpp"

#include <zlib.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <variant>

namespace krkr::xp3
{
    namespace
    {
        constexpr std::uint32_t kFileProtected          = 1u << 31;
        constexpr std::uint32_t kSegmEncodeMethodMask   = 0x07;
        constexpr std::uint32_t kSegmEncodeZlib         = 0x01;
        constexpr std::uint32_t kSegmEncodeRaw          = 0x00;

        auto index_offset_of(std::span<const std::uint8_t> archive) -> std::uint64_t
        {
            return krkr::read_u64_le(archive, 11);
        }

        auto hxv4_descriptor(const index_entry& e) -> std::tuple<std::uint64_t, std::uint32_t, std::uint16_t>
        {
            std::uint64_t offset = 0;
            std::uint32_t fsize  = 0;
            std::uint16_t flags  = 0;
            if (e.raw.size() >= 14)
            {
                offset = krkr::read_u64_le(e.raw, 0);
                fsize  = krkr::read_u32_le(e.raw, 8);
                flags  = krkr::read_u16_le(e.raw, 12);
            }
            return { offset, fsize, flags };
        }

        auto utf16_le_bytes(const std::u16string& s) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out;
            out.reserve(s.size() * 2);
            for (const std::uint16_t c : s)
            {
                krkr::write_u16_le(out, c);
            }
            return out;
        }
    } // namespace

    const std::array<std::uint8_t, 11> kXp3Sig = { 0x58, 0x50, 0x33, 0x0d, 0x0a, 0x20, 0x0a, 0x1a, 0x8b, 0x67, 0x01 };

    // ---------------------------------------------------------------------------
    // file / text helpers.
    // ---------------------------------------------------------------------------
    auto read_file(const std::filesystem::path& path) -> std::vector<std::uint8_t>
    {
        std::ifstream ifs{ path, std::ios::binary };
        if (!ifs)
        {
            detail::fail("cannot open file: " + path.generic_string());
        }
        ifs.seekg(0, std::ios::end);
        const auto size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);
        std::vector<std::uint8_t> out(static_cast<std::size_t>(size));
        if (size > 0)
        {
            ifs.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
        }
        return out;
    }

    auto write_file(const std::filesystem::path& path, std::span<const std::uint8_t> data) -> void
    {
        make_dirs(path.parent_path());
        std::ofstream ofs{ path, std::ios::binary };
        if (!ofs)
        {
            detail::fail("cannot open file for write: " + path.generic_string());
        }
        ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }

    auto make_dirs(const std::filesystem::path& path) -> void
    {
        if (!path.empty())
        {
            std::filesystem::create_directories(path);
        }
    }

    auto utf16_to_utf8(std::u16string_view text) -> std::string
    {
        std::string out;
        for (const std::uint16_t c : text)
        {
            if (c < 0x80)
            {
                out.push_back(static_cast<char>(c));
            }
            else if (c < 0x800)
            {
                out.push_back(static_cast<char>(0xc0 | (c >> 6)));
                out.push_back(static_cast<char>(0x80 | (c & 0x3f)));
            }
            else
            {
                out.push_back(static_cast<char>(0xe0 | (c >> 12)));
                out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3f)));
                out.push_back(static_cast<char>(0x80 | (c & 0x3f)));
            }
        }
        return out;
    }

    auto utf8_to_utf16(std::string_view text) -> std::u16string
    {
        std::u16string out;
        std::size_t i = 0;
        while (i < text.size())
        {
            const std::uint8_t c    = static_cast<std::uint8_t>(text[i]);
            std::uint32_t       cp  = 0;
            std::size_t extra = 0;
            if (c < 0x80)
            {
                cp = c;
            }
            else if ((c & 0xe0) == 0xc0)
            {
                cp = c & 0x1f; extra = 1;
            }
            else if ((c & 0xf0) == 0xe0)
            {
                cp = c & 0x0f; extra = 2;
            }
            else if ((c & 0xf8) == 0xf0)
            {
                cp = c & 0x07; extra = 3;
            }
            for (std::size_t k = 0; k < extra && i + 1 + k < text.size(); ++k)
            {
                cp = (cp << 6) | (static_cast<std::uint8_t>(text[i + 1 + k]) & 0x3f);
            }
            i += 1 + extra;
            if (cp < 0x10000)
            {
                out.push_back(static_cast<std::uint16_t>(cp));
            }
            else
            {
                cp -= 0x10000;
                out.push_back(static_cast<std::uint16_t>(0xd800 | (cp >> 10)));
                out.push_back(static_cast<std::uint16_t>(0xdc00 | (cp & 0x3ff)));
            }
        }
        return out;
    }

    auto inflate(std::span<const std::uint8_t> data) -> std::vector<std::uint8_t>
    {
        z_stream z{};
        if (inflateInit(&z) != Z_OK)
        {
            detail::fail("inflateInit failed");
        }
        std::vector<std::uint8_t> out;
        std::vector<std::uint8_t> buf(64 * 1024);
        z.next_in  = const_cast<Bytef*>(data.data());
        z.avail_in = static_cast<uInt>(data.size());
        int ret    = Z_OK;
        do
        {
            z.next_out  = buf.data();
            z.avail_out = static_cast<uInt>(buf.size());
            ret         = inflate(&z, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END)
            {
                inflateEnd(&z);
                detail::fail("zlib inflate failed");
            }
            out.insert(out.end(), buf.begin(), buf.begin() + (buf.size() - z.avail_out));
        } while (ret != Z_STREAM_END);
        inflateEnd(&z);
        return out;
    }

    auto deflate(std::span<const std::uint8_t> data) -> std::vector<std::uint8_t>
    {
        z_stream z{};
        if (deflateInit(&z, Z_DEFAULT_COMPRESSION) != Z_OK)
        {
            detail::fail("deflateInit failed");
        }
        std::vector<std::uint8_t> out;
        std::vector<std::uint8_t> buf(64 * 1024);
        z.next_in  = const_cast<Bytef*>(data.data());
        z.avail_in = static_cast<uInt>(data.size());
        int ret    = Z_OK;
        do
        {
            z.next_out  = buf.data();
            z.avail_out = static_cast<uInt>(buf.size());
            ret         = deflate(&z, Z_FINISH);
            if (ret != Z_OK && ret != Z_STREAM_END)
            {
                deflateEnd(&z);
                detail::fail("zlib deflate failed");
            }
            out.insert(out.end(), buf.begin(), buf.begin() + (buf.size() - z.avail_out));
        } while (ret != Z_STREAM_END);
        deflateEnd(&z);
        return out;
    }

    // ---------------------------------------------------------------------------
    // xp3 index parsing.
    // ---------------------------------------------------------------------------
    auto parse_index(std::span<const std::uint8_t> data) -> std::vector<index_entry>
    {
        if (data.size() < 0x13 ||
            !std::equal(kXp3Sig.begin(), kXp3Sig.end(), data.begin(), data.begin() + 11))
        {
            detail::fail("not an xp3 file (bad signature)");
        }

        const std::uint64_t io0 = index_offset_of(data);
        if (io0 >= data.size())
        {
            detail::fail("xp3 index offset out of range");
        }

        // Large-archive continuation record: the field at 0x0b points to a
        // 0x80 marker followed 9 bytes later by the real index offset.
        std::uint64_t io = io0;
        if (io + 4 <= data.size() && krkr::read_u32_le(data, io) == 0x80)
        {
            io = krkr::read_u64_le(data, io + 9);
            if (io >= data.size())
            {
                detail::fail("xp3 index offset (continued) out of range");
            }
        }

        const std::uint8_t compress = data[io];
        std::vector<std::uint8_t> index_data;
        if (compress == 1)
        {
            const std::uint64_t zsize = krkr::read_u64_le(data, io + 1);
            const std::uint64_t fsize = krkr::read_u64_le(data, io + 9);
            if (io + 17 + zsize > data.size())
            {
                detail::fail("xp3 compressed index out of range");
            }
            index_data = inflate(data.subspan(static_cast<std::size_t>(io + 17), static_cast<std::size_t>(zsize)));
            if (index_data.size() != fsize)
            {
                detail::fail("xp3 index size mismatch");
            }
        }
        else
        {
            const std::uint64_t fsize = krkr::read_u64_le(data, io + 1);
            if (io + 9 + fsize > data.size())
            {
                detail::fail("xp3 index out of range");
            }
            index_data.assign(data.begin() + static_cast<std::ptrdiff_t>(io + 9), data.begin() + static_cast<std::ptrdiff_t>(io + 9 + fsize));
        }

        std::vector<index_entry> entries;
        std::size_t pos = 0;
        while (pos < index_data.size() && index_data[pos] != 0xff)
        {
            if (pos + 12 > index_data.size())
            {
                break;
            }
            index_entry e;
            const auto sig4 = std::string{ reinterpret_cast<const char*>(&index_data[pos]), 4 };
            const std::int64_t esize = static_cast<std::int64_t>(krkr::read_u64_le(index_data, pos + 4));
            if (esize < 0 || (pos + 12 + static_cast<std::size_t>(esize)) > index_data.size())
            {
                detail::fail("xp3 entry size out of range");
            }
            const std::uint8_t* const entry_data = index_data.data() + pos + 12;
            const auto esize_u         = static_cast<std::size_t>(esize);
            e.sig                      = sig4;
            e.raw.assign(entry_data, entry_data + esize_u);

            const std::uint8_t* const end = entry_data + esize_u;
            const std::uint8_t*       p   = entry_data;
            if (sig4 == "File")
            {
                while (p < end)
                {
                    const auto csig = std::string{ reinterpret_cast<const char*>(p), 4 };
                    const std::int64_t csize = static_cast<std::int64_t>(krkr::read_u64_le(std::span<const std::uint8_t>{ p, static_cast<std::size_t>(esize_u) }, 4));
                    if (csize < 0 || (p + 12 + csize) > end)
                    {
                        detail::fail("xp3 chunk size out of range");
                    }
                    const std::uint8_t* cdata = p + 12;
                    const std::span<const std::uint8_t> cview{ cdata, static_cast<std::size_t>(csize) };
                    if (csig == "info")
                    {
                        e.info_flags = krkr::read_u32_le(cview, 0);
                        e.fsize      = static_cast<std::int64_t>(krkr::read_u64_le(cview, 4));
                        e.zsize      = static_cast<std::int64_t>(krkr::read_u64_le(cview, 12));
                        const std::uint16_t namelen = krkr::read_u16_le(cview, 20);
                        if (22u + static_cast<std::uint32_t>(namelen) * 2 <= static_cast<std::uint32_t>(csize))
                        {
                            e.name.assign(reinterpret_cast<const char16_t*>(cdata + 22), static_cast<std::size_t>(namelen));
                        }
                    }
                    else if (csig == "segm")
                    {
                        for (std::size_t off = 0; off + 28 <= static_cast<std::size_t>(csize); off += 28)
                        {
                            segm_t s;
                            s.flags  = krkr::read_u32_le(cview, off);
                            s.offset = krkr::read_u64_le(cview, off + 4);
                            s.fsize  = krkr::read_u64_le(cview, off + 12);
                            s.zsize  = krkr::read_u64_le(cview, off + 20);
                            e.segms.push_back(s);
                        }
                    }
                    else if (csig == "adlr" && csize == 4)
                    {
                        e.adlr = krkr::read_u32_le(cview, 0);
                    }
                    p += 12 + csize;
                }
            }
            entries.push_back(std::move(e));
            pos += 12 + esize_u;
        }
        return entries;
    }

    // ---------------------------------------------------------------------------
    // HxV4 index blob: decrypt + parse.
    // ---------------------------------------------------------------------------
    namespace
    {
        struct obj : std::variant<std::monostate, std::uint64_t, std::vector<std::uint8_t>, std::u16string, std::vector<obj>>
        {
            using variant::variant;
        };

        auto rd_i32_be(std::span<const std::uint8_t> buf, std::uint32_t& pos) -> std::int32_t
        {
            if (pos + 4 > buf.size())
            {
                krkr::detail::fail("index object overrun");
            }
            const auto v = std::int32_t
            {
                (static_cast<std::int32_t>(buf[pos])     << 24) |
                (static_cast<std::int32_t>(buf[pos + 1]) << 16) |
                (static_cast<std::int32_t>(buf[pos + 2]) <<  8) |
                 static_cast<std::int32_t>(buf[pos + 3])
            };
            pos += 4;
            return v;
        }

        auto rd_bytes(std::span<const std::uint8_t> buf, std::uint32_t& pos, std::size_t n) -> std::vector<std::uint8_t>
        {
            if (pos + n > buf.size())
            {
                krkr::detail::fail("index object overrun");
            }
            std::vector<std::uint8_t> out(&buf[pos], &buf[pos] + n);
            pos += static_cast<std::uint32_t>(n);
            return out;
        }

        auto read_object(std::span<const std::uint8_t> buf, std::uint32_t& pos) -> obj;
        auto read_array(std::span<const std::uint8_t> buf, std::uint32_t& pos, std::int32_t n) -> std::vector<obj>
        {
            std::vector<obj> out;
            out.reserve(static_cast<std::size_t>(n));
            for (std::int32_t i = 0; i < n; ++i)
            {
                out.push_back(read_object(buf, pos));
            }
            return out;
        }

        auto read_object(std::span<const std::uint8_t> buf, std::uint32_t& pos) -> obj
        {
            if (pos >= buf.size())
            {
                krkr::detail::fail("index object overrun");
            }
            const std::uint8_t t = buf[pos++];
            if (t <= 0x01)
            {
                return obj{ std::monostate{} };
            }
            if (t == 0x02)
            {
                const auto n   = rd_i32_be(buf, pos);
                const auto raw = rd_bytes(buf, pos, static_cast<std::size_t>(n) * 2);
                return obj{ std::u16string{ reinterpret_cast<const char16_t*>(raw.data()), static_cast<std::size_t>(n) } };
            }
            if (t == 0x03)
            {
                return obj{ rd_bytes(buf, pos, static_cast<std::size_t>(rd_i32_be(buf, pos))) };
            }
            if (t == 0x04 || t == 0x05)
            {
                std::uint64_t v = 0;
                for (int k = 0; k < 8; ++k)
                {
                    v = (v << 8) | buf[pos++];
                }
                return v;
            }
            if (t == 0x81)
            {
                return read_array(buf, pos, rd_i32_be(buf, pos));
            }
            if (t == 0xc1)
            {
                const auto n = rd_i32_be(buf, pos);
                for (std::int32_t i = 0; i < n; ++i)
                {
                    const auto kn = rd_i32_be(buf, pos);
                    rd_bytes(buf, pos, static_cast<std::size_t>(kn) * 2);
                    read_object(buf, pos);
                }
                return obj{ std::monostate{} };
            }
            krkr::detail::fail("unknown HxV4 index object type");
        }

        // Serializer for the HxV4 index object.  The root array is flat:
        //   [dirhash, filearray, dirhash2, filearray2, ...]
        // where filearray = [filehash, [id,key], filehash2, [id,key], ...].
        void write_index_group(std::vector<std::uint8_t>& out, const std::vector<std::uint8_t>& dirhash, const std::vector<std::pair<std::vector<std::uint8_t>, hvx_entry>>& files)
        {
            out.push_back(0x03);
            write_i32_be(out, 8);
            out.insert(out.end(), dirhash.begin(), dirhash.end());
            out.push_back(0x81);
            write_i32_be(out, static_cast<std::int32_t>(files.size() * 2));
            for (const auto& [filehash, e] : files)
            {
                out.push_back(0x03);
                write_i32_be(out, 32);
                out.insert(out.end(), filehash.begin(), filehash.end());
                out.push_back(0x81);
                write_i32_be(out, 2);
                out.push_back(0x04);
                write_i64_be(out, static_cast<std::int64_t>(e.id));
                out.push_back(0x04);
                write_i64_be(out, static_cast<std::int64_t>(e.key));
            }
        }

        auto serialize_index(const std::vector<file_entry>& files) -> std::vector<std::uint8_t>
        {
            // group by dirhash preserving first-seen order.
            std::map<std::string, std::size_t> dir_index;
            std::vector<std::vector<std::uint8_t>>       dir_hashes;
            std::vector<std::vector<std::pair<std::vector<std::uint8_t>, hvx_entry>>> groups;
            for (const auto& f : files)
            {
                if (f.plain_name)
                {
                    continue; // plaintext-named entries are outside the hash index
                }
                std::vector<std::uint8_t> dh(f.dirhash.begin(), f.dirhash.end());
                const auto key = std::string{ reinterpret_cast<const char*>(dh.data()), 8 };
                auto it        = dir_index.find(key);
                if (it == dir_index.end())
                {
                    dir_index[key] = dir_hashes.size();
                    dir_hashes.push_back(dh);
                    groups.emplace_back();
                    it = dir_index.find(key);
                }
                std::vector<std::uint8_t> fh(f.filehash.begin(), f.filehash.end());
                hvx_entry hvx;
                hvx.id       = f.id;
                hvx.key      = f.key;
                hvx.dirhash  = f.dirhash;
                hvx.filehash = f.filehash;
                groups[it->second].emplace_back(std::move(fh), hvx);
            }

            std::vector<std::uint8_t> out;
            out.push_back(0x81);
            write_i32_be(out, static_cast<std::int32_t>(dir_hashes.size() * 2));
            for (std::size_t i = 0; i < dir_hashes.size(); ++i)
            {
                write_index_group(out, dir_hashes[i], groups[i]);
            }
            return out;
        }
    } // namespace

    auto parse_hxv4_index(std::span<const std::uint8_t> archive, const index_entry& hxv4, params& p) -> std::vector<hvx_entry>
    {
        const auto [offset, fsize, flags] = hxv4_descriptor(hxv4);
        if (offset + fsize > archive.size())
        {
            detail::fail("HxV4 index blob out of range");
        }
        std::copy_n(archive.begin() + static_cast<std::ptrdiff_t>(offset), 16, p.blob_prefix.begin());

        std::vector<std::uint8_t> enc(archive.begin() + static_cast<std::ptrdiff_t>(offset + 16), archive.begin() + static_cast<std::ptrdiff_t>(offset + fsize));
        crypto::chacha20 ch{ p.index_key, std::span<const std::uint8_t, 8>{ p.index_nonce.data(), 8 }, 1 };
        ch.xor_stream(enc);
        if (enc.size() < 4)
        {
            detail::fail("HxV4 index blob too small");
        }
        std::copy_n(enc.begin(), 4, p.blob_header.begin());
        p.blob_flags = flags;

        std::cout << "[dbg] hxv4 offset=" << std::hex << offset << " fsize=" << fsize
                  << " prefix=" << krkr::to_hex(p.blob_prefix)
                  << " header=" << krkr::to_hex(p.blob_header) << std::dec << "\n";
        std::cout << "[dbg] key=" << krkr::to_hex(p.index_key)
                  << " nonce=" << krkr::to_hex(p.index_nonce) << "\n";
        std::cout << "[dbg] enc[0:32]=" << krkr::to_hex(std::span<const std::uint8_t>{ enc.data(), std::min<std::size_t>(32, enc.size()) }) << "\n";

        const auto index_data = inflate(std::span<const std::uint8_t>{ enc }.subspan(4));
        std::uint32_t       pos         = 0;
        const obj root        = read_object(index_data, pos);

        const auto* arr = std::get_if<std::vector<obj>>(&root);
        if (!arr)
        {
            detail::fail("HxV4 index root is not an array");
        }

        std::vector<hvx_entry> out;
        for (std::size_t i = 0; i + 1 < arr->size(); i += 2)
        {
            const auto& dirhash = *std::get_if<std::vector<std::uint8_t>>(&(*arr)[i]);
            const auto* sub     = std::get_if<std::vector<obj>>(&(*arr)[i + 1]);
            if (!sub)
            {
                detail::fail("HxV4 index malformed");
            }
            for (std::size_t j = 0; j + 1 < sub->size(); j += 2)
            {
                const auto& filehash = *std::get_if<std::vector<std::uint8_t>>(&(*sub)[j]);
                const auto* entry    = std::get_if<std::vector<obj>>(&(*sub)[j + 1]);
                if (!entry || entry->size() < 2)
                {
                    detail::fail("HxV4 index malformed");
                }
                hvx_entry e;
                e.id       = std::get<std::uint64_t>((*entry)[0]);
                e.key      = std::get<std::uint64_t>((*entry)[1]);
                e.fakename = convert_fakename(e.id);
                std::copy_n(dirhash.begin(), 8, e.dirhash.begin());
                std::copy_n(filehash.begin(), 32, e.filehash.begin());
                out.push_back(std::move(e));
            }
        }
        return out;
    }

    // ---------------------------------------------------------------------------
    // text handling.
    // ---------------------------------------------------------------------------
    namespace
    {
        auto swapbit(std::uint16_t d) -> std::uint16_t
        {
            return static_cast<std::uint16_t>(((d & 0xaaaa) >> 1) | ((d & 0x5555) << 1));
        }

        // Inverse of the krkr decrypt_text transformation (involution).
        auto text_transform(std::vector<std::uint8_t>& data, int enc_type) -> void
        {
            for (std::size_t i = 0; i + 1 < data.size(); i += 2)
            {
                std::uint16_t d = krkr::read_u16_le(data, i);
                if (enc_type == 1)
                {
                    d = swapbit(d);
                }
                else if (d > 0x20)
                {
                    d = static_cast<std::uint16_t>(d ^ static_cast<std::uint16_t>(((d & 0xfe) << 8) ^ 1));
                }
                if (enc_type != 2)
                {
                    krkr::write_u16_le(data, i, d);
                }
            }
        }

        auto is_text_header(const std::vector<std::uint8_t>& segdata) -> bool
        {
            return segdata.size() > 5 && segdata[0] == 0xfe && segdata[1] == 0xfe &&
                   segdata[3] == 0xff && segdata[4] == 0xfe;
        }
    } // namespace

    // ---------------------------------------------------------------------------
    // manifest.
    // ---------------------------------------------------------------------------
    namespace
    {
        void write_manifest(const manifest& m, const std::filesystem::path& path)
        {
            std::ofstream ofs{ path, std::ios::binary };
            if (!ofs)
            {
                detail::fail("cannot write manifest: " + path.generic_string());
            }
            ofs << "# krkrhxv4 manifest (unpack/pack round-trip)\n";
            ofs << "[global]\n";
            ofs << "index_key=" << krkr::to_hex(m.c.index_key) << "\n";
            ofs << "index_nonce=" << krkr::to_hex(m.c.index_nonce) << "\n";
            ofs << "filterkey="
                << krkr::to_hex(std::span<const std::uint8_t>{ reinterpret_cast<const std::uint8_t*>(&m.c.cx.filter_key), 8 }) << "\n";
            ofs << "mask=" << m.c.cx.mask << "\n";
            ofs << "offset=" << m.c.cx.offset << "\n";
            ofs << "random_type=" << m.c.cx.random_type << "\n";
            ofs << "prolog=" << m.c.cx.prolog_order[0] << "," << m.c.cx.prolog_order[1] << "," << m.c.cx.prolog_order[2] << "\n";
            ofs << "odd=" << m.c.cx.odd_branch_order[0] << "," << m.c.cx.odd_branch_order[1] << ","
                << m.c.cx.odd_branch_order[2] << "," << m.c.cx.odd_branch_order[3] << ","
                << m.c.cx.odd_branch_order[4] << "," << m.c.cx.odd_branch_order[5] << "\n";
            ofs << "even=" << m.c.cx.even_branch_order[0] << "," << m.c.cx.even_branch_order[1] << ","
                << m.c.cx.even_branch_order[2] << "," << m.c.cx.even_branch_order[3] << ","
                << m.c.cx.even_branch_order[4] << "," << m.c.cx.even_branch_order[5] << ","
                << m.c.cx.even_branch_order[6] << "," << m.c.cx.even_branch_order[7] << "\n";
            std::vector<std::uint8_t> cb;
            cb.reserve(m.c.cx.control_block.size() * 4);
            for (const std::uint32_t w : m.c.cx.control_block)
            {
                write_u32_le(cb, w);
            }
            ofs << "control_block=" << krkr::to_hex(cb) << "\n";
            ofs << "blob_prefix=" << krkr::to_hex(m.c.blob_prefix) << "\n";
            ofs << "blob_header=" << krkr::to_hex(m.c.blob_header) << "\n";
            ofs << "blob_flags=" << m.c.blob_flags << "\n";
            ofs << "index_compressed=" << (m.c.index_compressed ? 1 : 0) << "\n";
            ofs << "[entries]\n";
            for (const auto& f : m.files)
            {
                std::vector<std::uint8_t> name16;
                for (const std::uint16_t c : f.fakename)
                {
                    krkr::write_u16_le(name16, c);
                }
                ofs << "path=" << f.path << "\n";
                ofs << "  name=" << krkr::to_hex(name16) << "\n";
                ofs << "  dirhash=" << krkr::to_hex(f.dirhash) << "\n";
                ofs << "  filehash=" << krkr::to_hex(f.filehash) << "\n";
                ofs << "  id=" << f.id << "\n";
                ofs << "  key=" << f.key << "\n";
                ofs << "  enc_type=" << f.enc_type << "\n";
                ofs << "  info_flags=" << f.info_flags << "\n";
                ofs << "  seg_flags=" << f.seg_flags << "\n";
                ofs << "  adlr=" << f.adlr << "\n";
            }
            ofs << "[end]\n";
        }

        auto split_key_value(const std::string& line, std::string& key, std::string& value) -> bool
        {
            const auto eq = line.find('=');
            if (eq == std::string::npos)
            {
                return false;
            }
            key   = line.substr(0, eq);
            value = line.substr(eq + 1);
            return true;
        }

        auto parse_int_list(const std::string& s, std::vector<int>& out) -> void
        {
            out.clear();
            std::size_t start = 0;
            while (start <= s.size())
            {
                const auto comma = s.find(',', start);
                const auto part  = s.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
                if (!part.empty())
                {
                    out.push_back(std::stoi(part));
                }
                if (comma == std::string::npos)
                {
                    break;
                }
                start = comma + 1;
            }
        }

        auto refine_hex(std::span<std::uint8_t> target, const std::string& hex) -> void
        {
            std::vector<std::uint8_t> h;
            if (from_hex(hex, h) && h.size() == target.size())
            {
                std::copy_n(h.begin(), target.size(), target.begin());
            }
        }

        auto read_manifest(const std::filesystem::path& path) -> manifest
        {
            std::ifstream ifs{ path, std::ios::binary };
            if (!ifs)
            {
                detail::fail("cannot open manifest: " + path.generic_string());
            }
            manifest m;
            std::vector<int> prolog, odd, even;
            bool in_global = false, in_entries = false;
            file_entry current;
            bool has_current = false;

            auto commit = [&]()
            {
                if (has_current)
                {
                    m.files.push_back(std::move(current));
                    current     = file_entry{};
                    has_current = false;
                }
            };

            std::string line;
            while (std::getline(ifs, line))
            {
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }
                if (line.empty() || line[0] == '#')
                {
                    continue;
                }
                if (line == "[global]")
                {
                    in_global = true;
                    in_entries = false;
                    continue;
                }
                if (line == "[entries]")
                {
                    in_global = false;
                    in_entries = true;
                    continue;
                }
                if (line == "[end]")
                {
                    break;
                }

                std::string key, val;
                if (!split_key_value(line, key, val))
                {
                    continue;
                }
                if (key.rfind("  ", 0) == 0)
                {
                    key = key.substr(2);
                }

                if (in_global)
                {
                    if      (key == "index_key")
                    {
                        refine_hex(m.c.index_key, val);
                    }
                    else if (key == "index_nonce")
                    {
                        refine_hex(m.c.index_nonce, val);
                    }
                    else if (key == "filterkey")
                    {
                        std::vector<std::uint8_t> h;
                        if (from_hex(val, h) && h.size() == 8)
                        {
                            std::uint64_t v = 0;
                            for (std::size_t i = 0; i < 8; ++i)
                            {
                                v |= static_cast<std::uint64_t>(h[i]) << (i * 8);
                            }
                            m.c.cx.filter_key = v;
                        }
                    }
                    else if (key == "mask")
                    {
                        m.c.cx.mask = static_cast<std::uint32_t>(std::stoull(val));
                    }
                    else if (key == "offset")
                    {
                        m.c.cx.offset = static_cast<std::uint32_t>(std::stoull(val));
                    }
                    else if (key == "random_type")
                    {
                        m.c.cx.random_type = std::stoi(val);
                    }
                    else if (key == "prolog")
                    {
                        parse_int_list(val, prolog);
                    }
                    else if (key == "odd")
                    {
                        parse_int_list(val, odd);
                    }
                    else if (key == "even")
                    {
                        parse_int_list(val, even);
                    }
                    else if (key == "control_block")
                    {
                        std::vector<std::uint8_t> h;
                        if (from_hex(val, h))
                        {
                            m.c.cx.control_block.resize(h.size() / 4);
                            for (std::size_t i = 0; i < m.c.cx.control_block.size(); ++i)
                            {
                                m.c.cx.control_block[i] = krkr::read_u32_le(h, i * 4);
                            }
                        }
                    }
                    else if (key == "blob_prefix")
                    {
                        refine_hex(m.c.blob_prefix, val);
                    }
                    else if (key == "blob_header")
                    {
                        refine_hex(m.c.blob_header, val);
                    }
                    else if (key == "blob_flags")
                    {
                        m.c.blob_flags = static_cast<std::int16_t>(std::stoi(val));
                    }
                    else if (key == "index_compressed")
                    {
                        m.c.index_compressed = (val == "1");
                    }
                }
                else if (in_entries)
                {
                    if      (key == "path")
                    {
                        commit();
                        current.path = val;
                        has_current = true;
                    }
                    else if (key == "name")
                    {
                        std::vector<std::uint8_t> h;
                        if (from_hex(val, h))
                        {
                            current.fakename.assign(reinterpret_cast<const char16_t*>(h.data()), h.size() / 2);
                        }
                    }
                    else if (key == "dirhash")
                    {
                        std::vector<std::uint8_t> h;
                        if (from_hex(val, h) && h.size() == 8)
                        {
                            std::copy_n(h.begin(), 8, current.dirhash.begin());
                        }
                    }
                    else if (key == "filehash")
                    {
                        std::vector<std::uint8_t> h;
                        if (from_hex(val, h) && h.size() == 32)
                        {
                            std::copy_n(h.begin(), 32, current.filehash.begin());
                        }
                    }
                    else if (key == "id")
                    {
                        current.id = std::stoull(val);
                    }
                    else if (key == "key")
                    {
                        current.key = std::stoull(val);
                    }
                    else if (key == "enc_type")
                    {
                        current.enc_type = std::stoi(val);
                    }
                    else if (key == "info_flags")
                    {
                        current.info_flags = static_cast<std::uint32_t>(std::stoul(val));
                    }
                    else if (key == "seg_flags")
                    {
                        current.seg_flags = static_cast<std::uint32_t>(std::stoul(val));
                    }
                    else if (key == "adlr")
                    {
                        current.adlr = static_cast<std::uint32_t>(std::stoul(val));
                    }
                }
            }
            commit();

            if (prolog.size() >= 3)
            {
                std::copy_n(prolog.begin(), 3, m.c.cx.prolog_order.begin());
            }
            if (odd.size() >= 6)
            {
                std::copy_n(odd.begin(), 6, m.c.cx.odd_branch_order.begin());
            }
            if (even.size() >= 8)
            {
                std::copy_n(even.begin(), 8, m.c.cx.even_branch_order.begin());
            }
            return m;
        }
    } // namespace

    // ---------------------------------------------------------------------------
    // unpack.
    // ---------------------------------------------------------------------------
    auto unpack(const std::filesystem::path& inpath, const std::filesystem::path& outdir, const params& p, bool hash_names) -> manifest
    {
        const auto archive = read_file(inpath);
        auto       entries = parse_index(archive);

        const index_entry* hxv4 = nullptr;
        for (const auto& e : entries)
        {
            if (e.sig == "Hxv4")
            {
                hxv4 = &e;
            }
        }
        if (!hxv4)
        {
            detail::fail("no Hxv4 entry found in xp3");
        }

        manifest m;
        m.c = p;
        m.c.index_compressed = (index_offset_of(archive) < archive.size()) && archive[index_offset_of(archive)] == 1;

        const auto hvx = parse_hxv4_index(archive, *hxv4, m.c);

        std::map<std::u16string, const index_entry&> by_name;
        for (const auto& e : entries)
        {
            if (e.sig == "File" && !e.name.empty())
            {
                by_name.emplace(e.name, e);
            }
        }

        cx::cipher cipher{ m.c.cx };
        make_dirs(outdir);

        for (const auto& h : hvx)
        {
            auto it = by_name.find(h.fakename);
            if (it == by_name.end())
            {
                detail::fail("cannot find xp3 entry for fakename");
            }
            const index_entry& entry = it->second;

            std::vector<std::uint8_t> outdata;
            const auto      fk       = cipher.derive(h.key, h.id);
            int             enc_type = -1;
            for (const auto& segm : entry.segms)
            {
                if (segm.offset + segm.zsize > archive.size())
                {
                    detail::fail("segment out of range");
                }
                std::vector<std::uint8_t> segdata(archive.begin() + static_cast<std::ptrdiff_t>(segm.offset), archive.begin() + static_cast<std::ptrdiff_t>(segm.offset + segm.zsize));
                if ((segm.flags & kSegmEncodeMethodMask) == kSegmEncodeZlib)
                {
                    segdata = inflate(segdata);
                }
                cipher.content_crypt(fk, segdata);

                if (is_text_header(segdata))
                {
                    const int t        = segdata[2];
                    enc_type           = t;
                    std::vector<std::uint8_t> body(segdata.begin() + 5, segdata.end());
                    if (t == 2)
                    {
                        const auto dec = inflate(std::span<const std::uint8_t>{ body }.subspan(16));
                        outdata.insert(outdata.end(), dec.begin(), dec.end());
                    }
                    else
                    {
                        text_transform(body, t);
                        outdata.push_back(0xff);
                        outdata.push_back(0xfe);
                        outdata.insert(outdata.end(), body.begin(), body.end());
                    }
                }
                else
                {
                    outdata.insert(outdata.end(), segdata.begin(), segdata.end());
                }
            }

            std::string subpath;
            std::filesystem::path    disk_subpath;
            if (hash_names)
            {
                subpath      = krkr::to_hex(h.dirhash) + "/" + krkr::to_hex(h.filehash);
                disk_subpath = std::filesystem::path{ subpath };
            }
            else
            {
                subpath      = utf16_to_utf8(h.fakename);
                disk_subpath = std::filesystem::path{ h.fakename.begin(), h.fakename.end() };
            }
            write_file(outdir / disk_subpath, outdata);

            file_entry fe;
            fe.path       = subpath;
            fe.fakename   = h.fakename;
            fe.dirhash    = h.dirhash;
            fe.filehash   = h.filehash;
            fe.id         = h.id;
            fe.key        = h.key;
            fe.enc_type   = enc_type;
            fe.info_flags = entry.info_flags;
            fe.seg_flags  = entry.segms.empty() ? 0 : entry.segms[0].flags;
            fe.adlr       = entry.adlr;
            m.files.push_back(std::move(fe));
        }
        return m;
    }

    // ---------------------------------------------------------------------------
    // pack.
    // ---------------------------------------------------------------------------
    namespace
    {
        struct written
        {
            std::u16string name;
            std::uint64_t  offset;
            std::int64_t   fsize;
            std::int64_t   zsize;
            std::uint32_t  info_flags;
            std::uint32_t  seg_flags;
            std::uint32_t  adlr;
        };

        // Serializes the whole archive body (header + segments + HxV4 blob + index)
        // for the given files, reading their payloads from `outdir`/`path`.
        auto build_archive(const params& c, const std::vector<file_entry>& files, const std::filesystem::path& outdir) -> std::vector<std::uint8_t>
        {
            cx::cipher cipher{ c.cx };

            std::vector<std::uint8_t> content;
            content.reserve(1 << 20);
            content.insert(content.end(), kXp3Sig.begin(), kXp3Sig.end());
            content.resize(content.size() + 8, 0); // index offset placeholder

            std::vector<written> wfiles;
            wfiles.reserve(files.size());

            for (const auto& f : files)
            {
                const auto rel16 = utf8_to_utf16(f.path);
                auto       data  = read_file(outdir / std::filesystem::path{ rel16.begin(), rel16.end() });

                std::vector<std::uint8_t> stored;
                if (f.enc_type >= 0)
                {
                    stored.push_back(0xfe);
                    stored.push_back(0xfe);
                    stored.push_back(static_cast<std::uint8_t>(f.enc_type));
                    stored.push_back(0xff);
                    stored.push_back(0xfe);
                    if (f.enc_type == 2)
                    {
                        const auto compressed = deflate(data);
                        write_u64_le(stored, static_cast<std::uint64_t>(compressed.size()));
                        write_u64_le(stored, static_cast<std::uint64_t>(data.size()));
                        stored.insert(stored.end(), compressed.begin(), compressed.end());
                    }
                    else
                    {
                        std::vector<std::uint8_t> body(data.begin() + 2, data.end()); // strip BOM
                        if (data.size() < 2 || data[0] != 0xff || data[1] != 0xfe)
                        {
                            body = data;
                        }
                        text_transform(body, f.enc_type);
                        stored.insert(stored.end(), body.begin(), body.end());
                    }
                }
                else
                {
                    stored = std::move(data);
                }

                if (!f.plain_name)
                {
                    cipher.content_crypt(cipher.derive(f.key, f.id), stored);
                }
                const std::int64_t fsize = static_cast<std::int64_t>(stored.size());

                const bool compress = (f.seg_flags & kSegmEncodeMethodMask) == kSegmEncodeZlib;
                std::vector<std::uint8_t> payload;
                if (compress)
                {
                    payload = deflate(stored);
                }
                else
                {
                    payload = std::move(stored);
                }

                written w;
                w.name       = f.fakename;
                w.offset     = content.size();
                w.fsize      = fsize;
                w.zsize      = static_cast<std::int64_t>(payload.size());
                w.info_flags = f.info_flags;
                w.seg_flags  = f.seg_flags;
                w.adlr       = f.adlr;
                wfiles.push_back(w);
                content.insert(content.end(), payload.begin(), payload.end());
            }

            // HxV4 index blob
            const auto blob_raw      = serialize_index(files);
            const auto blob_zlib     = deflate(blob_raw);
            std::vector<std::uint8_t> decblob;
            // 4-byte header = inflated index size (little endian), as in the original.
            write_u32_le(decblob, static_cast<std::uint32_t>(blob_raw.size()));
            decblob.insert(decblob.end(), blob_zlib.begin(), blob_zlib.end());
            const std::span<const std::uint8_t, 8> nonce8{ c.index_nonce.data(), 8 };
            crypto::chacha20 ch{ c.index_key, nonce8, 1 };
            ch.xor_stream(decblob);
            // The engine verifies the Poly1305 tag over the encrypted payload
            // before decrypting (sub_1001F950): emit it as the blob prefix.
            const auto tag = crypto::index_blob_tag(c.index_key, nonce8, decblob);
            std::vector<std::uint8_t> blob(tag.begin(), tag.end());
            blob.insert(blob.end(), decblob.begin(), decblob.end());
            const std::uint64_t blob_offset = content.size();
            content.insert(content.end(), blob.begin(), blob.end());

            // index entry stream
            std::vector<std::uint8_t> index_stream;
            // Hxv4 entry (14 bytes payload)
            const char hxv4_sig[4] = { 'H', 'x', 'v', '4' };
            index_stream.insert(index_stream.end(), hxv4_sig, hxv4_sig + 4);
            write_u64_le(index_stream, 14);
            write_u64_le(index_stream, blob_offset);
            write_u32_le(index_stream, static_cast<std::uint32_t>(blob.size()));
            krkr::write_u16_le(index_stream, static_cast<std::uint16_t>(c.blob_flags));

            // File entries
            for (const auto& w : wfiles)
            {
                const auto name16 = utf16_le_bytes(w.name);
                // compute sizes
                const std::size_t info_payload = 22 + 2 * (w.name.size() + 1);
                const std::int64_t entry_size  = (12 + 4) + (12 + 28) + (12 + static_cast<std::int64_t>(info_payload));

                const char file_sig[4] = { 'F', 'i', 'l', 'e' };
                index_stream.insert(index_stream.end(), file_sig, file_sig + 4);
                write_u64_le(index_stream, static_cast<std::uint64_t>(entry_size));

                // adlr
                index_stream.insert(index_stream.end(), { 'a', 'd', 'l', 'r' });
                write_u64_le(index_stream, 4);
                write_u32_le(index_stream, w.adlr);
                // segm
                index_stream.insert(index_stream.end(), { 's', 'e', 'g', 'm' });
                write_u64_le(index_stream, 28);
                write_u32_le(index_stream, w.seg_flags);
                write_u64_le(index_stream, w.offset);
                write_u64_le(index_stream, static_cast<std::uint64_t>(w.fsize));
                write_u64_le(index_stream, static_cast<std::uint64_t>(w.zsize));
                // info
                index_stream.insert(index_stream.end(), { 'i', 'n', 'f', 'o' });
                write_u64_le(index_stream, static_cast<std::uint64_t>(info_payload));
                write_u32_le(index_stream, w.info_flags);
                write_u64_le(index_stream, static_cast<std::uint64_t>(w.fsize));
                write_u64_le(index_stream, static_cast<std::uint64_t>(w.zsize));
                krkr::write_u16_le(index_stream, static_cast<std::uint16_t>(w.name.size()));
                index_stream.insert(index_stream.end(), name16.begin(), name16.end());
                index_stream.push_back(0);
                index_stream.push_back(0);
            }

            // write index
            const std::uint64_t index_offset = content.size();
            write_u64_le(content, 11, index_offset);
            if (c.index_compressed)
            {
                content.push_back(0x01);
                const auto comp = deflate(index_stream);
                write_u64_le(content, static_cast<std::uint64_t>(comp.size()));
                write_u64_le(content, static_cast<std::uint64_t>(index_stream.size()));
                content.insert(content.end(), comp.begin(), comp.end());
            }
            else
            {
                content.push_back(0x00);
                write_u64_le(content, static_cast<std::uint64_t>(index_stream.size()));
                content.insert(content.end(), index_stream.begin(), index_stream.end());
            }

            return content;
        }

        auto adler32_update(std::uint32_t adler, std::span<const std::uint8_t> data) -> std::uint32_t
        {
            constexpr std::uint32_t base = 65521;
            std::uint32_t           s1   = adler & 0xffff;
            std::uint32_t           s2   = (adler >> 16) & 0xffff;
            for (const auto b : data)
            {
                s1 = (s1 + b) % base;
                s2 = (s2 + s1) % base;
            }
            return (s2 << 16) | s1;
        }

        // ASCII lowercase over UTF-16 code units (matches the game's storage
        // normalization; non-ASCII code units are left untouched).
        auto to_lower_u16(std::u16string_view text) -> std::u16string
        {
            std::u16string out{ text };
            for (auto& c : out)
            {
                if (c >= 0x41 && c <= 0x5a)
                {
                    c = static_cast<char16_t>(c + 0x20);
                }
            }
            return out;
        }

        // Splits a '/' separated relative path into (dir with trailing '/', leaf name),
        // both lowercased for hashing. Root-level files yield an empty dir.
        auto convert_paths_u16(std::u16string_view rel) -> std::pair<std::u16string, std::u16string>
        {
            const auto slash = rel.find_last_of(u'/');
            if (slash == std::u16string_view::npos)
            {
                return { {}, to_lower_u16(rel) };
            }
            return { to_lower_u16(rel.substr(0, slash + 1)), to_lower_u16(rel.substr(slash + 1)) };
        }
    } // namespace

    auto pack(const std::filesystem::path& manifest_path, const std::filesystem::path& outdir, const std::filesystem::path& outpath) -> void
    {
        const auto m       = read_manifest(manifest_path);
        const auto content = build_archive(m.c, m.files, outdir);
        write_file(outpath, content);
    }

    auto pack_dir(const std::filesystem::path& indir, const params& p, const std::filesystem::path& outpath) -> void
    {
        std::vector<file_entry> files;
        std::uint64_t           id = 0;
        for (const auto& de : std::filesystem::recursive_directory_iterator{ indir })
        {
            if (!de.is_regular_file())
            {
                continue;
            }

            // Keep the on-disk relative path in UTF-16 (round-trips through the
            // manifest's UTF-8 form) and compute the hashes over the lowercased
            // dir/file names, exactly as the game's HxV4 storage does.
            const auto rel16 = de.path().lexically_relative(indir).generic_u16string();

            // A leading '.' on the on-disk leaf marks a plaintext-named entry
            // (".startup.tjs" -> "startup.tjs").  The original archives carry
            // such entries NEXT TO the regular hash-resolved one: the payload
            // is stored unencrypted and zlib-compressed, the xp3 index holds
            // the real name, and the entry is NOT registered in the hash
            // index.  The engine resolves the file through its hash slot,
            // which points at the regular fakename twin emitted below.
            const auto slash    = rel16.find_last_of(u'/');
            const auto leaf     = rel16.substr(slash + 1);
            const bool is_plain = leaf.size() > 1 && leaf.front() == u'.';
            const auto real     = leaf.substr(1);
            const auto rel_hash = is_plain ? (slash == std::u16string::npos ? real : rel16.substr(0, slash + 1) + real)
                                           : rel16;

            const auto [dir, name] = convert_paths_u16(rel_hash);

            if (is_plain)
            {
                file_entry plain;
                plain.path       = utf16_to_utf8(rel16);
                plain.id         = id;
                plain.key        = id + 1; // unused: not hash-registered
                plain.fakename   = real;
                plain.plain_name = true;
                plain.enc_type   = -1; // binary, no text transform
                plain.info_flags = kFileProtected;
                plain.seg_flags  = kSegmEncodeZlib;
                plain.dirhash    = crypto::dirhash(dir);
                plain.filehash   = crypto::filehash(name);
                plain.adlr       = adler32_update(1, read_file(de.path()));
                files.push_back(std::move(plain));
            }

            file_entry f;
            f.path       = utf16_to_utf8(rel16);
            f.id         = id;
            f.key        = id + 1;
            f.fakename   = convert_fakename(f.id);
            f.enc_type   = -1; // binary, no text transform
            f.info_flags = kFileProtected;
            f.seg_flags  = kSegmEncodeRaw;

            f.dirhash  = crypto::dirhash(dir);
            f.filehash = crypto::filehash(name);

            const auto data = read_file(de.path());
            f.adlr          = adler32_update(1, data);

            files.push_back(std::move(f));
            ++id;
        }

        const auto content = build_archive(p, files, indir);
        write_file(outpath, content);
    }

    auto save_manifest(const manifest& m, const std::filesystem::path& path) -> void { write_manifest(m, path); }
    auto load_manifest(const std::filesystem::path& path) -> manifest { return read_manifest(path); }
} // namespace krkr::xp3