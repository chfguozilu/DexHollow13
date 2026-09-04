#include <zlib.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>

#include "dexhollow13/base/error.h"
#include "dexhollow13/bootstrap/bootstrap_format.h"

namespace dexhollow13::bootstrap {
namespace {

std::uint32_t ComputeCrc32(const std::uint8_t* data, std::size_t size) {
    uLong crc = crc32(0L, Z_NULL, 0U);
    const std::uint8_t* cursor = data;
    std::size_t remaining = size;
    while (remaining != 0U) {
        const std::size_t chunk =
            std::min(remaining, static_cast<std::size_t>(std::numeric_limits<uInt>::max()));
        crc = crc32(crc, cursor, static_cast<uInt>(chunk));
        cursor += chunk;
        remaining -= chunk;
    }
    return static_cast<std::uint32_t>(crc);
}

std::string ReadString(const ByteView& bytes, std::size_t& cursor, std::uint32_t length,
                       const std::string& purpose) {
    const char* start = reinterpret_cast<const char*>(bytes.DataAt(cursor, length, purpose));
    cursor += length;
    return std::string(start, length);
}

void SkipAlignment(const ByteView& bytes, std::size_t& cursor, const std::string& purpose) {
    while ((cursor & 3U) != 0U) {
        if (bytes.ReadU8(cursor, purpose) != 0U) {
            throw Error(purpose + " 的 alignment padding 必须为 0");
        }
        ++cursor;
    }
}

}  // namespace

BootstrapFile ReadBootstrap(const ByteView& bytes) {
    bytes.CheckRange(0U, kBootstrapHeaderSize, "bootstrap header");
    if (!std::equal(kBootstrapMagic.begin(), kBootstrapMagic.end(),
                    bytes.DataAt(0U, kBootstrapMagic.size(), "bootstrap magic"))) {
        throw Error("bootstrap magic 不正确");
    }

    const std::uint32_t version = bytes.ReadU32(8U, "bootstrap version");
    const std::uint32_t header_size = bytes.ReadU32(12U, "bootstrap header_size");
    const std::uint32_t flags = bytes.ReadU32(16U, "bootstrap flags");
    const std::uint32_t dex_count = bytes.ReadU32(20U, "bootstrap dex_count");
    const std::uint32_t package_length = bytes.ReadU32(24U, "bootstrap package_length");
    const std::uint32_t application_length = bytes.ReadU32(28U, "bootstrap application_length");
    const std::uint32_t factory_length = bytes.ReadU32(32U, "bootstrap factory_length");
    const std::uint32_t file_size = bytes.ReadU32(36U, "bootstrap file_size");
    const std::uint32_t stored_crc = bytes.ReadU32(40U, "bootstrap body_crc32");
    const std::uint32_t reserved = bytes.ReadU32(44U, "bootstrap reserved");

    if (version != kBootstrapVersion || header_size != kBootstrapHeaderSize || flags != 0U ||
        reserved != 0U || dex_count == 0U || file_size != bytes.size()) {
        throw Error("bootstrap Header 字段不受支持或文件大小不一致");
    }

    const ByteView body = bytes.Subview(kBootstrapHeaderSize, bytes.size() - kBootstrapHeaderSize,
                                        "bootstrap CRC body");
    if (stored_crc != ComputeCrc32(body.data(), body.size())) {
        throw Error("bootstrap CRC32 不正确");
    }

    BootstrapFile bootstrap;
    std::size_t cursor = kBootstrapHeaderSize;
    bootstrap.package_name = ReadString(bytes, cursor, package_length, "package_name");
    bootstrap.original_application =
        ReadString(bytes, cursor, application_length, "original_application");
    bootstrap.original_app_component_factory =
        ReadString(bytes, cursor, factory_length, "original_app_component_factory");
    SkipAlignment(bytes, cursor, "bootstrap strings");

    if (bootstrap.package_name.empty() || bootstrap.original_application.empty()) {
        throw Error("bootstrap package/application 不能为空");
    }

    bootstrap.dex_files.reserve(dex_count);
    std::unordered_set<std::uint32_t> ordinals;
    for (std::uint32_t index = 0U; index < dex_count; ++index) {
        bytes.CheckRange(cursor, kDexRecordHeaderSize, "bootstrap DEX record");
        const std::size_t record = cursor;
        DexRecord dex_record;
        dex_record.ordinal = bytes.ReadU32(record, "record.ordinal");
        dex_record.protected_method_count = bytes.ReadU32(record + 4U, "record.method_count");
        const std::uint32_t dex_name_length = bytes.ReadU32(record + 8U, "record.dex_name_length");
        const std::uint32_t payload_name_length =
            bytes.ReadU32(record + 12U, "record.payload_name_length");
        const std::uint32_t record_flags = bytes.ReadU32(record + 16U, "record.flags");
        const std::uint32_t record_reserved = bytes.ReadU32(record + 20U, "record.reserved");
        if (record_flags != 0U || record_reserved != 0U ||
            !ordinals.insert(dex_record.ordinal).second) {
            throw Error("bootstrap DEX record 的 flag/reserved/ordinal 非法");
        }

        std::copy_n(bytes.DataAt(record + 24U, 20U, "record.original_signature"), 20U,
                    dex_record.original_dex_signature.begin());
        std::copy_n(bytes.DataAt(record + 44U, 20U, "record.hollow_signature"), 20U,
                    dex_record.hollow_dex_signature.begin());
        cursor += kDexRecordHeaderSize;
        dex_record.hollow_dex_asset =
            ReadString(bytes, cursor, dex_name_length, "record.hollow_dex_asset");
        dex_record.payload_asset =
            ReadString(bytes, cursor, payload_name_length, "record.payload_asset");
        SkipAlignment(bytes, cursor, "bootstrap DEX record");

        if (dex_record.hollow_dex_asset.empty() || dex_record.payload_asset.empty()) {
            throw Error("bootstrap DEX asset 名称不能为空");
        }
        bootstrap.dex_files.push_back(std::move(dex_record));
    }

    if (cursor != bytes.size()) {
        throw Error("bootstrap 最后一个 DEX record 后存在未定义数据");
    }
    return bootstrap;
}

}  // namespace dexhollow13::bootstrap
