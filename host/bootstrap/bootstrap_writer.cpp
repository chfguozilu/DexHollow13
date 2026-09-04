#include <zlib.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_set>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"
#include "dexhollow13/bootstrap/bootstrap_format.h"

namespace dexhollow13::bootstrap {
namespace {

void AppendU32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

std::uint32_t CheckedU32(std::size_t value, const std::string& purpose) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw Error(purpose + " 超过 uint32_t 范围");
    }
    return static_cast<std::uint32_t>(value);
}

void AppendString(std::vector<std::uint8_t>& output, const std::string& value) {
    output.insert(output.end(), value.begin(), value.end());
}

void AlignToFour(std::vector<std::uint8_t>& output) {
    while ((output.size() & 3U) != 0U) {
        output.push_back(0U);
    }
}

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

}  // namespace

std::vector<std::uint8_t> WriteBootstrap(const BootstrapFile& bootstrap) {
    if (bootstrap.package_name.empty() || bootstrap.original_application.empty()) {
        throw Error("bootstrap 必须包含 package_name 和 original_application");
    }
    if (bootstrap.dex_files.empty()) {
        throw Error("bootstrap 至少需要一个 DEX record");
    }

    std::unordered_set<std::uint32_t> ordinals;
    for (const DexRecord& record : bootstrap.dex_files) {
        if (!ordinals.insert(record.ordinal).second) {
            throw Error("bootstrap 中出现重复 DEX ordinal");
        }
        if (record.hollow_dex_asset.empty() || record.payload_asset.empty()) {
            throw Error("bootstrap DEX record 的 asset 名称不能为空");
        }
    }

    std::vector<std::uint8_t> output;
    output.insert(output.end(), kBootstrapMagic.begin(), kBootstrapMagic.end());
    AppendU32(output, kBootstrapVersion);
    AppendU32(output, static_cast<std::uint32_t>(kBootstrapHeaderSize));
    AppendU32(output, 0U);  // flags：v1 不启用压缩或加密。
    AppendU32(output, CheckedU32(bootstrap.dex_files.size(), "bootstrap dex_count"));
    AppendU32(output, CheckedU32(bootstrap.package_name.size(), "package_name length"));
    AppendU32(output,
              CheckedU32(bootstrap.original_application.size(), "original_application length"));
    AppendU32(output,
              CheckedU32(bootstrap.original_app_component_factory.size(), "factory length"));
    AppendU32(output, 0U);  // file_size 最后回填。
    AppendU32(output, 0U);  // body_crc32 最后回填。
    AppendU32(output, 0U);  // reserved。

    if (output.size() != kBootstrapHeaderSize) {
        throw Error("内部错误：bootstrap header 大小不一致");
    }

    AppendString(output, bootstrap.package_name);
    AppendString(output, bootstrap.original_application);
    AppendString(output, bootstrap.original_app_component_factory);
    AlignToFour(output);

    for (const DexRecord& record : bootstrap.dex_files) {
        AppendU32(output, record.ordinal);
        AppendU32(output, record.protected_method_count);
        AppendU32(output, CheckedU32(record.hollow_dex_asset.size(), "hollow asset length"));
        AppendU32(output, CheckedU32(record.payload_asset.size(), "payload asset length"));
        AppendU32(output, 0U);  // record flags。
        AppendU32(output, 0U);  // record reserved。
        output.insert(output.end(), record.original_dex_signature.begin(),
                      record.original_dex_signature.end());
        output.insert(output.end(), record.hollow_dex_signature.begin(),
                      record.hollow_dex_signature.end());
        if ((output.size() & 3U) != 0U) {
            throw Error("内部错误：DEX record 固定 Header 没有 4 字节对齐");
        }
        AppendString(output, record.hollow_dex_asset);
        AppendString(output, record.payload_asset);
        AlignToFour(output);
    }

    MutableByteView writable(output.data(), output.size());
    writable.WriteU32(36U, CheckedU32(output.size(), "bootstrap file_size"), "file_size");
    const ByteView body = writable.AsReadOnly().Subview(
        kBootstrapHeaderSize, output.size() - kBootstrapHeaderSize, "bootstrap CRC body");
    writable.WriteU32(40U, ComputeCrc32(body.data(), body.size()), "body_crc32");
    return output;
}

}  // namespace dexhollow13::bootstrap
