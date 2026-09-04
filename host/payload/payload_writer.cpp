#include <zlib.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <unordered_set>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"
#include "dexhollow13/payload/payload_format.h"

namespace dexhollow13::payload {
namespace {

void AppendU32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

void AppendZeros(std::vector<std::uint8_t>& output, std::size_t count) {
    output.insert(output.end(), count, 0U);
}

void AlignToFour(std::vector<std::uint8_t>& output) {
    while ((output.size() & 3U) != 0U) {
        output.push_back(0U);
    }
}

std::uint32_t CheckedU32(std::size_t value, const std::string& purpose) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw Error(purpose + " 超过 Payload uint32_t 可表示范围");
    }
    return static_cast<std::uint32_t>(value);
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

std::vector<std::uint8_t> WritePayload(const PayloadFile& payload) {
    if (payload.methods.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw Error("Payload 方法数量超过 uint32_t 范围");
    }

    std::unordered_set<std::uint32_t> method_indices;
    for (const MethodPayload& method : payload.methods) {
        if (!method_indices.insert(method.method_idx).second) {
            throw Error("Payload 中出现重复 method_idx");
        }
        if (method.code_item.empty()) {
            throw Error("Payload 中的 code_item 不能为空");
        }
    }

    const std::size_t records_bytes =
        CheckedMultiply(payload.methods.size(), kPayloadRecordSize, "Payload records size");
    const std::size_t data_offset_size = kPayloadHeaderSize + records_bytes;
    const std::uint32_t data_offset = CheckedU32(data_offset_size, "Payload data_offset");

    // 先预留 Header 和 records。每个 record 的 data_offset 只有在附加 code_item 时才能确定，
    // 因此稍后通过 MutableByteView 回填。
    std::vector<std::uint8_t> output;
    output.reserve(data_offset_size);
    output.insert(output.end(), kPayloadMagic.begin(), kPayloadMagic.end());
    AppendU32(output, kPayloadVersion);
    AppendU32(output, static_cast<std::uint32_t>(kPayloadHeaderSize));
    AppendU32(output, kPayloadEndianTag);
    AppendU32(output, 0U);  // flags：为后续压缩/加密格式保留，当前必须为 0。
    AppendU32(output, payload.dex_ordinal);
    AppendU32(output, static_cast<std::uint32_t>(payload.methods.size()));
    AppendU32(output, static_cast<std::uint32_t>(kPayloadRecordSize));
    AppendU32(output, static_cast<std::uint32_t>(kPayloadHeaderSize));
    AppendU32(output, data_offset);
    AppendU32(output, 0U);  // file_size：所有 data 写完后回填。
    AppendU32(output, 0U);  // payload_crc32：覆盖 records_offset 到文件末尾。
    AppendU32(output, 0U);  // reserved。
    output.insert(output.end(), payload.original_dex_signature.begin(),
                  payload.original_dex_signature.end());
    output.insert(output.end(), payload.hollow_dex_signature.begin(),
                  payload.hollow_dex_signature.end());

    if (output.size() != kPayloadHeaderSize) {
        throw Error("内部错误：Payload Header 实际大小与格式常量不一致");
    }
    AppendZeros(output, records_bytes);

    for (std::size_t index = 0U; index < payload.methods.size(); ++index) {
        const MethodPayload& method = payload.methods[index];
        AlignToFour(output);
        const std::uint32_t method_data_offset = CheckedU32(output.size(), "method data_offset");
        const std::uint32_t code_item_size = CheckedU32(method.code_item.size(), "code_item_size");
        const std::uint32_t code_crc =
            ComputeCrc32(method.code_item.data(), method.code_item.size());

        output.insert(output.end(), method.code_item.begin(), method.code_item.end());

        const std::size_t record_offset = kPayloadHeaderSize + index * kPayloadRecordSize;
        MutableByteView writable(output.data(), output.size());
        writable.WriteU32(record_offset, method.method_idx, "record.method_idx");
        writable.WriteU32(record_offset + 4U, method.original_code_off, "record.original_code_off");
        writable.WriteU32(record_offset + 8U, code_item_size, "record.code_item_size");
        writable.WriteU32(record_offset + 12U, method_data_offset, "record.data_offset");
        writable.WriteU32(record_offset + 16U, method.insns_size, "record.insns_size");
        writable.WriteU32(record_offset + 20U, method.access_flags, "record.access_flags");
        writable.WriteU32(record_offset + 24U, static_cast<std::uint32_t>(method.stub_kind),
                          "record.stub_kind");
        writable.WriteU32(record_offset + 28U, method.flags, "record.flags");
        writable.WriteU32(record_offset + 32U, code_crc, "record.code_crc32");
        writable.WriteU32(record_offset + 36U, 0U, "record.reserved");
    }

    MutableByteView writable(output.data(), output.size());
    writable.WriteU32(44U, CheckedU32(output.size(), "Payload file_size"), "header.file_size");
    const ByteView crc_region = writable.AsReadOnly().Subview(
        kPayloadHeaderSize, output.size() - kPayloadHeaderSize, "Payload CRC region");
    writable.WriteU32(48U, ComputeCrc32(crc_region.data(), crc_region.size()),
                      "header.payload_crc32");
    return output;
}

}  // namespace dexhollow13::payload
