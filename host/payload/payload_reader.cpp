#include <zlib.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <unordered_set>

#include "dexhollow13/base/error.h"
#include "dexhollow13/payload/payload_format.h"

namespace dexhollow13::payload {
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

bool IsKnownStubKind(std::uint32_t value) {
    return value >= static_cast<std::uint32_t>(dex::StubKind::kReturnVoid) &&
           value <= static_cast<std::uint32_t>(dex::StubKind::kConstructorPrefixReturnVoid);
}

}  // namespace

PayloadView ReadPayloadView(const ByteView& bytes) {
    bytes.CheckRange(0U, kPayloadHeaderSize, "Payload header");
    if (!std::equal(kPayloadMagic.begin(), kPayloadMagic.end(),
                    bytes.DataAt(0U, kPayloadMagic.size(), "Payload magic"))) {
        throw Error("Payload magic 不正确");
    }

    const std::uint32_t version = bytes.ReadU32(8U, "Payload version");
    const std::uint32_t header_size = bytes.ReadU32(12U, "Payload header_size");
    const std::uint32_t endian_tag = bytes.ReadU32(16U, "Payload endian_tag");
    const std::uint32_t flags = bytes.ReadU32(20U, "Payload flags");
    const std::uint32_t dex_ordinal = bytes.ReadU32(24U, "Payload dex_ordinal");
    const std::uint32_t method_count = bytes.ReadU32(28U, "Payload method_count");
    const std::uint32_t record_size = bytes.ReadU32(32U, "Payload record_size");
    const std::uint32_t records_offset = bytes.ReadU32(36U, "Payload records_offset");
    const std::uint32_t data_offset = bytes.ReadU32(40U, "Payload data_offset");
    const std::uint32_t file_size = bytes.ReadU32(44U, "Payload file_size");
    const std::uint32_t stored_crc = bytes.ReadU32(48U, "Payload payload_crc32");
    const std::uint32_t reserved = bytes.ReadU32(52U, "Payload reserved");

    if (version != kPayloadVersion || header_size != kPayloadHeaderSize ||
        endian_tag != kPayloadEndianTag || flags != 0U || record_size != kPayloadRecordSize ||
        records_offset != kPayloadHeaderSize || reserved != 0U) {
        throw Error("Payload Header 版本、大小、端序或保留字段不受支持");
    }
    if (file_size != bytes.size()) {
        throw Error("Payload file_size 与真实文件大小不一致");
    }

    const std::size_t records_bytes = CheckedMultiply(static_cast<std::size_t>(method_count),
                                                      kPayloadRecordSize, "Payload records");
    bytes.CheckRange(records_offset, records_bytes, "Payload record array");
    if (data_offset < static_cast<std::uint64_t>(records_offset) + records_bytes ||
        data_offset > bytes.size() || (data_offset & 3U) != 0U) {
        throw Error("Payload data_offset 非法");
    }

    const ByteView crc_region =
        bytes.Subview(records_offset, bytes.size() - records_offset, "Payload CRC region");
    if (stored_crc != ComputeCrc32(crc_region.data(), crc_region.size())) {
        throw Error("Payload CRC32 不正确");
    }

    PayloadView payload;
    payload.dex_ordinal = dex_ordinal;
    std::copy_n(bytes.DataAt(56U, 20U, "original_dex_signature"), 20U,
                payload.original_dex_signature.begin());
    std::copy_n(bytes.DataAt(76U, 20U, "hollow_dex_signature"), 20U,
                payload.hollow_dex_signature.begin());
    payload.methods.reserve(method_count);

    std::unordered_set<std::uint32_t> method_indices;
    for (std::uint32_t index = 0U; index < method_count; ++index) {
        const std::size_t record = static_cast<std::size_t>(records_offset) +
                                   static_cast<std::size_t>(index) * kPayloadRecordSize;
        MethodPayloadView method;
        method.method_idx = bytes.ReadU32(record, "record.method_idx");
        method.original_code_off = bytes.ReadU32(record + 4U, "record.original_code_off");
        const std::uint32_t code_item_size = bytes.ReadU32(record + 8U, "record.code_item_size");
        const std::uint32_t method_data_offset = bytes.ReadU32(record + 12U, "record.data_offset");
        method.insns_size = bytes.ReadU32(record + 16U, "record.insns_size");
        method.access_flags = bytes.ReadU32(record + 20U, "record.access_flags");
        const std::uint32_t stub_kind = bytes.ReadU32(record + 24U, "record.stub_kind");
        method.flags = bytes.ReadU32(record + 28U, "record.flags");
        const std::uint32_t code_crc = bytes.ReadU32(record + 32U, "record.code_crc32");
        const std::uint32_t record_reserved = bytes.ReadU32(record + 36U, "record.reserved");

        if (!method_indices.insert(method.method_idx).second) {
            throw Error("Payload 中出现重复 method_idx");
        }
        if (!IsKnownStubKind(stub_kind) || record_reserved != 0U || code_item_size == 0U ||
            method_data_offset < data_offset || (method_data_offset & 3U) != 0U) {
            throw Error("Payload method record 包含非法字段");
        }
        bytes.CheckRange(method_data_offset, code_item_size, "Payload code_item");

        const std::uint8_t* code_begin =
            bytes.DataAt(method_data_offset, code_item_size, "Payload code_item data");
        if (code_crc != ComputeCrc32(code_begin, code_item_size)) {
            throw Error("Payload method code_item CRC32 不正确");
        }

        method.stub_kind = static_cast<dex::StubKind>(stub_kind);
        method.code_item_size = code_item_size;
        method.code_item = code_begin;
        payload.methods.push_back(std::move(method));
    }

    return payload;
}

PayloadFile ReadPayload(const ByteView& bytes) {
    // 所有格式校验只保留一份实现。Host 的拥有型结果在 View 校验成功后再逐项复制，避免
    // Runtime 与 Host 因两套 parser 演进不同步而接受不同的 Payload。
    const PayloadView view = ReadPayloadView(bytes);
    PayloadFile payload;
    payload.dex_ordinal = view.dex_ordinal;
    payload.original_dex_signature = view.original_dex_signature;
    payload.hollow_dex_signature = view.hollow_dex_signature;
    payload.methods.reserve(view.methods.size());
    for (const MethodPayloadView& source : view.methods) {
        MethodPayload method;
        method.method_idx = source.method_idx;
        method.original_code_off = source.original_code_off;
        method.insns_size = source.insns_size;
        method.access_flags = source.access_flags;
        method.stub_kind = source.stub_kind;
        method.flags = source.flags;
        method.code_item.assign(source.code_item, source.code_item + source.code_item_size);
        payload.methods.push_back(std::move(method));
    }
    return payload;
}

}  // namespace dexhollow13::payload
