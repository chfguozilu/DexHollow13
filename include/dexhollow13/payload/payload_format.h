#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "dexhollow13/dex/dex_integrity.h"
#include "dexhollow13/dex/stub_generator.h"

namespace dexhollow13::payload {

constexpr std::array<std::uint8_t, 8U> kPayloadMagic{{'D', 'H', '1', '3', 'P', 'A', 'Y', '\0'}};
constexpr std::uint32_t kPayloadVersion = 1U;
constexpr std::uint32_t kPayloadEndianTag = 0x12345678U;
constexpr std::size_t kPayloadHeaderSize = 96U;
constexpr std::size_t kPayloadRecordSize = 40U;

enum MethodFlags : std::uint32_t {
    kMethodDirect = 1U << 0U,
    kMethodConstructor = 1U << 1U,
    kMethodClassInitializer = 1U << 2U,
    kMethodHasTryItems = 1U << 3U,
};

struct MethodPayload {
    std::uint32_t method_idx = 0U;
    std::uint32_t original_code_off = 0U;
    std::uint32_t insns_size = 0U;
    std::uint32_t access_flags = 0U;
    dex::StubKind stub_kind = dex::StubKind::kReturnVoid;
    std::uint32_t flags = 0U;
    std::vector<std::uint8_t> code_item;
};

struct PayloadFile {
    std::uint32_t dex_ordinal = 0U;
    dex::Sha1Digest original_dex_signature{};
    dex::Sha1Digest hollow_dex_signature{};
    std::vector<MethodPayload> methods;
};

// PayloadView 不拥有 code_item 字节，只记录它们在输入 ByteView 中的位置。Android Runtime
// 使用这个形式可以让一百万个方法体继续驻留在只读 mmap 文件中，避免为每个 code_item
// 单独 malloc 和复制。调用者必须保证输入 ByteView 的底层内存在 View 使用期间一直有效。
struct MethodPayloadView {
    std::uint32_t method_idx = 0U;
    std::uint32_t original_code_off = 0U;
    std::uint32_t code_item_size = 0U;
    std::uint32_t insns_size = 0U;
    std::uint32_t access_flags = 0U;
    dex::StubKind stub_kind = dex::StubKind::kReturnVoid;
    std::uint32_t flags = 0U;
    const std::uint8_t* code_item = nullptr;
};

struct PayloadView {
    std::uint32_t dex_ordinal = 0U;
    dex::Sha1Digest original_dex_signature{};
    dex::Sha1Digest hollow_dex_signature{};
    std::vector<MethodPayloadView> methods;
};

// 将一个 DEX 的所有方法体写成独立 Payload。records 固定长度，code_item data 按 4 字节
// 对齐，便于 Android Runtime 直接把数据区地址作为 StandardDexFile::CodeItem 使用。
std::vector<std::uint8_t> WritePayload(const PayloadFile& payload);

// 零拷贝 Reader 完成与拥有型 Reader 相同的 Header、CRC、范围及重复 method_idx 校验。
// 返回值中的 code_item 指针直接引用 bytes，适合由 mmap 提供稳定生命周期的 Runtime。
PayloadView ReadPayloadView(const ByteView& bytes);

// Host 工具需要在输入缓冲区销毁后继续使用数据，因此拥有型 Reader 会在完成统一的 View
// 校验后复制各 code_item。Android Runtime 应优先使用上面的 ReadPayloadView()。
PayloadFile ReadPayload(const ByteView& bytes);

}  // namespace dexhollow13::payload
