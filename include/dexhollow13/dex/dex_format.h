#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace dexhollow13::dex {

constexpr std::size_t kDexHeaderSize = 0x70U;
constexpr std::uint32_t kDexEndianConstant = 0x12345678U;
constexpr std::uint32_t kNoIndex = 0xffffffffU;

constexpr std::size_t kStringIdItemSize = 4U;
constexpr std::size_t kTypeIdItemSize = 4U;
constexpr std::size_t kProtoIdItemSize = 12U;
constexpr std::size_t kFieldIdItemSize = 8U;
constexpr std::size_t kMethodIdItemSize = 8U;
constexpr std::size_t kClassDefItemSize = 32U;

// 这些 access flag 来自 DEX format。native/abstract 方法正常情况下 code_off 为 0，
// Transformer 仍然同时检查 flag 和 code_off，以便对畸形 DEX 给出明确诊断。
constexpr std::uint32_t kAccNative = 0x0100U;
constexpr std::uint32_t kAccAbstract = 0x0400U;
constexpr std::uint32_t kAccConstructor = 0x00010000U;

struct Header {
    std::array<std::uint8_t, 8U> magic{};
    std::uint32_t checksum = 0U;
    std::array<std::uint8_t, 20U> signature{};
    std::uint32_t file_size = 0U;
    std::uint32_t header_size = 0U;
    std::uint32_t endian_tag = 0U;
    std::uint32_t link_size = 0U;
    std::uint32_t link_off = 0U;
    std::uint32_t map_off = 0U;
    std::uint32_t string_ids_size = 0U;
    std::uint32_t string_ids_off = 0U;
    std::uint32_t type_ids_size = 0U;
    std::uint32_t type_ids_off = 0U;
    std::uint32_t proto_ids_size = 0U;
    std::uint32_t proto_ids_off = 0U;
    std::uint32_t field_ids_size = 0U;
    std::uint32_t field_ids_off = 0U;
    std::uint32_t method_ids_size = 0U;
    std::uint32_t method_ids_off = 0U;
    std::uint32_t class_defs_size = 0U;
    std::uint32_t class_defs_off = 0U;
    std::uint32_t data_size = 0U;
    std::uint32_t data_off = 0U;
};

struct MethodId {
    std::uint16_t class_idx = 0U;
    std::uint16_t proto_idx = 0U;
    std::uint32_t name_idx = 0U;
};

struct ClassDef {
    std::uint32_t class_idx = 0U;
    std::uint32_t access_flags = 0U;
    std::uint32_t superclass_idx = kNoIndex;
    std::uint32_t interfaces_off = 0U;
    std::uint32_t source_file_idx = kNoIndex;
    std::uint32_t annotations_off = 0U;
    std::uint32_t class_data_off = 0U;
    std::uint32_t static_values_off = 0U;
};

// EncodedMethod 是 class_data_item 解码后的“绝对 method_idx”。文件中保存的是
// method_idx_diff；枚举 direct_methods 和 virtual_methods 时必须分别从 0 开始累加。
struct EncodedMethod {
    std::uint32_t class_def_index = 0U;
    std::uint32_t method_idx = 0U;
    std::uint32_t access_flags = 0U;
    std::uint32_t code_off = 0U;
    bool is_direct = false;
};

// MethodInfo 把变换和日志真正需要的 ID 表信息解析成可读形式。
// descriptor 使用 DEX 原始形式，例如 Lcom/example/Secret;->test(I)I。
struct MethodInfo {
    EncodedMethod encoded_method;
    std::string class_descriptor;
    std::string name;
    std::string parameters_descriptor;
    std::string return_descriptor;

    [[nodiscard]] std::string PrettyName() const {
        return class_descriptor + "->" + name + "(" + parameters_descriptor + ")" +
               return_descriptor;
    }
};

}  // namespace dexhollow13::dex
