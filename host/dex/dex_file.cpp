#include "dexhollow13/dex/dex_file.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <sstream>
#include <utility>

#include "dexhollow13/base/error.h"
#include "dexhollow13/dex/leb128.h"

namespace dexhollow13::dex {
namespace {

constexpr std::size_t kMagicOffset = 0U;
constexpr std::size_t kChecksumOffset = 8U;
constexpr std::size_t kSignatureOffset = 12U;
constexpr std::size_t kFileSizeOffset = 32U;

// android-13.0.0_r84 的 StandardDexFile 接受 035、037、038、039 和 040。
// 036 因历史 Dalvik 兼容问题被规范刻意跳过。
constexpr std::array<std::array<std::uint8_t, 4U>, 5U> kSupportedVersions{{
    {{'0', '3', '5', '\0'}},
    {{'0', '3', '7', '\0'}},
    {{'0', '3', '8', '\0'}},
    {{'0', '3', '9', '\0'}},
    {{'0', '4', '0', '\0'}},
}};

std::string HexOffset(std::size_t offset) {
    std::ostringstream stream;
    stream << "0x" << std::hex << offset;
    return stream.str();
}

bool IsDataOffset(const Header& header, std::uint32_t offset) {
    if (offset < header.data_off) {
        return false;
    }
    const std::uint64_t data_end = static_cast<std::uint64_t>(header.data_off) + header.data_size;
    return static_cast<std::uint64_t>(offset) < data_end;
}

}  // namespace

DexFile::DexFile(std::vector<std::uint8_t> bytes) : bytes_(std::move(bytes)) {
    // header_ 只能在 bytes_ 完成移动后解析，否则 ByteView 可能指向已经失效的来源 vector。
    header_ = ParseAndValidateHeader();
}

Header DexFile::ParseAndValidateHeader() const {
    const ByteView bytes = view();
    bytes.CheckRange(0U, kDexHeaderSize, "DEX header");

    Header header;
    std::copy_n(bytes.DataAt(kMagicOffset, header.magic.size(), "DEX magic"), header.magic.size(),
                header.magic.begin());

    const std::array<std::uint8_t, 4U> standard_magic{{'d', 'e', 'x', '\n'}};
    if (!std::equal(standard_magic.begin(), standard_magic.end(), header.magic.begin())) {
        throw Error("输入不是标准 DEX：magic 应以 dex\\n 开头");
    }

    const bool version_supported = std::any_of(
        kSupportedVersions.begin(), kSupportedVersions.end(), [&header](const auto& version) {
            return std::equal(version.begin(), version.end(), header.magic.begin() + 4);
        });
    if (!version_supported) {
        std::string version(reinterpret_cast<const char*>(header.magic.data() + 4U), 3U);
        throw Error("android-13.0.0_r84 不支持 DEX version " + version);
    }

    header.checksum = bytes.ReadU32(kChecksumOffset, "header.checksum");
    std::copy_n(bytes.DataAt(kSignatureOffset, header.signature.size(), "header.signature"),
                header.signature.size(), header.signature.begin());
    header.file_size = bytes.ReadU32(kFileSizeOffset, "header.file_size");
    header.header_size = bytes.ReadU32(36U, "header.header_size");
    header.endian_tag = bytes.ReadU32(40U, "header.endian_tag");
    header.link_size = bytes.ReadU32(44U, "header.link_size");
    header.link_off = bytes.ReadU32(48U, "header.link_off");
    header.map_off = bytes.ReadU32(52U, "header.map_off");
    header.string_ids_size = bytes.ReadU32(56U, "header.string_ids_size");
    header.string_ids_off = bytes.ReadU32(60U, "header.string_ids_off");
    header.type_ids_size = bytes.ReadU32(64U, "header.type_ids_size");
    header.type_ids_off = bytes.ReadU32(68U, "header.type_ids_off");
    header.proto_ids_size = bytes.ReadU32(72U, "header.proto_ids_size");
    header.proto_ids_off = bytes.ReadU32(76U, "header.proto_ids_off");
    header.field_ids_size = bytes.ReadU32(80U, "header.field_ids_size");
    header.field_ids_off = bytes.ReadU32(84U, "header.field_ids_off");
    header.method_ids_size = bytes.ReadU32(88U, "header.method_ids_size");
    header.method_ids_off = bytes.ReadU32(92U, "header.method_ids_off");
    header.class_defs_size = bytes.ReadU32(96U, "header.class_defs_size");
    header.class_defs_off = bytes.ReadU32(100U, "header.class_defs_off");
    header.data_size = bytes.ReadU32(104U, "header.data_size");
    header.data_off = bytes.ReadU32(108U, "header.data_off");

    if (header.file_size != bytes.size()) {
        std::ostringstream stream;
        stream << "header.file_size 与真实文件大小不一致：header=0x" << std::hex << header.file_size
               << ", actual=0x" << bytes.size();
        throw Error(stream.str());
    }
    if (header.header_size != kDexHeaderSize) {
        throw Error("Android 13 标准 DEX 的 header_size 应为 0x70");
    }
    if (header.endian_tag != kDexEndianConstant) {
        throw Error("只支持标准小端 DEX，endian_tag 应为 0x12345678");
    }

    ValidateTable("string_ids", header.string_ids_size, header.string_ids_off, kStringIdItemSize);
    ValidateTable("type_ids", header.type_ids_size, header.type_ids_off, kTypeIdItemSize);
    ValidateTable("proto_ids", header.proto_ids_size, header.proto_ids_off, kProtoIdItemSize);
    ValidateTable("field_ids", header.field_ids_size, header.field_ids_off, kFieldIdItemSize);
    ValidateTable("method_ids", header.method_ids_size, header.method_ids_off, kMethodIdItemSize);
    ValidateTable("class_defs", header.class_defs_size, header.class_defs_off, kClassDefItemSize);

    // android-13.0.0_r84 的 DexFileVerifier::CheckHeader() 只对 type_ids 和
    // proto_ids 应用 kDexNoIndex16(0xffff) 上限。不要把“16 位最大索引 0xffff”误写成
    // method_ids 表最多只能有 65535 项：method_ids_size == 65536 时，最后一项的索引
    // 恰好是 0xffff，Android 13 可以正常接受。field/method ID 的绝对索引在
    // class_data_item 和 ART 内部均使用 uint32_t，本解析器也必须保留这个范围。
    if (header.type_ids_size > 65535U || header.proto_ids_size > 65535U) {
        throw Error("DEX 的 type_ids_size/proto_ids_size 超过 Android 13 的 65535 上限");
    }

    if ((header.data_off & 3U) != 0U) {
        throw Error("header.data_off 没有按 4 字节对齐");
    }
    bytes.CheckRange(header.data_off, header.data_size, "DEX data section");

    if (header.map_off == 0U || !IsDataOffset(header, header.map_off)) {
        throw Error("header.map_off 必须指向 data section 内的 map_list");
    }

    if ((header.link_size == 0U) != (header.link_off == 0U)) {
        throw Error("link_size 和 link_off 必须同时为 0，或同时为非 0");
    }
    if (header.link_size != 0U) {
        bytes.CheckRange(header.link_off, header.link_size, "DEX link section");
    }

    return header;
}

void DexFile::ValidateTable(const std::string& name, std::uint32_t count, std::uint32_t offset,
                            std::size_t item_size) const {
    if (count == 0U) {
        if (offset != 0U) {
            throw Error(name + " 的 count 为 0 时 offset 必须为 0");
        }
        return;
    }

    if (offset == 0U) {
        throw Error(name + " 非空但 offset 为 0");
    }
    if ((offset & 3U) != 0U) {
        throw Error(name + " 没有按 4 字节对齐");
    }

    const std::size_t byte_count =
        CheckedMultiply(static_cast<std::size_t>(count), item_size, name + " byte_count");
    view().CheckRange(offset, byte_count, name);
}

std::size_t DexFile::ItemOffset(const std::string& name, std::uint32_t table_offset,
                                std::uint32_t index, std::uint32_t count,
                                std::size_t item_size) const {
    if (index >= count) {
        std::ostringstream stream;
        stream << name << " index 越界：index=" << index << ", count=" << count;
        throw Error(stream.str());
    }

    const std::size_t relative =
        CheckedMultiply(static_cast<std::size_t>(index), item_size, name + " item offset");
    const std::size_t base = table_offset;
    if (relative > std::numeric_limits<std::size_t>::max() - base) {
        throw Error(name + " item offset 加法溢出");
    }
    const std::size_t result = base + relative;
    view().CheckRange(result, item_size, name + " item");
    return result;
}

std::string DexFile::GetString(std::uint32_t string_idx) const {
    const std::size_t item_offset = ItemOffset("string_ids", header_.string_ids_off, string_idx,
                                               header_.string_ids_size, kStringIdItemSize);
    const ByteView bytes = view();
    const std::uint32_t string_data_off = bytes.ReadU32(item_offset, "string_id.string_data_off");
    if (!IsDataOffset(header_, string_data_off)) {
        throw Error("string_data_off 不在 data section：" + HexOffset(string_data_off));
    }

    const auto utf16_size = ReadUleb128(bytes, string_data_off, "string_data.utf16_size");
    std::size_t cursor = utf16_size.next_offset;
    const std::size_t content_begin = cursor;

    // MUTF-8 使用单个 0 字节终止。Java 字符 U+0000 会编码为 C0 80，
    // 因此寻找第一个真实 0 字节不会误截断合法内容。
    while (bytes.ReadU8(cursor, "string_data MUTF-8") != 0U) {
        ++cursor;
    }

    const char* begin = reinterpret_cast<const char*>(
        bytes.DataAt(content_begin, cursor - content_begin, "string_data content"));
    return std::string(begin, cursor - content_begin);
}

std::string DexFile::GetTypeDescriptor(std::uint32_t type_idx) const {
    const std::size_t offset = ItemOffset("type_ids", header_.type_ids_off, type_idx,
                                          header_.type_ids_size, kTypeIdItemSize);
    const std::uint32_t descriptor_idx = view().ReadU32(offset, "type_id.descriptor_idx");
    return GetString(descriptor_idx);
}

MethodId DexFile::GetMethodId(std::uint32_t method_idx) const {
    const std::size_t offset = ItemOffset("method_ids", header_.method_ids_off, method_idx,
                                          header_.method_ids_size, kMethodIdItemSize);
    const ByteView bytes = view();
    MethodId method;
    method.class_idx = bytes.ReadU16(offset, "method_id.class_idx");
    method.proto_idx = bytes.ReadU16(offset + 2U, "method_id.proto_idx");
    method.name_idx = bytes.ReadU32(offset + 4U, "method_id.name_idx");

    if (method.class_idx >= header_.type_ids_size || method.proto_idx >= header_.proto_ids_size ||
        method.name_idx >= header_.string_ids_size) {
        throw Error("method_id 中的 class/proto/name index 越界");
    }
    return method;
}

ClassDef DexFile::GetClassDef(std::uint32_t class_def_idx) const {
    const std::size_t offset = ItemOffset("class_defs", header_.class_defs_off, class_def_idx,
                                          header_.class_defs_size, kClassDefItemSize);
    const ByteView bytes = view();
    ClassDef class_def;
    class_def.class_idx = bytes.ReadU32(offset, "class_def.class_idx");
    class_def.access_flags = bytes.ReadU32(offset + 4U, "class_def.access_flags");
    class_def.superclass_idx = bytes.ReadU32(offset + 8U, "class_def.superclass_idx");
    class_def.interfaces_off = bytes.ReadU32(offset + 12U, "class_def.interfaces_off");
    class_def.source_file_idx = bytes.ReadU32(offset + 16U, "class_def.source_file_idx");
    class_def.annotations_off = bytes.ReadU32(offset + 20U, "class_def.annotations_off");
    class_def.class_data_off = bytes.ReadU32(offset + 24U, "class_def.class_data_off");
    class_def.static_values_off = bytes.ReadU32(offset + 28U, "class_def.static_values_off");

    if (class_def.class_idx >= header_.type_ids_size) {
        throw Error("class_def.class_idx 越界");
    }
    if (class_def.superclass_idx != kNoIndex && class_def.superclass_idx >= header_.type_ids_size) {
        throw Error("class_def.superclass_idx 越界");
    }
    if (class_def.class_data_off != 0U && !IsDataOffset(header_, class_def.class_data_off)) {
        throw Error("class_def.class_data_off 不在 data section");
    }
    return class_def;
}

std::string DexFile::GetParametersDescriptor(std::uint32_t proto_idx) const {
    const std::size_t proto_offset = ItemOffset("proto_ids", header_.proto_ids_off, proto_idx,
                                                header_.proto_ids_size, kProtoIdItemSize);
    const ByteView bytes = view();
    const std::uint32_t parameters_off =
        bytes.ReadU32(proto_offset + 8U, "proto_id.parameters_off");
    if (parameters_off == 0U) {
        return {};
    }
    if (!IsDataOffset(header_, parameters_off) || (parameters_off & 3U) != 0U) {
        throw Error("proto_id.parameters_off 非法或没有按 4 字节对齐");
    }

    const std::uint32_t parameter_count = bytes.ReadU32(parameters_off, "type_list.size");
    const std::size_t list_bytes =
        CheckedMultiply(static_cast<std::size_t>(parameter_count), 2U, "type_list byte_count");
    bytes.CheckRange(static_cast<std::size_t>(parameters_off) + 4U, list_bytes, "type_list.list");

    std::string descriptor;
    for (std::uint32_t index = 0U; index < parameter_count; ++index) {
        const std::size_t type_offset =
            static_cast<std::size_t>(parameters_off) + 4U + static_cast<std::size_t>(index) * 2U;
        const std::uint16_t type_idx = bytes.ReadU16(type_offset, "type_list.type_idx");
        descriptor += GetTypeDescriptor(type_idx);
    }
    return descriptor;
}

std::string DexFile::GetReturnDescriptor(std::uint32_t proto_idx) const {
    const std::size_t proto_offset = ItemOffset("proto_ids", header_.proto_ids_off, proto_idx,
                                                header_.proto_ids_size, kProtoIdItemSize);
    const std::uint32_t return_type_idx =
        view().ReadU32(proto_offset + 4U, "proto_id.return_type_idx");
    return GetTypeDescriptor(return_type_idx);
}

MethodInfo DexFile::BuildMethodInfo(const EncodedMethod& encoded_method) const {
    const MethodId method_id = GetMethodId(encoded_method.method_idx);
    MethodInfo result;
    result.encoded_method = encoded_method;
    result.class_descriptor = GetTypeDescriptor(method_id.class_idx);
    result.name = GetString(method_id.name_idx);
    result.parameters_descriptor = GetParametersDescriptor(method_id.proto_idx);
    result.return_descriptor = GetReturnDescriptor(method_id.proto_idx);
    return result;
}

std::vector<MethodInfo> DexFile::EnumerateMethods() const {
    std::vector<MethodInfo> result;
    const ByteView bytes = view();

    for (std::uint32_t class_index = 0U; class_index < header_.class_defs_size; ++class_index) {
        const ClassDef class_def = GetClassDef(class_index);
        if (class_def.class_data_off == 0U) {
            continue;
        }

        std::size_t cursor = class_def.class_data_off;
        const auto static_fields_size = ReadUleb128(bytes, cursor, "class_data.static_fields_size");
        cursor = static_fields_size.next_offset;
        const auto instance_fields_size =
            ReadUleb128(bytes, cursor, "class_data.instance_fields_size");
        cursor = instance_fields_size.next_offset;
        const auto direct_methods_size =
            ReadUleb128(bytes, cursor, "class_data.direct_methods_size");
        cursor = direct_methods_size.next_offset;
        const auto virtual_methods_size =
            ReadUleb128(bytes, cursor, "class_data.virtual_methods_size");
        cursor = virtual_methods_size.next_offset;

        // encoded_field 包含 field_idx_diff 和 access_flags。虽然本项目不修改字段，
        // 仍必须逐项解码，才能准确找到紧随其后的 encoded_method 起点。
        const std::uint64_t total_field_count =
            static_cast<std::uint64_t>(static_fields_size.value) + instance_fields_size.value;
        if (total_field_count > header_.field_ids_size) {
            throw Error("class_data 中的字段数量超过 field_ids_size");
        }
        const auto skip_fields = [&](std::uint32_t count) {
            // static_fields 与 instance_fields 和两个 method 列表一样，分别使用独立的差分序列。
            // 因此不能把两个数量相加后用同一个 field_index 连续累加。
            std::uint32_t field_index = 0U;
            for (std::uint32_t ordinal = 0U; ordinal < count; ++ordinal) {
                const auto diff = ReadUleb128(bytes, cursor, "encoded_field.field_idx_diff");
                cursor = diff.next_offset;
                if (ordinal != 0U && diff.value == 0U) {
                    throw Error("同一 field 列表中除第一项外 field_idx_diff 不能为 0");
                }
                if (diff.value > std::numeric_limits<std::uint32_t>::max() - field_index) {
                    throw Error("encoded_field 的 field_idx 累加溢出");
                }
                field_index += diff.value;
                if (field_index >= header_.field_ids_size) {
                    throw Error("encoded_field.field_idx 越界");
                }
                const auto flags = ReadUleb128(bytes, cursor, "encoded_field.access_flags");
                cursor = flags.next_offset;
            }
        };

        skip_fields(static_fields_size.value);
        skip_fields(instance_fields_size.value);

        const auto read_methods = [&](std::uint32_t count, bool is_direct) {
            // direct_methods 和 virtual_methods 是两个独立的差分序列，必须在这里重新从 0 累加。
            std::uint32_t method_index = 0U;
            for (std::uint32_t ordinal = 0U; ordinal < count; ++ordinal) {
                const auto diff = ReadUleb128(bytes, cursor, "encoded_method.method_idx_diff");
                cursor = diff.next_offset;
                if (ordinal != 0U && diff.value == 0U) {
                    throw Error("同一 method 列表中除第一项外 method_idx_diff 不能为 0");
                }
                if (diff.value > std::numeric_limits<std::uint32_t>::max() - method_index) {
                    throw Error("encoded_method 的 method_idx 累加溢出");
                }
                method_index += diff.value;
                if (method_index >= header_.method_ids_size) {
                    throw Error("encoded_method.method_idx 越界");
                }

                const auto flags = ReadUleb128(bytes, cursor, "encoded_method.access_flags");
                cursor = flags.next_offset;
                const auto code_offset = ReadUleb128(bytes, cursor, "encoded_method.code_off");
                cursor = code_offset.next_offset;

                if (code_offset.value != 0U) {
                    if ((code_offset.value & 3U) != 0U ||
                        !IsDataOffset(header_, code_offset.value)) {
                        throw Error("encoded_method.code_off 非法：" +
                                    HexOffset(code_offset.value));
                    }
                }

                EncodedMethod encoded;
                encoded.class_def_index = class_index;
                encoded.method_idx = method_index;
                encoded.access_flags = flags.value;
                encoded.code_off = code_offset.value;
                encoded.is_direct = is_direct;

                MethodInfo info = BuildMethodInfo(encoded);
                const MethodId method_id = GetMethodId(method_index);
                if (method_id.class_idx != class_def.class_idx) {
                    throw Error("encoded_method 的声明类与当前 class_def 不一致：" +
                                info.PrettyName());
                }
                result.push_back(std::move(info));
            }
        };

        read_methods(direct_methods_size.value, true);
        read_methods(virtual_methods_size.value, false);
    }

    return result;
}

}  // namespace dexhollow13::dex
