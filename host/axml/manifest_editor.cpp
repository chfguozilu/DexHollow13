#include "dexhollow13/axml/manifest_editor.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"

namespace dexhollow13::axml {
namespace {

constexpr std::uint16_t kResStringPoolType = 0x0001U;
constexpr std::uint16_t kResXmlType = 0x0003U;
constexpr std::uint16_t kResXmlStartElementType = 0x0102U;
constexpr std::uint16_t kResXmlResourceMapType = 0x0180U;

constexpr std::uint32_t kNoString = 0xffffffffU;
constexpr std::uint32_t kStringPoolUtf8Flag = 1U << 8U;
constexpr std::uint32_t kStringPoolSortedFlag = 1U;
constexpr std::uint8_t kValueTypeString = 0x03U;

constexpr std::uint32_t kAndroidNameResourceId = 0x01010003U;
constexpr std::uint32_t kAndroidAppComponentFactoryResourceId = 0x0101057aU;
constexpr const char* kAndroidNamespace = "http://schemas.android.com/apk/res/android";

struct Chunk {
    std::uint16_t type = 0U;
    std::vector<std::uint8_t> bytes;
};

void AppendU16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void AppendU32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

void AlignToFour(std::vector<std::uint8_t>& output) {
    while ((output.size() & 3U) != 0U) {
        output.push_back(0U);
    }
}

std::uint32_t CheckedU32(std::size_t value, const std::string& purpose) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw Error(purpose + " 超过 uint32_t 范围");
    }
    return static_cast<std::uint32_t>(value);
}

void WriteU16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value,
              const std::string& purpose) {
    MutableByteView(bytes.data(), bytes.size()).WriteU16(offset, value, purpose);
}

void WriteU32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value,
              const std::string& purpose) {
    MutableByteView(bytes.data(), bytes.size()).WriteU32(offset, value, purpose);
}

struct Length8 {
    std::uint32_t value = 0U;
    std::size_t next = 0U;
};

Length8 ReadLength8(const ByteView& bytes, std::size_t offset, const std::string& purpose) {
    const std::uint8_t first = bytes.ReadU8(offset, purpose);
    if ((first & 0x80U) == 0U) {
        return {first, offset + 1U};
    }
    const std::uint8_t second = bytes.ReadU8(offset + 1U, purpose);
    return {(static_cast<std::uint32_t>(first & 0x7fU) << 8U) | second, offset + 2U};
}

struct Length16 {
    std::uint32_t value = 0U;
    std::size_t next = 0U;
};

Length16 ReadLength16(const ByteView& bytes, std::size_t offset, const std::string& purpose) {
    const std::uint16_t first = bytes.ReadU16(offset, purpose);
    if ((first & 0x8000U) == 0U) {
        return {first, offset + 2U};
    }
    const std::uint16_t second = bytes.ReadU16(offset + 2U, purpose);
    return {(static_cast<std::uint32_t>(first & 0x7fffU) << 16U) | second, offset + 4U};
}

void AppendUtf8CodePoint(std::string& output, std::uint32_t code_point) {
    if (code_point <= 0x7fU) {
        output.push_back(static_cast<char>(code_point));
    } else if (code_point <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    } else if (code_point <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (code_point >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | (code_point >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    }
}

struct RawString {
    std::string decoded;
    std::vector<std::uint8_t> encoded;
};

class StringPool final {
public:
    explicit StringPool(const std::vector<std::uint8_t>& chunk) { Parse(chunk); }

    [[nodiscard]] const std::string& Get(std::uint32_t index) const {
        if (index >= strings_.size()) {
            throw Error("Binary XML string index 越界");
        }
        return strings_[index].decoded;
    }

    [[nodiscard]] std::uint32_t FindOrAdd(const std::string& value) {
        for (std::size_t index = 0U; index < strings_.size(); ++index) {
            if (strings_[index].decoded == value) {
                return CheckedU32(index, "String pool index");
            }
        }

        RawString added;
        added.decoded = value;
        added.encoded = EncodeAscii(value);
        strings_.push_back(std::move(added));
        added_strings_ = true;
        return CheckedU32(strings_.size() - 1U, "String pool index");
    }

    [[nodiscard]] std::vector<std::uint8_t> Build() const {
        constexpr std::uint16_t header_size = 28U;
        const std::size_t index_bytes = CheckedMultiply(strings_.size(), 4U, "string offsets");
        const std::size_t style_index_bytes =
            CheckedMultiply(style_offsets_.size(), 4U, "style offsets");
        const std::uint32_t strings_start =
            CheckedU32(static_cast<std::size_t>(header_size) + index_bytes + style_index_bytes,
                       "stringsStart");

        std::vector<std::uint8_t> output;
        AppendU16(output, kResStringPoolType);
        AppendU16(output, header_size);
        AppendU32(output, 0U);  // chunk size 最后回填。
        AppendU32(output, CheckedU32(strings_.size(), "stringCount"));
        AppendU32(output, CheckedU32(style_offsets_.size(), "styleCount"));
        AppendU32(output, added_strings_ ? (flags_ & ~kStringPoolSortedFlag) : flags_);
        AppendU32(output, strings_start);
        AppendU32(output, 0U);  // stylesStart 在字符串数据完成后回填。

        std::size_t relative_string_offset = 0U;
        for (const RawString& string : strings_) {
            AppendU32(output, CheckedU32(relative_string_offset, "string offset"));
            relative_string_offset += string.encoded.size();
        }
        for (std::uint32_t offset : style_offsets_) {
            AppendU32(output, offset);
        }
        for (const RawString& string : strings_) {
            output.insert(output.end(), string.encoded.begin(), string.encoded.end());
        }
        AlignToFour(output);

        if (!style_data_.empty()) {
            WriteU32(output, 24U, CheckedU32(output.size(), "stylesStart"), "stylesStart");
            output.insert(output.end(), style_data_.begin(), style_data_.end());
            AlignToFour(output);
        }

        WriteU32(output, 4U, CheckedU32(output.size(), "string pool size"), "string pool size");
        return output;
    }

private:
    void Parse(const std::vector<std::uint8_t>& chunk) {
        const ByteView bytes(chunk.data(), chunk.size());
        bytes.CheckRange(0U, 28U, "Binary XML string pool header");
        if (bytes.ReadU16(0U, "string pool type") != kResStringPoolType ||
            bytes.ReadU16(2U, "string pool headerSize") != 28U ||
            bytes.ReadU32(4U, "string pool size") != chunk.size()) {
            throw Error("Binary XML string pool header 不受支持");
        }

        const std::uint32_t string_count = bytes.ReadU32(8U, "stringCount");
        const std::uint32_t style_count = bytes.ReadU32(12U, "styleCount");
        flags_ = bytes.ReadU32(16U, "string pool flags");
        utf8_ = (flags_ & kStringPoolUtf8Flag) != 0U;
        const std::uint32_t strings_start = bytes.ReadU32(20U, "stringsStart");
        const std::uint32_t styles_start = bytes.ReadU32(24U, "stylesStart");

        const std::size_t string_offsets_size =
            CheckedMultiply(static_cast<std::size_t>(string_count), 4U, "string offsets");
        const std::size_t style_offsets_size =
            CheckedMultiply(static_cast<std::size_t>(style_count), 4U, "style offsets");
        bytes.CheckRange(28U, string_offsets_size + style_offsets_size, "string/style offsets");
        if (strings_start < 28U + string_offsets_size + style_offsets_size ||
            strings_start > chunk.size()) {
            throw Error("Binary XML stringsStart 非法");
        }

        const std::size_t string_data_end = styles_start == 0U ? chunk.size() : styles_start;
        if (string_data_end < strings_start || string_data_end > chunk.size()) {
            throw Error("Binary XML stylesStart 非法");
        }
        if ((style_count == 0U) != (styles_start == 0U)) {
            throw Error("Binary XML styleCount 与 stylesStart 不一致");
        }

        style_offsets_.reserve(style_count);
        for (std::uint32_t index = 0U; index < style_count; ++index) {
            style_offsets_.push_back(bytes.ReadU32(
                28U + string_offsets_size + static_cast<std::size_t>(index) * 4U, "style offset"));
        }
        if (styles_start != 0U) {
            const std::uint8_t* style_begin =
                bytes.DataAt(styles_start, chunk.size() - styles_start, "style data");
            style_data_.assign(style_begin, style_begin + (chunk.size() - styles_start));
        }

        strings_.reserve(string_count);
        for (std::uint32_t index = 0U; index < string_count; ++index) {
            const std::uint32_t relative =
                bytes.ReadU32(28U + static_cast<std::size_t>(index) * 4U, "string offset");
            const std::size_t absolute = static_cast<std::size_t>(strings_start) + relative;
            if (absolute >= string_data_end) {
                throw Error("Binary XML string offset 超出 string data");
            }
            strings_.push_back(utf8_ ? ParseUtf8(bytes, absolute, string_data_end)
                                     : ParseUtf16(bytes, absolute, string_data_end));
        }
    }

    RawString ParseUtf8(const ByteView& bytes, std::size_t offset, std::size_t end) const {
        const Length8 utf16_length = ReadLength8(bytes, offset, "UTF-8 utf16 length");
        const Length8 byte_length = ReadLength8(bytes, utf16_length.next, "UTF-8 byte length");
        if (byte_length.next > end || byte_length.value > end - byte_length.next) {
            throw Error("Binary XML UTF-8 string 越界");
        }
        const std::size_t terminator = byte_length.next + byte_length.value;
        if (terminator >= end || bytes.ReadU8(terminator, "UTF-8 terminator") != 0U) {
            throw Error("Binary XML UTF-8 string 缺少终止字节");
        }

        RawString result;
        const char* text = reinterpret_cast<const char*>(
            bytes.DataAt(byte_length.next, byte_length.value, "UTF-8 content"));
        result.decoded.assign(text, byte_length.value);
        const std::uint8_t* raw =
            bytes.DataAt(offset, terminator + 1U - offset, "UTF-8 raw string");
        result.encoded.assign(raw, raw + (terminator + 1U - offset));
        return result;
    }

    RawString ParseUtf16(const ByteView& bytes, std::size_t offset, std::size_t end) const {
        const Length16 length = ReadLength16(bytes, offset, "UTF-16 length");
        const std::size_t content_bytes =
            CheckedMultiply(static_cast<std::size_t>(length.value), 2U, "UTF-16 content size");
        if (length.next > end || content_bytes > end - length.next ||
            content_bytes + 2U > end - length.next) {
            throw Error("Binary XML UTF-16 string 越界");
        }
        const std::size_t terminator = length.next + content_bytes;
        if (bytes.ReadU16(terminator, "UTF-16 terminator") != 0U) {
            throw Error("Binary XML UTF-16 string 缺少终止字");
        }

        RawString result;
        for (std::uint32_t index = 0U; index < length.value; ++index) {
            const std::uint16_t unit = bytes.ReadU16(
                length.next + static_cast<std::size_t>(index) * 2U, "UTF-16 code unit");
            std::uint32_t code_point = unit;
            if (unit >= 0xd800U && unit <= 0xdbffU) {
                if (index + 1U >= length.value) {
                    throw Error("Binary XML UTF-16 高代理项没有低代理项");
                }
                const std::uint16_t low =
                    bytes.ReadU16(length.next + static_cast<std::size_t>(index + 1U) * 2U,
                                  "UTF-16 low surrogate");
                if (low < 0xdc00U || low > 0xdfffU) {
                    throw Error("Binary XML UTF-16 代理项组合非法");
                }
                code_point = 0x10000U + ((static_cast<std::uint32_t>(unit) - 0xd800U) << 10U) +
                             (static_cast<std::uint32_t>(low) - 0xdc00U);
                ++index;
            } else if (unit >= 0xdc00U && unit <= 0xdfffU) {
                throw Error("Binary XML UTF-16 出现孤立低代理项");
            }
            AppendUtf8CodePoint(result.decoded, code_point);
        }

        const std::uint8_t* raw =
            bytes.DataAt(offset, terminator + 2U - offset, "UTF-16 raw string");
        result.encoded.assign(raw, raw + (terminator + 2U - offset));
        return result;
    }

    std::vector<std::uint8_t> EncodeAscii(const std::string& value) const {
        if (std::any_of(value.begin(), value.end(),
                        [](unsigned char character) { return character > 0x7fU; })) {
            throw Error("Manifest 新增类名必须是 ASCII：" + value);
        }

        std::vector<std::uint8_t> encoded;
        if (utf8_) {
            if (value.size() > 0x7fffU) {
                throw Error("Binary XML 新增 UTF-8 字符串过长");
            }
            const auto append_length = [&encoded](std::size_t length) {
                if (length <= 0x7fU) {
                    encoded.push_back(static_cast<std::uint8_t>(length));
                } else {
                    encoded.push_back(static_cast<std::uint8_t>(0x80U | ((length >> 8U) & 0x7fU)));
                    encoded.push_back(static_cast<std::uint8_t>(length & 0xffU));
                }
            };
            append_length(value.size());  // ASCII 的 UTF-16 长度等于 UTF-8 字节数。
            append_length(value.size());
            encoded.insert(encoded.end(), value.begin(), value.end());
            encoded.push_back(0U);
        } else {
            if (value.size() > 0x7fffffffU) {
                throw Error("Binary XML 新增 UTF-16 字符串过长");
            }
            if (value.size() <= 0x7fffU) {
                AppendU16(encoded, static_cast<std::uint16_t>(value.size()));
            } else {
                AppendU16(encoded,
                          static_cast<std::uint16_t>(0x8000U | ((value.size() >> 16U) & 0x7fffU)));
                AppendU16(encoded, static_cast<std::uint16_t>(value.size() & 0xffffU));
            }
            for (char character : value) {
                AppendU16(encoded, static_cast<std::uint8_t>(character));
            }
            AppendU16(encoded, 0U);
        }
        return encoded;
    }

    bool utf8_ = false;
    bool added_strings_ = false;
    std::uint32_t flags_ = 0U;
    std::vector<RawString> strings_;
    std::vector<std::uint32_t> style_offsets_;
    std::vector<std::uint8_t> style_data_;
};

std::vector<Chunk> ParseChildChunks(const std::vector<std::uint8_t>& input) {
    const ByteView bytes(input.data(), input.size());
    bytes.CheckRange(0U, 8U, "Binary XML root header");
    if (bytes.ReadU16(0U, "XML type") != kResXmlType || bytes.ReadU16(2U, "XML headerSize") != 8U ||
        bytes.ReadU32(4U, "XML size") != input.size()) {
        throw Error("AndroidManifest.xml 不是受支持的编译后 Binary XML");
    }

    std::vector<Chunk> chunks;
    std::size_t cursor = 8U;
    while (cursor < input.size()) {
        bytes.CheckRange(cursor, 8U, "Binary XML child chunk header");
        const std::uint16_t type = bytes.ReadU16(cursor, "child.type");
        const std::uint16_t header_size = bytes.ReadU16(cursor + 2U, "child.headerSize");
        const std::uint32_t size = bytes.ReadU32(cursor + 4U, "child.size");
        if (header_size < 8U || size < header_size || (size & 3U) != 0U) {
            throw Error("Binary XML child chunk 的 headerSize/size 非法");
        }
        const std::uint8_t* chunk_begin = bytes.DataAt(cursor, size, "Binary XML child chunk");
        chunks.push_back({type, std::vector<std::uint8_t>(chunk_begin, chunk_begin + size)});
        cursor += size;
    }
    if (cursor != input.size()) {
        throw Error("Binary XML child chunks 没有恰好覆盖整个文件");
    }
    return chunks;
}

std::optional<std::uint32_t> AttributeStringValue(const ByteView& chunk, std::size_t attribute,
                                                  const StringPool& strings) {
    const std::uint32_t raw_value = chunk.ReadU32(attribute + 8U, "attribute.rawValue");
    if (raw_value != kNoString) {
        static_cast<void>(strings.Get(raw_value));  // 先验证 index，再返回它。
        return raw_value;
    }
    const std::uint8_t data_type = chunk.ReadU8(attribute + 15U, "attribute.dataType");
    const std::uint32_t data = chunk.ReadU32(attribute + 16U, "attribute.data");
    if (data_type == kValueTypeString) {
        static_cast<void>(strings.Get(data));
        return data;
    }
    return std::nullopt;
}

std::string ResolveClassName(const std::string& package_name, const std::string& raw_name) {
    if (raw_name.empty()) {
        return {};
    }
    if (raw_name.front() == '.') {
        return package_name + raw_name;
    }
    if (raw_name.find('.') == std::string::npos) {
        return package_name + "." + raw_name;
    }
    return raw_name;
}

struct ElementView {
    std::uint32_t name_idx = 0U;
    std::size_t extension = 0U;
    std::size_t attributes = 0U;
    std::uint16_t attribute_size = 0U;
    std::uint16_t attribute_count = 0U;
};

ElementView ParseStartElement(const Chunk& owner) {
    const ByteView chunk(owner.bytes.data(), owner.bytes.size());
    if (owner.type != kResXmlStartElementType) {
        throw Error("内部错误：ParseStartElement 收到非 START_ELEMENT chunk");
    }
    const std::uint16_t node_header_size = chunk.ReadU16(2U, "start element headerSize");
    if (node_header_size < 16U || node_header_size + 20U > owner.bytes.size()) {
        throw Error("Binary XML START_ELEMENT node header 非法");
    }

    ElementView element;
    element.extension = node_header_size;
    element.name_idx = chunk.ReadU32(element.extension + 4U, "element.name");
    const std::uint16_t attribute_start = chunk.ReadU16(element.extension + 8U, "attributeStart");
    element.attribute_size = chunk.ReadU16(element.extension + 10U, "attributeSize");
    element.attribute_count = chunk.ReadU16(element.extension + 12U, "attributeCount");
    if (element.attribute_size < 20U) {
        throw Error("Binary XML attributeSize 小于 ResXMLTree_attribute");
    }
    element.attributes = element.extension + attribute_start;
    const std::size_t all_attributes = CheckedMultiply(
        element.attribute_count, element.attribute_size, "Binary XML attributes size");
    chunk.CheckRange(element.attributes, all_attributes, "Binary XML attributes");
    return element;
}

std::optional<std::size_t> FindAttribute(const Chunk& owner, const ElementView& element,
                                         const StringPool& strings, const std::string& name,
                                         std::optional<std::uint32_t> namespace_idx) {
    const ByteView chunk(owner.bytes.data(), owner.bytes.size());
    for (std::uint16_t index = 0U; index < element.attribute_count; ++index) {
        const std::size_t offset =
            element.attributes + static_cast<std::size_t>(index) * element.attribute_size;
        const std::uint32_t attribute_namespace = chunk.ReadU32(offset, "attribute.ns");
        const std::uint32_t attribute_name = chunk.ReadU32(offset + 4U, "attribute.name");
        if (strings.Get(attribute_name) == name &&
            (!namespace_idx.has_value() || attribute_namespace == namespace_idx.value())) {
            return offset;
        }
    }
    return std::nullopt;
}

void SetStringAttribute(Chunk& owner, const ElementView& parsed_element, const StringPool& strings,
                        std::uint32_t namespace_idx, std::uint32_t name_idx,
                        const std::string& name, std::uint32_t value_idx) {
    const auto existing = FindAttribute(owner, parsed_element, strings, name, namespace_idx);
    if (existing.has_value()) {
        WriteU32(owner.bytes, existing.value() + 8U, value_idx, "attribute.rawValue");
        WriteU16(owner.bytes, existing.value() + 12U, 8U, "attribute.typedValue.size");
        owner.bytes[existing.value() + 14U] = 0U;
        owner.bytes[existing.value() + 15U] = kValueTypeString;
        WriteU32(owner.bytes, existing.value() + 16U, value_idx, "attribute.typedValue.data");
        return;
    }

    // 新属性放在现有 attribute array 的末尾、chunk 其他尾部数据之前。
    // 标准属性大小是 20 字节；如果输入使用更大的 attributeSize，则把扩展字节清零保留。
    const std::size_t insert_offset =
        parsed_element.attributes +
        static_cast<std::size_t>(parsed_element.attribute_count) * parsed_element.attribute_size;
    std::vector<std::uint8_t> attribute(parsed_element.attribute_size, 0U);
    WriteU32(attribute, 0U, namespace_idx, "new attribute.ns");
    WriteU32(attribute, 4U, name_idx, "new attribute.name");
    WriteU32(attribute, 8U, value_idx, "new attribute.rawValue");
    WriteU16(attribute, 12U, 8U, "new attribute.typedValue.size");
    attribute[14U] = 0U;
    attribute[15U] = kValueTypeString;
    WriteU32(attribute, 16U, value_idx, "new attribute.typedValue.data");

    owner.bytes.insert(owner.bytes.begin() + static_cast<std::ptrdiff_t>(insert_offset),
                       attribute.begin(), attribute.end());
    WriteU16(owner.bytes, parsed_element.extension + 12U,
             static_cast<std::uint16_t>(parsed_element.attribute_count + 1U), "attributeCount");
    WriteU32(owner.bytes, 4U, CheckedU32(owner.bytes.size(), "START_ELEMENT size"), "chunk.size");
}

std::vector<std::uint32_t> ReadResourceMap(const Chunk* chunk) {
    if (chunk == nullptr) {
        return {};
    }
    const ByteView bytes(chunk->bytes.data(), chunk->bytes.size());
    if (bytes.ReadU16(2U, "resource map headerSize") != 8U ||
        (chunk->bytes.size() - 8U) % 4U != 0U) {
        throw Error("Binary XML resource map 格式非法");
    }
    std::vector<std::uint32_t> ids;
    const std::size_t count = (chunk->bytes.size() - 8U) / 4U;
    ids.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        ids.push_back(bytes.ReadU32(8U + index * 4U, "resource id"));
    }
    return ids;
}

std::vector<std::uint8_t> BuildResourceMap(std::vector<std::uint32_t> ids, std::uint32_t name_idx,
                                           std::uint32_t factory_idx) {
    const std::size_t needed = std::max(name_idx, factory_idx) + 1U;
    if (ids.size() < needed) {
        ids.resize(needed, 0U);
    }
    ids[name_idx] = kAndroidNameResourceId;
    ids[factory_idx] = kAndroidAppComponentFactoryResourceId;

    std::vector<std::uint8_t> output;
    AppendU16(output, kResXmlResourceMapType);
    AppendU16(output, 8U);
    AppendU32(output, CheckedU32(8U + ids.size() * 4U, "resource map size"));
    for (std::uint32_t id : ids) {
        AppendU32(output, id);
    }
    return output;
}

std::vector<std::uint8_t> BuildXml(const std::vector<Chunk>& chunks) {
    std::vector<std::uint8_t> output;
    AppendU16(output, kResXmlType);
    AppendU16(output, 8U);
    AppendU32(output, 0U);
    for (const Chunk& chunk : chunks) {
        output.insert(output.end(), chunk.bytes.begin(), chunk.bytes.end());
    }
    WriteU32(output, 4U, CheckedU32(output.size(), "Binary XML file size"), "XML size");
    return output;
}

}  // namespace

ManifestEditResult EditManifest(const std::vector<std::uint8_t>& input,
                                const std::string& shell_application,
                                const std::string& shell_component_factory) {
    std::vector<Chunk> chunks = ParseChildChunks(input);

    auto string_pool_it = std::find_if(chunks.begin(), chunks.end(), [](const Chunk& chunk) {
        return chunk.type == kResStringPoolType;
    });
    if (string_pool_it == chunks.end()) {
        throw Error("AndroidManifest.xml 缺少 string pool");
    }
    StringPool strings(string_pool_it->bytes);

    auto resource_map_it = std::find_if(chunks.begin(), chunks.end(), [](const Chunk& chunk) {
        return chunk.type == kResXmlResourceMapType;
    });
    Chunk* resource_map = resource_map_it == chunks.end() ? nullptr : &*resource_map_it;
    std::vector<std::uint32_t> resource_ids = ReadResourceMap(resource_map);

    const std::uint32_t android_namespace_idx = strings.FindOrAdd(kAndroidNamespace);
    const std::uint32_t name_idx = strings.FindOrAdd("name");
    const std::uint32_t factory_idx = strings.FindOrAdd("appComponentFactory");
    const std::uint32_t shell_application_idx = strings.FindOrAdd(shell_application);
    const std::uint32_t shell_factory_idx = strings.FindOrAdd(shell_component_factory);

    ManifestInfo original;
    Chunk* application_chunk = nullptr;

    // 先读取原启动信息。字符串池只会在末尾追加条目，所以所有旧 index 在此时仍然有效。
    for (Chunk& chunk : chunks) {
        if (chunk.type != kResXmlStartElementType) {
            continue;
        }
        const ElementView element = ParseStartElement(chunk);
        const std::string& element_name = strings.Get(element.name_idx);
        if (element_name == "manifest") {
            const auto package_attribute =
                FindAttribute(chunk, element, strings, "package", std::nullopt);
            if (!package_attribute.has_value()) {
                throw Error("AndroidManifest.xml 的 manifest 元素缺少 package 属性");
            }
            const ByteView chunk_bytes(chunk.bytes.data(), chunk.bytes.size());
            const auto package_value =
                AttributeStringValue(chunk_bytes, package_attribute.value(), strings);
            if (!package_value.has_value()) {
                throw Error("manifest package 不是字符串，无法解析应用包名");
            }
            original.package_name = strings.Get(package_value.value());
        } else if (element_name == "application") {
            if (application_chunk != nullptr) {
                throw Error("AndroidManifest.xml 包含多个 application 元素");
            }
            application_chunk = &chunk;

            const ByteView chunk_bytes(chunk.bytes.data(), chunk.bytes.size());
            const auto application_attribute =
                FindAttribute(chunk, element, strings, "name", android_namespace_idx);
            if (application_attribute.has_value()) {
                const auto value =
                    AttributeStringValue(chunk_bytes, application_attribute.value(), strings);
                if (!value.has_value()) {
                    throw Error("application android:name 不是字符串，当前不能安全接管");
                }
                original.original_application = strings.Get(value.value());
            }

            const auto factory_attribute = FindAttribute(
                chunk, element, strings, "appComponentFactory", android_namespace_idx);
            if (factory_attribute.has_value()) {
                const auto value =
                    AttributeStringValue(chunk_bytes, factory_attribute.value(), strings);
                if (!value.has_value()) {
                    throw Error("application android:appComponentFactory 不是字符串");
                }
                original.original_app_component_factory = strings.Get(value.value());
            }
        }
    }

    if (original.package_name.empty() || application_chunk == nullptr) {
        throw Error("AndroidManifest.xml 缺少 manifest package 或 application 元素");
    }
    if (original.original_application.empty()) {
        original.original_application = "android.app.Application";
    } else {
        original.original_application =
            ResolveClassName(original.package_name, original.original_application);
    }
    if (!original.original_app_component_factory.empty()) {
        original.original_app_component_factory =
            ResolveClassName(original.package_name, original.original_app_component_factory);
    }

    // 每增加一个属性都重新解析 ElementView，因为 vector::insert 会改变 attributeCount
    // 和后续插入位置。已有属性只原地更新，不改变 chunk 长度。
    SetStringAttribute(*application_chunk, ParseStartElement(*application_chunk), strings,
                       android_namespace_idx, name_idx, "name", shell_application_idx);
    SetStringAttribute(*application_chunk, ParseStartElement(*application_chunk), strings,
                       android_namespace_idx, factory_idx, "appComponentFactory",
                       shell_factory_idx);

    string_pool_it->bytes = strings.Build();
    const std::vector<std::uint8_t> new_resource_map =
        BuildResourceMap(std::move(resource_ids), name_idx, factory_idx);
    if (resource_map != nullptr) {
        resource_map->bytes = new_resource_map;
    } else {
        // AXML 约定 resource map 位于 string pool 之后。vector 插入会使旧指针失效，
        // 但 application 修改已经完成，后面不再使用这些指针。
        const auto insert_position = std::next(string_pool_it);
        chunks.insert(insert_position, {kResXmlResourceMapType, new_resource_map});
    }

    ManifestEditResult result;
    result.binary_xml = BuildXml(chunks);
    result.original = std::move(original);
    return result;
}

}  // namespace dexhollow13::axml
