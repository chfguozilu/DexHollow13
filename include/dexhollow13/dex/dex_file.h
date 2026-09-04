#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/dex/dex_format.h"

namespace dexhollow13::dex {

// DexFile 只处理 APK 中的标准 DEX（magic 为 "dex\n"）。
// Android 运行时生成的 CompactDex 不属于 APK 静态输入，遇到 cdex 会明确拒绝。
class DexFile {
public:
    explicit DexFile(std::vector<std::uint8_t> bytes);

    [[nodiscard]] const Header& header() const noexcept { return header_; }
    [[nodiscard]] ByteView view() const noexcept { return ByteView(bytes_.data(), bytes_.size()); }
    [[nodiscard]] const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
    [[nodiscard]] std::vector<std::uint8_t>& mutable_bytes() noexcept { return bytes_; }

    // Transformer 完成所有解析后，用这个函数转移最终 Hollow DEX，避免再复制整个文件。
    [[nodiscard]] std::vector<std::uint8_t> ReleaseBytes() noexcept { return std::move(bytes_); }

    [[nodiscard]] std::string GetString(std::uint32_t string_idx) const;
    [[nodiscard]] std::string GetTypeDescriptor(std::uint32_t type_idx) const;
    [[nodiscard]] MethodId GetMethodId(std::uint32_t method_idx) const;
    [[nodiscard]] ClassDef GetClassDef(std::uint32_t class_def_idx) const;

    // 返回参数描述符时不包含圆括号。例如 (ILjava/lang/String;)V 返回
    // "ILjava/lang/String;"，让调用者可以单独保留返回类型。
    [[nodiscard]] std::string GetParametersDescriptor(std::uint32_t proto_idx) const;
    [[nodiscard]] std::string GetReturnDescriptor(std::uint32_t proto_idx) const;

    // 按 class_defs 顺序枚举 class_data_item。每个类内部先返回 direct_methods，
    // 再返回 virtual_methods，与 DEX 文件中的物理顺序一致。
    [[nodiscard]] std::vector<MethodInfo> EnumerateMethods() const;

private:
    [[nodiscard]] Header ParseAndValidateHeader() const;
    void ValidateTable(const std::string& name, std::uint32_t count, std::uint32_t offset,
                       std::size_t item_size) const;
    [[nodiscard]] std::size_t ItemOffset(const std::string& name, std::uint32_t table_offset,
                                         std::uint32_t index, std::uint32_t count,
                                         std::size_t item_size) const;
    [[nodiscard]] MethodInfo BuildMethodInfo(const EncodedMethod& encoded_method) const;

    std::vector<std::uint8_t> bytes_;
    Header header_;
};

}  // namespace dexhollow13::dex
