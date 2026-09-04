#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/crypto/resource_crypto.h"

namespace dexhollow13::runtime {

crypto::ResourceKind ParseResourceKind(std::uint32_t raw_kind);

// bootstrap 很小，JNI 可以安全地用 byte[] 传递；函数返回认证后的拥有型明文。
std::vector<std::uint8_t> DecryptResourceBytes(const ByteView& sealed, crypto::ResourceKind kind,
                                               std::uint32_t ordinal);

// Hollow DEX 可能有十几 MB，直接把 input/output 文件 mmap 后解密，避免 Java heap 和额外
// Native vector 峰值。output_path 必须是 Java 在应用私有 code_cache 中创建的临时文件。
void DecryptResourceFile(const std::string& input_path, const std::string& output_path,
                         crypto::ResourceKind kind, std::uint32_t ordinal);

}  // namespace dexhollow13::runtime
