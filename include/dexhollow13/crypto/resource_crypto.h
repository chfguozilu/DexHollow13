#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "dexhollow13/base/byte_view.h"

namespace dexhollow13::crypto {

using MasterKey = std::array<std::uint8_t, 32U>;
using ResourceNonce = std::array<std::uint8_t, 24U>;
using AuthenticationTag = std::array<std::uint8_t, 16U>;

constexpr std::array<std::uint8_t, 8U> kSealedResourceMagic{{
    'D',
    'H',
    '1',
    '3',
    'S',
    'E',
    'A',
    'L',
}};
constexpr std::uint32_t kSealedResourceVersion = 1U;
constexpr std::size_t kSealedResourceHeaderSize = 72U;

enum class ResourceKind : std::uint32_t {
    kBootstrap = 1U,
    kHollowDex = 2U,
};

// SealedResourceView 只引用输入密文，不拥有数据。调用者必须让输入映射在解密结束前有效。
struct SealedResourceView {
    ResourceKind kind = ResourceKind::kBootstrap;
    std::uint32_t ordinal = 0U;
    std::uint32_t plaintext_size = 0U;
    ResourceNonce nonce{};
    AuthenticationTag tag{};
    const std::uint8_t* ciphertext = nullptr;
};

// 用 XChaCha20-Poly1305 加密并认证一个完整资源。nonce 必须由密码学安全随机源生成，且同一
// master_key 下不可重复；函数会把 kind、ordinal 和明文大小一并绑定到认证数据中。
std::vector<std::uint8_t> SealResource(const ByteView& plaintext, const MasterKey& master_key,
                                       const ResourceNonce& nonce, ResourceKind kind,
                                       std::uint32_t ordinal);

// 只解析并检查定长 Header、枚举、长度和范围，不进行解密。
SealedResourceView ReadSealedResourceView(const ByteView& sealed, ResourceKind expected_kind,
                                          std::uint32_t expected_ordinal);

// 解密前会验证 Poly1305 tag；认证失败时不会向调用者交付输出。
void OpenSealedResource(const ByteView& sealed, const MasterKey& master_key,
                        ResourceKind expected_kind, std::uint32_t expected_ordinal,
                        const MutableByteView& plaintext);

// 小资源的便捷拥有型接口。大型 Hollow DEX 应把输出直接写入 mmap，避免额外峰值复制。
std::vector<std::uint8_t> OpenSealedResource(const ByteView& sealed, const MasterKey& master_key,
                                             ResourceKind expected_kind,
                                             std::uint32_t expected_ordinal);

// 调用 Monocypher 的防优化擦除函数，供 Host 和 Runtime 缩短明文密钥驻留时间。
void SecureWipe(void* data, std::size_t size) noexcept;

}  // namespace dexhollow13::crypto
