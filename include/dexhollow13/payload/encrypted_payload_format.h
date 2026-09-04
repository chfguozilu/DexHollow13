#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/crypto/resource_crypto.h"
#include "dexhollow13/payload/payload_format.h"

namespace dexhollow13::payload {

constexpr std::array<std::uint8_t, 8U> kEncryptedPayloadMagic{{
    'D',
    'H',
    '1',
    '3',
    'E',
    'P',
    'A',
    'Y',
}};
constexpr std::uint32_t kEncryptedPayloadVersion = 1U;
constexpr std::uint32_t kEncryptedPayloadFlagAeadPerMethod = 1U;
constexpr std::size_t kEncryptedPayloadHeaderSize = 144U;
constexpr std::size_t kEncryptedPayloadRecordSize = 48U;

using PayloadNoncePrefix = std::array<std::uint8_t, 16U>;
using PayloadMetadataTag = std::array<std::uint8_t, 32U>;

// 一个 record 解码后的短生命周期值。Runtime 的百万方法稠密索引不能永久保存整份结构，
// 否则仅 metadata 就会消耗几十 MB；索引只保存下面 16 字节的 View，需要时再解码本结构。
struct EncryptedMethodPayload {
    std::uint32_t method_idx = 0U;
    std::uint32_t original_code_off = 0U;
    std::uint32_t code_item_size = 0U;
    std::uint32_t ciphertext_offset = 0U;
    std::uint32_t insns_size = 0U;
    std::uint32_t access_flags = 0U;
    dex::StubKind stub_kind = dex::StubKind::kReturnVoid;
    std::uint32_t flags = 0U;
    crypto::AuthenticationTag authentication_tag{};
    const std::uint8_t* encrypted_code_item = nullptr;
};

// record 指向已通过整文件 metadata tag 验证的 48 字节表项；encrypted_code_item 指向同一
// 只读 mmap 中的密文。两者都不拥有内存。
struct EncryptedMethodPayloadView {
    const std::uint8_t* record = nullptr;
    const std::uint8_t* encrypted_code_item = nullptr;
};

// method_key 是由 APK master key 和当前 DEX identity 派生的子密钥。Runtime 只保留这个
// DEX 级上下文，完成初始化后即可擦除临时 master key。
struct PayloadDecryptionContext {
    std::uint32_t dex_ordinal = 0U;
    dex::Sha1Digest original_dex_signature{};
    dex::Sha1Digest hollow_dex_signature{};
    PayloadNoncePrefix nonce_prefix{};
    crypto::MasterKey method_key{};
};

struct EncryptedPayloadView {
    PayloadDecryptionContext decryption;
    std::vector<EncryptedMethodPayloadView> methods;
};

// Host 把 TransformDex 生成的拥有型明文 Payload 改写为逐方法 AEAD 格式。nonce_prefix 必须
// 对每份 Payload 随机且唯一；method_idx 会组成 nonce 的剩余 8 字节。
std::vector<std::uint8_t> WriteEncryptedPayload(const PayloadFile& payload,
                                                const crypto::MasterKey& master_key,
                                                const PayloadNoncePrefix& nonce_prefix);

// 初始化阶段验证整个 Header、record table 和 ciphertext 的 keyed BLAKE2b tag，但不解密
// code_item。这样损坏会在安装 ART Hook 前失败，而明文仍按需产生。
EncryptedPayloadView ReadEncryptedPayloadView(const ByteView& bytes,
                                              const crypto::MasterKey& master_key);

// 把已经由 Reader 验证过的定长 record 解码为便于使用的字段值。
EncryptedMethodPayload DecodeEncryptedMethodPayload(const EncryptedMethodPayloadView& method);

// LoadMethod 命中时验证单方法 Poly1305 tag 并解密。输出必须与 record.code_item_size 相等。
void DecryptMethodCodeItem(const PayloadDecryptionContext& context,
                           const EncryptedMethodPayloadView& method,
                           const MutableByteView& plaintext);

}  // namespace dexhollow13::payload
