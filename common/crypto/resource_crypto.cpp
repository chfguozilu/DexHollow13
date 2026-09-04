#include "dexhollow13/crypto/resource_crypto.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#include "dexhollow13/base/error.h"
#include "monocypher.h"

namespace dexhollow13::crypto {
namespace {

constexpr std::size_t kAssociatedDataSize = 56U;

void AppendU32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

MasterKey DeriveResourceKey(const MasterKey& master_key, ResourceKind kind, std::uint32_t ordinal) {
    // 不直接让不同格式共用 master key。固定 domain 加上资源身份形成 KDF 输入，BLAKE2b keyed
    // mode 输出本资源的 256-bit 子密钥；ordinal 采用显式小端编码，Host/ARM 行为一致。
    std::vector<std::uint8_t> context{
        'D', 'H', '1', '3', '-', 'R', 'E', 'S', '-', 'K', 'D', 'F', '-', '1',
    };
    AppendU32(context, static_cast<std::uint32_t>(kind));
    AppendU32(context, ordinal);

    MasterKey derived{};
    crypto_blake2b_keyed(derived.data(), derived.size(), master_key.data(), master_key.size(),
                         context.data(), context.size());
    return derived;
}

bool IsKnownResourceKind(std::uint32_t raw_kind) {
    return raw_kind == static_cast<std::uint32_t>(ResourceKind::kBootstrap) ||
           raw_kind == static_cast<std::uint32_t>(ResourceKind::kHollowDex);
}

}  // namespace

std::vector<std::uint8_t> SealResource(const ByteView& plaintext, const MasterKey& master_key,
                                       const ResourceNonce& nonce, ResourceKind kind,
                                       std::uint32_t ordinal) {
    if (plaintext.empty() || plaintext.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw Error("加密资源为空或超过 uint32_t 可表示范围");
    }
    if (!IsKnownResourceKind(static_cast<std::uint32_t>(kind))) {
        throw Error("加密资源 kind 非法");
    }

    const std::size_t output_size = kSealedResourceHeaderSize + plaintext.size();
    std::vector<std::uint8_t> output;
    output.reserve(output_size);
    output.insert(output.end(), kSealedResourceMagic.begin(), kSealedResourceMagic.end());
    AppendU32(output, kSealedResourceVersion);
    AppendU32(output, static_cast<std::uint32_t>(kSealedResourceHeaderSize));
    AppendU32(output, static_cast<std::uint32_t>(kind));
    AppendU32(output, ordinal);
    AppendU32(output, static_cast<std::uint32_t>(plaintext.size()));
    AppendU32(output, 0U);  // reserved
    output.insert(output.end(), nonce.begin(), nonce.end());
    output.resize(output_size, 0U);  // 先给 16-byte tag 和等长 ciphertext 留出空间。

    MasterKey resource_key = DeriveResourceKey(master_key, kind, ordinal);
    crypto_aead_lock(output.data() + kSealedResourceHeaderSize, output.data() + kAssociatedDataSize,
                     resource_key.data(), nonce.data(), output.data(), kAssociatedDataSize,
                     plaintext.data(), plaintext.size());
    SecureWipe(resource_key.data(), resource_key.size());
    return output;
}

SealedResourceView ReadSealedResourceView(const ByteView& sealed, ResourceKind expected_kind,
                                          std::uint32_t expected_ordinal) {
    sealed.CheckRange(0U, kSealedResourceHeaderSize, "加密资源 Header");
    if (!std::equal(kSealedResourceMagic.begin(), kSealedResourceMagic.end(),
                    sealed.DataAt(0U, kSealedResourceMagic.size(), "加密资源 magic"))) {
        throw Error("加密资源 magic 不正确");
    }

    const std::uint32_t version = sealed.ReadU32(8U, "加密资源 version");
    const std::uint32_t header_size = sealed.ReadU32(12U, "加密资源 header_size");
    const std::uint32_t raw_kind = sealed.ReadU32(16U, "加密资源 kind");
    const std::uint32_t ordinal = sealed.ReadU32(20U, "加密资源 ordinal");
    const std::uint32_t plaintext_size = sealed.ReadU32(24U, "加密资源 plaintext_size");
    const std::uint32_t reserved = sealed.ReadU32(28U, "加密资源 reserved");
    if (version != kSealedResourceVersion || header_size != kSealedResourceHeaderSize ||
        !IsKnownResourceKind(raw_kind) || reserved != 0U || plaintext_size == 0U) {
        throw Error("加密资源 Header 字段不受支持");
    }
    if (raw_kind != static_cast<std::uint32_t>(expected_kind) || ordinal != expected_ordinal) {
        throw Error("加密资源 kind/ordinal 与请求不一致");
    }
    if (plaintext_size != sealed.size() - kSealedResourceHeaderSize) {
        throw Error("加密资源 plaintext_size 与密文长度不一致");
    }

    SealedResourceView view;
    view.kind = static_cast<ResourceKind>(raw_kind);
    view.ordinal = ordinal;
    view.plaintext_size = plaintext_size;
    std::copy_n(sealed.DataAt(32U, view.nonce.size(), "加密资源 nonce"), view.nonce.size(),
                view.nonce.begin());
    std::copy_n(sealed.DataAt(56U, view.tag.size(), "加密资源 tag"), view.tag.size(),
                view.tag.begin());
    view.ciphertext =
        sealed.DataAt(kSealedResourceHeaderSize, plaintext_size, "加密资源 ciphertext");
    return view;
}

void OpenSealedResource(const ByteView& sealed, const MasterKey& master_key,
                        ResourceKind expected_kind, std::uint32_t expected_ordinal,
                        const MutableByteView& plaintext) {
    const SealedResourceView view = ReadSealedResourceView(sealed, expected_kind, expected_ordinal);
    if (plaintext.size() != view.plaintext_size) {
        throw Error("加密资源输出缓冲区大小不一致");
    }

    MasterKey resource_key = DeriveResourceKey(master_key, view.kind, view.ordinal);
    const int result = crypto_aead_unlock(plaintext.data(), view.tag.data(), resource_key.data(),
                                          view.nonce.data(), sealed.data(), kAssociatedDataSize,
                                          view.ciphertext, view.plaintext_size);
    SecureWipe(resource_key.data(), resource_key.size());
    if (result != 0) {
        SecureWipe(plaintext.data(), plaintext.size());
        throw Error("加密资源认证失败：密钥错误或内容已被修改");
    }
}

std::vector<std::uint8_t> OpenSealedResource(const ByteView& sealed, const MasterKey& master_key,
                                             ResourceKind expected_kind,
                                             std::uint32_t expected_ordinal) {
    const SealedResourceView view = ReadSealedResourceView(sealed, expected_kind, expected_ordinal);
    std::vector<std::uint8_t> plaintext(view.plaintext_size);
    OpenSealedResource(sealed, master_key, expected_kind, expected_ordinal,
                       MutableByteView(plaintext.data(), plaintext.size()));
    return plaintext;
}

void SecureWipe(void* data, std::size_t size) noexcept {
    if (data != nullptr && size != 0U) {
        crypto_wipe(data, size);
    }
}

}  // namespace dexhollow13::crypto
