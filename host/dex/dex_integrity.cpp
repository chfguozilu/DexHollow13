#include "dexhollow13/dex/dex_integrity.h"

#include <openssl/evp.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"

namespace dexhollow13::dex {
namespace {

constexpr std::size_t kChecksumOffset = 8U;
constexpr std::size_t kSignatureOffset = 12U;
constexpr std::size_t kSignatureSize = 20U;
constexpr std::size_t kSignatureCoveredOffset = 32U;

}  // namespace

Sha1Digest ComputeDexSignature(const ByteView& dex) {
    dex.CheckRange(kSignatureCoveredOffset, 0U, "DEX signature 覆盖起点");

    Sha1Digest digest{};
    unsigned int digest_size = 0U;

    // EVP_Digest 是 OpenSSL 的统一摘要接口。EVP_sha1() 只选择 DEX 规范要求的算法；
    // 这里不把 SHA-1 当作抗碰撞安全机制，也不用于保护 Payload 的机密性。
    const int result =
        EVP_Digest(dex.data() + kSignatureCoveredOffset, dex.size() - kSignatureCoveredOffset,
                   digest.data(), &digest_size, EVP_sha1(), nullptr);
    if (result != 1 || digest_size != digest.size()) {
        throw Error("OpenSSL 计算 DEX SHA-1 signature 失败");
    }
    return digest;
}

std::uint32_t ComputeDexChecksum(const ByteView& dex) {
    dex.CheckRange(kSignatureOffset, kSignatureSize, "DEX checksum 覆盖起点");

    uLong checksum = adler32(0L, Z_NULL, 0U);
    const std::uint8_t* cursor = dex.data() + kSignatureOffset;
    std::size_t remaining = dex.size() - kSignatureOffset;

    // zlib 的单次输入长度是 uInt；循环分块使代码在 uInt 小于 size_t 的平台上也正确。
    while (remaining != 0U) {
        const std::size_t chunk_size =
            std::min(remaining, static_cast<std::size_t>(std::numeric_limits<uInt>::max()));
        checksum = adler32(checksum, cursor, static_cast<uInt>(chunk_size));
        cursor += chunk_size;
        remaining -= chunk_size;
    }
    return static_cast<std::uint32_t>(checksum);
}

void VerifyDexIntegrity(const ByteView& dex) {
    const Sha1Digest actual_signature = ComputeDexSignature(dex);
    const std::uint8_t* stored_signature =
        dex.DataAt(kSignatureOffset, kSignatureSize, "header.signature");
    if (!std::equal(actual_signature.begin(), actual_signature.end(), stored_signature)) {
        throw Error("输入 DEX 的 SHA-1 signature 不正确");
    }

    const std::uint32_t stored_checksum = dex.ReadU32(kChecksumOffset, "header.checksum");
    if (stored_checksum != ComputeDexChecksum(dex)) {
        throw Error("输入 DEX 的 Adler32 checksum 不正确");
    }
}

void RepairDexIntegrity(std::vector<std::uint8_t>& dex) {
    MutableByteView writable(dex.data(), dex.size());
    const Sha1Digest signature = ComputeDexSignature(writable.AsReadOnly());
    writable.CopyFrom(kSignatureOffset, signature.data(), signature.size(),
                      "写回 header.signature");

    const std::uint32_t checksum = ComputeDexChecksum(writable.AsReadOnly());
    writable.WriteU32(kChecksumOffset, checksum, "写回 header.checksum");
}

}  // namespace dexhollow13::dex
