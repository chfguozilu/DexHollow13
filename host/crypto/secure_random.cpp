#include "dexhollow13/crypto/secure_random.h"

#include <openssl/rand.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

#include "dexhollow13/base/error.h"

namespace dexhollow13::crypto {

void FillSecureRandom(std::uint8_t* output, std::size_t size) {
    if (output == nullptr && size != 0U) {
        throw Error("随机数输出指针为空");
    }
    std::size_t remaining = size;
    std::uint8_t* cursor = output;
    while (remaining != 0U) {
        const std::size_t chunk =
            std::min(remaining, static_cast<std::size_t>(std::numeric_limits<int>::max()));
        // RAND_bytes 使用操作系统 CSPRNG，并在内部处理 DRBG 状态。返回值不为 1 时不能继续
        // 生成密钥或 nonce，否则会把未初始化/可预测数据当成密码材料。
        if (RAND_bytes(cursor, static_cast<int>(chunk)) != 1) {
            throw Error("OpenSSL RAND_bytes 生成密码学随机数失败");
        }
        cursor += chunk;
        remaining -= chunk;
    }
}

}  // namespace dexhollow13::crypto
