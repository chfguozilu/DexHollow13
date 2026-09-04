#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "dexhollow13/crypto/resource_crypto.h"

namespace dexhollow13::crypto {

// Runtime 模板 SO 中唯一的 64 字节占位符。Host 打包时把它替换成：
//
//   前 32 字节：随机 mask
//   后 32 字节：master_key XOR mask
//
// 这不是把客户端密钥变成不可提取的秘密，只是避免 SO 中出现连续的明文 key，并保证每个
// 受保护 APK 使用独立随机密钥。真正的安全边界仍在文档中明确说明。
constexpr std::array<std::uint8_t, 64U> kEmbeddedKeyTemplate{{
    0x91U, 0xc2U, 0x23U, 0x16U, 0xb8U, 0xa0U, 0xc7U, 0x09U, 0xb3U, 0xaaU, 0x27U, 0x57U, 0x0bU,
    0xe6U, 0x64U, 0x58U, 0x9fU, 0x2fU, 0x30U, 0x0bU, 0xc2U, 0xd8U, 0x93U, 0xf2U, 0x83U, 0x8fU,
    0xfcU, 0x88U, 0x26U, 0x51U, 0x95U, 0xbaU, 0x85U, 0x11U, 0x47U, 0x41U, 0x0dU, 0x14U, 0x8bU,
    0x00U, 0xd7U, 0x5cU, 0xb6U, 0xb9U, 0x3bU, 0x39U, 0x89U, 0x58U, 0x6dU, 0x71U, 0xf4U, 0x4fU,
    0x1eU, 0xe1U, 0xe5U, 0x5dU, 0xe2U, 0x42U, 0xb3U, 0x00U, 0xa6U, 0x5eU, 0xfaU, 0xb6U,
}};

// 返回注入当前 APK 密钥后的 SO 副本。要求占位符恰好出现一次，避免误补丁或漏补丁。
std::vector<std::uint8_t> PatchEmbeddedMasterKey(const std::vector<std::uint8_t>& library,
                                                 const MasterKey& master_key,
                                                 const MasterKey& random_mask);

// Runtime 从已经补丁过的只读 key material 恢复 master key。若 Host 漏掉补丁，后续 AEAD
// 认证必然失败；Runtime 不再复制一份模板常量用于比较，避免 SO 内出现第二个占位符。
MasterKey LoadEmbeddedMasterKey();

}  // namespace dexhollow13::crypto
