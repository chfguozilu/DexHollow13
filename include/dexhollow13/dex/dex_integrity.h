#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "dexhollow13/base/byte_view.h"

namespace dexhollow13::dex {

using Sha1Digest = std::array<std::uint8_t, 20U>;

// DEX signature 覆盖 offset 32（file_size）到文件结尾，不包含 magic、checksum
// 和 signature 字段本身。
Sha1Digest ComputeDexSignature(const ByteView& dex);

// DEX checksum 覆盖 offset 12（signature）到文件结尾，不包含 magic 和 checksum。
std::uint32_t ComputeDexChecksum(const ByteView& dex);

// 在修改方法体前验证输入 DEX 自身是一致的。坏输入不应被继续加工成一个更难定位的坏 APK。
void VerifyDexIntegrity(const ByteView& dex);

// 修复顺序必须先 signature 后 checksum，因为 checksum 的覆盖范围包含 signature。
void RepairDexIntegrity(std::vector<std::uint8_t>& dex);

}  // namespace dexhollow13::dex
