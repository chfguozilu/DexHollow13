#pragma once

#include <climits>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"

namespace dexhollow13::dex {

template <typename T>
struct Leb128Value {
    T value{};
    std::size_t next_offset = 0U;
};

// DEX 的 ULEB128 最多用 5 个字节表示一个 uint32_t。
// 返回 next_offset 而不是修改裸指针，使调用点仍然保留“相对文件起点”的 offset。
inline Leb128Value<std::uint32_t> ReadUleb128(const ByteView& view, std::size_t offset,
                                              const std::string& purpose) {
    std::uint32_t result = 0U;

    for (std::size_t index = 0U; index < 5U; ++index) {
        const std::uint8_t byte = view.ReadU8(offset + index, purpose);

        // 第五个字节只能贡献 uint32_t 的最高 4 bit。如果高半字节还有数据，
        // 即使 continuation bit 已经清零，数值也已经超过 uint32_t。
        if (index == 4U && (byte & 0xf0U) != 0U) {
            throw Error(purpose + " 的 ULEB128 超过 uint32_t 范围");
        }

        result |= static_cast<std::uint32_t>(byte & 0x7fU) << static_cast<unsigned int>(index * 7U);

        if ((byte & 0x80U) == 0U) {
            return {result, offset + index + 1U};
        }
    }

    throw Error(purpose + " 的 ULEB128 超过 5 字节或没有终止");
}

// encoded_catch_handler.size 使用 SLEB128：正数表示只有 typed handlers，
// 0 或负数表示 typed handlers 后面还跟一个 catch-all 地址。
inline Leb128Value<std::int32_t> ReadSleb128(const ByteView& view, std::size_t offset,
                                             const std::string& purpose) {
    std::int64_t result = 0;
    unsigned int shift = 0U;

    for (std::size_t index = 0U; index < 5U; ++index) {
        const std::uint8_t byte = view.ReadU8(offset + index, purpose);
        result |= static_cast<std::int64_t>(byte & 0x7fU) << shift;
        shift += 7U;

        if ((byte & 0x80U) == 0U) {
            // 终止字节的 0x40 是当前编码的符号位。
            if ((byte & 0x40U) != 0U && shift < 64U) {
                result |= -(static_cast<std::int64_t>(1) << shift);
            }

            if (result < static_cast<std::int64_t>(INT32_MIN) ||
                result > static_cast<std::int64_t>(INT32_MAX)) {
                throw Error(purpose + " 的 SLEB128 超过 int32_t 范围");
            }
            return {static_cast<std::int32_t>(result), offset + index + 1U};
        }
    }

    throw Error(purpose + " 的 SLEB128 超过 5 字节或没有终止");
}

}  // namespace dexhollow13::dex
