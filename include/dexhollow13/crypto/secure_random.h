#pragma once

#include <cstddef>
#include <cstdint>

namespace dexhollow13::crypto {

// Host 端使用 OpenSSL CSPRNG。失败时抛出 Error，绝不退化到时间戳或 std::rand()。
void FillSecureRandom(std::uint8_t* output, std::size_t size);

}  // namespace dexhollow13::crypto
