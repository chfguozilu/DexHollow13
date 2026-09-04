#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>

#include "dexhollow13/base/error.h"

namespace dexhollow13 {

// ByteView 是一段只读字节内存的非拥有视图。
//
// DEX 中的绝大多数字段都是相对于文件起点的 offset。直接执行
// reinterpret_cast<const uint32_t*>(data + offset) 会同时引入三个问题：
//   1. offset 可能越界；
//   2. 指针可能没有按 uint32_t 对齐；
//   3. 代码错误地依赖 Host CPU 的端序。
// ByteView 在每次读取前检查范围，并显式按 DEX 小端序组合整数。
class ByteView {
public:
    ByteView() = default;

    ByteView(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {
        if (data_ == nullptr && size_ != 0U) {
            throw Error("ByteView 收到空指针，但 size 不为 0");
        }
    }

    [[nodiscard]] const std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0U; }

    // CheckRange 使用 length > size - offset，而不是 offset + length > size。
    // 后一种写法在两个大整数相加溢出时可能把非法范围误判为合法。
    void CheckRange(std::size_t offset, std::size_t length, const std::string& purpose) const {
        if (offset > size_ || length > size_ - offset) {
            std::ostringstream stream;
            stream << purpose << " 越界：offset=0x" << std::hex << offset << ", size=0x" << length
                   << ", file_size=0x" << size_;
            throw Error(stream.str());
        }
    }

    [[nodiscard]] const std::uint8_t* DataAt(std::size_t offset, std::size_t length,
                                             const std::string& purpose) const {
        CheckRange(offset, length, purpose);
        return data_ + offset;
    }

    [[nodiscard]] std::uint8_t ReadU8(std::size_t offset, const std::string& purpose) const {
        return *DataAt(offset, 1U, purpose);
    }

    [[nodiscard]] std::uint16_t ReadU16(std::size_t offset, const std::string& purpose) const {
        const std::uint8_t* value = DataAt(offset, 2U, purpose);
        return static_cast<std::uint16_t>(value[0]) |
               static_cast<std::uint16_t>(static_cast<std::uint16_t>(value[1]) << 8U);
    }

    [[nodiscard]] std::uint32_t ReadU32(std::size_t offset, const std::string& purpose) const {
        const std::uint8_t* value = DataAt(offset, 4U, purpose);
        return static_cast<std::uint32_t>(value[0]) | (static_cast<std::uint32_t>(value[1]) << 8U) |
               (static_cast<std::uint32_t>(value[2]) << 16U) |
               (static_cast<std::uint32_t>(value[3]) << 24U);
    }

    [[nodiscard]] ByteView Subview(std::size_t offset, std::size_t length,
                                   const std::string& purpose) const {
        return ByteView(DataAt(offset, length, purpose), length);
    }

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0U;
};

// MutableByteView 与 ByteView 的职责相同，但只提供变换阶段真正需要的写操作。
// 它不暴露裸的整数指针，保证写回 Hollow 指令和 Header 时仍然经过边界检查。
class MutableByteView {
public:
    MutableByteView(std::uint8_t* data, std::size_t size) : data_(data), read_view_(data, size) {}

    [[nodiscard]] std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return read_view_.size(); }
    [[nodiscard]] ByteView AsReadOnly() const noexcept { return read_view_; }

    void WriteU16(std::size_t offset, std::uint16_t value, const std::string& purpose) const {
        read_view_.CheckRange(offset, 2U, purpose);
        data_[offset] = static_cast<std::uint8_t>(value & 0xffU);
        data_[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    }

    void WriteU32(std::size_t offset, std::uint32_t value, const std::string& purpose) const {
        read_view_.CheckRange(offset, 4U, purpose);
        data_[offset] = static_cast<std::uint8_t>(value & 0xffU);
        data_[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
        data_[offset + 2U] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
        data_[offset + 3U] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
    }

    void CopyFrom(std::size_t offset, const std::uint8_t* source, std::size_t length,
                  const std::string& purpose) const {
        read_view_.CheckRange(offset, length, purpose);
        if (source == nullptr && length != 0U) {
            throw Error(purpose + " 的 source 是空指针");
        }
        std::memcpy(data_ + offset, source, length);
    }

private:
    std::uint8_t* data_;
    ByteView read_view_;
};

// CheckedMultiply 专门处理“元素数量 × 元素大小”的 offset 计算。
// DEX 中的数量来自文件本身，不检查乘法溢出会让后续范围检查失效。
inline std::size_t CheckedMultiply(std::size_t left, std::size_t right,
                                   const std::string& purpose) {
    if (left != 0U && right > std::numeric_limits<std::size_t>::max() / left) {
        throw Error(purpose + " 发生 size_t 乘法溢出");
    }
    return left * right;
}

}  // namespace dexhollow13
