#include "dexhollow13/base/file_io.h"

#include <fstream>
#include <limits>
#include <sstream>

#include "dexhollow13/base/error.h"

namespace dexhollow13 {

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path) {
    // ate 让文件指针初始位于末尾，从而可以先取得文件大小，再一次性分配内存。
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw Error("无法打开输入文件：" + path.string());
    }

    const std::streampos end_position = input.tellg();
    if (end_position < 0) {
        throw Error("无法取得输入文件大小：" + path.string());
    }

    const auto unsigned_size = static_cast<std::uintmax_t>(end_position);
    if (unsigned_size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())) {
        throw Error("输入文件大于当前进程可以寻址的内存：" + path.string());
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(unsigned_size));
    input.seekg(0, std::ios::beg);

    if (!bytes.empty()) {
        // std::istream::read 使用 streamsize；在转换前先验证不会超过其最大值。
        if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
            throw Error("输入文件超过 std::streamsize 可表示范围：" + path.string());
        }
        input.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        if (!input) {
            throw Error("读取输入文件失败或文件在读取期间发生变化：" + path.string());
        }
    }

    return bytes;
}

void WriteFile(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw Error("无法创建输出文件：" + path.string());
    }

    if (!bytes.empty()) {
        if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
            throw Error("输出文件超过 std::streamsize 可表示范围：" + path.string());
        }
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }

    // close 时也可能因为磁盘空间不足等原因失败，因此显式 flush 并检查状态。
    output.flush();
    if (!output) {
        throw Error("写入输出文件失败：" + path.string());
    }
}

}  // namespace dexhollow13
