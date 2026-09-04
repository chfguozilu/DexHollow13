#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

namespace dexhollow13 {

// 一次性读取完整文件。APK 和 DEX 的 Host 处理本来就需要随机访问，
// 因此这里不采用流式解析，以换取更直接、容易审计的 offset 语义。
std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path);

// 将内容写入新文件或截断已有文件。调用者负责选择最终路径；
// APK 模块完成后会在更高一层增加“临时文件写完再原子改名”。
void WriteFile(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes);

}  // namespace dexhollow13
