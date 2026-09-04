#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

struct zip;

namespace dexhollow13::apk {

enum class Compression {
    kStore,
    kDeflate,
};

// ZipArchive 在 input APK 的完整副本上原地编辑。
//
// 复制后再编辑有两个好处：未修改 entry 的压缩数据和 metadata 由 libzip 保留；
// 任一步失败时只丢弃 work APK，不会破坏用户的原始输入。
class ZipArchive final {
public:
    ZipArchive(const std::filesystem::path& input, const std::filesystem::path& working_copy);
    ~ZipArchive();

    ZipArchive(const ZipArchive&) = delete;
    ZipArchive& operator=(const ZipArchive&) = delete;

    [[nodiscard]] bool HasEntry(const std::string& name) const;
    [[nodiscard]] std::vector<std::string> ListEntries() const;
    [[nodiscard]] std::vector<std::uint8_t> ReadEntry(const std::string& name) const;

    void DeleteEntry(const std::string& name);
    void AddOrReplace(const std::string& name, const std::vector<std::uint8_t>& bytes,
                      Compression compression);

    // Close 提交 central directory。必须显式调用；析构函数只负责丢弃未提交修改，
    // 从而避免异常展开时意外产出一个看似成功的 APK。
    void Close();

private:
    [[nodiscard]] std::int64_t Locate(const std::string& name) const;
    [[nodiscard]] std::string LastError() const;

    zip* archive_ = nullptr;
    bool closed_ = false;
};

}  // namespace dexhollow13::apk
