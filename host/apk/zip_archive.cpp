#include "dexhollow13/apk/zip_archive.h"

#include <zip.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sstream>
#include <utility>

#include "dexhollow13/base/error.h"

namespace dexhollow13::apk {

ZipArchive::ZipArchive(const std::filesystem::path& input,
                       const std::filesystem::path& working_copy) {
    std::error_code file_error;
    std::filesystem::copy_file(input, working_copy,
                               std::filesystem::copy_options::overwrite_existing, file_error);
    if (file_error) {
        throw Error("复制 APK 到工作文件失败：" + file_error.message());
    }

    int zip_error = 0;
    archive_ = zip_open(working_copy.c_str(), 0, &zip_error);
    if (archive_ == nullptr) {
        zip_error_t detail;
        zip_error_init(&detail);
        zip_error_set(&detail, zip_error, errno);
        const std::string message = zip_error_strerror(&detail);
        zip_error_fini(&detail);
        throw Error("libzip 打开工作 APK 失败：" + message);
    }
}

ZipArchive::~ZipArchive() {
    if (archive_ != nullptr && !closed_) {
        // zip_discard 不会写 central directory，专用于失败路径。它还会释放 archive_。
        zip_discard(archive_);
    }
}

std::int64_t ZipArchive::Locate(const std::string& name) const {
    if (archive_ == nullptr || closed_) {
        throw Error("尝试访问已经关闭的 APK");
    }
    return zip_name_locate(archive_, name.c_str(), ZIP_FL_ENC_GUESS);
}

std::string ZipArchive::LastError() const {
    if (archive_ == nullptr) {
        return "archive 为空";
    }
    return zip_strerror(archive_);
}

bool ZipArchive::HasEntry(const std::string& name) const { return Locate(name) >= 0; }

std::vector<std::string> ZipArchive::ListEntries() const {
    const zip_int64_t count = zip_get_num_entries(archive_, 0);
    if (count < 0) {
        throw Error("libzip 读取 entry 数量失败：" + LastError());
    }

    std::vector<std::string> names;
    names.reserve(static_cast<std::size_t>(count));
    for (zip_uint64_t index = 0U; index < static_cast<zip_uint64_t>(count); ++index) {
        const char* name = zip_get_name(archive_, index, ZIP_FL_ENC_GUESS);
        if (name == nullptr) {
            throw Error("libzip 读取 entry 名称失败：" + LastError());
        }
        names.emplace_back(name);
    }
    return names;
}

std::vector<std::uint8_t> ZipArchive::ReadEntry(const std::string& name) const {
    const std::int64_t signed_index = Locate(name);
    if (signed_index < 0) {
        throw Error("APK 中不存在 entry：" + name);
    }

    zip_stat_t stat{};
    zip_stat_init(&stat);
    const auto index = static_cast<zip_uint64_t>(signed_index);
    if (zip_stat_index(archive_, index, ZIP_FL_UNCHANGED, &stat) != 0) {
        throw Error("libzip 读取 entry 信息失败：" + name + "：" + LastError());
    }
    if ((stat.valid & ZIP_STAT_SIZE) == 0U || stat.size > std::numeric_limits<std::size_t>::max()) {
        throw Error("APK entry 大小不可表示：" + name);
    }

    zip_file_t* file = zip_fopen_index(archive_, index, ZIP_FL_UNCHANGED);
    if (file == nullptr) {
        throw Error("libzip 打开 entry 失败：" + name + "：" + LastError());
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(stat.size));
    std::size_t total_read = 0U;
    while (total_read < bytes.size()) {
        const std::size_t request =
            std::min(bytes.size() - total_read,
                     static_cast<std::size_t>(std::numeric_limits<zip_uint64_t>::max()));
        const zip_int64_t read_count = zip_fread(file, bytes.data() + total_read, request);
        if (read_count < 0) {
            zip_fclose(file);
            throw Error("libzip 读取 entry 内容失败：" + name);
        }
        if (read_count == 0) {
            zip_fclose(file);
            throw Error("APK entry 在达到声明大小前结束：" + name);
        }
        total_read += static_cast<std::size_t>(read_count);
    }

    if (zip_fclose(file) != 0) {
        throw Error("libzip 关闭 entry 失败：" + name);
    }
    return bytes;
}

void ZipArchive::DeleteEntry(const std::string& name) {
    const std::int64_t index = Locate(name);
    if (index < 0) {
        return;
    }
    if (zip_delete(archive_, static_cast<zip_uint64_t>(index)) != 0) {
        throw Error("libzip 删除 entry 失败：" + name + "：" + LastError());
    }
}

void ZipArchive::AddOrReplace(const std::string& name, const std::vector<std::uint8_t>& bytes,
                              Compression compression) {
    // zip_source_buffer(..., freep=1) 要求缓冲区由 malloc 分配，libzip 会在 source
    // 生命周期结束时调用 free。复制一次可保证调用者的 vector 提前析构也不会悬空。
    void* owned_buffer = nullptr;
    if (!bytes.empty()) {
        owned_buffer = std::malloc(bytes.size());
        if (owned_buffer == nullptr) {
            throw Error("为 APK entry 分配内存失败：" + name);
        }
        std::memcpy(owned_buffer, bytes.data(), bytes.size());
    }

    zip_source_t* source = zip_source_buffer(archive_, owned_buffer, bytes.size(), 1);
    if (source == nullptr) {
        std::free(owned_buffer);
        throw Error("libzip 创建 entry source 失败：" + name + "：" + LastError());
    }

    const zip_int64_t index =
        zip_file_add(archive_, name.c_str(), source, ZIP_FL_OVERWRITE | ZIP_FL_ENC_UTF_8);
    if (index < 0) {
        // zip_file_add 失败时 source 仍属于调用者，zip_source_free 会连同缓冲区一起释放。
        zip_source_free(source);
        throw Error("libzip 添加 entry 失败：" + name + "：" + LastError());
    }

    const zip_int32_t method = compression == Compression::kStore ? ZIP_CM_STORE : ZIP_CM_DEFLATE;
    if (zip_set_file_compression(archive_, static_cast<zip_uint64_t>(index), method, 0U) != 0) {
        throw Error("libzip 设置 entry 压缩方式失败：" + name + "：" + LastError());
    }
}

void ZipArchive::Close() {
    if (archive_ == nullptr || closed_) {
        throw Error("APK 已经关闭，不能重复提交");
    }

    // zip_close 失败时 archive 仍保持打开，调用者必须 zip_discard；成功时 libzip 才会
    // 消费 handle。先把成员置空，确保异常离开后析构函数不会二次处理同一个对象。
    zip_t* archive_to_close = archive_;
    archive_ = nullptr;
    closed_ = true;
    if (zip_close(archive_to_close) != 0) {
        const std::string message = zip_strerror(archive_to_close);
        zip_discard(archive_to_close);
        throw Error("libzip 提交 APK central directory 失败：" + message);
    }
}

}  // namespace dexhollow13::apk
