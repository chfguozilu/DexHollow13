#include "resource_decryptor.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "dexhollow13/base/error.h"
#include "dexhollow13/crypto/key_material.h"

namespace dexhollow13::runtime {
namespace {

class ScopedFile final {
public:
    explicit ScopedFile(int descriptor) : descriptor_(descriptor) {}
    ~ScopedFile() {
        if (descriptor_ >= 0) {
            close(descriptor_);
        }
    }

    ScopedFile(const ScopedFile&) = delete;
    ScopedFile& operator=(const ScopedFile&) = delete;

    [[nodiscard]] int get() const noexcept { return descriptor_; }

private:
    int descriptor_ = -1;
};

class ScopedMapping final {
public:
    ScopedMapping(void* address, std::size_t size) : address_(address), size_(size) {}
    ~ScopedMapping() {
        if (address_ != MAP_FAILED) {
            munmap(address_, size_);
        }
    }

    ScopedMapping(const ScopedMapping&) = delete;
    ScopedMapping& operator=(const ScopedMapping&) = delete;

    [[nodiscard]] void* data() const noexcept { return address_; }

private:
    void* address_ = MAP_FAILED;
    std::size_t size_ = 0U;
};

class ScopedMasterKey final {
public:
    ScopedMasterKey() : value_(crypto::LoadEmbeddedMasterKey()) {}
    ~ScopedMasterKey() { crypto::SecureWipe(value_.data(), value_.size()); }

    ScopedMasterKey(const ScopedMasterKey&) = delete;
    ScopedMasterKey& operator=(const ScopedMasterKey&) = delete;

    [[nodiscard]] const crypto::MasterKey& value() const noexcept { return value_; }

private:
    crypto::MasterKey value_{};
};

std::size_t ReadRegularFileSize(int descriptor, const std::string& purpose) {
    struct stat status{};
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size <= 0) {
        throw Error(purpose + " 不是非空普通文件，errno=" + std::to_string(errno));
    }
    const auto unsigned_size = static_cast<std::uint64_t>(status.st_size);
    if (unsigned_size > std::numeric_limits<std::size_t>::max()) {
        throw Error(purpose + " 大小超过当前进程 size_t 范围");
    }
    return static_cast<std::size_t>(unsigned_size);
}

}  // namespace

crypto::ResourceKind ParseResourceKind(std::uint32_t raw_kind) {
    if (raw_kind == static_cast<std::uint32_t>(crypto::ResourceKind::kBootstrap)) {
        return crypto::ResourceKind::kBootstrap;
    }
    if (raw_kind == static_cast<std::uint32_t>(crypto::ResourceKind::kHollowDex)) {
        return crypto::ResourceKind::kHollowDex;
    }
    throw Error("JNI 请求了未知的加密资源 kind");
}

std::vector<std::uint8_t> DecryptResourceBytes(const ByteView& sealed, crypto::ResourceKind kind,
                                               std::uint32_t ordinal) {
    ScopedMasterKey master_key;
    return crypto::OpenSealedResource(sealed, master_key.value(), kind, ordinal);
}

void DecryptResourceFile(const std::string& input_path, const std::string& output_path,
                         crypto::ResourceKind kind, std::uint32_t ordinal) {
    const int input_descriptor = open(input_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input_descriptor < 0) {
        throw Error("打开加密资源缓存失败，errno=" + std::to_string(errno));
    }
    ScopedFile input_file(input_descriptor);
    const std::size_t input_size = ReadRegularFileSize(input_file.get(), "加密资源缓存");
    void* input_address = mmap(nullptr, input_size, PROT_READ, MAP_PRIVATE, input_file.get(), 0);
    if (input_address == MAP_FAILED) {
        throw Error("mmap 加密资源缓存失败，errno=" + std::to_string(errno));
    }
    ScopedMapping input_mapping(input_address, input_size);

    const ByteView sealed(static_cast<const std::uint8_t*>(input_mapping.data()), input_size);
    const crypto::SealedResourceView resource =
        crypto::ReadSealedResourceView(sealed, kind, ordinal);
    const int output_descriptor =
        open(output_path.c_str(), O_RDWR | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (output_descriptor < 0) {
        throw Error("打开 Hollow DEX 临时文件失败，errno=" + std::to_string(errno));
    }
    ScopedFile output_file(output_descriptor);
    if (fchmod(output_file.get(), S_IRUSR | S_IWUSR) != 0 ||
        ftruncate(output_file.get(), static_cast<off_t>(resource.plaintext_size)) != 0) {
        throw Error("调整 Hollow DEX 临时文件失败，errno=" + std::to_string(errno));
    }

    void* output_address = mmap(nullptr, resource.plaintext_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, output_file.get(), 0);
    if (output_address == MAP_FAILED) {
        throw Error("mmap Hollow DEX 临时文件失败，errno=" + std::to_string(errno));
    }
    ScopedMapping output_mapping(output_address, resource.plaintext_size);

    try {
        ScopedMasterKey master_key;
        crypto::OpenSealedResource(
            sealed, master_key.value(), kind, ordinal,
            MutableByteView(static_cast<std::uint8_t*>(output_mapping.data()),
                            resource.plaintext_size));
        if (msync(output_mapping.data(), resource.plaintext_size, MS_SYNC) != 0 ||
            fsync(output_file.get()) != 0) {
            throw Error("提交 Hollow DEX 临时明文失败，errno=" + std::to_string(errno));
        }
    } catch (...) {
        crypto::SecureWipe(output_mapping.data(), resource.plaintext_size);
        static_cast<void>(msync(output_mapping.data(), resource.plaintext_size, MS_SYNC));
        static_cast<void>(ftruncate(output_file.get(), 0));
        throw;
    }
}

}  // namespace dexhollow13::runtime
