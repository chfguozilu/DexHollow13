#include "dexhollow13/apk/apk_packer.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

#include "dexhollow13/apk/zip_archive.h"
#include "dexhollow13/axml/manifest_editor.h"
#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"
#include "dexhollow13/base/file_io.h"
#include "dexhollow13/bootstrap/bootstrap_format.h"
#include "dexhollow13/crypto/key_material.h"
#include "dexhollow13/crypto/resource_crypto.h"
#include "dexhollow13/crypto/secure_random.h"
#include "dexhollow13/dex/dex_transformer.h"
#include "dexhollow13/payload/encrypted_payload_format.h"
#include "dexhollow13/payload/payload_format.h"

namespace dexhollow13::apk {
namespace {

constexpr const char* kManifestEntry = "AndroidManifest.xml";
// Loader 在读到 bootstrap 之前还不知道其他资源的随机名称，所以唯独这个
// 入口必须是固定路径。点开头目录和中性 .dat 后缀只用于降低解压后的
// 显眼程度；安全性仍然由认证加密提供，不依赖隐藏文件名。
constexpr const char* kAssetNamespace = "assets/.d13/";
constexpr const char* kBootstrapAsset = ".d13/0.dat";
constexpr const char* kShellApplication = "com.dexhollow13.loader.ShellApplication";
constexpr const char* kShellComponentFactory = "com.dexhollow13.loader.ShellComponentFactory";

struct DexEntry {
    std::string name;
    std::uint32_t ordinal = 0U;
};

struct RuntimeAbiSelection {
    bool arm64 = false;
    bool arm32 = false;
};

class WorkFiles final {
public:
    WorkFiles(std::filesystem::path archive, std::filesystem::path aligned)
        : archive_(std::move(archive)), aligned_(std::move(aligned)) {}

    ~WorkFiles() {
        // 这里只删除本次 ProtectApk 明确创建的两个同目录工作文件，绝不递归清理目录。
        std::error_code ignored;
        std::filesystem::remove(archive_, ignored);
        std::filesystem::remove(aligned_, ignored);
    }

    [[nodiscard]] const std::filesystem::path& archive() const noexcept { return archive_; }
    [[nodiscard]] const std::filesystem::path& aligned() const noexcept { return aligned_; }

private:
    std::filesystem::path archive_;
    std::filesystem::path aligned_;
};

class SensitiveMasterKey final {
public:
    SensitiveMasterKey() {
        // 每次处理 APK 都生成独立 256-bit master key。它不会写入 assets；Host 只把经过随机
        // mask 拆分的材料补丁到本次 APK 的两个 Runtime SO 副本。
        crypto::FillSecureRandom(value_.data(), value_.size());
    }

    ~SensitiveMasterKey() { crypto::SecureWipe(value_.data(), value_.size()); }

    SensitiveMasterKey(const SensitiveMasterKey&) = delete;
    SensitiveMasterKey& operator=(const SensitiveMasterKey&) = delete;

    [[nodiscard]] const crypto::MasterKey& value() const noexcept { return value_; }

private:
    crypto::MasterKey value_{};
};

template <typename Array>
Array GenerateRandomArray() {
    Array output{};
    crypto::FillSecureRandom(output.data(), output.size());
    return output;
}

std::string GenerateOpaqueAssetName(std::unordered_set<std::string>* allocated_names) {
    if (allocated_names == nullptr) {
        throw Error("生成资源名时收到空的去重集合");
    }

    // DEX 和 Payload 使用同一目录、同一后缀和 128-bit 随机名。不在名称中
    // 暴露 classesN、payloadN 或 ordinal；它们的真实类型和顺序保存在已加密的
    // bootstrap 内。虽然 128-bit 随机碰撞概率已经极低，仍显式去重，避免
    // 任何情况下两份资源覆盖同一 ZIP entry。
    constexpr char kHexDigits[] = "0123456789abcdef";
    for (std::size_t attempt = 0U; attempt < 32U; ++attempt) {
        const std::array<std::uint8_t, 16U> random =
            GenerateRandomArray<std::array<std::uint8_t, 16U>>();
        std::string name = ".d13/r/";
        name.reserve(name.size() + random.size() * 2U + 4U);
        for (const std::uint8_t byte : random) {
            name.push_back(kHexDigits[byte >> 4U]);
            name.push_back(kHexDigits[byte & 0x0fU]);
        }
        name += ".dat";
        if (allocated_names->insert(name).second) {
            return name;
        }
    }
    throw Error("连续生成重复的随机资源名");
}

std::filesystem::path CreateUniqueWorkFile(const std::filesystem::path& output_apk,
                                           const std::string& stage) {
    // 临时文件必须与最终输出位于同一目录，最后的 rename 才不会跨文件系统。mkstemp 会
    // 原子创建 0600 文件，既避免并发两次加壳互相覆盖，也不会碰撞用户已有的同名文件。
    std::string path_template = output_apk.string() + ".dh13-" + stage + "-XXXXXX";
    std::vector<char> writable(path_template.begin(), path_template.end());
    writable.push_back('\0');
    const int descriptor = mkstemp(writable.data());
    if (descriptor < 0) {
        throw Error("创建 APK 临时文件失败，errno=" + std::to_string(errno));
    }
    if (close(descriptor) != 0) {
        const int close_error = errno;
        std::error_code ignored;
        std::filesystem::remove(writable.data(), ignored);
        throw Error("关闭 APK 临时文件失败，errno=" + std::to_string(close_error));
    }
    return std::filesystem::path(writable.data());
}

bool EndsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::optional<std::uint32_t> ParseRootDexOrdinal(const std::string& name) {
    if (name == "classes.dex") {
        return 0U;
    }
    if (!EndsWith(name, ".dex") || name.rfind("classes", 0U) != 0U) {
        return std::nullopt;
    }

    const std::string number = name.substr(7U, name.size() - 7U - 4U);
    if (number.empty() || number.front() == '0') {
        return std::nullopt;
    }
    std::size_t parsed = 0U;
    unsigned long value = 0UL;
    try {
        value = std::stoul(number, &parsed, 10);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (parsed != number.size() || value < 2UL || value > 0xffffffffUL) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value - 1UL);
}

std::vector<DexEntry> FindRootDexEntries(const std::vector<std::string>& names) {
    std::vector<DexEntry> dex_files;
    for (const std::string& name : names) {
        const auto ordinal = ParseRootDexOrdinal(name);
        if (ordinal.has_value()) {
            dex_files.push_back({name, ordinal.value()});
        }
    }
    std::sort(dex_files.begin(), dex_files.end(), [](const DexEntry& left, const DexEntry& right) {
        return left.ordinal < right.ordinal;
    });
    if (dex_files.empty() || dex_files.front().ordinal != 0U) {
        throw Error("输入 APK 缺少根 classes.dex");
    }
    for (std::size_t index = 0U; index < dex_files.size(); ++index) {
        if (dex_files[index].ordinal != index) {
            throw Error("输入 APK 的 classes*.dex 序号不连续");
        }
    }
    return dex_files;
}

bool IsV1SignatureEntry(const std::string& name) {
    if (name.rfind("META-INF/", 0U) != 0U) {
        return false;
    }
    return name == "META-INF/MANIFEST.MF" || EndsWith(name, ".SF") || EndsWith(name, ".RSA") ||
           EndsWith(name, ".DSA") || EndsWith(name, ".EC");
}

// 三个文件都使用项目专属前缀。业务 APK 可以继续携带它自己的 libshadowhook.so 和
// libshadowhook_nothing.so；只有真正占用 DexHollow13 私有名称时才属于不可合并冲突。
constexpr const char* kRuntimeLibraryName = "libdexhollow13_shell.so";
constexpr const char* kShadowHookLibraryName = "libdexhollow13_shadowhook.so";
constexpr const char* kShadowHookNothingLibraryName = "libdexhollow13_shadowhook_nothing.so";

RuntimeAbiSelection SelectRuntimeAbis(const std::vector<std::string>& entries) {
    RuntimeAbiSelection selection;
    bool has_input_native_library = false;
    std::vector<std::string> unsupported_abis;

    for (const std::string& entry : entries) {
        if (entry.rfind("lib/", 0U) != 0U || !EndsWith(entry, ".so")) {
            continue;
        }
        const std::size_t abi_end = entry.find('/', 4U);
        if (abi_end == std::string::npos || abi_end == 4U || abi_end + 1U == entry.size()) {
            continue;
        }

        has_input_native_library = true;
        const std::string abi = entry.substr(4U, abi_end - 4U);
        const std::string filename = entry.substr(abi_end + 1U);
        if (filename == kRuntimeLibraryName || filename == kShadowHookLibraryName ||
            filename == kShadowHookNothingLibraryName) {
            throw Error("输入 APK 的 Native 库名与 DexHollow13 Runtime 冲突：" + entry);
        }

        if (abi == "arm64-v8a") {
            selection.arm64 = true;
        } else if (abi == "armeabi-v7a") {
            selection.arm32 = true;
        } else if (std::find(unsupported_abis.begin(), unsupported_abis.end(), abi) ==
                   unsupported_abis.end()) {
            unsupported_abis.push_back(abi);
        }
    }

    if (!unsupported_abis.empty()) {
        std::string message = "输入 APK 含 DexHollow13 未支持的 Native ABI：";
        for (std::size_t index = 0U; index < unsupported_abis.size(); ++index) {
            message += (index == 0U ? "" : ", ") + unsupported_abis[index];
        }
        throw Error(message + "；请先生成只含 arm64-v8a/armeabi-v7a 的 base APK");
    }

    if (!has_input_native_library) {
        // 纯 Java/Kotlin APK 没有既有 ABI 约束，两套 Runtime 都写入，设备可自行选择进程位数。
        selection.arm64 = true;
        selection.arm32 = true;
    } else if (!selection.arm64 && !selection.arm32) {
        throw Error("输入 APK 没有 DexHollow13 支持的 ARM Native ABI");
    }
    return selection;
}

void RequireRegularFile(const std::filesystem::path& path, const std::string& purpose) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) || error) {
        throw Error(purpose + " 不存在或不是普通文件：" + path.string());
    }
}

// 在 PATH 中查找可执行文件。std::filesystem 只负责文件系统操作，本身没有与
// execvp(3) 等价的查找函数，所以这里按 POSIX 的冒号分隔规则逐项检查。
std::optional<std::filesystem::path> FindExecutableOnPath(const std::string& name) {
    const char* path_environment = std::getenv("PATH");
    if (path_environment == nullptr) {
        return std::nullopt;
    }

    const std::string search_path(path_environment);
    std::size_t begin = 0U;
    while (begin <= search_path.size()) {
        const std::size_t end = search_path.find(':', begin);
        const std::string directory = search_path.substr(begin, end - begin);
        // PATH 中的空项目按 POSIX 语义表示当前目录。
        const std::filesystem::path candidate =
            (directory.empty() ? std::filesystem::path(".") : std::filesystem::path(directory)) /
            name;
        std::error_code error;
        if (std::filesystem::is_regular_file(candidate, error) && !error &&
            access(candidate.c_str(), X_OK) == 0) {
            return candidate;
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1U;
    }
    return std::nullopt;
}

void RunZipalign(const std::filesystem::path& executable, const std::filesystem::path& input,
                 const std::filesystem::path& output) {
    const pid_t child = fork();
    if (child < 0) {
        throw Error("fork zipalign 失败，errno=" + std::to_string(errno));
    }
    if (child == 0) {
        // execl 直接传递 argv，不经过 shell；APK 路径中的空格和特殊字符不会变成命令注入。
        execl(executable.c_str(), executable.filename().c_str(), "-f", "-p", "4", input.c_str(),
              output.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            throw Error("waitpid zipalign 失败，errno=" + std::to_string(errno));
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        throw Error("zipalign 执行失败，exit_status=" + std::to_string(status));
    }
}

std::optional<std::filesystem::path> RuntimeRootIfValid(const std::filesystem::path& root) {
    if (std::filesystem::is_regular_file(root / "classes.dex") &&
        std::filesystem::is_regular_file(root / "lib/arm64-v8a" / kRuntimeLibraryName) &&
        std::filesystem::is_regular_file(root / "lib/armeabi-v7a" / kRuntimeLibraryName) &&
        std::filesystem::is_regular_file(root / "lib/arm64-v8a" / kShadowHookLibraryName) &&
        std::filesystem::is_regular_file(root / "lib/armeabi-v7a" / kShadowHookLibraryName) &&
        std::filesystem::is_regular_file(root / "lib/arm64-v8a" / kShadowHookNothingLibraryName) &&
        std::filesystem::is_regular_file(root / "lib/armeabi-v7a" /
                                         kShadowHookNothingLibraryName)) {
        return root;
    }
    return std::nullopt;
}

}  // namespace

RuntimeArtifacts FindRuntimeArtifacts(const std::filesystem::path& executable_path) {
    if (const char* environment = std::getenv("DEXHOLLOW_RUNTIME_DIR")) {
        const auto root = RuntimeRootIfValid(environment);
        if (root.has_value()) {
            return {root.value() / "classes.dex",
                    root.value() / "lib/arm64-v8a" / kRuntimeLibraryName,
                    root.value() / "lib/armeabi-v7a" / kRuntimeLibraryName,
                    root.value() / "lib/arm64-v8a" / kShadowHookLibraryName,
                    root.value() / "lib/armeabi-v7a" / kShadowHookLibraryName,
                    root.value() / "lib/arm64-v8a" / kShadowHookNothingLibraryName,
                    root.value() / "lib/armeabi-v7a" / kShadowHookNothingLibraryName};
        }
        throw Error("DEXHOLLOW_RUNTIME_DIR 不包含完整 Runtime artifacts");
    }

    std::error_code error;
    const std::filesystem::path absolute_executable =
        std::filesystem::canonical(executable_path, error);
    if (!error) {
        // 发布包采用 dist/dex-hollow + dist/runtime/ 的自包含布局。用户只需要执行
        // dist/dex-hollow，不必知道 Loader DEX 和 Native SO 的具体位置。
        const std::filesystem::path release_candidate =
            absolute_executable.parent_path() / "runtime";
        const auto release_root = RuntimeRootIfValid(release_candidate);
        if (release_root.has_value()) {
            return {release_root.value() / "classes.dex",
                    release_root.value() / "lib/arm64-v8a" / kRuntimeLibraryName,
                    release_root.value() / "lib/armeabi-v7a" / kRuntimeLibraryName,
                    release_root.value() / "lib/arm64-v8a" / kShadowHookLibraryName,
                    release_root.value() / "lib/armeabi-v7a" / kShadowHookLibraryName,
                    release_root.value() / "lib/arm64-v8a" / kShadowHookNothingLibraryName,
                    release_root.value() / "lib/armeabi-v7a" / kShadowHookNothingLibraryName};
        }

        // 开发构建采用 build/dex-hollow + out/runtime/。保留这个候选路径可以让开发者
        // 直接运行 build/dex-hollow，而不必先制作发布目录。
        const std::filesystem::path build_tree_candidate =
            absolute_executable.parent_path().parent_path() / "out/runtime";
        const auto root = RuntimeRootIfValid(build_tree_candidate);
        if (root.has_value()) {
            return {root.value() / "classes.dex",
                    root.value() / "lib/arm64-v8a" / kRuntimeLibraryName,
                    root.value() / "lib/armeabi-v7a" / kRuntimeLibraryName,
                    root.value() / "lib/arm64-v8a" / kShadowHookLibraryName,
                    root.value() / "lib/armeabi-v7a" / kShadowHookLibraryName,
                    root.value() / "lib/arm64-v8a" / kShadowHookNothingLibraryName,
                    root.value() / "lib/armeabi-v7a" / kShadowHookNothingLibraryName};
        }
    }
    throw Error(
        "找不到 Runtime artifacts：请执行 tools/build_release.sh，或设置 "
        "DEXHOLLOW_RUNTIME_DIR");
}

std::filesystem::path FindZipalign() {
    if (const char* explicit_path = std::getenv("DEXHOLLOW_ZIPALIGN")) {
        RequireRegularFile(explicit_path, "DEXHOLLOW_ZIPALIGN");
        return explicit_path;
    }

    const char* build_tools_environment = std::getenv("DEXHOLLOW_BUILD_TOOLS");
    const std::string build_tools_version =
        build_tools_environment != nullptr && build_tools_environment[0] != '\0'
            ? build_tools_environment
            : "33.0.2";

    // ANDROID_SDK_ROOT 是当前推荐名称；ANDROID_HOME 作为 Android 工具链仍广泛使用的
    // 兼容名称。这里只在环境变量存在时拼接路径，不把任何开发机目录编进程序。
    const char* sdk_root = std::getenv("ANDROID_SDK_ROOT");
    if (sdk_root == nullptr || sdk_root[0] == '\0') {
        sdk_root = std::getenv("ANDROID_HOME");
    }
    if (sdk_root != nullptr && sdk_root[0] != '\0') {
        const std::filesystem::path candidate =
            std::filesystem::path(sdk_root) / "build-tools" / build_tools_version / "zipalign";
        if (std::filesystem::is_regular_file(candidate)) {
            return candidate;
        }
    }

    if (const auto path_candidate = FindExecutableOnPath("zipalign"); path_candidate.has_value()) {
        return path_candidate.value();
    }

    throw Error(
        "找不到 zipalign：请设置 DEXHOLLOW_ZIPALIGN，或设置 ANDROID_SDK_ROOT/"
        "ANDROID_HOME 并安装 build-tools/" +
        build_tools_version + "，也可以把 zipalign 加入 PATH");
}

ApkPackReport ProtectApk(const std::filesystem::path& input_apk,
                         const std::filesystem::path& output_apk, const RuntimeArtifacts& artifacts,
                         const std::filesystem::path& zipalign) {
    RequireRegularFile(input_apk, "输入 APK");
    RequireRegularFile(artifacts.loader_dex, "Loader DEX");
    RequireRegularFile(artifacts.arm64_library, "ARM64 Runtime SO");
    RequireRegularFile(artifacts.arm_library, "ARM Runtime SO");
    RequireRegularFile(artifacts.arm64_shadowhook_library, "ARM64 ShadowHook SO");
    RequireRegularFile(artifacts.arm_shadowhook_library, "ARM ShadowHook SO");
    RequireRegularFile(artifacts.arm64_shadowhook_nothing_library, "ARM64 ShadowHook nothing SO");
    RequireRegularFile(artifacts.arm_shadowhook_nothing_library, "ARM ShadowHook nothing SO");
    RequireRegularFile(zipalign, "zipalign");

    const std::filesystem::path work_archive = CreateUniqueWorkFile(output_apk, "archive");
    std::filesystem::path aligned_archive;
    try {
        aligned_archive = CreateUniqueWorkFile(output_apk, "aligned");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(work_archive, ignored);
        throw;
    }
    WorkFiles cleanup(work_archive, aligned_archive);

    ZipArchive archive(input_apk, work_archive);
    const std::vector<std::string> original_entries = archive.ListEntries();
    const std::vector<DexEntry> dex_entries = FindRootDexEntries(original_entries);
    const RuntimeAbiSelection runtime_abis = SelectRuntimeAbis(original_entries);
    SensitiveMasterKey master_key;
    std::unordered_set<std::string> allocated_asset_names;
    allocated_asset_names.insert(kBootstrapAsset);

    // assets/.d13 是本项目的完整私有命名空间。静默覆盖同名业务资源会让输入不可逆，
    // 因此即使 Manifest 尚未指向 Shell，也必须拒绝冲突。
    for (const std::string& entry : original_entries) {
        if (entry.rfind(kAssetNamespace, 0U) == 0U) {
            throw Error("输入 APK 已占用 DexHollow13 assets 命名空间：" + entry);
        }
    }

    if (!archive.HasEntry(kManifestEntry)) {
        throw Error("输入 APK 缺少 AndroidManifest.xml");
    }
    const axml::ManifestEditResult manifest = axml::EditManifest(
        archive.ReadEntry(kManifestEntry), kShellApplication, kShellComponentFactory);
    if (manifest.original.original_application == kShellApplication ||
        manifest.original.original_app_component_factory == kShellComponentFactory) {
        throw Error("输入 APK 看起来已经经过 DexHollow13 处理");
    }

    bootstrap::BootstrapFile bootstrap_file;
    bootstrap_file.package_name = manifest.original.package_name;
    bootstrap_file.original_application = manifest.original.original_application;
    bootstrap_file.original_app_component_factory =
        manifest.original.original_app_component_factory;

    ApkPackReport report;
    report.input_apk = input_apk;
    report.output_apk = output_apk;
    report.package_name = manifest.original.package_name;
    report.original_application = manifest.original.original_application;
    report.original_app_component_factory = manifest.original.original_app_component_factory;
    if (runtime_abis.arm64) {
        report.runtime_abis.emplace_back("arm64-v8a");
    }
    if (runtime_abis.arm32) {
        report.runtime_abis.emplace_back("armeabi-v7a");
    }

    for (const DexEntry& dex_entry : dex_entries) {
        dex::TransformResult transformed;
        try {
            transformed = dex::TransformDex(archive.ReadEntry(dex_entry.name), dex_entry.ordinal);
        } catch (const Error& error) {
            throw Error("处理 " + dex_entry.name + " 失败：" + error.what());
        }
        payload::PayloadFile parsed_payload =
            payload::ReadPayload(ByteView(transformed.payload.data(), transformed.payload.size()));
        const payload::PayloadNoncePrefix payload_nonce =
            GenerateRandomArray<payload::PayloadNoncePrefix>();
        const crypto::ResourceNonce dex_nonce = GenerateRandomArray<crypto::ResourceNonce>();
        std::vector<std::uint8_t> encrypted_payload =
            payload::WriteEncryptedPayload(parsed_payload, master_key.value(), payload_nonce);
        std::vector<std::uint8_t> encrypted_hollow_dex = crypto::SealResource(
            ByteView(transformed.hollow_dex.data(), transformed.hollow_dex.size()),
            master_key.value(), dex_nonce, crypto::ResourceKind::kHollowDex, dex_entry.ordinal);

        // APK 中只允许写入加密格式。这里用独立 Reader 验证完整 metadata tag；若 Writer 的
        // offset 或认证范围错误，应在 Host 端失败，而不是留到手机启动时才暴露。
        payload::EncryptedPayloadView encrypted_view = payload::ReadEncryptedPayloadView(
            ByteView(encrypted_payload.data(), encrypted_payload.size()), master_key.value());
        if (encrypted_view.methods.size() != transformed.protected_count) {
            throw Error("加密 Payload 方法数量与保护统计不一致");
        }
        crypto::SecureWipe(encrypted_view.decryption.method_key.data(),
                           encrypted_view.decryption.method_key.size());

        const std::string hollow_asset = GenerateOpaqueAssetName(&allocated_asset_names);
        const std::string payload_asset = GenerateOpaqueAssetName(&allocated_asset_names);
        // Hollow DEX 整体是 AEAD ciphertext，在统计上接近随机；对它运行
        // deflate 不会有效缩小体积，只会增加 Host 打包和 Runtime 提取开销。
        // Payload 则保留了已认证但可读的定长 Record 表，真实大应用测量证明
        // deflate 仍能明显压缩这一部分，所以两类资源采用不同 ZIP 策略。
        archive.AddOrReplace("assets/" + hollow_asset, encrypted_hollow_dex, Compression::kStore);
        archive.AddOrReplace("assets/" + payload_asset, encrypted_payload, Compression::kDeflate);
        archive.DeleteEntry(dex_entry.name);

        bootstrap::DexRecord record;
        record.ordinal = dex_entry.ordinal;
        record.protected_method_count = transformed.protected_count;
        record.hollow_dex_asset = hollow_asset;
        record.payload_asset = payload_asset;
        record.original_dex_signature = parsed_payload.original_dex_signature;
        record.hollow_dex_signature = parsed_payload.hollow_dex_signature;
        bootstrap_file.dex_files.push_back(std::move(record));

        report.dex_files.push_back({dex_entry.name, hollow_asset, payload_asset,
                                    transformed.protected_count, transformed.no_code_count,
                                    transformed.skipped_count});
        report.total_protected_methods += transformed.protected_count;
        report.total_no_code_methods += transformed.no_code_count;
        report.total_unprotected_methods += transformed.skipped_count;

        // Host 已经把密文交给 ZipArchive，随后不再需要这些方法体明文。显式擦除可以缩短它们
        // 在长时间处理大型 APK 时留在 allocator 内存中的时间窗口。
        crypto::SecureWipe(transformed.payload.data(), transformed.payload.size());
        crypto::SecureWipe(transformed.hollow_dex.data(), transformed.hollow_dex.size());
        for (payload::MethodPayload& method : parsed_payload.methods) {
            crypto::SecureWipe(method.code_item.data(), method.code_item.size());
        }
    }

    for (const std::string& entry : original_entries) {
        if (IsV1SignatureEntry(entry)) {
            archive.DeleteEntry(entry);
        }
    }

    archive.AddOrReplace(kManifestEntry, manifest.binary_xml, Compression::kDeflate);
    archive.AddOrReplace("classes.dex", ReadFile(artifacts.loader_dex), Compression::kDeflate);
    // libdexhollow13_shell.so 通过 ELF DT_NEEDED 依赖项目私有名称的 ShadowHook。三者必须
    // 作为一个 ABI 原子地加入，否则 System.loadLibrary("dexhollow13_shell") 会在 linker
    // 阶段失败。原 APK 自带的 libshadowhook*.so 保持原样，两套库不会互相覆盖。
    if (runtime_abis.arm64) {
        crypto::MasterKey key_mask = GenerateRandomArray<crypto::MasterKey>();
        const std::vector<std::uint8_t> patched_runtime = crypto::PatchEmbeddedMasterKey(
            ReadFile(artifacts.arm64_library), master_key.value(), key_mask);
        crypto::SecureWipe(key_mask.data(), key_mask.size());
        archive.AddOrReplace("lib/arm64-v8a/" + std::string(kRuntimeLibraryName), patched_runtime,
                             Compression::kStore);
        archive.AddOrReplace("lib/arm64-v8a/" + std::string(kShadowHookLibraryName),
                             ReadFile(artifacts.arm64_shadowhook_library), Compression::kStore);
        archive.AddOrReplace("lib/arm64-v8a/" + std::string(kShadowHookNothingLibraryName),
                             ReadFile(artifacts.arm64_shadowhook_nothing_library),
                             Compression::kStore);
    }
    if (runtime_abis.arm32) {
        crypto::MasterKey key_mask = GenerateRandomArray<crypto::MasterKey>();
        const std::vector<std::uint8_t> patched_runtime = crypto::PatchEmbeddedMasterKey(
            ReadFile(artifacts.arm_library), master_key.value(), key_mask);
        crypto::SecureWipe(key_mask.data(), key_mask.size());
        archive.AddOrReplace("lib/armeabi-v7a/" + std::string(kRuntimeLibraryName), patched_runtime,
                             Compression::kStore);
        archive.AddOrReplace("lib/armeabi-v7a/" + std::string(kShadowHookLibraryName),
                             ReadFile(artifacts.arm_shadowhook_library), Compression::kStore);
        archive.AddOrReplace("lib/armeabi-v7a/" + std::string(kShadowHookNothingLibraryName),
                             ReadFile(artifacts.arm_shadowhook_nothing_library),
                             Compression::kStore);
    }

    std::vector<std::uint8_t> bootstrap_bytes = bootstrap::WriteBootstrap(bootstrap_file);
    const crypto::ResourceNonce bootstrap_nonce = GenerateRandomArray<crypto::ResourceNonce>();
    const std::vector<std::uint8_t> encrypted_bootstrap = crypto::SealResource(
        ByteView(bootstrap_bytes.data(), bootstrap_bytes.size()), master_key.value(),
        bootstrap_nonce, crypto::ResourceKind::kBootstrap, 0U);
    // 落入 APK 前走一遍真正的认证解密和独立 Bootstrap Reader，避免 Loader 在手机上才暴露
    // key 注入、AEAD Header 或内部 offset 错误。
    std::vector<std::uint8_t> verified_bootstrap =
        crypto::OpenSealedResource(ByteView(encrypted_bootstrap.data(), encrypted_bootstrap.size()),
                                   master_key.value(), crypto::ResourceKind::kBootstrap, 0U);
    static_cast<void>(
        bootstrap::ReadBootstrap(ByteView(verified_bootstrap.data(), verified_bootstrap.size())));
    crypto::SecureWipe(verified_bootstrap.data(), verified_bootstrap.size());
    archive.AddOrReplace("assets/" + std::string(kBootstrapAsset), encrypted_bootstrap,
                         Compression::kStore);
    crypto::SecureWipe(bootstrap_bytes.data(), bootstrap_bytes.size());
    archive.Close();

    RunZipalign(zipalign, work_archive, aligned_archive);

    std::error_code rename_error;
    std::filesystem::rename(aligned_archive, output_apk, rename_error);
    if (rename_error) {
        throw Error("提交最终 APK 失败：" + rename_error.message());
    }
    return report;
}

std::filesystem::path DefaultProtectedApkPath(const std::filesystem::path& input_apk) {
    const std::string filename = input_apk.filename().string();
    if (filename.empty()) {
        throw Error("输入 APK 文件名为空");
    }
    return std::filesystem::current_path() / ("app-protected-unsigned-" + filename);
}

}  // namespace dexhollow13::apk
