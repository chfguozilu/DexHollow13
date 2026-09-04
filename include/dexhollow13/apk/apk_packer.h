#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "dexhollow13/dex/dex_transformer.h"

namespace dexhollow13::apk {

struct RuntimeArtifacts {
    std::filesystem::path loader_dex;
    std::filesystem::path arm64_library;
    std::filesystem::path arm_library;
    std::filesystem::path arm64_shadowhook_library;
    std::filesystem::path arm_shadowhook_library;
    std::filesystem::path arm64_shadowhook_nothing_library;
    std::filesystem::path arm_shadowhook_nothing_library;
};

struct DexPackReport {
    std::string original_entry;
    std::string hollow_asset;
    std::string payload_asset;
    std::uint32_t protected_methods = 0U;
    std::uint32_t no_code_methods = 0U;
    std::uint32_t unprotected_methods = 0U;
};

struct ApkPackReport {
    std::filesystem::path input_apk;
    std::filesystem::path output_apk;
    std::string package_name;
    std::string original_application;
    std::string original_app_component_factory;
    // 实际写入受保护 APK 的 Runtime ABI。纯 Java APK 为两项；自带 SO 的 APK 保持输入
    // 已有的 ARM ABI 集合，避免改变 PackageManager 的进程位数选择。
    std::vector<std::string> runtime_abis;
    std::vector<DexPackReport> dex_files;
    std::uint32_t total_protected_methods = 0U;
    std::uint32_t total_no_code_methods = 0U;
    std::uint32_t total_unprotected_methods = 0U;
};

RuntimeArtifacts FindRuntimeArtifacts(const std::filesystem::path& executable_path);
std::filesystem::path FindZipalign();

ApkPackReport ProtectApk(const std::filesystem::path& input_apk,
                         const std::filesystem::path& output_apk, const RuntimeArtifacts& artifacts,
                         const std::filesystem::path& zipalign);

std::filesystem::path DefaultProtectedApkPath(const std::filesystem::path& input_apk);

}  // namespace dexhollow13::apk
