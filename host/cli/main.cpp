#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>

#include "dexhollow13/apk/apk_packer.h"
#include "dexhollow13/apk/zip_archive.h"
#include "dexhollow13/axml/manifest_editor.h"
#include "dexhollow13/base/error.h"
#include "dexhollow13/base/file_io.h"
#include "dexhollow13/dex/dex_transformer.h"
#include "dexhollow13/payload/payload_format.h"

namespace {

void PrintUsage(const char* program) {
    std::cerr << "用法：\n"
              << "  " << program << " input.apk\n\n"
              << "开发期内部命令：\n"
              << "  " << program
              << " --transform-dex input.dex hollow.dex payload.bin [dex_ordinal]\n"
              << "  " << program << " --edit-manifest input.apk output.apk\n";
}

std::uint32_t ParseOrdinal(const char* text) {
    const std::string value(text);
    std::size_t parsed = 0U;
    const unsigned long number = std::stoul(value, &parsed, 10);
    if (parsed != value.size() || number > 0xffffffffUL) {
        throw dexhollow13::Error("dex_ordinal 必须是 uint32_t 十进制整数");
    }
    return static_cast<std::uint32_t>(number);
}

int TransformSingleDex(int argc, char** argv) {
    const std::filesystem::path input_path(argv[2]);
    const std::filesystem::path hollow_path(argv[3]);
    const std::filesystem::path payload_path(argv[4]);
    const std::uint32_t ordinal = argc == 6 ? ParseOrdinal(argv[5]) : 0U;

    dexhollow13::dex::TransformResult result =
        dexhollow13::dex::TransformDex(dexhollow13::ReadFile(input_path), ordinal);

    // 在落盘前再用独立 Reader 解析一次 Payload，防止 Writer 内部的 offset 回填错误
    // 被带到 APK Runtime 阶段才发现。
    const auto verified_payload = dexhollow13::payload::ReadPayload(
        dexhollow13::ByteView(result.payload.data(), result.payload.size()));
    if (verified_payload.methods.size() != result.protected_count) {
        throw dexhollow13::Error("内部错误：Payload 方法数与保护统计不一致");
    }

    dexhollow13::WriteFile(hollow_path, result.hollow_dex);
    dexhollow13::WriteFile(payload_path, result.payload);

    std::cout << "DEX 变换完成\n"
              << "  输入：" << input_path << '\n'
              << "  Hollow DEX：" << hollow_path << '\n'
              << "  Payload：" << payload_path << '\n'
              << "  已保护方法：" << result.protected_count << '\n'
              << "  无 code_item 方法：" << result.no_code_count << '\n'
              << "  有代码但未保护：" << result.skipped_count << "\n\n";

    for (const auto& method : result.methods) {
        std::cout << '[' << dexhollow13::dex::MethodActionName(method.action)
                  << "] method_idx=" << method.method_idx << ", code_off=0x" << std::hex
                  << method.code_off << std::dec << ", " << method.method_name;
        if (!method.reason.empty()) {
            std::cout << " -- " << method.reason;
        }
        std::cout << '\n';
    }
    return EXIT_SUCCESS;
}

int EditManifestForSmokeTest(char** argv) {
    const std::filesystem::path input_path(argv[2]);
    const std::filesystem::path output_path(argv[3]);
    dexhollow13::apk::ZipArchive archive(input_path, output_path);
    const std::vector<std::uint8_t> manifest = archive.ReadEntry("AndroidManifest.xml");
    const auto edited =
        dexhollow13::axml::EditManifest(manifest, "com.dexhollow13.loader.ShellApplication",
                                        "com.dexhollow13.loader.ShellComponentFactory");
    archive.AddOrReplace("AndroidManifest.xml", edited.binary_xml,
                         dexhollow13::apk::Compression::kDeflate);
    archive.Close();

    std::cout << "Manifest 编辑完成\n"
              << "  package：" << edited.original.package_name << '\n'
              << "  原 Application：" << edited.original.original_application << '\n'
              << "  原 AppComponentFactory："
              << (edited.original.original_app_component_factory.empty()
                      ? "<none>"
                      : edited.original.original_app_component_factory)
              << '\n';
    return EXIT_SUCCESS;
}

int ProtectCompleteApk(const std::filesystem::path& input_path,
                       const std::filesystem::path& executable_path) {
    const std::filesystem::path output_path = dexhollow13::apk::DefaultProtectedApkPath(input_path);
    const dexhollow13::apk::RuntimeArtifacts artifacts =
        dexhollow13::apk::FindRuntimeArtifacts(executable_path);
    const dexhollow13::apk::ApkPackReport report = dexhollow13::apk::ProtectApk(
        input_path, output_path, artifacts, dexhollow13::apk::FindZipalign());

    std::cout << "DexHollow13 APK 处理完成\n"
              << "  package：" << report.package_name << '\n'
              << "  原 Application：" << report.original_application << '\n'
              << "  原 AppComponentFactory："
              << (report.original_app_component_factory.empty()
                      ? "<none>"
                      : report.original_app_component_factory)
              << '\n'
              << "  DEX 数量：" << report.dex_files.size() << '\n'
              << "  Runtime ABI：";
    for (std::size_t index = 0U; index < report.runtime_abis.size(); ++index) {
        std::cout << (index == 0U ? "" : ", ") << report.runtime_abis[index];
    }
    std::cout << '\n'
              << "  已保护方法：" << report.total_protected_methods << '\n'
              << "  无 code_item 方法：" << report.total_no_code_methods << '\n'
              << "  有代码但未保护：" << report.total_unprotected_methods << '\n';
    for (const auto& dex : report.dex_files) {
        std::cout << "    " << dex.original_entry << " -> assets/" << dex.hollow_asset
                  << "，protected=" << dex.protected_methods << "，no_code=" << dex.no_code_methods
                  << "，unprotected=" << dex.unprotected_methods << '\n';
    }
    std::cout << "  输出（未签名）：" << report.output_apk << '\n';
    return EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if ((argc == 5 || argc == 6) && std::string(argv[1]) == "--transform-dex") {
            return TransformSingleDex(argc, argv);
        }
        if (argc == 4 && std::string(argv[1]) == "--edit-manifest") {
            return EditManifestForSmokeTest(argv);
        }

        if (argc == 2) {
            return ProtectCompleteApk(argv[1], argv[0]);
        }

        PrintUsage(argv[0]);
        return EXIT_FAILURE;
    } catch (const dexhollow13::Error& error) {
        std::cerr << "dex-hollow: " << error.what() << '\n';
        return EXIT_FAILURE;
    } catch (const std::exception& error) {
        std::cerr << "dex-hollow: 未预期错误：" << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
