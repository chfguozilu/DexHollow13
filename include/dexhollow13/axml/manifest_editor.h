#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dexhollow13::axml {

struct ManifestInfo {
    std::string package_name;
    std::string original_application;
    std::string original_app_component_factory;
};

struct ManifestEditResult {
    std::vector<std::uint8_t> binary_xml;
    ManifestInfo original;
};

// 修改编译后的 AndroidManifest.xml：
//   android:name                -> ShellApplication
//   android:appComponentFactory -> ShellComponentFactory
// 同时返回修改前的启动信息，供加密启动索引和运行时 Application 交接使用。
ManifestEditResult EditManifest(const std::vector<std::uint8_t>& input,
                                const std::string& shell_application,
                                const std::string& shell_component_factory);

}  // namespace dexhollow13::axml
