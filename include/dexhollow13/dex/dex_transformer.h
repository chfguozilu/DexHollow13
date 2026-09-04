#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dexhollow13::dex {

enum class MethodAction {
    kProtected,
    kSkippedNoCode,
    kSkippedConstructor,
    kSkippedStubTooLarge,
};

struct MethodReport {
    std::uint32_t method_idx = 0U;
    std::uint32_t code_off = 0U;
    std::uint32_t code_item_size = 0U;
    std::string method_name;
    MethodAction action = MethodAction::kSkippedNoCode;
    std::string reason;
};

struct TransformOptions {
    // 默认验证 Header 中原有的 signature/checksum。测试畸形输入时可以关闭，
    // 正式 APK 管线永远保持开启。
    bool verify_input_integrity = true;

    // 构造器会使用专用的 verifier-safe 前缀桩；遇到初始化前复杂控制流时仍会明确跳过。
    bool protect_constructors = true;
};

struct TransformResult {
    std::vector<std::uint8_t> hollow_dex;
    std::vector<std::uint8_t> payload;
    std::vector<MethodReport> methods;

    std::uint32_t protected_count = 0U;
    // native/abstract 的 code_off 为 0，本来就没有 CodeItem，不属于保护遗漏。
    std::uint32_t no_code_count = 0U;
    // 有 CodeItem，但 Host 无法证明 Hollow 桩合法而保留原实现的方法数量。
    std::uint32_t skipped_count = 0U;
};

TransformResult TransformDex(std::vector<std::uint8_t> input_dex, std::uint32_t dex_ordinal,
                             const TransformOptions& options = {});

const char* MethodActionName(MethodAction action) noexcept;

}  // namespace dexhollow13::dex
