#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "dexhollow13/payload/encrypted_payload_format.h"

namespace dexhollow13::runtime {

// 一个方法绑定描述了同一方法的两份 CodeItem：
//
//   hollow_code_item     -> Runtime 解密出的 Hollow DEX 桩方法体
//   encrypted_code_item  -> Payload mmap 中的逐方法密文
//   shadow_code_item     -> 首次 LoadMethod 命中时认证解密出的稳定 Native 内存
//
// Runtime 不会把 shadow_code_item 写回 hollow_code_item。前者只会被写入 ArtMethod::data_，
// 让 ART 的解释执行路径从按需解密内存取指令。
struct ArtMethodBinding {
    payload::EncryptedMethodPayloadView encrypted_method;
};

// DEX signature 和 Hollow DEX 大小属于整份 DEX，而不是单个方法。按 DEX 分组后，包含
// 一百万个方法的应用也只保存几十份 signature，不会在每个哈希节点中重复 20 字节身份。
struct ArtDexBindings {
    payload::PayloadDecryptionContext decryption;
    std::size_t hollow_dex_size = 0U;
    std::vector<ArtMethodBinding> methods;
};

// 安装 Android 13 ART 方法加载 Hook。
//
// 该函数只能在受保护 DEX 尚未开始定义类时调用。调用成功后 bindings 中各密文指针所指向
// 的 Payload mmap 必须在进程余下生命周期内保持有效。
void InstallArtHooksOrThrow(const std::vector<ArtDexBindings>& bindings);

// 返回已经由 LoadMethod Hook 绑定到 Shadow CodeItem 的方法数量，供日志与端到端测试使用。
std::size_t BoundArtMethodCount() noexcept;

}  // namespace dexhollow13::runtime
