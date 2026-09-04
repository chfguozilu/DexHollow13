#include "art_hook_engine.h"

#include <android/api-level.h>
#include <android/log.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <unordered_map>
#include <utility>

#include "dexhollow13/base/error.h"
#include "dexhollow13/crypto/resource_crypto.h"
#include "dexhollow13/payload/encrypted_payload_format.h"
#include "shadowhook.h"

namespace dexhollow13::runtime {
namespace {

constexpr const char* kLogTag = "DexHollow13";

// 本项目把 Runtime 明确钉在 Android 13。下面的字段偏移来自 android-13.0.0_r84：
//   art/runtime/art_method.h -> class ArtMethod
//
// ArtMethod 的前四个固定宽度字段依次是：
//   GcRoot<mirror::Class>  4 bytes
//   access_flags_          4 bytes
//   dex_method_index_      4 bytes
//   method_index_          2 bytes
//   hotness_count_         2 bytes
//
// 因而 ARM32/ARM64 的 data_ 都从 16 开始；区别只在 data_ 自身的指针宽度，以及紧随其后的
// quick entrypoint 偏移。这里不修改 quick entrypoint，让 LinkCode 按 ART 原有逻辑选择 Nterp
// 或 quick-to-interpreter bridge。
constexpr std::size_t kArtMethodAccessFlagsOffset = 4U;
constexpr std::size_t kArtMethodDexMethodIndexOffset = 8U;
constexpr std::size_t kArtMethodDataOffset = 16U;
constexpr std::size_t kDexFileBeginOffset = sizeof(void*);
constexpr std::size_t kDexSignatureOffset = 12U;
constexpr std::size_t kDexSignatureSize = 20U;

// art/libdexfile/dex/modifiers.h。设置它后 JIT 不再为受保护方法收集热点并编译代码，确保
// ArtMethod::data_ 始终表示 CodeItem 指针，而不会进入依赖编译产物的路径。
constexpr std::uint32_t kAccCompileDontBother = 0x02000000U;

// Android 13 r84 中 ClassLinker::LoadMethod 的 mangled symbol。设备侧 libart.so 已通过
// readelf 验证该符号位于全局符号表中，ShadowHook 能按库名和符号名定位它。
constexpr const char* kLoadMethodSymbol =
    "_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_13ClassAccessor6MethodE"
    "NS_6ObjPtrINS_6mirror5ClassEEEPNS_9ArtMethodE";

using DexSignature = std::array<std::uint8_t, kDexSignatureSize>;

struct DexSignatureHash {
    std::size_t operator()(const DexSignature& signature) const noexcept {
        // FNV-1a 足够用于进程内索引；DEX signature 的身份安全性来自完整 20 字节相等比较，
        // hash 碰撞只会多做一次 operator==，不会把两个方法混为一谈。
        std::size_t value = 2166136261U;
        std::size_t prime = 16777619U;
        if constexpr (sizeof(std::size_t) == 8U) {
            value = static_cast<std::size_t>(1469598103934665603ULL);
            prime = static_cast<std::size_t>(1099511628211ULL);
        }
        for (const std::uint8_t byte : signature) {
            value = (value ^ byte) * prime;
        }
        return value;
    }
};

struct ShadowTarget {
    payload::EncryptedMethodPayloadView encrypted_method;
    // 使用 Clang __atomic builtin 读写这个裸指针，使结构仍可放入稠密 vector。第一个成功
    // 认证解密的线程发布指针；竞争失败线程会擦除并释放自己的临时副本。
    const std::uint8_t* decrypted_code_item = nullptr;
};

struct DexShadowTargets {
    std::size_t dex_size = 0U;
    payload::PayloadDecryptionContext decryption;
    // method_idx 在一个常规 DEX 中接近稠密。用 method_idx 直接下标访问只需要一次
    // signature 哈希，并避免为每个方法分配 unordered_map node。空槽的 code_item 为 null。
    std::vector<ShadowTarget> methods;
};

// ObjPtr<mirror::Class> 在 r84 中仅含一个 uintptr_t，因此用 uintptr_t 保持 ARM32/ARM64
// ABI 一致。其余 ART 类型在这里都作为不透明指针：本项目无需链接任何私有 ART C++ 头文件。
using LoadMethodFunction = void (*)(void* class_linker, const void* dex_file,
                                    const void* class_accessor_method, std::uintptr_t klass,
                                    void* destination_art_method);

std::unordered_map<DexSignature, DexShadowTargets, DexSignatureHash> g_shadow_dex_files;
std::atomic<std::size_t> g_bound_method_count{0U};
void* g_load_method_stub = nullptr;

[[noreturn]] void AbortProtectedMethod(std::uint32_t method_idx, const char* reason) noexcept {
    // 受保护方法已经在 Payload 索引中命中。此后如果认证、分配或 ART
    // 不变量检查失败，继续运行就会安静地执行 Hollow 默认返回桩。这会把
    // 密文篡改伪装成业务结果，所以这一路径必须 fail-closed 终止当前进程。
    __android_log_print(ANDROID_LOG_FATAL, kLogTag,
                        "Protected method binding aborted: method_idx=%u, reason=%s", method_idx,
                        reason);
    std::abort();
}

template <typename T>
T ReadArtMethodField(const void* art_method, std::size_t offset) noexcept {
    T value{};
    std::memcpy(&value, static_cast<const std::uint8_t*>(art_method) + offset, sizeof(value));
    return value;
}

template <typename T>
void WriteArtMethodField(void* art_method, std::size_t offset, const T& value) noexcept {
    std::memcpy(static_cast<std::uint8_t*>(art_method) + offset, &value, sizeof(value));
}

const std::uint8_t* GetOrDecryptCodeItem(DexShadowTargets& dex_targets, ShadowTarget& target,
                                         const payload::EncryptedMethodPayload& method) noexcept {
    const std::uint8_t* existing = __atomic_load_n(&target.decrypted_code_item, __ATOMIC_ACQUIRE);
    if (existing != nullptr) {
        return existing;
    }

    const std::size_t code_size = method.code_item_size;
    auto* candidate = new (std::nothrow) std::uint8_t[code_size];
    if (candidate == nullptr) {
        AbortProtectedMethod(method.method_idx, "allocate decrypted CodeItem failed");
    }

    try {
        payload::DecryptMethodCodeItem(dex_targets.decryption, target.encrypted_method,
                                       MutableByteView(candidate, code_size));
        const ByteView code(candidate, code_size);
        if (code_size < 16U ||
            code.ReadU32(12U, "解密 code_item.insns_size") != method.insns_size) {
            throw Error("解密 code_item Header 与认证 record 不一致");
        }
    } catch (const std::exception& error) {
        __android_log_print(ANDROID_LOG_FATAL, kLogTag,
                            "Decrypt CodeItem failed: method_idx=%u, error=%s", method.method_idx,
                            error.what());
        crypto::SecureWipe(candidate, code_size);
        delete[] candidate;
        std::abort();
    }

    const std::uint8_t* expected = nullptr;
    if (!__atomic_compare_exchange_n(&target.decrypted_code_item, &expected, candidate, false,
                                     __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
        crypto::SecureWipe(candidate, code_size);
        delete[] candidate;
        return expected;
    }
    return candidate;
}

void LoadMethodProxy(void* class_linker, const void* dex_file, const void* class_accessor_method,
                     std::uintptr_t klass, void* destination_art_method) {
    // shared mode 要求每次进入代理函数都清理 ShadowHook 的调用栈状态。使用 RAII scope 后，
    // 即使未来在本函数中增加提前 return，也不会漏掉清理。
    SHADOWHOOK_STACK_SCOPE();

    // 必须先让 ART 完整初始化 ArtMethod。LoadMethod 原函数返回时，data_ 才是 Hollow DEX
    // 中的 CodeItem 地址，dex_method_index_ 和 access_flags_ 也才具有最终初始值。
    SHADOWHOOK_CALL_PREV(LoadMethodProxy, class_linker, dex_file, class_accessor_method, klass,
                         destination_art_method);

    if (destination_art_method == nullptr) {
        return;
    }

    // DexFile 是带虚函数的 C++ 类。r84 中对象起始处是 vptr，紧随其后的第一个数据成员
    // 就是 begin_。InMemoryDexClassLoader 会把 ByteBuffer 内容复制到 ART 管理的内存，因此
    // 不能用 Java DirectByteBuffer 的原地址；必须从当前 DexFile 取得真实 Begin()。
    if (dex_file == nullptr) {
        return;
    }
    const std::uint8_t* dex_begin =
        ReadArtMethodField<const std::uint8_t*>(dex_file, kDexFileBeginOffset);
    if (dex_begin == nullptr || std::memcmp(dex_begin, "dex\n", 4U) != 0) {
        // 系统 CompactDex 或其他非标准 DEX 不属于 DexHollow13 的保护对象。
        return;
    }

    const std::uint32_t actual_method_idx =
        ReadArtMethodField<std::uint32_t>(destination_art_method, kArtMethodDexMethodIndexOffset);
    DexSignature signature;
    std::memcpy(signature.data(), dex_begin + kDexSignatureOffset, kDexSignatureSize);
    auto dex_found = g_shadow_dex_files.find(signature);
    if (dex_found == g_shadow_dex_files.end() ||
        actual_method_idx >= dex_found->second.methods.size()) {
        // Loader 自身、系统类、未抽取构造函数等都不在索引中，必须完全保持 ART 原行为。
        return;
    }

    ShadowTarget& target = dex_found->second.methods[actual_method_idx];
    if (target.encrypted_method.record == nullptr ||
        target.encrypted_method.encrypted_code_item == nullptr) {
        return;
    }
    payload::EncryptedMethodPayload encrypted;
    try {
        encrypted = payload::DecodeEncryptedMethodPayload(target.encrypted_method);
    } catch (const std::exception& error) {
        __android_log_print(ANDROID_LOG_FATAL, kLogTag,
                            "Decode protected method record failed: method_idx=%u, error=%s",
                            actual_method_idx, error.what());
        std::abort();
    }

    if (encrypted.original_code_off >= dex_found->second.dex_size) {
        AbortProtectedMethod(actual_method_idx, "Shadow CodeItem offset out of range");
    }
    const void* actual_hollow_code_item =
        ReadArtMethodField<const void*>(destination_art_method, kArtMethodDataOffset);
    const void* expected_hollow_code_item = dex_begin + encrypted.original_code_off;
    if (actual_hollow_code_item != expected_hollow_code_item) {
        // signature + method_idx + code_off 三重核对。任何一个不一致都宁可保留桩，也不能让
        // 一个 ArtMethod 执行另一个方法的寄存器布局和指令。
        AbortProtectedMethod(actual_method_idx, "Shadow CodeItem address mismatch");
    }

    // 只有当前方法走到 LoadMethod 时才认证并解密它的 code_item。明文分配后保持到进程结束，
    // 因为 ArtMethod::data_ 是裸指针；它不会被复制或写回 Hollow DEX/Payload。
    const void* shadow_code_item = GetOrDecryptCodeItem(dex_found->second, target, encrypted);
    if (shadow_code_item == nullptr) {
        AbortProtectedMethod(actual_method_idx, "decrypted CodeItem pointer is null");
    }
    WriteArtMethodField(destination_art_method, kArtMethodDataOffset, shadow_code_item);

    // access_flags_ 在 ART 中是 atomic<uint32_t>。Clang 的原子 builtin 可在不依赖 ART
    // 私有 std::atomic 类型布局的前提下执行同样的 fetch_or，并保留 verifier 后续添加的位。
    auto* access_flags = reinterpret_cast<std::uint32_t*>(
        static_cast<std::uint8_t*>(destination_art_method) + kArtMethodAccessFlagsOffset);
    __atomic_fetch_or(access_flags, kAccCompileDontBother, __ATOMIC_RELAXED);

    g_bound_method_count.fetch_add(1U, std::memory_order_relaxed);
}

}  // namespace

void InstallArtHooksOrThrow(const std::vector<ArtDexBindings>& bindings) {
    if (android_get_device_api_level() != 33) {
        throw Error("当前 Runtime 仅支持 Android 13 / API 33");
    }
    if (bindings.empty()) {
        throw Error("Payload 中没有可绑定的普通方法");
    }
    if (g_load_method_stub != nullptr || !g_shadow_dex_files.empty()) {
        throw Error("ART Hook Engine 被重复安装");
    }

    std::size_t total_method_count = 0U;
    decltype(g_shadow_dex_files) prepared_dex_files;
    prepared_dex_files.reserve(bindings.size());
    for (const ArtDexBindings& dex_binding : bindings) {
        if (dex_binding.hollow_dex_size < 0x70U || dex_binding.methods.empty()) {
            continue;
        }

        std::uint32_t maximum_method_idx = 0U;
        for (const ArtMethodBinding& method : dex_binding.methods) {
            const payload::EncryptedMethodPayload encrypted =
                payload::DecodeEncryptedMethodPayload(method.encrypted_method);
            if (encrypted.encrypted_code_item == nullptr || encrypted.code_item_size < 16U ||
                encrypted.original_code_off == 0U ||
                encrypted.original_code_off >= dex_binding.hollow_dex_size) {
                throw Error("ART CodeItem binding 的指针、DEX 大小或 code_off 非法");
            }
            maximum_method_idx = std::max(maximum_method_idx, encrypted.method_idx);
        }
        if (maximum_method_idx == std::numeric_limits<std::uint32_t>::max()) {
            throw Error("ART method_idx 无法转换为稠密索引大小");
        }

        DexShadowTargets targets;
        targets.dex_size = dex_binding.hollow_dex_size;
        targets.decryption = dex_binding.decryption;
        targets.methods.resize(static_cast<std::size_t>(maximum_method_idx) + 1U);
        for (const ArtMethodBinding& method : dex_binding.methods) {
            const payload::EncryptedMethodPayload encrypted =
                payload::DecodeEncryptedMethodPayload(method.encrypted_method);
            ShadowTarget& slot = targets.methods[encrypted.method_idx];
            if (slot.encrypted_method.record != nullptr &&
                slot.encrypted_method.record != method.encrypted_method.record) {
                throw Error("同一个 DEX method_idx 被映射到不一致的 Payload 记录");
            }
            slot.encrypted_method = method.encrypted_method;
        }

        const auto inserted = prepared_dex_files.emplace(
            dex_binding.decryption.hollow_dex_signature, std::move(targets));
        if (!inserted.second) {
            throw Error("Payload 中出现重复 Hollow DEX signature");
        }
        total_method_count += dex_binding.methods.size();
    }
    if (total_method_count == 0U) {
        throw Error("Payload 中没有可绑定的普通方法");
    }

    // 所有分配和格式检查都成功后再一次性发布索引。这样即使构建百万方法索引时发生
    // bad_alloc，全局 Hook 状态仍保持完全未初始化，而不是留下半份 registry。
    g_shadow_dex_files = std::move(prepared_dex_files);

    // ShadowHook shared mode 可以与 App 进程中其他合法 Hook 共存。第二个参数关闭第三方库
    // 自身的 verbose 调试日志；DexHollow13 对安装失败仍会输出明确 errno 和错误文本。
    const int init_error = shadowhook_init(SHADOWHOOK_MODE_SHARED, false);
    if (init_error != SHADOWHOOK_ERRNO_OK) {
        g_shadow_dex_files.clear();
        throw Error("ShadowHook 初始化失败：" + std::to_string(init_error) + " / " +
                    shadowhook_to_errmsg(init_error));
    }

    void* original = nullptr;
    g_load_method_stub = shadowhook_hook_sym_name(
        "libart.so", kLoadMethodSymbol, reinterpret_cast<void*>(LoadMethodProxy), &original);
    const int hook_error = shadowhook_get_errno();
    if (g_load_method_stub == nullptr || hook_error != SHADOWHOOK_ERRNO_OK || original == nullptr) {
        g_load_method_stub = nullptr;
        g_shadow_dex_files.clear();
        throw Error("Hook ClassLinker::LoadMethod 失败：" + std::to_string(hook_error) + " / " +
                    shadowhook_to_errmsg(hook_error));
    }

    __android_log_print(ANDROID_LOG_INFO, kLogTag,
                        "ART Shadow CodeItem hook installed, records=%zu", total_method_count);
}

std::size_t BoundArtMethodCount() noexcept {
    return g_bound_method_count.load(std::memory_order_relaxed);
}

}  // namespace dexhollow13::runtime
