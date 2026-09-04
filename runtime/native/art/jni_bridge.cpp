#include <android/log.h>
#include <jni.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "art_hook_engine.h"
#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"
#include "dexhollow13/crypto/key_material.h"
#include "dexhollow13/crypto/resource_crypto.h"
#include "dexhollow13/payload/encrypted_payload_format.h"
#include "resource_decryptor.h"

namespace dexhollow13::runtime {
namespace {

constexpr const char* kLogTag = "DexHollow13";
constexpr std::size_t kDexHeaderMinimum = 0x70U;
constexpr std::size_t kDexSignatureOffset = 12U;
constexpr std::size_t kDexSignatureSize = 20U;
constexpr std::size_t kDexMethodIdsSizeOffset = 88U;

std::mutex g_runtime_mutex;
bool g_initialized = false;

// 输入是 Java 从 code_cache 文件建立的 MappedByteBuffer。保存数组的 global reference
// 会让 Payload 密文映射在进程整个生命周期保持有效。ART 打开 DEX 时会另行复制 DEX；
// 仍保留 Hollow 数组引用，便于明确其生命周期契约。
jobjectArray g_hollow_buffer_array = nullptr;
jobjectArray g_payload_buffer_array = nullptr;

void LogInfo(const std::string& message) {
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "%s", message.c_str());
}

void ThrowIllegalState(JNIEnv* env, const std::string& message) {
    jclass exception_class = env->FindClass("java/lang/IllegalStateException");
    if (exception_class != nullptr) {
        env->ThrowNew(exception_class, message.c_str());
        env->DeleteLocalRef(exception_class);
    }
}

std::string ReadJavaString(JNIEnv* env, jstring value, const std::string& purpose) {
    if (value == nullptr) {
        throw Error(purpose + " 是 null");
    }
    const char* utf = env->GetStringUTFChars(value, nullptr);
    if (utf == nullptr) {
        throw Error("读取 " + purpose + " UTF-8 内容失败");
    }
    const std::string result(utf);
    env->ReleaseStringUTFChars(value, utf);
    if (result.empty()) {
        throw Error(purpose + " 为空");
    }
    return result;
}

struct DirectBuffer {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0U;
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

class ScopedBindingKeyWiper final {
public:
    explicit ScopedBindingKeyWiper(std::vector<ArtDexBindings>* bindings) : bindings_(bindings) {}
    ~ScopedBindingKeyWiper() {
        for (ArtDexBindings& binding : *bindings_) {
            crypto::SecureWipe(binding.decryption.method_key.data(),
                               binding.decryption.method_key.size());
        }
    }

    ScopedBindingKeyWiper(const ScopedBindingKeyWiper&) = delete;
    ScopedBindingKeyWiper& operator=(const ScopedBindingKeyWiper&) = delete;

private:
    std::vector<ArtDexBindings>* bindings_;
};

DirectBuffer GetDirectBuffer(JNIEnv* env, jobject buffer, const std::string& purpose) {
    if (buffer == nullptr) {
        throw Error(purpose + " 是 null");
    }
    void* address = env->GetDirectBufferAddress(buffer);
    const jlong capacity = env->GetDirectBufferCapacity(buffer);
    if (address == nullptr || capacity <= 0) {
        throw Error(purpose + " 必须是非空 DirectByteBuffer");
    }
    return {static_cast<const std::uint8_t*>(address), static_cast<std::size_t>(capacity)};
}

void ValidateHollowDex(const DirectBuffer& dex, const payload::EncryptedPayloadView& payload_file,
                       std::uint32_t expected_ordinal) {
    const ByteView bytes(dex.data, dex.size);
    bytes.CheckRange(0U, kDexHeaderMinimum, "Runtime Hollow DEX header");
    const std::array<std::uint8_t, 4U> magic{{'d', 'e', 'x', '\n'}};
    if (!std::equal(magic.begin(), magic.end(), bytes.data())) {
        throw Error("Runtime Hollow buffer 不是标准 DEX");
    }
    if (payload_file.decryption.dex_ordinal != expected_ordinal) {
        throw Error("Payload dex_ordinal 与 ByteBuffer 顺序不一致");
    }

    const std::uint8_t* stored_signature =
        bytes.DataAt(kDexSignatureOffset, kDexSignatureSize, "Runtime DEX signature");
    if (!std::equal(payload_file.decryption.hollow_dex_signature.begin(),
                    payload_file.decryption.hollow_dex_signature.end(), stored_signature)) {
        throw Error("Hollow DEX signature 与 Payload identity 不一致");
    }

    const std::uint32_t method_ids_size =
        bytes.ReadU32(kDexMethodIdsSizeOffset, "Runtime Hollow DEX method_ids_size");
    for (const payload::EncryptedMethodPayloadView& method_view : payload_file.methods) {
        const payload::EncryptedMethodPayload method =
            payload::DecodeEncryptedMethodPayload(method_view);
        if (method.method_idx >= method_ids_size) {
            throw Error("Payload method_idx 超过 Hollow DEX method_ids_size");
        }
        if (method.encrypted_code_item == nullptr || method.code_item_size < 16U) {
            throw Error("加密 Payload code_item 小于 StandardDexFile::CodeItem Header");
        }
        if (method.original_code_off == 0U || (method.original_code_off & 3U) != 0U) {
            throw Error("Payload original_code_off 非法");
        }
        bytes.CheckRange(method.original_code_off, method.code_item_size,
                         "Hollow DEX 中的原 CodeItem 区域");
    }
}

void Initialize(JNIEnv* env, jobjectArray hollow_buffers, jobjectArray payload_buffers) {
    if (hollow_buffers == nullptr || payload_buffers == nullptr) {
        throw Error("JNI ByteBuffer arrays 不能为空");
    }
    const jsize dex_count = env->GetArrayLength(hollow_buffers);
    const jsize payload_count = env->GetArrayLength(payload_buffers);
    if (dex_count <= 0 || dex_count != payload_count) {
        throw Error("Hollow DEX 与 Payload ByteBuffer 数量不一致");
    }

    std::vector<ArtDexBindings> bindings;
    bindings.reserve(static_cast<std::size_t>(dex_count));
    ScopedBindingKeyWiper binding_key_wiper(&bindings);
    ScopedMasterKey master_key;
    for (jsize index = 0; index < dex_count; ++index) {
        jobject dex_object = env->GetObjectArrayElement(hollow_buffers, index);
        jobject payload_object = env->GetObjectArrayElement(payload_buffers, index);
        if (env->ExceptionCheck()) {
            throw Error("读取 JNI ByteBuffer array 失败");
        }

        const DirectBuffer dex = GetDirectBuffer(env, dex_object, "Hollow DEX buffer");
        const DirectBuffer payload_buffer = GetDirectBuffer(env, payload_object, "Payload buffer");
        payload::EncryptedPayloadView payload_file = payload::ReadEncryptedPayloadView(
            ByteView(payload_buffer.data, payload_buffer.size), master_key.value());
        ValidateHollowDex(dex, payload_file, static_cast<std::uint32_t>(index));

        ArtDexBindings dex_bindings;
        dex_bindings.decryption = payload_file.decryption;
        dex_bindings.hollow_dex_size = dex.size;
        dex_bindings.methods.reserve(payload_file.methods.size());
        for (const payload::EncryptedMethodPayloadView& method_view : payload_file.methods) {
            dex_bindings.methods.push_back({method_view});
        }
        bindings.push_back(std::move(dex_bindings));
        crypto::SecureWipe(payload_file.decryption.method_key.data(),
                           payload_file.decryption.method_key.size());

        env->DeleteLocalRef(dex_object);
        env->DeleteLocalRef(payload_object);
    }

    jobjectArray hollow_global = static_cast<jobjectArray>(env->NewGlobalRef(hollow_buffers));
    jobjectArray payload_global = static_cast<jobjectArray>(env->NewGlobalRef(payload_buffers));
    if (hollow_global == nullptr || payload_global == nullptr) {
        if (hollow_global != nullptr) {
            env->DeleteGlobalRef(hollow_global);
        }
        if (payload_global != nullptr) {
            env->DeleteGlobalRef(payload_global);
        }
        throw Error("创建 DirectByteBuffer global reference 失败");
    }

    // 先提交 JNI global reference，再安装 Hook。Hook 一旦成功，任何随后定义的 App 类都
    // 可能立即访问 Payload mmap 地址，所以其生命周期必须先准备完整。
    g_hollow_buffer_array = hollow_global;
    g_payload_buffer_array = payload_global;

    try {
        InstallArtHooksOrThrow(bindings);
    } catch (...) {
        // Hook 安装失败时还没有受保护方法能经 Hook 运行，可以安全撤销本次初始化状态。
        g_hollow_buffer_array = nullptr;
        g_payload_buffer_array = nullptr;
        env->DeleteGlobalRef(hollow_global);
        env->DeleteGlobalRef(payload_global);
        throw;
    }

    g_initialized = true;
    LogInfo("Native Runtime initialized for " + std::to_string(dex_count) + " DEX file(s)");
}

}  // namespace
}  // namespace dexhollow13::runtime

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_dexhollow13_loader_NativeBridge_nativeDecryptResource(JNIEnv* env, jclass /* clazz */,
                                                               jbyteArray sealed_array,
                                                               jint raw_kind, jint ordinal) {
    if (sealed_array == nullptr || ordinal < 0) {
        dexhollow13::runtime::ThrowIllegalState(env, "加密资源 byte[]/ordinal 非法");
        return nullptr;
    }
    try {
        const jsize sealed_size = env->GetArrayLength(sealed_array);
        if (sealed_size <= 0) {
            throw dexhollow13::Error("加密资源 byte[] 为空");
        }
        std::vector<std::uint8_t> sealed(static_cast<std::size_t>(sealed_size));
        env->GetByteArrayRegion(sealed_array, 0, sealed_size,
                                reinterpret_cast<jbyte*>(sealed.data()));
        if (env->ExceptionCheck()) {
            return nullptr;
        }

        std::vector<std::uint8_t> plaintext = dexhollow13::runtime::DecryptResourceBytes(
            dexhollow13::ByteView(sealed.data(), sealed.size()),
            dexhollow13::runtime::ParseResourceKind(static_cast<std::uint32_t>(raw_kind)),
            static_cast<std::uint32_t>(ordinal));
        jbyteArray output = env->NewByteArray(static_cast<jsize>(plaintext.size()));
        if (output == nullptr) {
            dexhollow13::crypto::SecureWipe(plaintext.data(), plaintext.size());
            return nullptr;
        }
        env->SetByteArrayRegion(output, 0, static_cast<jsize>(plaintext.size()),
                                reinterpret_cast<const jbyte*>(plaintext.data()));
        dexhollow13::crypto::SecureWipe(plaintext.data(), plaintext.size());
        return output;
    } catch (const std::exception& error) {
        if (!env->ExceptionCheck()) {
            dexhollow13::runtime::ThrowIllegalState(env, error.what());
        }
        return nullptr;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_dexhollow13_loader_NativeBridge_nativeDecryptResourceFile(JNIEnv* env, jclass /* clazz */,
                                                                   jstring input_path,
                                                                   jstring output_path,
                                                                   jint raw_kind, jint ordinal) {
    if (ordinal < 0) {
        dexhollow13::runtime::ThrowIllegalState(env, "加密资源 ordinal 非法");
        return;
    }
    try {
        dexhollow13::runtime::DecryptResourceFile(
            dexhollow13::runtime::ReadJavaString(env, input_path, "密文缓存路径"),
            dexhollow13::runtime::ReadJavaString(env, output_path, "明文临时路径"),
            dexhollow13::runtime::ParseResourceKind(static_cast<std::uint32_t>(raw_kind)),
            static_cast<std::uint32_t>(ordinal));
    } catch (const std::exception& error) {
        if (!env->ExceptionCheck()) {
            dexhollow13::runtime::ThrowIllegalState(env, error.what());
        }
    }
}

extern "C" JNIEXPORT void JNICALL Java_com_dexhollow13_loader_NativeBridge_nativeInitialize(
    JNIEnv* env, jclass /* clazz */, jobjectArray hollow_buffers, jobjectArray payload_buffers) {
    std::lock_guard<std::mutex> lock(dexhollow13::runtime::g_runtime_mutex);
    if (dexhollow13::runtime::g_initialized) {
        dexhollow13::runtime::ThrowIllegalState(env, "DexHollow13 Native Runtime 被重复初始化");
        return;
    }

    try {
        dexhollow13::runtime::Initialize(env, hollow_buffers, payload_buffers);
    } catch (const std::exception& error) {
        if (!env->ExceptionCheck()) {
            dexhollow13::runtime::ThrowIllegalState(env, error.what());
        }
    }
}

extern "C" JNIEXPORT jlong JNICALL Java_com_dexhollow13_loader_NativeBridge_nativeBoundMethodCount(
    JNIEnv* /* env */, jclass /* clazz */) {
    return static_cast<jlong>(dexhollow13::runtime::BoundArtMethodCount());
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* /* vm */, void* /* reserved */) {
    return JNI_VERSION_1_6;
}
