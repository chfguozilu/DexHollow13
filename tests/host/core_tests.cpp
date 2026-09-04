#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"
#include "dexhollow13/bootstrap/bootstrap_format.h"
#include "dexhollow13/crypto/key_material.h"
#include "dexhollow13/crypto/resource_crypto.h"
#include "dexhollow13/dex/dex_file.h"
#include "dexhollow13/dex/leb128.h"
#include "dexhollow13/dex/stub_generator.h"
#include "dexhollow13/payload/encrypted_payload_format.h"
#include "dexhollow13/payload/payload_format.h"

namespace {

void Require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error("测试失败：" + message);
    }
}

template <typename Function>
void RequireDexError(Function function, const std::string& message) {
    try {
        function();
    } catch (const dexhollow13::Error&) {
        return;
    }
    throw std::runtime_error("测试失败（预期抛出 dexhollow13::Error）：" + message);
}

void TestByteViewAndLeb128() {
    const std::array<std::uint8_t, 8U> bytes{{
        0x78U,
        0x56U,
        0x34U,
        0x12U,  // 小端 uint32_t 0x12345678。
        0xe5U,
        0x8eU,
        0x26U,  // ULEB128 624485。
        0x00U,
    }};
    const dexhollow13::ByteView view(bytes.data(), bytes.size());
    Require(view.ReadU32(0U, "test") == 0x12345678U, "ReadU32 必须按小端读取");

    const auto decoded = dexhollow13::dex::ReadUleb128(view, 4U, "test uleb");
    Require(decoded.value == 624485U, "ULEB128 数值错误");
    Require(decoded.next_offset == 7U, "ULEB128 next_offset 错误");

    RequireDexError([&view]() { static_cast<void>(view.ReadU32(6U, "越界测试")); },
                    "ByteView 应拒绝越界整数");

    const std::array<std::uint8_t, 5U> overflow{{0xffU, 0xffU, 0xffU, 0xffU, 0x10U}};
    const dexhollow13::ByteView overflow_view(overflow.data(), overflow.size());
    RequireDexError(
        [&overflow_view]() {
            static_cast<void>(dexhollow13::dex::ReadUleb128(overflow_view, 0U, "overflow"));
        },
        "ULEB128 应拒绝 uint32_t 溢出");
}

void TestReturnStubs() {
    const auto void_stub = dexhollow13::dex::BuildReturnStub("V");
    const auto int_stub = dexhollow13::dex::BuildReturnStub("I");
    const auto object_stub = dexhollow13::dex::BuildReturnStub("Ljava/lang/String;");
    const auto wide_stub = dexhollow13::dex::BuildReturnStub("J");

    Require(void_stub.code_units.size() == 1U && void_stub.code_units.back() == 0x000eU,
            "void stub 应为 return-void");
    Require(int_stub.code_units.size() == 2U && int_stub.code_units.back() == 0x000fU,
            "int stub 应以 return v0 结束");
    Require(object_stub.code_units.size() == 2U && object_stub.code_units.back() == 0x0011U,
            "object stub 应以 return-object v0 结束");
    Require(wide_stub.code_units.size() == 3U && wide_stub.code_units.back() == 0x0010U,
            "wide stub 应以 return-wide v0 结束");

    // 模拟真实 com.dragon.read 中 cleanup(J)J 的失败形态：insns_size=92 时，旧实现把
    // const-wide/16 放到 dex_pc 89，它的 operand 位于 90；try 又从 90 开始，ART 因而
    // 报 “try block starts inside an instruction (90)”。新规划必须把 const-wide 提前。
    dexhollow13::dex::CodeItemLayout layout;
    layout.insns_size = 92U;
    layout.insns_offset = 0U;
    layout.tries.push_back({90U, 1U, 0U});
    dexhollow13::dex::CatchHandler handler;
    handler.typed_handlers.push_back({0U, 90U});
    layout.handlers.push_back(handler);

    auto planned_wide = wide_stub;
    std::string reason;
    Require(dexhollow13::dex::PlanStubPlacement(layout, &planned_wide, &reason),
            "wide stub 应能避开 try/catch 指令边界");
    Require(planned_wide.write_dex_pcs == std::vector<std::uint32_t>({88U, 89U, 91U}),
            "wide stub 应把 const-wide/16 从冲突的末尾位置前移");

    std::vector<std::uint8_t> hollow_insns(layout.insns_size * 2U, 0xffU);
    dexhollow13::MutableByteView writable(hollow_insns.data(), hollow_insns.size());
    dexhollow13::dex::ApplyReturnStub(writable, layout, planned_wide);
    const dexhollow13::ByteView result(hollow_insns.data(), hollow_insns.size());
    Require(result.ReadU16(88U * 2U, "wide const") == 0x0016U &&
                result.ReadU16(89U * 2U, "wide operand") == 0U &&
                result.ReadU16(90U * 2U, "try start") == 0U &&
                result.ReadU16(91U * 2U, "wide return") == 0x0010U,
            "wide stub 写入后 try 起点必须仍是 nop opcode");
}

void WriteU32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xffU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    bytes[offset + 2U] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    bytes[offset + 3U] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
}

std::vector<std::uint8_t> BuildDexHeaderForIdLimitTest(std::uint32_t type_ids_size,
                                                       std::uint32_t proto_ids_size,
                                                       std::uint32_t field_ids_size,
                                                       std::uint32_t method_ids_size) {
    constexpr std::size_t kHeaderSize = 0x70U;
    constexpr std::size_t kTypeIdSize = 4U;
    constexpr std::size_t kProtoIdSize = 12U;
    constexpr std::size_t kFieldIdSize = 8U;
    constexpr std::size_t kMethodIdSize = 8U;
    const std::size_t type_offset = kHeaderSize;
    const std::size_t proto_offset =
        type_offset + static_cast<std::size_t>(type_ids_size) * kTypeIdSize;
    const std::size_t field_offset =
        proto_offset + static_cast<std::size_t>(proto_ids_size) * kProtoIdSize;
    const std::size_t method_offset =
        field_offset + static_cast<std::size_t>(field_ids_size) * kFieldIdSize;
    const std::size_t data_offset =
        method_offset + static_cast<std::size_t>(method_ids_size) * kMethodIdSize;
    std::vector<std::uint8_t> bytes(data_offset + 4U, 0U);

    const std::array<std::uint8_t, 8U> magic{{'d', 'e', 'x', '\n', '0', '3', '5', '\0'}};
    std::copy(magic.begin(), magic.end(), bytes.begin());
    WriteU32(bytes, 32U, static_cast<std::uint32_t>(bytes.size()));
    WriteU32(bytes, 36U, static_cast<std::uint32_t>(kHeaderSize));
    WriteU32(bytes, 40U, 0x12345678U);
    WriteU32(bytes, 52U, static_cast<std::uint32_t>(data_offset));
    WriteU32(bytes, 64U, type_ids_size);
    WriteU32(bytes, 68U, type_ids_size == 0U ? 0U : static_cast<std::uint32_t>(type_offset));
    WriteU32(bytes, 72U, proto_ids_size);
    WriteU32(bytes, 76U, proto_ids_size == 0U ? 0U : static_cast<std::uint32_t>(proto_offset));
    WriteU32(bytes, 80U, field_ids_size);
    WriteU32(bytes, 84U, field_ids_size == 0U ? 0U : static_cast<std::uint32_t>(field_offset));
    WriteU32(bytes, 88U, method_ids_size);
    WriteU32(bytes, 92U, method_ids_size == 0U ? 0U : static_cast<std::uint32_t>(method_offset));
    WriteU32(bytes, 104U, 4U);
    WriteU32(bytes, 108U, static_cast<std::uint32_t>(data_offset));
    return bytes;
}

void TestDexIdTableLimits() {
    // method_ids_size 是“项目数量”，65536 项的最大索引才是 65535。这个边界来自
    // 实际大型 APK，也是本次回归要覆盖的值。
    auto max_field_and_method_ids = BuildDexHeaderForIdLimitTest(0U, 0U, 65536U, 65536U);
    const dexhollow13::dex::DexFile accepted(std::move(max_field_and_method_ids));
    Require(
        accepted.header().field_ids_size == 65536U && accepted.header().method_ids_size == 65536U,
        "DEX 应接受 field_ids_size/method_ids_size == 65536");

    // Android 13 r84 的 DexFileVerifier 对 type/proto 表保留 0xffff 项上限。
    auto too_many_type_ids = BuildDexHeaderForIdLimitTest(65536U, 0U, 0U, 0U);
    RequireDexError(
        [&too_many_type_ids]() {
            static_cast<void>(dexhollow13::dex::DexFile(std::move(too_many_type_ids)));
        },
        "DEX 应拒绝 type_ids_size == 65536");
}

void TestPayloadRoundTrip() {
    dexhollow13::payload::PayloadFile input;
    input.dex_ordinal = 2U;
    for (std::size_t index = 0U; index < input.original_dex_signature.size(); ++index) {
        input.original_dex_signature[index] = static_cast<std::uint8_t>(index);
        input.hollow_dex_signature[index] = static_cast<std::uint8_t>(0xf0U + index);
    }

    dexhollow13::payload::MethodPayload first;
    first.method_idx = 7U;
    first.original_code_off = 0x100U;
    first.insns_size = 2U;
    first.access_flags = 1U;
    first.stub_kind = dexhollow13::dex::StubKind::kReturnScalarZero;
    first.flags = dexhollow13::payload::kMethodDirect;
    first.code_item = {1U, 2U, 3U, 4U, 5U};
    input.methods.push_back(first);

    dexhollow13::payload::MethodPayload second;
    second.method_idx = 11U;
    second.original_code_off = 0x200U;
    second.insns_size = 3U;
    second.stub_kind = dexhollow13::dex::StubKind::kReturnWideZero;
    second.code_item = {9U, 8U, 7U, 6U};
    input.methods.push_back(second);

    const std::vector<std::uint8_t> encoded = dexhollow13::payload::WritePayload(input);
    const auto view = dexhollow13::payload::ReadPayloadView(
        dexhollow13::ByteView(encoded.data(), encoded.size()));
    Require(
        view.methods.size() == 2U && view.methods[0].code_item_size == first.code_item.size() &&
            std::equal(first.code_item.begin(), first.code_item.end(), view.methods[0].code_item),
        "Payload 零拷贝 View 必须指向原始 code_item 数据");
    const auto decoded =
        dexhollow13::payload::ReadPayload(dexhollow13::ByteView(encoded.data(), encoded.size()));

    Require(decoded.dex_ordinal == input.dex_ordinal, "dex_ordinal round-trip 失败");
    Require(decoded.original_dex_signature == input.original_dex_signature,
            "original signature round-trip 失败");
    Require(decoded.hollow_dex_signature == input.hollow_dex_signature,
            "hollow signature round-trip 失败");
    Require(decoded.methods.size() == 2U, "method_count round-trip 失败");
    Require(decoded.methods[0].method_idx == 7U && decoded.methods[0].code_item == first.code_item,
            "第一个 method record round-trip 失败");
    Require(
        decoded.methods[1].method_idx == 11U && decoded.methods[1].code_item == second.code_item,
        "第二个 method record round-trip 失败");

    std::vector<std::uint8_t> damaged = encoded;
    damaged.back() ^= 0x80U;
    RequireDexError(
        [&damaged]() {
            static_cast<void>(dexhollow13::payload::ReadPayload(
                dexhollow13::ByteView(damaged.data(), damaged.size())));
        },
        "Payload Reader 应拒绝 CRC 不一致的数据");

    // APK 中不直接写入上面的调试期明文 Payload，而是转换为逐方法认证密文。构造两个至少
    // 含 Standard CodeItem Header 的测试方法，验证初始化只读元数据、LoadMethod 按需解密，
    // 以及任意 ciphertext 修改都会在安装 Hook 前被 metadata tag 拒绝。
    input.methods[0].code_item.resize(20U, 0x41U);
    input.methods[1].code_item.resize(22U, 0x92U);
    WriteU32(input.methods[0].code_item, 12U, input.methods[0].insns_size);
    WriteU32(input.methods[1].code_item, 12U, input.methods[1].insns_size);

    dexhollow13::crypto::MasterKey master_key{};
    for (std::size_t index = 0U; index < master_key.size(); ++index) {
        master_key[index] = static_cast<std::uint8_t>(0x20U + index);
    }
    dexhollow13::payload::PayloadNoncePrefix nonce_prefix{};
    for (std::size_t index = 0U; index < nonce_prefix.size(); ++index) {
        nonce_prefix[index] = static_cast<std::uint8_t>(0xa0U + index);
    }
    const std::vector<std::uint8_t> encrypted =
        dexhollow13::payload::WriteEncryptedPayload(input, master_key, nonce_prefix);
    const auto encrypted_view = dexhollow13::payload::ReadEncryptedPayloadView(
        dexhollow13::ByteView(encrypted.data(), encrypted.size()), master_key);
    Require(encrypted_view.methods.size() == input.methods.size(),
            "加密 Payload method_count round-trip 失败");
    for (std::size_t index = 0U; index < input.methods.size(); ++index) {
        std::vector<std::uint8_t> plaintext(input.methods[index].code_item.size());
        dexhollow13::payload::DecryptMethodCodeItem(
            encrypted_view.decryption, encrypted_view.methods[index],
            dexhollow13::MutableByteView(plaintext.data(), plaintext.size()));
        Require(plaintext == input.methods[index].code_item, "加密 Payload 单方法按需解密结果错误");
    }

    std::vector<std::uint8_t> damaged_encrypted = encrypted;
    damaged_encrypted.back() ^= 0x01U;
    RequireDexError(
        [&damaged_encrypted, &master_key]() {
            static_cast<void>(dexhollow13::payload::ReadEncryptedPayloadView(
                dexhollow13::ByteView(damaged_encrypted.data(), damaged_encrypted.size()),
                master_key));
        },
        "加密 Payload Reader 应拒绝被修改的 ciphertext");
}

void TestResourceEncryptionAndKeyInjection() {
    dexhollow13::crypto::MasterKey master_key{};
    dexhollow13::crypto::ResourceNonce nonce{};
    for (std::size_t index = 0U; index < master_key.size(); ++index) {
        master_key[index] = static_cast<std::uint8_t>(index + 1U);
    }
    for (std::size_t index = 0U; index < nonce.size(); ++index) {
        nonce[index] = static_cast<std::uint8_t>(0xe0U - index);
    }
    const std::vector<std::uint8_t> plaintext{
        'd', 'e', 'x', '\n', '0', '3', '9', '\0', 1U, 2U, 3U, 4U, 5U, 6U,
    };
    const std::vector<std::uint8_t> sealed = dexhollow13::crypto::SealResource(
        dexhollow13::ByteView(plaintext.data(), plaintext.size()), master_key, nonce,
        dexhollow13::crypto::ResourceKind::kHollowDex, 3U);
    Require(!std::equal(plaintext.begin(), plaintext.end(), sealed.begin()),
            "加密资源不能保留 DEX 明文开头");
    const std::vector<std::uint8_t> opened = dexhollow13::crypto::OpenSealedResource(
        dexhollow13::ByteView(sealed.data(), sealed.size()), master_key,
        dexhollow13::crypto::ResourceKind::kHollowDex, 3U);
    Require(opened == plaintext, "XChaCha20-Poly1305 资源 round-trip 失败");

    std::vector<std::uint8_t> damaged = sealed;
    damaged.back() ^= 0x80U;
    RequireDexError(
        [&damaged, &master_key]() {
            static_cast<void>(dexhollow13::crypto::OpenSealedResource(
                dexhollow13::ByteView(damaged.data(), damaged.size()), master_key,
                dexhollow13::crypto::ResourceKind::kHollowDex, 3U));
        },
        "资源解密必须拒绝错误的 Poly1305 tag");

    // 模拟一个只含一次模板占位符的 SO，确认 Host 写入 mask/(key XOR mask) 后能够恢复 key，
    // 且文件中不存在连续的 32-byte master key。
    std::vector<std::uint8_t> library{0x7fU, 'E', 'L', 'F'};
    library.insert(library.end(), dexhollow13::crypto::kEmbeddedKeyTemplate.begin(),
                   dexhollow13::crypto::kEmbeddedKeyTemplate.end());
    library.push_back(0U);
    dexhollow13::crypto::MasterKey mask{};
    mask.fill(0x5aU);
    const std::vector<std::uint8_t> patched =
        dexhollow13::crypto::PatchEmbeddedMasterKey(library, master_key, mask);
    const std::size_t key_offset = 4U;
    for (std::size_t index = 0U; index < master_key.size(); ++index) {
        Require(static_cast<std::uint8_t>(patched[key_offset + index] ^
                                          patched[key_offset + master_key.size() + index]) ==
                    master_key[index],
                "补丁后的 Runtime key material 无法恢复 master key");
    }
    Require(std::search(patched.begin(), patched.end(), master_key.begin(), master_key.end()) ==
                patched.end(),
            "Runtime SO 中不应出现连续明文 master key");
}

void TestBootstrapRoundTrip() {
    dexhollow13::bootstrap::BootstrapFile input;
    input.package_name = "com.example.app";
    input.original_application = "com.example.app.RealApplication";
    input.original_app_component_factory = "com.example.app.RealFactory";

    dexhollow13::bootstrap::DexRecord record;
    record.ordinal = 1U;
    record.protected_method_count = 42U;
    record.hollow_dex_asset = ".d13/r/0123456789abcdef0123456789abcdef.dat";
    record.payload_asset = ".d13/r/fedcba9876543210fedcba9876543210.dat";
    record.original_dex_signature[0] = 0x12U;
    record.hollow_dex_signature[19] = 0x34U;
    input.dex_files.push_back(record);

    const std::vector<std::uint8_t> bytes = dexhollow13::bootstrap::WriteBootstrap(input);
    const auto decoded =
        dexhollow13::bootstrap::ReadBootstrap(dexhollow13::ByteView(bytes.data(), bytes.size()));
    Require(decoded.package_name == input.package_name, "bootstrap package round-trip 失败");
    Require(decoded.original_application == input.original_application,
            "bootstrap Application round-trip 失败");
    Require(decoded.original_app_component_factory == input.original_app_component_factory,
            "bootstrap factory round-trip 失败");
    Require(decoded.dex_files.size() == 1U && decoded.dex_files[0].ordinal == 1U &&
                decoded.dex_files[0].protected_method_count == 42U,
            "bootstrap DEX record round-trip 失败");
    Require(decoded.dex_files[0].hollow_dex_asset == record.hollow_dex_asset &&
                decoded.dex_files[0].payload_asset == record.payload_asset,
            "bootstrap asset name round-trip 失败");

    std::vector<std::uint8_t> damaged = bytes;
    damaged.back() ^= 1U;
    RequireDexError(
        [&damaged]() {
            static_cast<void>(dexhollow13::bootstrap::ReadBootstrap(
                dexhollow13::ByteView(damaged.data(), damaged.size())));
        },
        "bootstrap Reader 应拒绝 CRC 错误");
}

}  // namespace

int main() {
    try {
        TestByteViewAndLeb128();
        TestReturnStubs();
        TestDexIdTableLimits();
        TestPayloadRoundTrip();
        TestResourceEncryptionAndKeyInjection();
        TestBootstrapRoundTrip();
        std::cout << "全部 Host core tests 通过\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
