#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "dexhollow13/base/error.h"
#include "dexhollow13/payload/encrypted_payload_format.h"
#include "monocypher.h"

namespace dexhollow13::payload {
namespace {

constexpr std::size_t kAuthenticatedHeaderSize = 112U;
constexpr std::size_t kMetadataTagOffset = 112U;
constexpr std::size_t kMethodMetadataSize = 32U;
constexpr std::size_t kMethodAssociatedDataSize = 89U;
constexpr std::size_t kDexMethodIndexCount = 65536U;

struct PayloadKeys {
    crypto::MasterKey method{};
    crypto::MasterKey metadata{};
};

void AppendU32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

std::uint32_t CheckedU32(std::size_t value, const std::string& purpose) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw Error(purpose + " 超过 uint32_t 可表示范围");
    }
    return static_cast<std::uint32_t>(value);
}

bool IsKnownStubKind(std::uint32_t value) {
    return value >= static_cast<std::uint32_t>(dex::StubKind::kReturnVoid) &&
           value <= static_cast<std::uint32_t>(dex::StubKind::kConstructorPrefixReturnVoid);
}

PayloadKeys DerivePayloadKeys(const crypto::MasterKey& master_key, std::uint32_t dex_ordinal,
                              const dex::Sha1Digest& original_signature,
                              const dex::Sha1Digest& hollow_signature) {
    std::vector<std::uint8_t> context{
        'D', 'H', '1', '3', '-', 'P', 'A', 'Y', 'L', 'O', 'A', 'D', '-', 'K', 'D', 'F', '-', '1',
    };
    AppendU32(context, dex_ordinal);
    context.insert(context.end(), original_signature.begin(), original_signature.end());
    context.insert(context.end(), hollow_signature.begin(), hollow_signature.end());

    std::array<std::uint8_t, 64U> derived{};
    crypto_blake2b_keyed(derived.data(), derived.size(), master_key.data(), master_key.size(),
                         context.data(), context.size());
    PayloadKeys keys;
    std::copy_n(derived.begin(), keys.method.size(), keys.method.begin());
    std::copy_n(derived.begin() + static_cast<std::ptrdiff_t>(keys.method.size()),
                keys.metadata.size(), keys.metadata.begin());
    crypto::SecureWipe(derived.data(), derived.size());
    return keys;
}

crypto::ResourceNonce BuildMethodNonce(const PayloadNoncePrefix& prefix, std::uint32_t method_idx,
                                       std::uint32_t original_code_off) {
    crypto::ResourceNonce nonce{};
    std::copy(prefix.begin(), prefix.end(), nonce.begin());
    for (std::size_t index = 0U; index < 4U; ++index) {
        nonce[16U + index] = static_cast<std::uint8_t>(method_idx >> (index * 8U));
        nonce[20U + index] = static_cast<std::uint8_t>(original_code_off >> (index * 8U));
    }
    return nonce;
}

std::array<std::uint8_t, kMethodAssociatedDataSize> BuildMethodAssociatedData(
    std::uint32_t dex_ordinal, const dex::Sha1Digest& original_signature,
    const dex::Sha1Digest& hollow_signature, const EncryptedMethodPayload& method) {
    std::array<std::uint8_t, kMethodAssociatedDataSize> associated_data{};
    const std::array<std::uint8_t, 13U> domain{{
        'D',
        'H',
        '1',
        '3',
        '-',
        'M',
        'E',
        'T',
        'H',
        'O',
        'D',
        '-',
        '1',
    }};
    std::size_t cursor = 0U;
    const auto append_bytes = [&associated_data, &cursor](const std::uint8_t* data,
                                                          std::size_t size) {
        std::copy_n(data, size, associated_data.begin() + static_cast<std::ptrdiff_t>(cursor));
        cursor += size;
    };
    const auto append_u32 = [&append_bytes](std::uint32_t value) {
        const std::array<std::uint8_t, 4U> encoded{{
            static_cast<std::uint8_t>(value & 0xffU),
            static_cast<std::uint8_t>((value >> 8U) & 0xffU),
            static_cast<std::uint8_t>((value >> 16U) & 0xffU),
            static_cast<std::uint8_t>((value >> 24U) & 0xffU),
        }};
        append_bytes(encoded.data(), encoded.size());
    };

    append_bytes(domain.data(), domain.size());
    append_u32(dex_ordinal);
    append_bytes(original_signature.data(), original_signature.size());
    append_bytes(hollow_signature.data(), hollow_signature.size());
    append_u32(method.method_idx);
    append_u32(method.original_code_off);
    append_u32(method.code_item_size);
    append_u32(method.ciphertext_offset);
    append_u32(method.insns_size);
    append_u32(method.access_flags);
    append_u32(static_cast<std::uint32_t>(method.stub_kind));
    append_u32(method.flags);
    return associated_data;
}

PayloadMetadataTag ComputeMetadataTag(const ByteView& bytes,
                                      const crypto::MasterKey& metadata_key) {
    PayloadMetadataTag tag{};
    crypto_blake2b_ctx context;
    crypto_blake2b_keyed_init(&context, tag.size(), metadata_key.data(), metadata_key.size());
    crypto_blake2b_update(&context, bytes.data(), kAuthenticatedHeaderSize);
    crypto_blake2b_update(&context, bytes.data() + kEncryptedPayloadHeaderSize,
                          bytes.size() - kEncryptedPayloadHeaderSize);
    crypto_blake2b_final(&context, tag.data());
    return tag;
}

}  // namespace

std::vector<std::uint8_t> WriteEncryptedPayload(const PayloadFile& payload,
                                                const crypto::MasterKey& master_key,
                                                const PayloadNoncePrefix& nonce_prefix) {
    if (payload.methods.empty() || payload.methods.size() > kDexMethodIndexCount) {
        throw Error("加密 Payload 方法数量为空或超过单 DEX method_idx 范围");
    }

    std::vector<bool> method_indices(kDexMethodIndexCount, false);
    for (const MethodPayload& method : payload.methods) {
        if (method.method_idx >= kDexMethodIndexCount || method_indices[method.method_idx] ||
            method.code_item.empty()) {
            throw Error("加密 Payload 出现重复 method_idx 或空 code_item");
        }
        method_indices[method.method_idx] = true;
    }

    const std::size_t records_size = CheckedMultiply(
        payload.methods.size(), kEncryptedPayloadRecordSize, "加密 Payload records");
    const std::size_t data_offset_size = kEncryptedPayloadHeaderSize + records_size;
    const std::uint32_t data_offset = CheckedU32(data_offset_size, "加密 Payload data_offset");

    std::vector<std::uint8_t> output;
    output.reserve(data_offset_size);
    output.insert(output.end(), kEncryptedPayloadMagic.begin(), kEncryptedPayloadMagic.end());
    AppendU32(output, kEncryptedPayloadVersion);
    AppendU32(output, static_cast<std::uint32_t>(kEncryptedPayloadHeaderSize));
    AppendU32(output, kPayloadEndianTag);
    AppendU32(output, kEncryptedPayloadFlagAeadPerMethod);
    AppendU32(output, payload.dex_ordinal);
    AppendU32(output, static_cast<std::uint32_t>(payload.methods.size()));
    AppendU32(output, static_cast<std::uint32_t>(kEncryptedPayloadRecordSize));
    AppendU32(output, static_cast<std::uint32_t>(kEncryptedPayloadHeaderSize));
    AppendU32(output, data_offset);
    AppendU32(output, 0U);  // file_size 最后回填。
    AppendU32(output, 0U);  // reserved
    AppendU32(output, 0U);  // reserved
    output.insert(output.end(), payload.original_dex_signature.begin(),
                  payload.original_dex_signature.end());
    output.insert(output.end(), payload.hollow_dex_signature.begin(),
                  payload.hollow_dex_signature.end());
    output.insert(output.end(), nonce_prefix.begin(), nonce_prefix.end());
    output.resize(kEncryptedPayloadHeaderSize + records_size, 0U);

    PayloadKeys keys =
        DerivePayloadKeys(master_key, payload.dex_ordinal, payload.original_dex_signature,
                          payload.hollow_dex_signature);
    for (std::size_t index = 0U; index < payload.methods.size(); ++index) {
        const MethodPayload& source = payload.methods[index];
        while ((output.size() & 3U) != 0U) {
            output.push_back(0U);
        }

        EncryptedMethodPayload method;
        method.method_idx = source.method_idx;
        method.original_code_off = source.original_code_off;
        method.code_item_size = CheckedU32(source.code_item.size(), "code_item_size");
        method.insns_size = source.insns_size;
        method.access_flags = source.access_flags;
        method.stub_kind = source.stub_kind;
        method.flags = source.flags;
        const std::uint32_t method_data_offset = CheckedU32(output.size(), "method data_offset");
        method.ciphertext_offset = method_data_offset;
        const auto associated_data =
            BuildMethodAssociatedData(payload.dex_ordinal, payload.original_dex_signature,
                                      payload.hollow_dex_signature, method);
        const crypto::ResourceNonce nonce =
            BuildMethodNonce(nonce_prefix, method.method_idx, method.original_code_off);

        const std::size_t cipher_begin = output.size();
        output.resize(cipher_begin + source.code_item.size());
        crypto_aead_lock(output.data() + cipher_begin, method.authentication_tag.data(),
                         keys.method.data(), nonce.data(), associated_data.data(),
                         associated_data.size(), source.code_item.data(), source.code_item.size());

        const std::size_t record_offset =
            kEncryptedPayloadHeaderSize + index * kEncryptedPayloadRecordSize;
        MutableByteView writable(output.data(), output.size());
        writable.WriteU32(record_offset, method.method_idx, "record.method_idx");
        writable.WriteU32(record_offset + 4U, method.original_code_off, "record.original_code_off");
        writable.WriteU32(record_offset + 8U, method.code_item_size, "record.code_item_size");
        writable.WriteU32(record_offset + 12U, method_data_offset, "record.data_offset");
        writable.WriteU32(record_offset + 16U, method.insns_size, "record.insns_size");
        writable.WriteU32(record_offset + 20U, method.access_flags, "record.access_flags");
        writable.WriteU32(record_offset + 24U, static_cast<std::uint32_t>(method.stub_kind),
                          "record.stub_kind");
        writable.WriteU32(record_offset + 28U, method.flags, "record.flags");
        writable.CopyFrom(record_offset + kMethodMetadataSize, method.authentication_tag.data(),
                          method.authentication_tag.size(), "record.authentication_tag");
    }

    MutableByteView writable(output.data(), output.size());
    writable.WriteU32(44U, CheckedU32(output.size(), "加密 Payload file_size"), "file_size");
    const PayloadMetadataTag metadata_tag =
        ComputeMetadataTag(writable.AsReadOnly(), keys.metadata);
    writable.CopyFrom(kMetadataTagOffset, metadata_tag.data(), metadata_tag.size(),
                      "Payload metadata tag");
    crypto::SecureWipe(keys.method.data(), keys.method.size());
    crypto::SecureWipe(keys.metadata.data(), keys.metadata.size());
    return output;
}

EncryptedPayloadView ReadEncryptedPayloadView(const ByteView& bytes,
                                              const crypto::MasterKey& master_key) {
    bytes.CheckRange(0U, kEncryptedPayloadHeaderSize, "加密 Payload Header");
    if (!std::equal(kEncryptedPayloadMagic.begin(), kEncryptedPayloadMagic.end(),
                    bytes.DataAt(0U, kEncryptedPayloadMagic.size(), "加密 Payload magic"))) {
        throw Error("加密 Payload magic 不正确");
    }

    const std::uint32_t version = bytes.ReadU32(8U, "Payload version");
    const std::uint32_t header_size = bytes.ReadU32(12U, "Payload header_size");
    const std::uint32_t endian_tag = bytes.ReadU32(16U, "Payload endian_tag");
    const std::uint32_t flags = bytes.ReadU32(20U, "Payload flags");
    const std::uint32_t dex_ordinal = bytes.ReadU32(24U, "Payload dex_ordinal");
    const std::uint32_t method_count = bytes.ReadU32(28U, "Payload method_count");
    const std::uint32_t record_size = bytes.ReadU32(32U, "Payload record_size");
    const std::uint32_t records_offset = bytes.ReadU32(36U, "Payload records_offset");
    const std::uint32_t data_offset = bytes.ReadU32(40U, "Payload data_offset");
    const std::uint32_t file_size = bytes.ReadU32(44U, "Payload file_size");
    const std::uint32_t reserved0 = bytes.ReadU32(48U, "Payload reserved0");
    const std::uint32_t reserved1 = bytes.ReadU32(52U, "Payload reserved1");
    if (version != kEncryptedPayloadVersion || header_size != kEncryptedPayloadHeaderSize ||
        endian_tag != kPayloadEndianTag || flags != kEncryptedPayloadFlagAeadPerMethod ||
        record_size != kEncryptedPayloadRecordSize ||
        records_offset != kEncryptedPayloadHeaderSize || file_size != bytes.size() ||
        reserved0 != 0U || reserved1 != 0U || method_count == 0U) {
        throw Error("加密 Payload Header 字段不受支持");
    }

    const std::size_t records_bytes = CheckedMultiply(
        static_cast<std::size_t>(method_count), kEncryptedPayloadRecordSize, "Payload records");
    bytes.CheckRange(records_offset, records_bytes, "加密 Payload record array");
    if (data_offset < static_cast<std::uint64_t>(records_offset) + records_bytes ||
        data_offset > bytes.size() || (data_offset & 3U) != 0U) {
        throw Error("加密 Payload data_offset 非法");
    }

    EncryptedPayloadView payload;
    payload.decryption.dex_ordinal = dex_ordinal;
    std::copy_n(bytes.DataAt(56U, 20U, "original_dex_signature"), 20U,
                payload.decryption.original_dex_signature.begin());
    std::copy_n(bytes.DataAt(76U, 20U, "hollow_dex_signature"), 20U,
                payload.decryption.hollow_dex_signature.begin());
    std::copy_n(bytes.DataAt(96U, payload.decryption.nonce_prefix.size(), "nonce_prefix"),
                payload.decryption.nonce_prefix.size(), payload.decryption.nonce_prefix.begin());

    PayloadKeys keys = DerivePayloadKeys(master_key, payload.decryption.dex_ordinal,
                                         payload.decryption.original_dex_signature,
                                         payload.decryption.hollow_dex_signature);
    const PayloadMetadataTag expected_tag = ComputeMetadataTag(bytes, keys.metadata);
    const std::uint8_t* stored_tag =
        bytes.DataAt(kMetadataTagOffset, expected_tag.size(), "Payload metadata tag");
    if (crypto_verify32(expected_tag.data(), stored_tag) != 0) {
        crypto::SecureWipe(keys.method.data(), keys.method.size());
        crypto::SecureWipe(keys.metadata.data(), keys.metadata.size());
        throw Error("加密 Payload 元数据认证失败");
    }
    payload.decryption.method_key = keys.method;
    crypto::SecureWipe(keys.method.data(), keys.method.size());
    crypto::SecureWipe(keys.metadata.data(), keys.metadata.size());

    payload.methods.reserve(method_count);
    std::vector<bool> method_indices(kDexMethodIndexCount, false);
    std::size_t previous_data_end = data_offset;
    for (std::uint32_t index = 0U; index < method_count; ++index) {
        const std::size_t record = static_cast<std::size_t>(records_offset) +
                                   static_cast<std::size_t>(index) * kEncryptedPayloadRecordSize;
        EncryptedMethodPayload method;
        method.method_idx = bytes.ReadU32(record, "record.method_idx");
        method.original_code_off = bytes.ReadU32(record + 4U, "record.original_code_off");
        method.code_item_size = bytes.ReadU32(record + 8U, "record.code_item_size");
        method.ciphertext_offset = bytes.ReadU32(record + 12U, "record.data_offset");
        method.insns_size = bytes.ReadU32(record + 16U, "record.insns_size");
        method.access_flags = bytes.ReadU32(record + 20U, "record.access_flags");
        const std::uint32_t stub_kind = bytes.ReadU32(record + 24U, "record.stub_kind");
        method.flags = bytes.ReadU32(record + 28U, "record.flags");
        std::copy_n(bytes.DataAt(record + kMethodMetadataSize, method.authentication_tag.size(),
                                 "record.authentication_tag"),
                    method.authentication_tag.size(), method.authentication_tag.begin());

        if (method.method_idx >= kDexMethodIndexCount || method_indices[method.method_idx] ||
            !IsKnownStubKind(stub_kind) || method.code_item_size < 16U ||
            method.original_code_off == 0U || (method.original_code_off & 3U) != 0U ||
            method.ciphertext_offset < data_offset || (method.ciphertext_offset & 3U) != 0U ||
            method.ciphertext_offset < previous_data_end) {
            throw Error("加密 Payload method record 包含非法或重叠字段");
        }
        method_indices[method.method_idx] = true;
        bytes.CheckRange(method.ciphertext_offset, method.code_item_size,
                         "Payload method ciphertext");
        previous_data_end =
            static_cast<std::size_t>(method.ciphertext_offset) + method.code_item_size;
        method.stub_kind = static_cast<dex::StubKind>(stub_kind);
        method.encrypted_code_item = bytes.DataAt(method.ciphertext_offset, method.code_item_size,
                                                  "Payload method ciphertext");
        payload.methods.push_back(
            {bytes.DataAt(record, kEncryptedPayloadRecordSize, "Payload method record"),
             method.encrypted_code_item});
    }
    return payload;
}

EncryptedMethodPayload DecodeEncryptedMethodPayload(const EncryptedMethodPayloadView& view) {
    if (view.record == nullptr || view.encrypted_code_item == nullptr) {
        throw Error("加密 Payload method view 指针为空");
    }
    const ByteView record(view.record, kEncryptedPayloadRecordSize);
    EncryptedMethodPayload method;
    method.method_idx = record.ReadU32(0U, "record.method_idx");
    method.original_code_off = record.ReadU32(4U, "record.original_code_off");
    method.code_item_size = record.ReadU32(8U, "record.code_item_size");
    method.ciphertext_offset = record.ReadU32(12U, "record.data_offset");
    method.insns_size = record.ReadU32(16U, "record.insns_size");
    method.access_flags = record.ReadU32(20U, "record.access_flags");
    method.stub_kind = static_cast<dex::StubKind>(record.ReadU32(24U, "record.stub_kind"));
    method.flags = record.ReadU32(28U, "record.flags");
    std::copy_n(record.DataAt(kMethodMetadataSize, method.authentication_tag.size(),
                              "record.authentication_tag"),
                method.authentication_tag.size(), method.authentication_tag.begin());
    method.encrypted_code_item = view.encrypted_code_item;
    return method;
}

void DecryptMethodCodeItem(const PayloadDecryptionContext& context,
                           const EncryptedMethodPayloadView& method_view,
                           const MutableByteView& plaintext) {
    const EncryptedMethodPayload method = DecodeEncryptedMethodPayload(method_view);
    if (plaintext.size() != method.code_item_size || method.encrypted_code_item == nullptr) {
        throw Error("方法解密输出大小或密文指针非法");
    }
    const auto associated_data = BuildMethodAssociatedData(
        context.dex_ordinal, context.original_dex_signature, context.hollow_dex_signature, method);
    const crypto::ResourceNonce nonce =
        BuildMethodNonce(context.nonce_prefix, method.method_idx, method.original_code_off);
    const int result = crypto_aead_unlock(plaintext.data(), method.authentication_tag.data(),
                                          context.method_key.data(), nonce.data(),
                                          associated_data.data(), associated_data.size(),
                                          method.encrypted_code_item, method.code_item_size);
    if (result != 0) {
        crypto::SecureWipe(plaintext.data(), plaintext.size());
        throw Error("方法 code_item 认证失败");
    }
}

}  // namespace dexhollow13::payload
