#include "dexhollow13/dex/dex_transformer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/base/error.h"
#include "dexhollow13/dex/code_item.h"
#include "dexhollow13/dex/dex_file.h"
#include "dexhollow13/dex/dex_format.h"
#include "dexhollow13/dex/dex_integrity.h"
#include "dexhollow13/dex/stub_generator.h"
#include "dexhollow13/payload/payload_format.h"

namespace dexhollow13::dex {
namespace {

struct PlannedMethod {
    MethodInfo info;
    CodeItemLayout layout;
    StubProgram stub;
    std::vector<std::uint8_t> original_code_item;
};

std::uint32_t CheckedU32(std::size_t value, const std::string& purpose) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw Error(purpose + " 超过 uint32_t 范围");
    }
    return static_cast<std::uint32_t>(value);
}

bool HasEnoughRegisters(const CodeItemLayout& layout, StubKind kind) {
    if (kind == StubKind::kReturnVoid || kind == StubKind::kConstructorPrefixReturnVoid) {
        return true;
    }
    if (kind == StubKind::kReturnWideZero) {
        return layout.registers_size >= 2U;
    }
    return layout.registers_size >= 1U;
}

std::uint32_t BuildPayloadFlags(const PlannedMethod& method) {
    std::uint32_t flags = 0U;
    if (method.info.encoded_method.is_direct) {
        flags |= payload::kMethodDirect;
    }
    if (method.info.name == "<init>") {
        flags |= payload::kMethodConstructor;
    }
    if (method.info.name == "<clinit>") {
        flags |= payload::kMethodClassInitializer;
    }
    if (method.layout.tries_size != 0U) {
        flags |= payload::kMethodHasTryItems;
    }
    return flags;
}

}  // namespace

const char* MethodActionName(MethodAction action) noexcept {
    switch (action) {
        case MethodAction::kProtected:
            return "protected";
        case MethodAction::kSkippedNoCode:
            return "skipped_no_code";
        case MethodAction::kSkippedConstructor:
            return "skipped_constructor";
        case MethodAction::kSkippedStubTooLarge:
            return "skipped_stub_too_large";
    }
    return "unknown";
}

TransformResult TransformDex(std::vector<std::uint8_t> input_dex, std::uint32_t dex_ordinal,
                             const TransformOptions& options) {
    DexFile dex_file(std::move(input_dex));
    if (options.verify_input_integrity) {
        VerifyDexIntegrity(dex_file.view());
    }

    const Sha1Digest original_signature = ComputeDexSignature(dex_file.view());
    const std::vector<MethodInfo> method_infos = dex_file.EnumerateMethods();

    TransformResult result;
    result.methods.reserve(method_infos.size());
    std::vector<PlannedMethod> plans;
    plans.reserve(method_infos.size());

    // 第一遍只解析与复制，不修改任何字节。这样后面的某个方法失败时，不会出现前半部分
    // 已经被清空、后半部分还没进入 Payload 的不可恢复状态。
    for (const MethodInfo& info : method_infos) {
        MethodReport report;
        report.method_idx = info.encoded_method.method_idx;
        report.code_off = info.encoded_method.code_off;
        report.method_name = info.PrettyName();

        if (info.encoded_method.code_off == 0U) {
            report.action = MethodAction::kSkippedNoCode;
            report.reason = "encoded_method.code_off == 0（通常为 abstract/native）";
            result.methods.push_back(std::move(report));
            ++result.no_code_count;
            continue;
        }

        if ((info.encoded_method.access_flags & (kAccNative | kAccAbstract)) != 0U) {
            throw Error("native/abstract 方法却含有非 0 code_off：" + info.PrettyName());
        }

        if (info.name == "<init>" && !options.protect_constructors) {
            report.action = MethodAction::kSkippedConstructor;
            report.reason = "TransformOptions 明确关闭构造器保护";
            result.methods.push_back(std::move(report));
            ++result.skipped_count;
            continue;
        }
        CodeItemLayout layout = ParseCodeItem(dex_file.view(), info.encoded_method.code_off,
                                              dex_file.header().type_ids_size);
        if (layout.debug_info_off != 0U && layout.debug_info_off >= dex_file.bytes().size()) {
            throw Error("debug_info_off 越界：" + info.PrettyName());
        }

        StubProgram stub;
        if (info.name == "<init>") {
            std::string constructor_reason;
            const auto constructor_stub =
                BuildConstructorStub(dex_file, layout, &constructor_reason);
            if (!constructor_stub.has_value()) {
                report.action = MethodAction::kSkippedConstructor;
                report.reason = std::move(constructor_reason);
                result.methods.push_back(std::move(report));
                ++result.skipped_count;
                continue;
            }
            stub = constructor_stub.value();
        } else {
            stub = BuildReturnStub(info.return_descriptor);
        }
        if (stub.code_units.size() > layout.insns_size || !HasEnoughRegisters(layout, stub.kind)) {
            report.action = MethodAction::kSkippedStubTooLarge;
            report.reason = "原 code_item 的指令或寄存器数量不足以放入类型正确的返回桩";
            result.methods.push_back(std::move(report));
            ++result.skipped_count;
            continue;
        }
        std::string placement_reason;
        if (!PlanStubPlacement(layout, &stub, &placement_reason)) {
            report.action = MethodAction::kSkippedStubTooLarge;
            report.reason = std::move(placement_reason);
            result.methods.push_back(std::move(report));
            ++result.skipped_count;
            continue;
        }

        const ByteView code_bytes =
            dex_file.view().Subview(layout.code_off, layout.total_size, "复制原始 code_item");
        std::vector<std::uint8_t> original(code_bytes.data(),
                                           code_bytes.data() + code_bytes.size());

        report.code_item_size = CheckedU32(layout.total_size, "code_item_size");
        report.action = MethodAction::kProtected;
        report.reason =
            info.name == "<init>"
                ? "原始完整 code_item 已写入 Payload，DEX 仅保留 verifier 所需初始化前缀"
                : "原始完整 code_item 已写入 Payload，DEX 中替换为默认返回桩";
        result.methods.push_back(std::move(report));
        ++result.protected_count;

        plans.push_back({info, std::move(layout), std::move(stub), std::move(original)});
    }

    // 不同方法在格式上可以引用相同 code_off。完全共享时可以只修改一次；
    // 但如果共享方法要求不同返回桩，任何一种覆盖都会让另一个方法校验失败，因此拒绝。
    std::unordered_map<std::uint32_t, StubProgram> shared_stubs;
    for (const PlannedMethod& plan : plans) {
        const auto inserted = shared_stubs.emplace(plan.layout.code_off, plan.stub);
        if (!inserted.second && (inserted.first->second.code_units != plan.stub.code_units ||
                                 inserted.first->second.write_dex_pcs != plan.stub.write_dex_pcs ||
                                 inserted.first->second.preserved_prefix_code_units !=
                                     plan.stub.preserved_prefix_code_units)) {
            throw Error("共享同一 code_off 的方法需要不同 Hollow stub：" + plan.info.PrettyName());
        }
    }

    // 除完全相同的 code_off 外，两个 code_item 不允许部分重叠。部分重叠通常意味着输入 DEX
    // 已损坏，继续写会同时破坏两个 Payload 记录的语义。
    std::vector<const PlannedMethod*> sorted;
    sorted.reserve(plans.size());
    for (const PlannedMethod& plan : plans) {
        sorted.push_back(&plan);
    }
    std::sort(sorted.begin(), sorted.end(),
              [](const PlannedMethod* left, const PlannedMethod* right) {
                  return left->layout.code_off < right->layout.code_off;
              });
    for (std::size_t index = 1U; index < sorted.size(); ++index) {
        const PlannedMethod& previous = *sorted[index - 1U];
        const PlannedMethod& current = *sorted[index];
        if (previous.layout.code_off == current.layout.code_off) {
            if (previous.layout.total_size != current.layout.total_size) {
                throw Error("同一 code_off 被解析出不同 code_item 大小");
            }
            continue;
        }
        const std::uint64_t previous_end =
            static_cast<std::uint64_t>(previous.layout.code_off) + previous.layout.total_size;
        if (current.layout.code_off < previous_end) {
            throw Error("两个 code_item 的文件范围发生部分重叠");
        }
    }

    std::unordered_set<std::uint32_t> transformed_offsets;
    MutableByteView writable(dex_file.mutable_bytes().data(), dex_file.mutable_bytes().size());
    for (const PlannedMethod& plan : plans) {
        if (transformed_offsets.insert(plan.layout.code_off).second) {
            ApplyReturnStub(writable, plan.layout, plan.stub);
        }
    }

    RepairDexIntegrity(dex_file.mutable_bytes());
    const Sha1Digest hollow_signature = ComputeDexSignature(dex_file.view());

    payload::PayloadFile payload_file;
    payload_file.dex_ordinal = dex_ordinal;
    payload_file.original_dex_signature = original_signature;
    payload_file.hollow_dex_signature = hollow_signature;
    payload_file.methods.reserve(plans.size());
    for (PlannedMethod& plan : plans) {
        payload::MethodPayload method;
        method.method_idx = plan.info.encoded_method.method_idx;
        method.original_code_off = plan.info.encoded_method.code_off;
        method.insns_size = plan.layout.insns_size;
        method.access_flags = plan.info.encoded_method.access_flags;
        method.stub_kind = plan.stub.kind;
        method.flags = BuildPayloadFlags(plan);
        method.code_item = std::move(plan.original_code_item);
        payload_file.methods.push_back(std::move(method));
    }

    result.payload = payload::WritePayload(payload_file);
    result.hollow_dex = dex_file.ReleaseBytes();
    return result;
}

}  // namespace dexhollow13::dex
