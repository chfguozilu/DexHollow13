#include "dexhollow13/dex/stub_generator.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <vector>

#include "dexhollow13/base/error.h"
#include "dexhollow13/dex/dex_file.h"

namespace dexhollow13::dex {
namespace {

// 下列值是完整的 16-bit DEX code unit，而不是单独 opcode。
// 目标寄存器统一选择 v0，因此寄存器字段的 bit 都是 0。
constexpr std::uint16_t kNop = 0x0000U;
constexpr std::uint16_t kReturnVoid = 0x000eU;
constexpr std::uint16_t kReturn = 0x000fU;
constexpr std::uint16_t kReturnWide = 0x0010U;
constexpr std::uint16_t kReturnObject = 0x0011U;
constexpr std::uint16_t kConst4V0Zero = 0x0012U;
constexpr std::uint16_t kConstWide16V0 = 0x0016U;

bool IsScalarDescriptor(char descriptor) {
    switch (descriptor) {
        case 'Z':
        case 'B':
        case 'S':
        case 'C':
        case 'I':
        case 'F':
            return true;
        default:
            return false;
    }
}

std::uint32_t InstructionWidth(std::uint8_t opcode) {
    // 宽度表来自 android-13.0.0_r84 的 dex_instruction_list.h 与 dex_instruction.cc。
    // 这里只扫描构造函数的可执行前缀，但仍覆盖 DEX 035-040 的全部有效 opcode，避免把
    // 某条指令的 operand 错认成 invoke-direct。
    switch (opcode) {
        case 0x00U:
            return 0U;  // nop 的复杂 payload 需要结合完整 code unit 单独处理。
        case 0x01U:
        case 0x04U:
        case 0x07U:
        case 0x0aU:
        case 0x0bU:
        case 0x0cU:
        case 0x0dU:
        case 0x0eU:
        case 0x0fU:
        case 0x10U:
        case 0x11U:
        case 0x12U:
        case 0x1dU:
        case 0x1eU:
        case 0x21U:
        case 0x27U:
        case 0x28U:
            return 1U;
        case 0x02U:
        case 0x05U:
        case 0x08U:
        case 0x13U:
        case 0x15U:
        case 0x16U:
        case 0x19U:
        case 0x1aU:
        case 0x1cU:
        case 0x1fU:
        case 0x20U:
        case 0x22U:
        case 0x23U:
        case 0x29U:
            return 2U;
        case 0x03U:
        case 0x06U:
        case 0x09U:
        case 0x14U:
        case 0x17U:
        case 0x1bU:
        case 0x24U:
        case 0x25U:
        case 0x26U:
        case 0x2aU:
        case 0x2bU:
        case 0x2cU:
            return 3U;
        case 0x18U:
            return 5U;
        case 0xfaU:
        case 0xfbU:
            return 4U;
        default:
            break;
    }

    if ((opcode >= 0x2dU && opcode <= 0x3dU) || (opcode >= 0x44U && opcode <= 0x6dU) ||
        (opcode >= 0x90U && opcode <= 0xafU) || (opcode >= 0xd0U && opcode <= 0xe2U) ||
        opcode >= 0xfeU) {
        return 2U;
    }
    if ((opcode >= 0x6eU && opcode <= 0x72U) || (opcode >= 0x74U && opcode <= 0x78U) ||
        (opcode >= 0xfcU && opcode <= 0xfdU)) {
        return 3U;
    }
    if ((opcode >= 0x7bU && opcode <= 0x8fU) || (opcode >= 0xb0U && opcode <= 0xcfU)) {
        return 1U;
    }

    // 0x3e..0x43、0x73、0x79..0x7a 与 0xe3..0xf9 在 Android 13 中保留未使用。
    // 通过返回 0 让调用者拒绝畸形或未来版本指令，而不是按 1 code unit 猜测后继续扫描。
    return 0U;
}

bool IsUnsupportedControlFlowBeforeConstructorCall(std::uint8_t opcode) {
    // return 会形成“未初始化 this 就正常离开方法”的非法路径；switch 还需要解析独立
    // payload，这里继续保守拒绝。throw 则是合法的构造器参数检查失败路径，可以原样保留。
    // if/goto 在 BuildConstructorStub 中做目标边界验证后允许保留。
    return (opcode >= 0x0eU && opcode <= 0x11U) || opcode == 0x2bU || opcode == 0x2cU;
}

std::optional<std::int64_t> BranchOffset(const DexFile& dex_file, std::size_t instruction_offset,
                                         std::uint16_t first, std::uint8_t opcode) {
    if (opcode == 0x28U) {
        // goto/10t 的 signed 8-bit offset 位于第一个 code unit 的高字节。用显式减法完成
        // 符号扩展，避免依赖 unsigned -> int8_t 超范围转换的实现定义行为。
        const std::int64_t raw = static_cast<std::int64_t>((first >> 8U) & 0xffU);
        return raw >= 0x80 ? raw - 0x100 : raw;
    }
    if (opcode == 0x29U || (opcode >= 0x32U && opcode <= 0x3dU)) {
        const std::int64_t raw =
            dex_file.view().ReadU16(instruction_offset + 2U, "constructor branch/16 offset");
        return raw >= 0x8000 ? raw - 0x10000 : raw;
    }
    if (opcode == 0x2aU) {
        const std::uint32_t low =
            dex_file.view().ReadU16(instruction_offset + 2U, "constructor goto/32 low offset");
        const std::uint32_t high =
            dex_file.view().ReadU16(instruction_offset + 4U, "constructor goto/32 high offset");
        const std::uint32_t raw_unsigned = low | (high << 16U);
        const std::int64_t raw = static_cast<std::int64_t>(raw_unsigned);
        return raw >= 0x80000000LL ? raw - 0x100000000LL : raw;
    }
    return std::nullopt;
}

void ClearAlias(std::vector<std::int64_t>* aliases, std::uint32_t first_register, bool wide) {
    if (first_register < aliases->size()) {
        (*aliases)[first_register] = -1;
    }
    if (wide && first_register + 1U < aliases->size()) {
        (*aliases)[first_register + 1U] = -1;
    }
}

void ClearAliasesWrittenByInstruction(const DexFile& dex_file, std::size_t instruction_offset,
                                      std::uint16_t first, std::uint8_t opcode,
                                      std::vector<std::int64_t>* aliases) {
    std::uint32_t destination = 0U;
    bool writes = false;
    bool wide = false;

    // 这里仅回答“指令会覆盖哪些目标寄存器”，无需解析源操作数。分组依据同样来自
    // dex_instruction_list.h 的 format/opcode 语义。invoke、return、branch、put 等没有
    // 直接目标寄存器；它们不会让一个已经建立的 p0 move-object 别名凭空失效。
    if (opcode == 0x01U || opcode == 0x04U || opcode == 0x07U || opcode == 0x12U ||
        opcode == 0x20U || opcode == 0x21U || opcode == 0x23U ||
        (opcode >= 0x52U && opcode <= 0x58U) || (opcode >= 0x7bU && opcode <= 0x8fU) ||
        (opcode >= 0xb0U && opcode <= 0xcfU) || (opcode >= 0xd0U && opcode <= 0xd7U)) {
        writes = true;
        destination = (first >> 8U) & 0x0fU;
    } else if (opcode == 0x02U || opcode == 0x05U || opcode == 0x08U ||
               (opcode >= 0x0aU && opcode <= 0x0dU) || (opcode >= 0x13U && opcode <= 0x1cU) ||
               opcode == 0x22U || (opcode >= 0x2dU && opcode <= 0x31U) ||
               (opcode >= 0x44U && opcode <= 0x4aU) || (opcode >= 0x60U && opcode <= 0x66U) ||
               (opcode >= 0x90U && opcode <= 0xafU) || (opcode >= 0xd8U && opcode <= 0xe2U) ||
               opcode == 0xfeU || opcode == 0xffU) {
        writes = true;
        destination = (first >> 8U) & 0xffU;
    } else if (opcode == 0x03U || opcode == 0x06U || opcode == 0x09U) {
        writes = true;
        destination =
            dex_file.view().ReadU16(instruction_offset + 2U, "constructor move/16 destination");
    }

    wide = opcode == 0x04U || opcode == 0x05U || opcode == 0x06U || opcode == 0x0bU ||
           (opcode >= 0x16U && opcode <= 0x19U) || opcode == 0x45U || opcode == 0x53U ||
           opcode == 0x61U || opcode == 0x7dU || opcode == 0x7eU || opcode == 0x80U ||
           opcode == 0x81U || opcode == 0x83U || opcode == 0x86U || opcode == 0x88U ||
           opcode == 0x89U || opcode == 0x8bU || (opcode >= 0x9bU && opcode <= 0xa5U) ||
           (opcode >= 0xabU && opcode <= 0xafU) || (opcode >= 0xbbU && opcode <= 0xc5U) ||
           (opcode >= 0xcbU && opcode <= 0xcfU);
    if (writes) {
        ClearAlias(aliases, destination, wide);
    }
}

}  // namespace

StubProgram BuildReturnStub(const std::string& return_descriptor) {
    if (return_descriptor == "V") {
        return {StubKind::kReturnVoid, {kReturnVoid}, {}, 0U};
    }

    if (return_descriptor == "J" || return_descriptor == "D") {
        // const-wide/16 v0, #0 占两个 code unit，第二个 code unit 是 16-bit literal 0。
        return {StubKind::kReturnWideZero, {kConstWide16V0, 0U, kReturnWide}, {}, 0U};
    }

    if (!return_descriptor.empty() &&
        (return_descriptor.front() == 'L' || return_descriptor.front() == '[')) {
        return {StubKind::kReturnObjectNull, {kConst4V0Zero, kReturnObject}, {}, 0U};
    }

    if (return_descriptor.size() == 1U && IsScalarDescriptor(return_descriptor.front())) {
        return {StubKind::kReturnScalarZero, {kConst4V0Zero, kReturn}, {}, 0U};
    }

    throw Error("无法为非法返回类型生成 Hollow stub：" + return_descriptor);
}

std::optional<StubProgram> BuildConstructorStub(const DexFile& dex_file,
                                                const CodeItemLayout& code_item,
                                                std::string* reason) {
    if (reason == nullptr) {
        throw Error("BuildConstructorStub.reason 不能为空");
    }
    if (code_item.ins_size == 0U || code_item.registers_size < code_item.ins_size) {
        *reason = "构造器 code_item 没有合法的 p0 输入寄存器";
        return std::nullopt;
    }

    const std::uint32_t p0 = code_item.registers_size - code_item.ins_size;
    std::uint32_t dex_pc = 0U;
    std::vector<bool> instruction_starts(static_cast<std::size_t>(code_item.insns_size) + 1U,
                                         false);
    struct BranchEdge {
        std::uint32_t origin = 0U;
        std::int64_t target = 0;
    };
    std::vector<BranchEdge> branch_edges;
    // -1 表示不是 p0 别名；-2 表示方法入口自带的 p0；非负数表示建立该别名的 move-object
    // dex_pc。记录定义位置后，可以验证前面的分支是否会跳过这次别名赋值。
    std::vector<std::int64_t> recent_p0_aliases(code_item.registers_size, -1);
    recent_p0_aliases[p0] = -2;
    while (dex_pc < code_item.insns_size) {
        instruction_starts[dex_pc] = true;
        const std::size_t instruction_offset =
            code_item.insns_offset + static_cast<std::size_t>(dex_pc) * 2U;
        const std::uint16_t first =
            dex_file.view().ReadU16(instruction_offset, "constructor instruction");
        const std::uint8_t opcode = static_cast<std::uint8_t>(first & 0xffU);

        if (opcode == 0x00U) {
            if ((first & 0xff00U) != 0U) {
                *reason = "this/super <init> 前出现 switch/array-data payload";
                return std::nullopt;
            }
            ++dex_pc;
            continue;
        }

        const std::uint32_t width = InstructionWidth(opcode);
        if (width == 0U || width > code_item.insns_size - dex_pc) {
            *reason = "this/super <init> 前出现未知或截断的 DEX 指令";
            return std::nullopt;
        }

        if (IsUnsupportedControlFlowBeforeConstructorCall(opcode)) {
            *reason = "this/super <init> 前出现 return 或 switch";
            return std::nullopt;
        }
        const auto relative_branch = BranchOffset(dex_file, instruction_offset, first, opcode);
        if (relative_branch.has_value()) {
            const std::int64_t target = static_cast<std::int64_t>(dex_pc) + relative_branch.value();
            if (target < 0 || target >= static_cast<std::int64_t>(code_item.insns_size)) {
                *reason = "this/super <init> 前的 if/goto 目标越界";
                return std::nullopt;
            }
            branch_edges.push_back({dex_pc, target});
        }

        // javac/D8 为 invoke-*/range 准备连续参数区时，常先用 move-object 把 p0 搬到 v0，
        // 再以 v0 作为 receiver。只比较 receiver==p0 会错过这种合法构造器。这里跟踪一段
        // 连续 move-object 指令中的 p0 别名；遇到其他指令就清空临时别名，只保留直接 p0，
        // 避免做一个不完整的数据流分析后产生假阳性。
        bool is_object_move = false;
        std::uint32_t move_destination = 0U;
        std::uint32_t move_source = 0U;
        if (opcode == 0x07U) {
            is_object_move = true;
            move_destination = (first >> 8U) & 0x0fU;
            move_source = (first >> 12U) & 0x0fU;
        } else if (opcode == 0x08U) {
            is_object_move = true;
            move_destination = (first >> 8U) & 0xffU;
            move_source = dex_file.view().ReadU16(instruction_offset + 2U,
                                                  "constructor move-object/from16 source");
        } else if (opcode == 0x09U) {
            is_object_move = true;
            move_destination = dex_file.view().ReadU16(instruction_offset + 2U,
                                                       "constructor move-object/16 destination");
            move_source = dex_file.view().ReadU16(instruction_offset + 4U,
                                                  "constructor move-object/16 source");
        }
        if (is_object_move) {
            if (move_destination < recent_p0_aliases.size()) {
                recent_p0_aliases[move_destination] =
                    move_source < recent_p0_aliases.size() && recent_p0_aliases[move_source] != -1
                        ? static_cast<std::int64_t>(dex_pc)
                        : -1;
            }
        } else {
            ClearAliasesWrittenByInstruction(dex_file, instruction_offset, first, opcode,
                                             &recent_p0_aliases);
        }

        if (opcode == 0x70U || opcode == 0x76U) {
            const std::uint16_t target_method = dex_file.view().ReadU16(
                instruction_offset + 2U, "constructor invoke-direct method_idx");
            const std::uint16_t registers = dex_file.view().ReadU16(
                instruction_offset + 4U, "constructor invoke-direct registers");
            const std::uint32_t argument_count =
                opcode == 0x70U ? static_cast<std::uint32_t>((first >> 12U) & 0x0fU)
                                : static_cast<std::uint32_t>((first >> 8U) & 0xffU);
            const std::uint32_t receiver = opcode == 0x70U
                                               ? static_cast<std::uint32_t>(registers & 0x0fU)
                                               : static_cast<std::uint32_t>(registers);

            if (argument_count != 0U && receiver < recent_p0_aliases.size() &&
                recent_p0_aliases[receiver] != -1) {
                const MethodId invoked = dex_file.GetMethodId(target_method);
                if (dex_file.GetString(invoked.name_idx) == "<init>") {
                    const std::uint32_t prefix_end = dex_pc + width;
                    const std::int64_t receiver_definition = recent_p0_aliases[receiver];
                    for (const BranchEdge& edge : branch_edges) {
                        const std::size_t target_index = static_cast<std::size_t>(edge.target);
                        if (edge.target >= static_cast<std::int64_t>(prefix_end) ||
                            !instruction_starts[target_index]) {
                            // 目标落在初始化调用之后意味着某条路径能绕开这次
                            // <init>；目标不是已扫描的 opcode 起点则说明输入控制流跳进了
                            // operand。两种情况都不能只保留此前缀。
                            *reason =
                                "this/super <init> 前的 if/goto 可跳过初始化调用或目标不是指令起点";
                            return std::nullopt;
                        }
                        if (receiver_definition >= 0 &&
                            static_cast<std::int64_t>(edge.origin) < receiver_definition &&
                            edge.target > receiver_definition) {
                            // 这条边从别名赋值之前直接跳到赋值之后；该路径到达 invoke 时，receiver
                            // 不一定是 p0。不能仅凭线性扫描最后一次看到的 move-object
                            // 判断支配关系。
                            *reason = "if/goto 可以绕过构造器 receiver 的 p0 别名赋值";
                            return std::nullopt;
                        }
                    }

                    // try_item 可以存在于构造器主体中，但不能覆盖 uninitialized-this 前缀。
                    // 否则前缀指令抛异常时会跳到已经被改成 nop 的 handler，校验器会看到一条
                    // “尚未初始化 this 就 return-void”的路径。只要 try 从 prefix_end 之后开始，
                    // Hollow 前缀自身没有异常边，后续 try 区域全是 nop，handler 也不会变为可达。
                    for (const TryItem& item : code_item.tries) {
                        if (item.start_addr < prefix_end) {
                            *reason = "try_item 覆盖 this/super 初始化完成前的构造器前缀";
                            return std::nullopt;
                        }
                    }

                    if (prefix_end >= code_item.insns_size) {
                        *reason = "原构造器没有空间在初始化调用后放置 return-void";
                        return std::nullopt;
                    }
                    return StubProgram{
                        StubKind::kConstructorPrefixReturnVoid, {kReturnVoid}, {}, prefix_end};
                }
            }
        }
        dex_pc += width;
    }

    *reason = "没有找到以 p0 为 receiver 的 this/super <init> 调用";
    return std::nullopt;
}

bool PlanStubPlacement(const CodeItemLayout& code_item, StubProgram* stub, std::string* reason) {
    if (stub == nullptr || reason == nullptr) {
        throw Error("PlanStubPlacement 的 stub/reason 不能为空");
    }
    stub->write_dex_pcs.clear();
    if (stub->code_units.empty()) {
        *reason = "Hollow stub 不能为空";
        return false;
    }
    if (stub->preserved_prefix_code_units > code_item.insns_size ||
        stub->code_units.size() >
            static_cast<std::size_t>(code_item.insns_size - stub->preserved_prefix_code_units)) {
        *reason = "原 code_item 没有足够空间容纳 Hollow stub";
        return false;
    }

    const std::uint32_t terminal_pc = code_item.insns_size - 1U;
    if (stub->kind != StubKind::kReturnWideZero) {
        // void、标量和对象桩的每条指令都只占一个 code unit，所以连续放在末尾不会制造
        // “operand 被 try/catch 当成指令入口”的问题。
        const std::uint32_t start =
            code_item.insns_size - static_cast<std::uint32_t>(stub->code_units.size());
        stub->write_dex_pcs.reserve(stub->code_units.size());
        for (std::uint32_t index = 0U; index < stub->code_units.size(); ++index) {
            stub->write_dex_pcs.push_back(start + index);
        }
        return true;
    }

    if (stub->code_units.size() != 3U || stub->code_units[0] != kConstWide16V0 ||
        stub->code_units[2] != kReturnWide) {
        throw Error("wide Hollow stub 的内部结构不符合预期");
    }

    // Android 13 MethodVerifier::ScanTryCatchBlocks 要求 try 起点和每个 handler 地址都是
    // opcode 起点。try 终点在 r84 中没有单独报错，但它在 DEX 语义上同样是指令边界，
    // 因此也纳入约束，避免生成只对当前 verifier 实现“碰巧可用”的 DEX。
    std::vector<std::uint32_t> required_opcode_starts;
    required_opcode_starts.reserve(code_item.tries.size() * 2U + code_item.handlers.size() * 2U);
    for (const TryItem& item : code_item.tries) {
        required_opcode_starts.push_back(item.start_addr);
        required_opcode_starts.push_back(item.start_addr + item.insn_count);
    }
    for (const CatchHandler& handler : code_item.handlers) {
        for (const TypeAddressPair& typed : handler.typed_handlers) {
            required_opcode_starts.push_back(typed.address);
        }
        if (handler.has_catch_all) {
            required_opcode_starts.push_back(handler.catch_all_address);
        }
    }
    std::sort(required_opcode_starts.begin(), required_opcode_starts.end());
    required_opcode_starts.erase(
        std::unique(required_opcode_starts.begin(), required_opcode_starts.end()),
        required_opcode_starts.end());

    // return-wide 固定放在最后，确保从方法入口以及任意可达的 nop 路径都不会走出 insns[]。
    // const-wide/16 可以提前：它本身不抛异常，随后只经过 nop，最后仍返回 v0 中的 0。
    // 倒序搜索优先保持原来的“尽量靠近末尾”布局。
    const std::uint32_t latest_setup_pc = terminal_pc - 2U;
    for (std::uint32_t setup_pc = latest_setup_pc;; --setup_pc) {
        const std::uint32_t operand_pc = setup_pc + 1U;
        const bool operand_must_be_opcode = std::binary_search(
            required_opcode_starts.begin(), required_opcode_starts.end(), operand_pc);
        if (!operand_must_be_opcode) {
            stub->write_dex_pcs = {setup_pc, operand_pc, terminal_pc};
            return true;
        }
        if (setup_pc == stub->preserved_prefix_code_units) {
            break;
        }
    }

    *reason = "try/catch 的指令边界占满可用位置，无法安全放置 wide 返回桩";
    return false;
}

void ApplyReturnStub(MutableByteView dex, const CodeItemLayout& code_item,
                     const StubProgram& stub) {
    if (stub.code_units.empty()) {
        throw Error("Hollow stub 不能为空");
    }
    if (stub.code_units.size() > code_item.insns_size) {
        std::ostringstream stream;
        stream << "code_item@0x" << std::hex << code_item.code_off << " 只有 " << std::dec
               << code_item.insns_size << " 个 code unit，放不下 " << stub.code_units.size()
               << " 个 code unit 的返回桩";
        throw Error(stream.str());
    }
    if (stub.preserved_prefix_code_units > code_item.insns_size ||
        stub.code_units.size() >
            static_cast<std::size_t>(code_item.insns_size - stub.preserved_prefix_code_units)) {
        throw Error("Hollow stub 与需要保留的构造器前缀发生重叠");
    }
    if (stub.write_dex_pcs.size() != stub.code_units.size()) {
        throw Error("Hollow stub 尚未完成写入位置规划");
    }

    for (std::uint32_t index = stub.preserved_prefix_code_units; index < code_item.insns_size;
         ++index) {
        dex.WriteU16(code_item.insns_offset + static_cast<std::size_t>(index) * 2U, kNop,
                     "清空 code_item.insns");
    }

    for (std::size_t index = 0U; index < stub.code_units.size(); ++index) {
        const std::uint32_t dex_pc = stub.write_dex_pcs[index];
        if (dex_pc < stub.preserved_prefix_code_units || dex_pc >= code_item.insns_size) {
            throw Error("Hollow stub 的规划写入位置越界或覆盖构造器前缀");
        }
        dex.WriteU16(code_item.insns_offset + static_cast<std::size_t>(dex_pc) * 2U,
                     stub.code_units[index], "写入 Hollow 返回桩");
    }
}

}  // namespace dexhollow13::dex
