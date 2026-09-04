#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/dex/code_item.h"

namespace dexhollow13::dex {

class DexFile;

enum class StubKind : std::uint32_t {
    kReturnVoid = 1U,
    kReturnScalarZero = 2U,
    kReturnObjectNull = 3U,
    kReturnWideZero = 4U,
    kConstructorPrefixReturnVoid = 5U,
};

struct StubProgram {
    StubKind kind = StubKind::kReturnVoid;
    std::vector<std::uint16_t> code_units;
    // code_units 是桩所需的逻辑 code unit；write_dex_pcs 则说明每个 code unit 最终写到
    // insns[] 的哪个下标。多数桩连续放在末尾；wide 桩可能把 const-wide/16 提前，避免
    // 它的立即数 operand 恰好占用 try/catch 表要求必须是 opcode 起点的位置。
    std::vector<std::uint32_t> write_dex_pcs;
    // 普通方法为 0。构造函数必须保留完成 uninitialized-this 初始化所需的前缀；
    // ApplyReturnStub 只会从这个位置之后开始写 nop。
    std::uint32_t preserved_prefix_code_units = 0U;
};

// 根据方法返回描述符生成最短默认返回桩。
// 注意：构造方法还需要满足 uninitialized-this 规则，不能仅调用这个函数后直接覆盖。
StubProgram BuildReturnStub(const std::string& return_descriptor);

// 尝试为构造函数构建 verifier-safe Hollow 桩。当前允许 this/super <init> 前的 if/goto，
// 但会证明每个目标都落在已扫描的初始化前缀内；try_item 也不能覆盖该前缀。不支持时返回
// nullopt，并把可读原因写入 reason。初始化后的构造器主体可以正常包含 try/catch。
std::optional<StubProgram> BuildConstructorStub(const DexFile& dex_file,
                                                const CodeItemLayout& code_item,
                                                std::string* reason);

// 根据具体 code_item 为桩选择写入位置。必须在 ApplyReturnStub 之前调用。
//
// 这个步骤不能只做“桩长度 <= insns_size”的判断：const-wide/16 占两个 code unit，第二个
// code unit 是 operand，不是新指令。如果 try_item.start_addr 或 catch handler 地址正好指向
// 该 operand，Android 13 verifier 会以“starts inside an instruction”拒绝整个类。函数会让
// 所有 try 边界和 handler 入口继续落在 opcode 起点；找不到合法布局时返回 false。
bool PlanStubPlacement(const CodeItemLayout& code_item, StubProgram* stub, std::string* reason);

// 先把整个 insns[] 改为 nop，再把返回桩放在末尾。放在末尾的原因是：
// 原 code_item 的 catch handler 入口可能指向 insns 中间；从任意 handler 入口继续执行
// nop 都会最终到达同一个合法返回，而不会从数组末尾 fall-through。
void ApplyReturnStub(MutableByteView dex, const CodeItemLayout& code_item, const StubProgram& stub);

}  // namespace dexhollow13::dex
