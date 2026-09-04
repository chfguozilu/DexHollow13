#include "dexhollow13/dex/code_item.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <sstream>
#include <unordered_set>

#include "dexhollow13/base/error.h"
#include "dexhollow13/dex/leb128.h"

namespace dexhollow13::dex {
namespace {

constexpr std::size_t kCodeItemHeaderSize = 16U;
constexpr std::size_t kTryItemSize = 8U;

std::string CodeLabel(std::uint32_t code_off, const std::string& field) {
    std::ostringstream stream;
    stream << "code_item@0x" << std::hex << code_off << "." << field;
    return stream.str();
}

}  // namespace

CodeItemLayout ParseCodeItem(const ByteView& dex, std::uint32_t code_off,
                             std::uint32_t type_ids_size) {
    if ((code_off & 3U) != 0U) {
        throw Error(CodeLabel(code_off, "offset") + " 没有按 4 字节对齐");
    }
    dex.CheckRange(code_off, kCodeItemHeaderSize, CodeLabel(code_off, "header"));

    CodeItemLayout layout;
    layout.code_off = code_off;
    layout.registers_size = dex.ReadU16(code_off, CodeLabel(code_off, "registers_size"));
    layout.ins_size =
        dex.ReadU16(static_cast<std::size_t>(code_off) + 2U, CodeLabel(code_off, "ins_size"));
    layout.outs_size =
        dex.ReadU16(static_cast<std::size_t>(code_off) + 4U, CodeLabel(code_off, "outs_size"));
    layout.tries_size =
        dex.ReadU16(static_cast<std::size_t>(code_off) + 6U, CodeLabel(code_off, "tries_size"));
    layout.debug_info_off =
        dex.ReadU32(static_cast<std::size_t>(code_off) + 8U, CodeLabel(code_off, "debug_info_off"));
    layout.insns_size =
        dex.ReadU32(static_cast<std::size_t>(code_off) + 12U, CodeLabel(code_off, "insns_size"));

    layout.insns_offset = static_cast<std::size_t>(code_off) + kCodeItemHeaderSize;
    const std::size_t instruction_bytes = CheckedMultiply(
        static_cast<std::size_t>(layout.insns_size), 2U, CodeLabel(code_off, "insns byte size"));
    dex.CheckRange(layout.insns_offset, instruction_bytes, CodeLabel(code_off, "insns"));

    std::size_t cursor = layout.insns_offset + instruction_bytes;
    if (layout.tries_size == 0U) {
        // 没有 try_item 时，code_item 在 insns[] 最后一个 code unit 后立即结束，
        // 即使 insns_size 是奇数也没有 padding。
        layout.total_size = cursor - code_off;
        return layout;
    }

    // try_item 要求 4 字节对齐。insns 是 uint16_t 数组，因此仅在 code unit 数为奇数时
    // 需要额外跳过一个 uint16_t padding。
    if ((layout.insns_size & 1U) != 0U) {
        const std::uint16_t padding = dex.ReadU16(cursor, CodeLabel(code_off, "padding"));
        if (padding != 0U) {
            throw Error(CodeLabel(code_off, "padding") + " 应为 0");
        }
        cursor += 2U;
    }

    layout.tries_offset = cursor;
    const std::size_t tries_bytes = CheckedMultiply(static_cast<std::size_t>(layout.tries_size),
                                                    kTryItemSize, CodeLabel(code_off, "tries"));
    dex.CheckRange(layout.tries_offset, tries_bytes, CodeLabel(code_off, "try_item array"));

    layout.tries.reserve(layout.tries_size);
    for (std::uint32_t index = 0U; index < layout.tries_size; ++index) {
        const std::size_t try_offset =
            layout.tries_offset + static_cast<std::size_t>(index) * kTryItemSize;
        TryItem item;
        item.start_addr = dex.ReadU32(try_offset, CodeLabel(code_off, "try_item.start_addr"));
        item.insn_count = dex.ReadU16(try_offset + 4U, CodeLabel(code_off, "try_item.insn_count"));
        item.handler_off =
            dex.ReadU16(try_offset + 6U, CodeLabel(code_off, "try_item.handler_off"));

        if (item.insn_count == 0U || item.start_addr >= layout.insns_size ||
            static_cast<std::uint64_t>(item.start_addr) + item.insn_count > layout.insns_size) {
            throw Error(CodeLabel(code_off, "try_item") + " 的指令范围越界或为空");
        }
        layout.tries.push_back(item);
    }

    cursor += tries_bytes;
    layout.handlers_offset = cursor;
    const auto handler_count = ReadUleb128(dex, cursor, CodeLabel(code_off, "handlers_size"));
    cursor = handler_count.next_offset;
    if (handler_count.value == 0U) {
        throw Error(CodeLabel(code_off, "handlers_size") + " 在 tries_size 非 0 时不能为 0");
    }

    layout.handlers.reserve(handler_count.value);
    std::unordered_set<std::uint32_t> valid_handler_offsets;

    for (std::uint32_t handler_index = 0U; handler_index < handler_count.value; ++handler_index) {
        const std::size_t relative_offset = cursor - layout.handlers_offset;
        if (relative_offset > std::numeric_limits<std::uint16_t>::max()) {
            throw Error(CodeLabel(code_off, "encoded_catch_handler") +
                        " 相对偏移超过 try_item.handler_off 的 uint16_t 范围");
        }

        CatchHandler handler;
        handler.handler_off = static_cast<std::uint32_t>(relative_offset);
        valid_handler_offsets.insert(handler.handler_off);

        const auto signed_size = ReadSleb128(dex, cursor, CodeLabel(code_off, "handler.size"));
        cursor = signed_size.next_offset;
        const std::int64_t signed_count = signed_size.value;
        const std::uint64_t typed_count =
            static_cast<std::uint64_t>(signed_count < 0 ? -signed_count : signed_count);

        // 每个 typed handler 至少需要两个 ULEB128 字节。这个上界能在进入循环前阻止
        // 恶意 count 让解析器执行几十亿次，即便最终每次读取都会做边界检查。
        if (typed_count > dex.size() / 2U) {
            throw Error(CodeLabel(code_off, "handler.size") + " 声明了不可能容纳的处理器数量");
        }

        handler.typed_handlers.reserve(static_cast<std::size_t>(typed_count));
        for (std::uint64_t pair_index = 0U; pair_index < typed_count; ++pair_index) {
            const auto type = ReadUleb128(dex, cursor, CodeLabel(code_off, "handler.type_idx"));
            cursor = type.next_offset;
            const auto address = ReadUleb128(dex, cursor, CodeLabel(code_off, "handler.address"));
            cursor = address.next_offset;

            if (type.value >= type_ids_size) {
                throw Error(CodeLabel(code_off, "handler.type_idx") + " 越界");
            }
            if (address.value >= layout.insns_size) {
                throw Error(CodeLabel(code_off, "handler.address") + " 不指向有效指令");
            }
            handler.typed_handlers.push_back({type.value, address.value});
        }

        if (signed_count <= 0) {
            const auto catch_all = ReadUleb128(dex, cursor, CodeLabel(code_off, "catch_all_addr"));
            cursor = catch_all.next_offset;
            if (catch_all.value >= layout.insns_size) {
                throw Error(CodeLabel(code_off, "catch_all_addr") + " 不指向有效指令");
            }
            handler.has_catch_all = true;
            handler.catch_all_address = catch_all.value;
        }

        layout.handlers.push_back(std::move(handler));
    }

    for (const TryItem& item : layout.tries) {
        if (valid_handler_offsets.find(item.handler_off) == valid_handler_offsets.end()) {
            throw Error(CodeLabel(code_off, "try_item.handler_off") +
                        " 没有指向任何 encoded_catch_handler 的起点");
        }
    }

    layout.total_size = cursor - code_off;
    return layout;
}

}  // namespace dexhollow13::dex
