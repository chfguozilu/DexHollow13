#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "dexhollow13/base/byte_view.h"

namespace dexhollow13::dex {

struct TryItem {
    std::uint32_t start_addr = 0U;
    std::uint16_t insn_count = 0U;
    std::uint16_t handler_off = 0U;
};

struct TypeAddressPair {
    std::uint32_t type_idx = 0U;
    std::uint32_t address = 0U;
};

struct CatchHandler {
    // handler_off 是相对于 encoded_catch_handler_list 起点的字节偏移，
    // try_item.handler_off 正是使用这个坐标系。
    std::uint32_t handler_off = 0U;
    std::vector<TypeAddressPair> typed_handlers;
    bool has_catch_all = false;
    std::uint32_t catch_all_address = 0U;
};

struct CodeItemLayout {
    std::uint32_t code_off = 0U;
    std::uint16_t registers_size = 0U;
    std::uint16_t ins_size = 0U;
    std::uint16_t outs_size = 0U;
    std::uint16_t tries_size = 0U;
    std::uint32_t debug_info_off = 0U;
    std::uint32_t insns_size = 0U;

    std::size_t insns_offset = 0U;
    std::size_t tries_offset = 0U;
    std::size_t handlers_offset = 0U;
    std::size_t total_size = 0U;

    std::vector<TryItem> tries;
    std::vector<CatchHandler> handlers;
};

// 解析 StandardDexFile::CodeItem，并返回整个 item 的精确字节长度。
// type_ids_size 用于验证 catch handler 引用的异常类型。
CodeItemLayout ParseCodeItem(const ByteView& dex, std::uint32_t code_off,
                             std::uint32_t type_ids_size);

}  // namespace dexhollow13::dex
