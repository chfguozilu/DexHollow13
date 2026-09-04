#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dexhollow13/base/byte_view.h"
#include "dexhollow13/dex/dex_integrity.h"

namespace dexhollow13::bootstrap {

constexpr std::array<std::uint8_t, 8U> kBootstrapMagic{{
    'D',
    'H',
    '1',
    '3',
    'B',
    'O',
    'O',
    'T',
}};
constexpr std::uint32_t kBootstrapVersion = 1U;
constexpr std::size_t kBootstrapHeaderSize = 48U;
constexpr std::size_t kDexRecordHeaderSize = 64U;

struct DexRecord {
    std::uint32_t ordinal = 0U;
    std::uint32_t protected_method_count = 0U;
    std::string hollow_dex_asset;
    std::string payload_asset;
    dex::Sha1Digest original_dex_signature{};
    dex::Sha1Digest hollow_dex_signature{};
};

struct BootstrapFile {
    std::string package_name;
    std::string original_application;
    std::string original_app_component_factory;
    std::vector<DexRecord> dex_files;
};

std::vector<std::uint8_t> WriteBootstrap(const BootstrapFile& bootstrap);
BootstrapFile ReadBootstrap(const ByteView& bytes);

}  // namespace dexhollow13::bootstrap
