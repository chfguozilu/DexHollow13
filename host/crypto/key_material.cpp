#include "dexhollow13/crypto/key_material.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "dexhollow13/base/error.h"

namespace dexhollow13::crypto {

std::vector<std::uint8_t> PatchEmbeddedMasterKey(const std::vector<std::uint8_t>& library,
                                                 const MasterKey& master_key,
                                                 const MasterKey& random_mask) {
    auto first = std::search(library.begin(), library.end(), kEmbeddedKeyTemplate.begin(),
                             kEmbeddedKeyTemplate.end());
    if (first == library.end()) {
        throw Error("Runtime SO 中找不到 embedded key 占位符");
    }
    const auto second =
        std::search(first + static_cast<std::ptrdiff_t>(kEmbeddedKeyTemplate.size()), library.end(),
                    kEmbeddedKeyTemplate.begin(), kEmbeddedKeyTemplate.end());
    if (second != library.end()) {
        throw Error("Runtime SO 中 embedded key 占位符出现多次");
    }

    std::vector<std::uint8_t> patched = library;
    const std::size_t offset = static_cast<std::size_t>(first - library.begin());
    for (std::size_t index = 0U; index < master_key.size(); ++index) {
        patched[offset + index] = random_mask[index];
        patched[offset + master_key.size() + index] =
            static_cast<std::uint8_t>(master_key[index] ^ random_mask[index]);
    }
    return patched;
}

}  // namespace dexhollow13::crypto
