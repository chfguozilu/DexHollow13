cmake_minimum_required(VERSION 3.22)

# Host 加壳器使用 C++17。当前代码会尽量采用容易理解的 C++11 写法；
# C++17 主要用于 std::filesystem，避免自行拼接和规范化跨平台路径。
project(DexHollow13 VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DEXHOLLOW13_BUILD_TESTS "构建 Host 端单元测试" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(DexHollowWarnings)

# zlib 用于 DEX 的 Adler32 checksum，也会用于后续 APK ZIP 处理。
find_package(ZLIB REQUIRED)

# OpenSSL 在 Host 侧负责 DEX 格式要求的 SHA-1，以及通过 RAND_bytes
# 生成每次打包独立的 master key 和 nonce。实际的资源加密由 Monocypher 完成。
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Monocypher 4.0.3 提供 Host 与 Android Runtime 共用的 XChaCha20-Poly1305 和 keyed BLAKE2b。
# 单独建立第三方目标，避免把项目自己的严格 warning 选项施加到 vendored C 源码。
add_library(dexhollow_monocypher STATIC
    vendor/monocypher/src/monocypher.c
)
target_include_directories(dexhollow_monocypher PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/monocypher/src"
)

# libzip 负责 APK 这个 ZIP 容器的增删改。DEX、Manifest 和 Payload 的语义仍由项目实现；
# 使用成熟 ZIP 库可以避免自己重复处理 ZIP64、data descriptor 和 central directory。
find_path(LIBZIP_INCLUDE_DIR zip.h REQUIRED)
find_library(LIBZIP_LIBRARY NAMES zip REQUIRED)
add_library(LibZip::LibZip UNKNOWN IMPORTED)
set_target_properties(LibZip::LibZip PROPERTIES
    IMPORTED_LOCATION "${LIBZIP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBZIP_INCLUDE_DIR}"
)

add_library(dexhollow_host_core STATIC
    common/crypto/resource_crypto.cpp
    common/payload/encrypted_payload.cpp
    host/base/file_io.cpp
    host/apk/zip_archive.cpp
    host/apk/apk_packer.cpp
    host/axml/manifest_editor.cpp
    host/bootstrap/bootstrap_reader.cpp
    host/bootstrap/bootstrap_writer.cpp
    host/crypto/key_material.cpp
    host/crypto/secure_random.cpp
    host/dex/code_item.cpp
    host/dex/dex_file.cpp
    host/dex/dex_integrity.cpp
    host/dex/stub_generator.cpp
    host/dex/dex_transformer.cpp
    host/payload/payload_reader.cpp
    host/payload/payload_writer.cpp
)

target_include_directories(dexhollow_host_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(dexhollow_host_core
    PUBLIC
        OpenSSL::Crypto
        LibZip::LibZip
        ZLIB::ZLIB
    PRIVATE
        dexhollow_monocypher
)

dexhollow_enable_warnings(dexhollow_host_core)

add_executable(dex-hollow host/cli/main.cpp)
target_link_libraries(dex-hollow PRIVATE dexhollow_host_core)
dexhollow_enable_warnings(dex-hollow)

if(DEXHOLLOW13_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests/host)
endif()
