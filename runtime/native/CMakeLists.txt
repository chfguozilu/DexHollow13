cmake_minimum_required(VERSION 4.0.2)
project(DexHollow13Runtime LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(DEXHOLLOW_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# Host 与 Runtime 必须使用完全相同的 AEAD 实现和字节格式。Monocypher 是独立的 vendored C
# 目标，不使用 DexHollow13 或 ShadowHook 的告警/编译定义。
add_library(dexhollow_monocypher STATIC
    "${DEXHOLLOW_ROOT}/vendor/monocypher/src/monocypher.c"
)
target_include_directories(dexhollow_monocypher PUBLIC
    "${DEXHOLLOW_ROOT}/vendor/monocypher/src"
)

# ShadowHook v2.0.1 以源码方式固定在 vendor 中。使用它自己的 CMakeLists 构建，
# 单独指定 binary dir，避免其产物和 DexHollow13 对象文件混在一起。
set(SHADOWHOOK_ROOT "${DEXHOLLOW_ROOT}/vendor/shadowhook/shadowhook/src/main/cpp")
add_subdirectory("${SHADOWHOOK_ROOT}" "${CMAKE_BINARY_DIR}/vendor/shadowhook" EXCLUDE_FROM_ALL)

# 不能沿用上游的 libshadowhook.so 名称：被保护的业务 APK 可能已经使用另一个版本的
# ShadowHook。这里同时改变实际文件名和 ELF SONAME，使 linker 能把两套库明确区分开。
set_target_properties(shadowhook PROPERTIES OUTPUT_NAME "dexhollow13_shadowhook")
set_target_properties(shadowhook_nothing PROPERTIES OUTPUT_NAME "dexhollow13_shadowhook_nothing")

# ShadowHook 会按名字定位自身，并主动 dlopen 极小的 nothing 辅助库。只改 OUTPUT_NAME 会让
# 这两次内部查找仍指向业务 APK 的 libshadowhook*.so，因此还要同步覆盖内部名称常量。
target_compile_definitions(shadowhook PRIVATE
    SH_LINKER_SHADOWHOOK_BASE_NAME="libdexhollow13_shadowhook.so"
    SH_LINKER_SHADOWHOOK_NOTHING_BASE_NAME="libdexhollow13_shadowhook_nothing.so"
    # 两份独立 ShadowHook 即使文件名不同，也会各自把 ART ELF 内未使用的代码间隙当作
    # branch island。业务 App 稍后初始化自己的 ShadowHook 时，无法看见本实例的分配表，
    # 可能覆盖本壳的 island，最终让 LoadMethod 跳进 BRK。这里对唯一且足够长的 ART
    # LoadMethod 使用无 island 的绝对跳转，从根源上消除跨实例的 ELF-gap 所有权冲突。
    DEXHOLLOW13_SHADOWHOOK_WITHOUT_ISLAND=1
)

# v2.0.1 上游使用 -Weverything -Werror。NDK r25c/Clang 14 会额外启用这条针对 C90 的
# 诊断，但 ShadowHook 已明确要求 C11，语句之后声明变量在 C11 中完全合法。这里只在集成层
# 关闭该误报，不改动对应业务逻辑，也不放宽 DexHollow13 自己的警告设置。
target_compile_options(shadowhook PRIVATE
    -Wno-declaration-after-statement
    # linux-syscall-support 是 ShadowHook 内嵌的 Google 第三方头文件，其中双下划线名称
    # 是有意为之；Clang 14 的 -Weverything 会把它们视为保留标识符。
    -Wno-reserved-identifier
    # v2.0.1 为更新 Android 版本预留了架构宏；在 API 33 构建中个别宏不会被引用。
    -Wno-unused-macros
)

add_library(dexhollow SHARED
    "${DEXHOLLOW_ROOT}/common/crypto/resource_crypto.cpp"
    "${DEXHOLLOW_ROOT}/common/payload/encrypted_payload.cpp"
    src/art_hook_engine.cpp
    src/jni_bridge.cpp
    src/key_material.cpp
    src/resource_decryptor.cpp
)

# target 名称继续使用 dexhollow，减少 CMake 内部改动；OUTPUT_NAME 决定最终文件名和 SONAME。
set_target_properties(dexhollow PROPERTIES OUTPUT_NAME "dexhollow13_shell")

# ShadowHook 初始化时会 dlopen(libdexhollow13_shadowhook_nothing.so)，借助这个极小的辅助
# ELF 探测 Android linker 的 soinfo 布局。它不是链接依赖，因此必须显式建立构建依赖。
add_dependencies(dexhollow shadowhook_nothing)

target_include_directories(dexhollow PRIVATE
    "${DEXHOLLOW_ROOT}/include"
    "${SHADOWHOOK_ROOT}/include"
)

# log 是 Android logcat 接口；z 用于复用 Host/Runtime 一致的 Payload CRC32 校验。
find_library(ANDROID_LOG_LIBRARY log REQUIRED)
find_library(ANDROID_Z_LIBRARY z REQUIRED)
target_link_libraries(dexhollow PRIVATE
    dexhollow_monocypher
    shadowhook
    ${ANDROID_LOG_LIBRARY}
    ${ANDROID_Z_LIBRARY}
)

target_compile_options(dexhollow PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
)
