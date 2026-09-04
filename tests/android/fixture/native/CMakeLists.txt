cmake_minimum_required(VERSION 3.22)

# 这个库不是 DexHollow13 Runtime，而是模拟“被保护 APK 自己携带的业务 SO”。
# 它让端到端测试能够发现 InMemoryDexClassLoader 丢失 nativeLibraryPath 的回归。
project(DexHollow13FixtureNative LANGUAGES CXX)

add_library(fixture_shadowhook SHARED business_shadowhook.cpp)
set_target_properties(fixture_shadowhook PROPERTIES OUTPUT_NAME "shadowhook")

add_library(fixture_shadowhook_nothing SHARED business_shadowhook_nothing.cpp)
set_target_properties(fixture_shadowhook_nothing PROPERTIES OUTPUT_NAME "shadowhook_nothing")

add_library(fixturebusiness SHARED fixture_business.cpp)
target_link_libraries(fixturebusiness PRIVATE fixture_shadowhook)

# JNI 函数本身只使用最基础的 C++11；关闭编译器扩展可以避免测试代码依赖 NDK 私有语法。
set_target_properties(fixturebusiness fixture_shadowhook fixture_shadowhook_nothing PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

foreach(target fixturebusiness fixture_shadowhook fixture_shadowhook_nothing)
    target_compile_options(${target} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror
    )
endforeach()
