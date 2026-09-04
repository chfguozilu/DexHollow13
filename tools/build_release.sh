#!/usr/bin/env bash

# 生成可以直接携带和运行的 dist/ 发布目录。
#
# 发布目录布局为：
#   dist/dex-hollow          Host 命令行程序
#   dist/runtime/classes.dex Java Loader
#   dist/runtime/lib/...     ARM64/ARM32 Runtime 与 ShadowHook
#
# 脚本只在 DexHollow13 项目内部写入 build/、out/ 和 dist/。
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
build_dir="$project_dir/build"
dist_dir="$project_dir/dist"
cmake_bin="${DEXHOLLOW_CMAKE_BIN:-$(command -v cmake)}"

# Runtime 构建脚本会同时构建 Loader DEX 和两个 ABI 的 Native 库。
"$script_dir/build_runtime.sh"

# Host 使用本机编译器和系统库构建。RelWithDebInfo 既启用优化，也保留足够的调试信息。
"$cmake_bin" \
    -S "$project_dir" \
    -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DDEXHOLLOW13_BUILD_TESTS=ON
"$cmake_bin" --build "$build_dir" --parallel
ctest --test-dir "$build_dir" --output-on-failure

# 只重建本项目管理的可执行文件和 runtime/。使用者经常会把待处理 APK 放在 dist/
# 旁边直接运行命令；不能为了刷新发布产物而删除这些不属于构建系统的文件。
# runtime/ 仍整体重建，确保已经改名或移除的旧版 SO 不会残留。
mkdir -p "$dist_dir"
"$cmake_bin" -E remove_directory "$dist_dir/runtime"
mkdir -p \
    "$dist_dir/runtime/lib/arm64-v8a" \
    "$dist_dir/runtime/lib/armeabi-v7a"
"$cmake_bin" -E copy "$build_dir/dex-hollow" "$dist_dir/dex-hollow"
"$cmake_bin" -E copy "$project_dir/out/runtime/classes.dex" \
    "$dist_dir/runtime/classes.dex"

for abi in arm64-v8a armeabi-v7a; do
    for library in \
        libdexhollow13_shell.so \
        libdexhollow13_shadowhook.so \
        libdexhollow13_shadowhook_nothing.so; do
        "$cmake_bin" -E copy \
            "$project_dir/out/runtime/lib/$abi/$library" \
            "$dist_dir/runtime/lib/$abi/$library"
    done
done

printf 'DexHollow13 release:\n'
printf '  %s\n' "$dist_dir/dex-hollow"
printf '  %s\n' "$dist_dir/runtime"
