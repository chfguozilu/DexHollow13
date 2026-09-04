#!/usr/bin/env bash

# 构建 APK 中真正需要的七个运行时文件：一个 Loader DEX，以及两个 ABI 各三个 SO。
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
# 不依赖开发机固定目录：优先读取官方推荐的 ANDROID_SDK_ROOT，同时兼容旧项目常用的
# ANDROID_HOME。两者都没有时立即给出明确错误，避免后面只看到某个工具“文件不存在”。
sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk_root" ]]; then
    printf '错误：请先设置 ANDROID_SDK_ROOT（或 ANDROID_HOME）为 Android SDK 根目录。\n' >&2
    exit 1
fi
sdk_root="${sdk_root%/}"
ndk_version="${DEXHOLLOW_NDK_VERSION:-25.2.9519653}"
build_tools="${DEXHOLLOW_BUILD_TOOLS:-33.0.2}"
sdk_ninja_version="${DEXHOLLOW_NINJA_CMAKE_VERSION:-3.22.1}"

ndk_root="$sdk_root/ndk/$ndk_version"
ndk_host_tag="linux-x86_64"
llvm_strip="$ndk_root/toolchains/llvm/prebuilt/$ndk_host_tag/bin/llvm-strip"
# ShadowHook v2.0.1 的上游 CMakeLists 要求 CMake 4.0.2。这里使用 PATH 中的 CMake，
# 仍显式使用 Android SDK 附带的 Ninja 和 NDK toolchain，不会写入项目目录以外的位置。
cmake_bin="${DEXHOLLOW_CMAKE_BIN:-$(command -v cmake)}"
ninja_bin="$sdk_root/cmake/$sdk_ninja_version/bin/ninja"
out_dir="$project_dir/out/runtime"
loader_classes="$out_dir/loader-classes"
loader_jar="$out_dir/loader.jar"
loader_dex_dir="$out_dir/loader-dex"

rm -rf "$out_dir" "$project_dir/build/runtime-arm64-v8a" "$project_dir/build/runtime-armeabi-v7a"
mkdir -p "$loader_classes" "$loader_dex_dir" "$out_dir/lib/arm64-v8a" "$out_dir/lib/armeabi-v7a"

mapfile -t loader_sources < <(find "$project_dir/runtime/loader/src" -type f -name '*.java' -print | sort)
javac -Xlint:-options -source 8 -target 8 \
    -bootclasspath "$sdk_root/platforms/android-33/android.jar" \
    -d "$loader_classes" \
    "${loader_sources[@]}"
jar --create --file "$loader_jar" -C "$loader_classes" .

"$sdk_root/build-tools/$build_tools/d8" \
    --lib "$sdk_root/platforms/android-33/android.jar" \
    --min-api 33 \
    --output "$loader_dex_dir" \
    "$loader_jar"
"$cmake_bin" -E copy "$loader_dex_dir/classes.dex" "$out_dir/classes.dex"

build_native() {
    local abi="$1"
    local build_dir="$project_dir/build/runtime-$abi"
    "$cmake_bin" \
        -S "$project_dir/runtime/native" \
        -B "$build_dir" \
        -G Ninja \
        -DCMAKE_MAKE_PROGRAM="$ninja_bin" \
        -DCMAKE_TOOLCHAIN_FILE="$ndk_root/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" \
        -DANDROID_PLATFORM=android-33 \
        -DANDROID_STL=c++_static \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo
    "$cmake_bin" --build "$build_dir"
    "$cmake_bin" -E copy \
        "$build_dir/libdexhollow13_shell.so" \
        "$out_dir/lib/$abi/libdexhollow13_shell.so"
    "$cmake_bin" -E copy \
        "$build_dir/vendor/shadowhook/libdexhollow13_shadowhook.so" \
        "$out_dir/lib/$abi/libdexhollow13_shadowhook.so"
    "$cmake_bin" -E copy \
        "$build_dir/vendor/shadowhook/libdexhollow13_shadowhook_nothing.so" \
        "$out_dir/lib/$abi/libdexhollow13_shadowhook_nothing.so"

    # build/ 中保留带调试信息的原始 SO，便于 native 崩溃符号化；真正打入 APK 的 out/runtime
    # 副本剥离非运行时符号。--strip-unneeded 不会删除 JNI 和 DT_NEEDED 所需的动态符号。
    "$llvm_strip" --strip-unneeded "$out_dir/lib/$abi/libdexhollow13_shell.so"
    "$llvm_strip" --strip-unneeded "$out_dir/lib/$abi/libdexhollow13_shadowhook.so"
}

build_native arm64-v8a
build_native armeabi-v7a

printf 'Runtime artifacts:\n'
printf '  %s\n' "$out_dir/classes.dex"
printf '  %s\n' "$out_dir/lib/arm64-v8a/libdexhollow13_shell.so"
printf '  %s\n' "$out_dir/lib/arm64-v8a/libdexhollow13_shadowhook.so"
printf '  %s\n' "$out_dir/lib/arm64-v8a/libdexhollow13_shadowhook_nothing.so"
printf '  %s\n' "$out_dir/lib/armeabi-v7a/libdexhollow13_shell.so"
printf '  %s\n' "$out_dir/lib/armeabi-v7a/libdexhollow13_shadowhook.so"
printf '  %s\n' "$out_dir/lib/armeabi-v7a/libdexhollow13_shadowhook_nothing.so"
