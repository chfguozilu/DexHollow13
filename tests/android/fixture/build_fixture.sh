#!/usr/bin/env bash

# 这个脚本只构建测试 APK，不参与最终 dex-hollow 命令。
# 它直接调用 SDK 工具，避免为了一个很小的 fixture 引入 Gradle 与插件版本变量。
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "$script_dir/../../.." && pwd)"
sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk_root" ]]; then
    printf '错误：请先设置 ANDROID_SDK_ROOT（或 ANDROID_HOME）为 Android SDK 根目录。\n' >&2
    exit 1
fi
sdk_root="${sdk_root%/}"
build_tools="${DEXHOLLOW_BUILD_TOOLS:-33.0.2}"
ndk_version="${DEXHOLLOW_NDK_VERSION:-25.2.9519653}"
sdk_ninja_version="${DEXHOLLOW_NINJA_CMAKE_VERSION:-3.22.1}"
cmake_bin="${DEXHOLLOW_CMAKE_BIN:-$(command -v cmake)}"
ninja_bin="$sdk_root/cmake/$sdk_ninja_version/bin/ninja"
fixture_name="${DEXHOLLOW_FIXTURE_NAME:-fixture}"
manifest_file="${DEXHOLLOW_FIXTURE_MANIFEST:-$script_dir/AndroidManifest.xml}"
work_dir="$project_dir/out/android-$fixture_name-build"
classes_dir="$work_dir/classes"
secondary_classes_dir="$work_dir/secondary-classes"
main_dex_dir="$work_dir/main-dex"
secondary_dex_dir="$work_dir/secondary-dex"
native_apk_dir="$work_dir/apk-native"
unsigned_apk="$work_dir/$fixture_name-unsigned.apk"
main_jar="$work_dir/fixture-main.jar"
secondary_jar="$work_dir/fixture-secondary.jar"
secondary_source="$script_dir/src/com/example/dexhollowfixture/SecondarySecret.java"

# 每次重建只清理项目 out/ 下这个明确的测试目录，不触碰用户的其他文件。
rm -rf "$work_dir"
mkdir -p "$classes_dir" "$secondary_classes_dir" "$main_dex_dir" "$secondary_dex_dir" \
    "$native_apk_dir/lib/arm64-v8a" "$native_apk_dir/lib/armeabi-v7a"

# 同时构建两个 ABI 的“原应用业务库”。加壳器看到输入已有 Native ABI 后，必须只注入与
# 输入匹配的 Runtime；ARM32 回归还会移除 arm64 目录，强制设备创建 32 位进程。
build_fixture_native() {
    local abi="$1"
    local native_build_dir="$work_dir/native-$abi"
    "$cmake_bin" \
        -S "$script_dir/native" \
        -B "$native_build_dir" \
        -G Ninja \
        -DCMAKE_MAKE_PROGRAM="$ninja_bin" \
        -DCMAKE_TOOLCHAIN_FILE="$sdk_root/ndk/$ndk_version/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" \
        -DANDROID_PLATFORM=android-33 \
        -DANDROID_STL=c++_static \
        -DCMAKE_BUILD_TYPE=Release
    "$cmake_bin" --build "$native_build_dir"
    for library in libfixturebusiness.so libshadowhook.so libshadowhook_nothing.so; do
        "$cmake_bin" -E copy "$native_build_dir/$library" \
            "$native_apk_dir/lib/$abi/$library"
    done
}

build_fixture_native arm64-v8a
build_fixture_native armeabi-v7a

"$sdk_root/build-tools/$build_tools/aapt2" link \
    -I "$sdk_root/platforms/android-33/android.jar" \
    --manifest "$manifest_file" \
    --min-sdk-version 33 \
    --target-sdk-version 33 \
    -o "$unsigned_apk"

# Android API 作为 bootclasspath，项目源码仍按 Java 8 字节码编译，随后由 D8 转成 DEX。
# 先编译将进入 classes2.dex 的类，再把它作为 javac classpath 编译主 DEX。这样 MainActivity
# 保留对 SecondarySecret 的真实类型引用，而不是用反射掩盖跨 DEX 解析问题。
javac -Xlint:-options -source 8 -target 8 \
    -bootclasspath "$sdk_root/platforms/android-33/android.jar" \
    -d "$secondary_classes_dir" \
    "$secondary_source"

mapfile -t java_sources < <(find "$script_dir/src" -type f -name '*.java' \
    ! -path "$secondary_source" -print | sort)
javac -Xlint:-options -source 8 -target 8 \
    -bootclasspath "$sdk_root/platforms/android-33/android.jar" \
    -classpath "$secondary_classes_dir" \
    -d "$classes_dir" \
    "${java_sources[@]}"

# Build Tools 33 的 D8 不把目录当作 program file，因此分别封装主、次两个 JAR。
jar --create --file "$main_jar" -C "$classes_dir" .
jar --create --file "$secondary_jar" -C "$secondary_classes_dir" .

"$sdk_root/build-tools/$build_tools/d8" \
    --lib "$sdk_root/platforms/android-33/android.jar" \
    --lib "$secondary_jar" \
    --min-api 33 \
    --output "$main_dex_dir" \
    "$main_jar"

"$sdk_root/build-tools/$build_tools/d8" \
    --lib "$sdk_root/platforms/android-33/android.jar" \
    --min-api 33 \
    --output "$secondary_dex_dir" \
    "$secondary_jar"

# aapt2 已经创建资源 APK。给第二个 DEX 使用规范根名称 classes2.dex；测试包暂不签名。
cp "$secondary_dex_dir/classes.dex" "$main_dex_dir/classes2.dex"
(cd "$main_dex_dir" && zip -q -j "$unsigned_apk" classes.dex classes2.dex)

# extractNativeLibs=false 要求 SO 在 APK 内保持 Stored；最终的 dex-hollow 还会统一执行
# zipalign，使 linker 可以直接 mmap 这里的业务库和壳 Runtime。
(cd "$native_apk_dir" && zip -q -0 -r "$unsigned_apk" lib)

printf '%s\n' "$unsigned_apk"
