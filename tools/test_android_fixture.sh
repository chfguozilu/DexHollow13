#!/usr/bin/env bash

# DexHollow13 Android 13 端到端回归测试。
#
# 默认依次测试 arm64-v8a 和 armeabi-v7a。所有本机产物都写在项目 out/ 内；设备侧只会
# 创建一个固定名称的临时 UI XML，并在脚本退出时删除。正式 dex-hollow 输出始终未签名，
# 这里使用项目内 debug keystore 只是为了把测试副本安装到开发机。
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk_root" ]]; then
    printf '错误：请先设置 ANDROID_SDK_ROOT（或 ANDROID_HOME）为 Android SDK 根目录。\n' >&2
    exit 1
fi
sdk_root="${sdk_root%/}"
build_tools="${DEXHOLLOW_BUILD_TOOLS:-33.0.2}"
test_abis="${DEXHOLLOW_TEST_ABIS:-both}"
package_name="com.example.dexhollowfixture"
activity_name="$package_name/.MainActivity"
device_xml="/data/local/tmp/dh13-window.xml"
expected_text="answer=42, wide=4886718347, caught=-1, secondary=dex2-ok, object=true, control=111, array=14, native=49, hot=39998"

apksigner="$sdk_root/build-tools/$build_tools/apksigner"
zipalign="$sdk_root/build-tools/$build_tools/zipalign"
keystore="$project_dir/out/test-signing/debug.keystore"
protected_unsigned="$project_dir/app-protected-unsigned-fixture-unsigned.apk"

cleanup_device_temp() {
    # 该路径由本脚本独占，只删除自己创建的测试临时文件。
    adb shell rm -f "$device_xml" >/dev/null 2>&1 || true
}
trap cleanup_device_temp EXIT

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf '缺少命令：%s\n' "$1" >&2
        exit 1
    fi
}

require_tool adb
require_tool cmake
require_tool keytool
require_tool zip
require_tool unzip

if [[ "$test_abis" != "both" && "$test_abis" != "arm64" && "$test_abis" != "arm32" ]]; then
    printf 'DEXHOLLOW_TEST_ABIS 只能是 both、arm64 或 arm32\n' >&2
    exit 1
fi

# Host、Runtime 和双 DEX fixture 全部从源码重建，防止旧 Reader/新 Payload 之类的产物
# 不同步问题形成假失败。
cmake -S "$project_dir" -B "$project_dir/build"
cmake --build "$project_dir/build" -j 4
ctest --test-dir "$project_dir/build" --output-on-failure
ANDROID_SDK_ROOT="$sdk_root" "$project_dir/tools/build_runtime.sh"
ANDROID_SDK_ROOT="$sdk_root" "$project_dir/tests/android/fixture/build_fixture.sh"

(
    cd "$project_dir"
    ANDROID_SDK_ROOT="$sdk_root" \
        "$project_dir/build/dex-hollow" \
        "$project_dir/out/android-fixture-build/fixture-unsigned.apk"
)

# 成品契约检查：Host 输出经过 zipalign，但没有任何可验证 APK 签名。
"$zipalign" -c -p 4 "$protected_unsigned"
if "$apksigner" verify "$protected_unsigned" >/dev/null 2>&1; then
    printf '错误：dex-hollow 输出不应携带有效签名\n' >&2
    exit 1
fi

# APK 内启动索引/Hollow DEX 必须是整体 AEAD 容器，Payload 必须是逐方法
# 密文格式。DEX/Payload 文件名每次打包都随机，因此测试先按命名规则
# 枚举资源，再用 magic 区分两种格式。真正的 tag、错误密钥和篡改拒绝
# 由 Host 单元测试覆盖。
asset_magic() {
    unzip -p "$protected_unsigned" "$1" | \
        { dd bs=1 count=8 2>/dev/null; cat >/dev/null; } | \
        od -An -tx1 | tr -d ' \n'
}
if [[ "$(asset_magic assets/.d13/0.dat)" != "444831335345414c" ]]; then
    printf '错误：APK 中的启动索引不是预期认证密文\n' >&2
    exit 1
fi

mapfile -t opaque_assets < <(
    unzip -Z1 "$protected_unsigned" | \
        sed -n '/^assets\/\.d13\/r\/[0-9a-f]\{32\}\.dat$/p'
)
if [[ "${#opaque_assets[@]}" -ne 4 ]]; then
    printf '错误：双 DEX fixture 应该产生 4 份随机命名的 DEX/Payload 资源\n' >&2
    exit 1
fi
sealed_count=0
payload_count=0
for asset in "${opaque_assets[@]}"; do
    case "$(asset_magic "$asset")" in
        444831335345414c) ((sealed_count += 1)) ;;
        4448313345504159) ((payload_count += 1)) ;;
        *)
            printf '错误：未知的加密资源格式：%s\n' "$asset" >&2
            exit 1
            ;;
    esac
done
if [[ "$sealed_count" -ne 2 || "$payload_count" -ne 2 ]]; then
    printf '错误：APK 中 DexHollow13 静态资源不是预期加密格式\n' >&2
    exit 1
fi

mkdir -p "$project_dir/out/test-signing"
if [[ ! -f "$keystore" ]]; then
    keytool -genkeypair -noprompt \
        -keystore "$keystore" \
        -storepass android \
        -keypass android \
        -alias androiddebugkey \
        -dname "CN=DexHollow13 Test,O=DexHollow13,C=CN" \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000
fi

sign_test_apk() {
    local input="$1"
    local output="$2"
    "$apksigner" sign \
        --ks "$keystore" \
        --ks-pass pass:android \
        --key-pass pass:android \
        --out "$output" \
        "$input"
    "$apksigner" verify "$output"
}

# out/ 是可以随时删除的构建目录，其中的测试证书也会跟着消失。设备上如果还留着上一次
# 回归安装的 fixture，新生成的测试证书就无法用 -r 覆盖旧版本。这里只卸载项目自己
# 固定命名的测试包，不会碰用户正在测试的真实应用；后续各 ABI 用例使用同一把本轮证书，
# 因而仍然可以通过 -r 连续覆盖安装。
adb uninstall "$package_name" >/dev/null 2>&1 || true

run_device_case() {
    local signed_apk="$1"
    local expected_abi="$2"
    local expect_custom_components="$3"

    adb install -r --no-incremental "$signed_apk"
    adb shell am force-stop "$package_name"
    adb logcat -c
    adb shell input keyevent KEYCODE_WAKEUP
    adb shell wm dismiss-keyguard
    adb shell am start -W -n "$activity_name"

    local actual_abi
    actual_abi="$(adb shell dumpsys package "$package_name" | \
        sed -n 's/^[[:space:]]*primaryCpuAbi=//p' | head -n 1 | tr -d '\r')"
    if [[ "$actual_abi" != "$expected_abi" ]]; then
        printf 'ABI 不一致：expected=%s actual=%s\n' "$expected_abi" "$actual_abi" >&2
        exit 1
    fi

    adb shell uiautomator dump "$device_xml" >/dev/null
    local hierarchy
    hierarchy="$(adb exec-out cat "$device_xml" | tr -d '\r')"
    adb shell rm -f "$device_xml"
    if [[ "$hierarchy" != *"$expected_text"* ]]; then
        printf '界面没有出现预期结果：%s\n' "$expected_text" >&2
        exit 1
    fi

    local runtime_log
    runtime_log="$(adb logcat -d -v brief | tr -d '\r')"
    if [[ "$runtime_log" != *"Native Runtime initialized for 2 DEX file(s)"* ||
          "$runtime_log" == *"FATAL EXCEPTION"* ]]; then
        printf 'Runtime 日志不满足成功条件\n%s\n' "$runtime_log" >&2
        exit 1
    fi
    if [[ "$expect_custom_components" == "yes" ]]; then
        if [[ "$runtime_log" != *"FixtureApplication.onCreate"* ||
              "$runtime_log" != *"FixtureComponentFactory.instantiateApplication"* ||
              "$runtime_log" != *"FixtureComponentFactory.instantiateActivity"* ]]; then
            printf '原 Application/AppComponentFactory 委托日志不完整\n%s\n' \
                "$runtime_log" >&2
            exit 1
        fi
    elif [[ "$runtime_log" == *"FixtureApplication.onCreate"* ||
            "$runtime_log" == *"FixtureComponentFactory.instantiateActivity"* ]]; then
        printf '默认启动组件用例不应调用 fixture 自定义组件\n%s\n' "$runtime_log" >&2
        exit 1
    fi

    # code_cache 只留下两份 DEX 密文缓存、两份 Payload 密文缓存和一个跨进程锁文件。
    # Hollow 明文临时文件在 mmap 后已经 unlink，因此 maps 中能看到 deleted 映射，但目录中
    # 不能残留 .plain。这个检查也防止 Loader 被误改回 allocateDirect()。
    local cache_dir="/data/user/0/$package_name/code_cache/dexhollow13"
    local cache_file_count
    cache_file_count="$(adb shell run-as "$package_name" find "$cache_dir" \
        -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d '[:space:]')"
    local process_id
    process_id="$(adb shell pidof "$package_name" | tr -d '\r')"
    local mapped_cache_count
    mapped_cache_count="$(adb shell run-as "$package_name" cat "/proc/$process_id/maps" 2>/dev/null | \
        grep -c '/code_cache/dexhollow13/' || true)"
    local plaintext_file_count
    plaintext_file_count="$(adb shell run-as "$package_name" find "$cache_dir" \
        -maxdepth 1 -type f -name '*.plain' 2>/dev/null | wc -l | tr -d '[:space:]')"
    if (( cache_file_count < 5 || mapped_cache_count < 4 || plaintext_file_count != 0 )); then
        printf '加密 mmap 缓存不满足预期：cache_files=%s mapped=%s plaintext=%s\n' \
            "$cache_file_count" "$mapped_cache_count" "$plaintext_file_count" >&2
        exit 1
    fi
    printf 'PASS: %s，%s\n' "$expected_abi" "$expected_text"
}

if [[ "$test_abis" == "both" || "$test_abis" == "arm64" ]]; then
    arm64_signed="$project_dir/out/test-signing/fixture-protected-arm64-signed.apk"
    sign_test_apk "$protected_unsigned" "$arm64_signed"
    run_device_case "$arm64_signed" "arm64-v8a" "yes"
fi

if [[ "$test_abis" == "both" || "$test_abis" == "arm32" ]]; then
    arm32_unsigned="$project_dir/out/test-signing/fixture-protected-arm32-unsigned.apk"
    arm32_aligned="$project_dir/out/test-signing/fixture-protected-arm32-aligned.apk"
    arm32_signed="$project_dir/out/test-signing/fixture-protected-arm32-signed.apk"

    cp "$protected_unsigned" "$arm32_unsigned"
    # 只修改测试副本。移除 64 位目录后，64 位设备会为该 APK 选择 armeabi-v7a 进程。
    zip -q -d "$arm32_unsigned" 'lib/arm64-v8a/*'
    "$zipalign" -f -p 4 "$arm32_unsigned" "$arm32_aligned"
    sign_test_apk "$arm32_aligned" "$arm32_signed"
    run_device_case "$arm32_signed" "armeabi-v7a" "yes"
fi

# 默认的 android.app.Application 和“未声明 AppComponentFactory”是另一条启动分支。
# 在常规 both/arm64 回归中再构建一份只替换 Manifest 的 fixture，确保 Shell 不依赖
# 输入 APK 一定声明自定义启动类。双 ABI APK 在当前 64 位设备上会自然选择 arm64-v8a。
if [[ "$test_abis" == "both" || "$test_abis" == "arm64" ]]; then
    default_input="$project_dir/out/android-default-fixture-build/default-fixture-unsigned.apk"
    default_unsigned="$project_dir/app-protected-unsigned-default-fixture-unsigned.apk"
    default_signed="$project_dir/out/test-signing/default-fixture-protected-arm64-signed.apk"

    ANDROID_SDK_ROOT="$sdk_root" \
        DEXHOLLOW_FIXTURE_NAME=default-fixture \
        DEXHOLLOW_FIXTURE_MANIFEST="$project_dir/tests/android/fixture/AndroidManifestDefault.xml" \
        "$project_dir/tests/android/fixture/build_fixture.sh"

    default_report="$(
        cd "$project_dir"
        ANDROID_SDK_ROOT="$sdk_root" "$project_dir/build/dex-hollow" "$default_input"
    )"
    printf '%s\n' "$default_report"
    if [[ "$default_report" != *"原 Application：android.app.Application"* ||
          "$default_report" != *"原 AppComponentFactory：<none>"* ]]; then
        printf '默认启动组件的 bootstrap 报告不正确\n' >&2
        exit 1
    fi

    sign_test_apk "$default_unsigned" "$default_signed"
    run_device_case "$default_signed" "arm64-v8a" "no"
fi
