# 01：构建与测试环境

## 1. 开发环境

```text
设备：Xiaomi Mi 8（dipper）
Android：13 / API 33
构建类型：userdebug/test-keys
ABI：arm64-v8a, armeabi-v7a, armeabi
root：Magisk，仅用于开发调试
```

当前 fingerprint 在每次刷机后都应重新记录，因为 LineageOS 对 ART 的补丁和编译选项
可能改变 Native 函数布局，所以不能仅根据“都是 Android 13”就使用硬编码绝对地址

## 2. AOSP 参考基线

参考仓库：

```text
https://cs.android.com/android/platform/superproject/+/android-13.0.0_r84:art/
```

Runtime 的结构推导和源码说明必须引用这个版本。LineageOS 真机二进制可能带有额外补丁，
所以实现还需要通过符号解析、特征匹配和运行时不变量校验确认实际布局

## 3. 本机工具

项目优先使用以下固定版本：

```text
compileSdk：33
build-tools：33.0.2
NDK：25.2.9519653
CMake：系统 CMake >= 4.0.2（Host 与 Android Native）
Ninja：SDK CMake 3.22.1 目录中附带的 Ninja
```

即使系统安装了更新版本，构建脚本也不应悄悄切换 NDK，因为不同 NDK 可能改变链接结果、
默认 STL 配置和可用 API

Native 阶段使用较新的系统 CMake，是因为固定的 ShadowHook v2.0.1 上游源码声明了
`cmake_minimum_required(VERSION 4.0.2)`。Android 交叉编译仍使用 NDK r25c 的 toolchain 文件，
构建后端仍是 SDK 中的 Ninja；换 CMake 前端不等于换 NDK

## 4. Host 依赖

Debian/Ubuntu 上至少需要：

```text
g++ 或 clang++
libzip-dev
zlib1g-dev
libssl-dev
JDK（提供 javac、jar 和 keytool）
```

libzip 只处理 APK 的 ZIP 容器；DEX、Binary XML、Payload 和 bootstrap 语义均由本项目解析。
OpenSSL 在 Host 侧计算 DEX Header 规定的 SHA-1 signature，zlib 计算 Adler32 checksum 和
Payload CRC32。这里使用 SHA-1 是遵守 DEX 格式，而不是把 SHA-1 当作安全哈希方案

## 5. 构建入口

```bash
export ANDROID_SDK_ROOT=/home/ignite/Software/Android/Sdk
./tools/build_release.sh
```

`build_runtime.sh` 会删除并重建项目内的 `out/runtime` 和两个 Native 构建目录；
`build_release.sh` 随后重建 Host，并把运行所需文件汇总到 `dist/`。这些脚本不写
`Project2` 之外的路径
