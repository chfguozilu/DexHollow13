# DexHollow13

DexHollow13 是一个面向 Android 13 / ART 的 DEX 方法体抽取型保护器。它把原 APK 的
`classes*.dex` 移到 `assets/dexhollow/`，将方法实现替换为可通过 verifier 的桩，再由
应用进程中的 Native Runtime 把 `ArtMethod` 指向 Payload 中的 Shadow CodeItem。

项目的核心约束是：原始指令不会在任何时刻写回 Hollow DEX。

## 1. 支持范围

- Android 13（API 33），源码基线为 `android-13.0.0_r84`。
- `arm64-v8a` 和 `armeabi-v7a`。
- 单个 base APK 内的一个或多个 `classes*.dex`。
- 自定义或默认 `Application`，以及常见的自定义 `AppComponentFactory`。
- direct、virtual、static、instance、`<clinit>` 和常见构造方法。
- 完整保存带 try/catch、switch、array-data 等内容的 Standard DEX `code_item`。
- 输入 APK 可以已有签名；输出固定为 zipalign 后的未签名 APK。

当前不支持 split APK/APKS/XAPK、CompactDex 输入、Android 12/14，以及无条件适配所有
厂商改动过的 Android 13 ART。构造器支持初始化前的 if/goto 和 p0 寄存器搬运；如果分支
可能绕过 `this/super.<init>`、出现 switch，或 try 区间覆盖初始化前缀，则明确报告为
未保护。详见 `docs/05-constructor-stubs.md`。

v1 保留每个 `encoded_method.code_off` 并在原指令区写桩，所以少数只有 1 个 code unit 的
标量/对象返回方法，或不足 3 个 code unit 的 wide 返回方法，物理上放不下“置零+返回”。
这些极短方法保留原实现并计入“有代码但未保护”，不会被静默算作已保护。

## 2. 构建

本机需要 C++ 编译器、JDK、Android SDK 33、Build Tools 33.0.2、NDK r25c、Ninja、
libzip、zlib、OpenSSL，以及能够构建 ShadowHook v2.0.1 的 CMake 4.0.2 或更高版本。

```bash
cd DexHollow13
export ANDROID_SDK_ROOT=/home/ignite/Software/Android/Sdk
./tools/build_release.sh
```

成功后得到自包含目录：

```text
dist/
├── dex-hollow
└── runtime/
    ├── classes.dex
    └── lib/
        ├── arm64-v8a/
        └── armeabi-v7a/
```

`dex-hollow` 会自动从同目录的 `runtime/` 查找 Loader 和 SO。若需要使用另一个 Runtime
目录，可以设置 `DEXHOLLOW_RUNTIME_DIR`。完整环境说明见 `docs/01-build-environment.md`。

发布目录始终携带两套 Runtime；写入 APK 时则遵守输入的 Native ABI：纯 Java/Kotlin APK
写入两套，自带 SO 的 APK 只写入原本已经存在的 `arm64-v8a`/`armeabi-v7a` 套件。这避免
新增 ABI 改变 PackageManager 的进程位数选择。含 x86、x86_64、旧 armeabi 等未支持 SO
的输入会被拒绝，不会生成部分 ABI 可以运行、部分 ABI 启动崩溃的产物。

## 3. 使用

```bash
cd /path/to/apk-directory
/path/to/DexHollow13/dist/dex-hollow your-app.apk
```

成功后，当前目录出现：

```text
app-protected-PhotoGallery.apk
```

该文件已经过 `zipalign`，但没有 APK 签名。之后可由使用者自己的发布流程签名，例如：

```bash
apksigner sign --ks your-release.jks app-protected-your-app.apk
```

命令行会报告原 `Application`、原 `AppComponentFactory`、DEX 数量，并把方法统计分成
“已保护”“原本无 code_item”“有代码但未保护”三组。开发期还保留 `--transform-dex`
单 DEX 诊断入口。

## 4. APK 中的结果

```text
classes.dex                                  只含 Java Loader
assets/dexhollow/bootstrap.bin               原启动类名和 DEX 清单
assets/dexhollow/dex/classes.dex             第一份 Hollow DEX
assets/dexhollow/dex/classes2.dex            第二份 Hollow DEX（如果存在）
assets/dexhollow/payload/payload1.bin         第一份 Payload
assets/dexhollow/payload/payload2.bin         第二份 Payload（如果存在）
lib/arm64-v8a/libdexhollow.so                 ARM64 Runtime
lib/arm64-v8a/libshadowhook.so                ARM64 Hook 引擎
lib/arm64-v8a/libshadowhook_nothing.so        ShadowHook linker 探测辅助库
lib/armeabi-v7a/...                           对应的 ARM32 文件
```

上表展示纯 Java APK 的双 ABI 结果；自带单 ABI SO 的输入只会出现匹配的 Runtime 目录。

原 APK 根目录中的 `classes*.dex` 会被删除，因此初始 `PathClassLoader` 只能找到 Loader。
`ShellComponentFactory` 在 Framework 创建任何业务组件前，构造包含全部 Hollow DEX 的
`InMemoryDexClassLoader`；Native Hook 则在业务类定义之前安装。

## 5. 自动化验证

连接 Android 13 测试机后执行：

```bash
export ANDROID_SDK_ROOT=/home/ignite/Software/Android/Sdk
./tools/test_android_fixture.sh
```

脚本从源码重建 Host、Runtime 和双 DEX fixture，先验证输出未签名且 zipalign 正确，再分别
安装 ARM64 与强制 ARM32 的测试 APK。测试覆盖自定义启动组件、构造器、异常表、两种 switch、
array-data、对象/整数/宽返回值，以及 20,000 次热点调用。测试签名只用于安装测试副本，
不改变“加壳器输出未签名”的契约。

除 fixture 外，项目也已用一个有效签名、5 DEX 的 AndroidX APK 做过真机冷启动：54,881 个
方法进入 Payload/Shadow 索引，原 `CoreComponentFactory` 正常委托，界面成功显示业务结果。

## 6. 代码与文档入口

代码：

```text
host/              电脑端 APK/DEX 变换器
runtime/loader/    APK 根 classes.dex 中的 Java 启动层
runtime/native/    Android 13 ART Shadow CodeItem 引擎
include/           Host 公共结构与接口
tests/             Host 单元测试和 Android 真机 fixture
docs/              从文件格式到 Runtime 时序的教程
third_party/       固定版本的 ShadowHook 及依赖说明
```

文档：

1. `docs/00-project-scope.md`
2. `docs/02-payload-format.md`
3. `docs/03-android13-bootstrap.md`
4. `docs/04-art-shadow-code-item.md`
5. `docs/05-constructor-stubs.md`
6. `docs/06-testing.md`
