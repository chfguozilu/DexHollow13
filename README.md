<img width="808" height="199" alt="图片" src="https://github.com/user-attachments/assets/fbf14411-a683-4bb8-8b27-0bc713ba522a" /><img width="808" height="199" alt="图片" src="https://github.com/user-attachments/assets/0688c7fb-47fa-4a15-8e4c-e67bab5e9eb1" /># DexHollow13

DexHollow13 是一个面向 Android 13 / ART 的 dex 方法体抽取工具。它接收一个
apk，抽取其中可保护方法的 `code_item`，然后生成一个经过 zipalign 但没有
签名的新 apk

项目的核心规则是：真实方法体不会写回 Hollow dex。ART verifier 始终校验
类型正确的默认返回桩；真实 `code_item` 在 `ClassLinker::LoadMethod` 命中时才从
加密 Payload 中单独解密，并只会被交给当前进程中的 `ArtMethod`

## 功能

- 直接处理 base apk，支持一个或多个 `classes*.dex`
- 自动保存原 `Application` 和 `AppComponentFactory`，启动时正确交还控制权
- 生成可通过 verifier 的 Hollow dex，保留 try/catch、switch 和 array-data 等完整
  CodeItem 结构
- bootstrap 和 Hollow dex 整体使用 XChaCha20-Poly1305 认证加密
- Payload 使用逐方法认证加密，未加载的方法保持密文
- 每次打包生成独立的随机密钥、nonce 和资源文件名
- 支持 `arm64-v8a` 和 `armeabi-v7a`，不会擅自改变原 apk 的 Native ABI 选择
- 壳使用私有命名的 ShadowHook，可与业务 apk 自带的 ShadowHook 共存
- 输出始终未签名，签名由使用者自己的发布流程完成

## 支持范围

| 项目          | 当前支持                                                     |
| ------------- | ------------------------------------------------------------ |
| Android       | Android 13 / API 33                                          |
| AOSP 参考版本 | `android-13.0.0_r84`                                         |
| CPU           | ARM64、ARM32                                                 |
| apk           | 单个 base apk，可含多 dex                                    |
| 启动组件      | 默认/自定义 Application，常见 AppComponentFactory            |
| 方法          | direct、virtual、static、instance、`<clinit>` 和常见构造方法 |

暂不支持 split apk/apkS/Xapk、CompactDex 输入、x86/x86_64，也不承诺兼容任意
厂商修改过的 Android 13 ART。`ArtMethod` 字段偏移、`DexFile` 布局和
`ClassLinker::LoadMethod` 符号都是 ART 私有 ABI，换 Android 版本时必须重新核对

## 构建

### 依赖

- C++17 编译器
- JDK
- Android SDK 33
- Android Build Tools 33.0.2
- Android NDK 25.2.9519653
- CMake 4.0.2 或更高版本
- Ninja
- libzip、zlib 和 OpenSSL 开发包

ShadowHook 和 Monocypher 的固定版本已放在 `vendor/`，不需要另外下载

先设置本机 Android SDK 路径：

```bash
export ANDROID_SDK_ROOT=/path/to/Android/Sdk
```

然后必须要保证 shell 脚本有执行的权限才能开始构建：

```bash
cd DexHollow13
find . -name "*.sh" | xargs chmod a+x
./tools/build_release.sh
```

如果本机版本不同，可以用环境变量覆盖，不需要改 CMake 或脚本：

```bash
export dexHOLLOW_BUILD_TOOLS=33.0.2
export dexHOLLOW_NDK_VERSION=25.2.9519653
export dexHOLLOW_CMAKE_BIN=/path/to/cmake
export dexHOLLOW_ZIPALIGN=/path/to/zipalign
```

构建成功后得到：

```text
dist/
├── dex-hollow
└── runtime/
    ├── classes.dex
    └── lib/
        ├── arm64-v8a/
        └── armeabi-v7a/
```

## 使用

```bash
cd /path/to/apk-directory
/path/to/DexHollow13/dist/dex-hollow your-app.apk
```

当前目录会生成：

```text
app-protected-unsigned-your-app.apk
```

输出已经做过 zipalign，但故意没有签名。正式发布时使用自己的密钥：

```bash
apksigner sign --ks your-release.jks app-protected-unsigned-your-app.apk
```

## apk 中会出现什么

```text
classes.dex                         Java Loader
assets/.d13/0.dat                   加密启动索引，固定名称
assets/.d13/r/<32位随机名>.dat      加密 Hollow dex 或加密 Payload
lib/<abi>/libdexhollow13_shell.so   Native Runtime
lib/<abi>/libdexhollow13_shadowhook.so
lib/<abi>/libdexhollow13_shadowhook_nothing.so
```

dex 和 Payload 使用同一目录、同一 `.dat` 后缀，文件名每次打包都会改变。
固定的 `0.dat` 是 Loader 找到其他随机资源前必须知道的入口。这种命名只是让
解压结果不那么显眼，不是安全边界

## 运行过程概览

```text
ShellComponentFactory 被 Android Framework 创建
    ↓
解密启动索引，找到全部 dex/Payload 资源
    ↓
解密 Hollow dex，映射后立即删除临时明文文件
    ↓
认证 Payload 元数据，建立 method_idx 索引
    ↓
安装 ClassLinker::LoadMethod Hook
    ↓
InMemoryDexClassLoader 打开所有 Hollow dex
    ↓
某个受保护方法被加载时，只解密它自己的 code_item
```

详细时序见 [架构说明](docs/architecture.md)

## 测试

Host 单元测试：

```bash
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

连接 Android 13 测试机后执行完整 ARM64/ARM32 回归：

```bash
export ANDROID_SDK_ROOT=/path/to/Android/Sdk
./tools/test_android_fixture.sh
```

详细覆盖范围和故障定位见 [测试说明](docs/testing.md)

## 项目目录

```text
host/              电脑端 apk/dex 处理器
common/            Host 和 Android Runtime 共用的格式与加密实现
include/           C++ 公共接口
runtime/loader/    进入 apk 根 classes.dex 的 Java Loader
runtime/native/    Android 13 ART 适配和 Shadow CodeItem 实现
tests/             Host 单元测试和 Android fixture
tools/             构建、发布和真机回归脚本
vendor/            固定版本的第三方源码与许可证
docs/              项目文档
```

## 文档

- [架构与启动流程](docs/architecture.md)
- [内部文件格式](docs/file-formats.md)
- [安全边界](docs/security.md)
- [测试与故障定位](docs/testing.md)
- [第三方依赖](vendor/README.md)

## 需要知道的限制

- 无法安全生成默认返回桩的极短方法或特殊构造器会保留原实现，CLI 会
  明确统计，不会把它们假装成已保护
- 已解密的 Shadow CodeItem 必须保留到进程结束，因为 `ArtMethod::data_` 保存的
  是原始指针
- 离线客户端必须同时携带解密能力。静态资源加密可以增加提取成本，但无法
  阻止具有 root/进程内存读取能力的对手 dump 正在运行的明文
- 加密数据难以被 zip 再压缩，加上 Hollow dex 和 Payload 同时存在，产物体积会
  明显大于输入 apk

这些限制和当前的密钥方案在 [安全边界](docs/security.md) 中有更完整说明

## 示例：

先把项目拉到本地

<img width="808" height="199" alt="图片" src="https://github.com/user-attachments/assets/a4cbbfd7-14e7-40f8-96d3-d1e8d6592239" />

然后进入目录，设置ANDROID_SDK_ROOT，因为Sdk中有这些默认版本的工具链，所以没有设置额外的环境变量，如果遇到报错，那么按照前面去设置一下就行了

<img width="965" height="527" alt="图片" src="https://github.com/user-attachments/assets/c668344f-221b-4876-aae8-56cfc6944871" />

编译完成之后就可以开始给 app 加壳了

<img width="933" height="205" alt="图片" src="https://github.com/user-attachments/assets/a334900d-5115-4ca4-8e4b-7cdb913ea4ea" />

<img width="980" height="672" alt="图片" src="https://github.com/user-attachments/assets/8a07412a-b5e0-47cd-acbc-e2d69b8a4682" />

