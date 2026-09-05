# 第三方依赖

`vendor/` 专门放项目随仓库固定的第三方源码。ShadowHook 和 Monocypher 是两个
平级依赖，它们没有互相包含：

```text
vendor/
├── monocypher/
└── shadowhook/
```

## 依赖清单

| 库 | 版本 | 用途 |
|---|---|---|
| [ShadowHook](https://github.com/bytedance/android-inline-hook) | 2.0.1 | Hook Android 13 `ClassLinker::LoadMethod` |
| [Monocypher](https://monocypher.org/) | 4.0.3 | XChaCha20-Poly1305、keyed BLAKE2b、敏感数据擦除 |

Host 还使用系统开发包：

| 库 | 用途 |
|---|---|
| libzip | 读写 APK ZIP 容器 |
| zlib | DEX Adler32 和 CRC32 |
| OpenSSL Crypto | DEX SHA-1 以及 `RAND_bytes` CSPRNG |

## 为什么把源码放进仓库

Host 和 Android Runtime 必须使用完全相同的密文格式，ART Hook 也对 ShadowHook 版本和
编译选项敏感。固定源码可以避免构建机自动升级依赖后产生不同的二进制行为

ShadowHook 上游仓库中的示例 App、系统测试、Gradle wrapper、文档站和 Git 元数据不参与
DexHollow13 构建，所以没有随项目保留。目前只保留 Native C/C++ 源码、上游 README 和
完整许可证。Monocypher 同样只保留公开单文件实现、README 和许可证

## 项目内的小范围适配

ShadowHook 使用 DexHollow13 专属文件名和 SONAME，避免覆盖业务 APK 自带的
`libshadowhook.so`。集成时还做了两处有限调整：

- `sh_linker.c` 允许通过编译定义覆盖库名和 nothing 辅助库名
- ARM64/ARM32 的目标 Hook 可以禁用 branch island，避免两套独立 ShadowHook 抢占
  `libart.so` 同一代码间隙

