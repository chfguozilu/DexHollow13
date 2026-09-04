# 测试与故障定位

## Host 单元测试

```bash
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

单元测试不需要手机，主要覆盖：

- ULEB128/SLEB128 边界
- dex SHA-1 signature 和 Adler32 checksum
- `code_item` 大小、try/catch 和对齐
- Hollow 桩，包括 wide 返回和 try/catch dex_pc 不能落在指令中间
- Binary XML Manifest 修改
- 启动索引和 Payload 读写
- 资源 AEAD 往返、篡改拒绝和错误类型拒绝
- 逐方法 Payload 解密和元数据 tag
- Runtime so 密钥注入和“so 中不直接出现连续 master key”

## Android 端到端测试

```bash
export ANDROID_SDK_ROOT=/path/to/Android/Sdk
./tools/test_android_fixture.sh
```

脚本会从源码重新构建 Host、Java Loader、ARM64/ARM32 Runtime 和双 dex fixture，
不会复用一份不知道是否过期的二进制文件

它会顺序检查：

1. CLI 输出名称为 `app-protected-unsigned-*.apk`
2. 输出 zipalign 正确，且 `apksigner verify` 明确失败
3. apk 内存在固定 `assets/.d13/0.dat` 入口
4. 双 dex fixture 产生 4 份不重复的 128-bit 随机 `.dat` 名称
5. 启动索引/Hollow dex 使用 `DH13SEAL`，Payload 使用 `DH13EPAY`
6. ARM64 安装、冷启动和业务结果
7. 移除 ARM64 so 后强制使用 ARM32，再次安装和验证
8. 默认 Application/无 AppComponentFactory 分支
9. `code_cache` 只留 `.enc` 密文缓存，不留 `.plain` dex

两种 ABI 都应显示：

```text
answer=42, wide=4886718347, caught=-1, secondary=dex2-ok,
object=true, control=111, array=14, native=49, hot=39998
```

| 字段        | 验证内容                                     |
| ----------- | -------------------------------------------- |
| `answer`    | 实例方法、构造器、if/goto、`/range`、p0 别名 |
| `wide`      | long 参数、wide 寄存器与返回                 |
| `caught`    | try_item 和 encoded catch handler            |
| `secondary` | 第二个 dex 及 identity 匹配                  |
| `object`    | 引用返回                                     |
| `control`   | packed-switch 和 sparse-switch               |
| `array`     | fill-array-data payload                      |
| `native`    | 业务 ClassLoader 加载 apk 自带 so            |
| `hot`       | synchronized 方法和 20,000 次热点调用        |

## 已验证环境

```text
设备：Xiaomi Mi 8 (dipper)
系统：LineageOS Android 13 userdebug/test-keys
ABI：arm64-v8a / armeabi-v7a
AOSP 对照：android-13.0.0_r84
```

userdebug、Magisk 和 root 只用于读日志、内存映射和 tombstone，产生的 apk 运行时不依赖
它们

除 fixture 外，还验证过：

- 5 dex AndroidX apk：54,881 个受保护方法，原 CoreComponentFactory 正常工作
- 21 dex 大型 apk：1,060,481 个受保护方法，完成用户协议、偏好页、主页
  “我的”和“书架”交互；业务自带 ShadowHook 1.1.1 与壳内 2.0.1 共存

## 常见故障定位

```text
打包失败
    ↓
先看 CLI 报告：Manifest、dex 边界、ABI 还是资源冲突

安装失败
    ↓
检查是否已签名、zipalign 是否正确、设备 ABI 是否匹配

最早启动崩溃
    ↓
搜索 logcat DexHollow13：启动索引、dex/Payload 认证、Hook 安装到哪一步

ClassNotFoundException
    ↓
检查 ShellComponentFactory 返回的 ClassLoader 和原 Factory 委托

UnsatisfiedLinkError
    ↓
检查当前 ABI、nativeLibraryDir 和 sourceDir!/lib/<abi> 搜索路径

VerifyError
    ↓
检查 Hollow 桩、构造器 uninitialized-this、try/catch dex_pc 和多 code-unit 指令

SIGSEGV / SIGTRAP / libart
    ↓
核对 Android 13 r84 私有符号、DexFile/ArtMethod 偏移和其他 Hook 框架冲突
```

Runtime 的 Native 构建目录保留 `RelWithDebInfo` 未剥离 so，而 `out/runtime` 和 `dist/runtime`
是用于打包的剥离副本。分析 tombstone 时应使用同 ABI、同次构建的未剥离 so
