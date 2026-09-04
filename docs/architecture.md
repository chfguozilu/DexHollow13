# 架构与启动流程

## 整体分层

DexHollow13 由三部分组成：

| 部分           | 运行位置 | 主要工作                                                     |
| -------------- | -------- | ------------------------------------------------------------ |
| Host Packer    | 电脑     | 解析 apk/dex、生成桩、抽取方法体、加密资源、重组 apk         |
| Java Loader    | apk 进程 | 接管最早启动入口、准备 dex/Payload、创建业务 ClassLoader     |
| Native Runtime | apk 进程 | 认证/解密资源、安装 ART Hook、为 ArtMethod 绑定 Shadow CodeItem |

三层的分工很明确：Host 只产生文件，Loader 只管启动交接，Native Runtime
才处理 ART 私有结构

## Host 处理 apk

```text
读取 AndroidManifest.xml
    ↓
保存原 Application 和 AppComponentFactory
    ↓
枚举根目录 classes.dex、classes2.dex ...
    ↓
解析 class_data_item / encoded_method / code_item
    ↓
可保护方法：保存完整 code_item，原位置改成类型正确的桩
    ↓
重算 dex SHA-1 signature 和 Adler32 checksum
    ↓
加密 Hollow dex、逐方法加密 Payload
    ↓
生成随机 .dat 资源名，写入加密启动索引
    ↓
替换 Manifest 启动类，写入 Loader dex 和 Native so
    ↓
移除旧 apk 签名，zipalign，输出未签名 apk
```

### 为什么有些方法不保护

当前版本保留 `encoded_method.code_off`，因此 Hollow 桩必须放回原 `insns[]` 空间，不能扩
大 `code_item` 并覆盖后续数据。普通方法会将原指令替换为 `nop` 和类型正确的默认返回桩，
例如 `整数返回 0、对象返回 null、void 直接返回`。返回桩放在 `insns[]` 末尾，是为了让入口
和原 `catch handler` 对应的顺序执行路径最终都能到达合法返回点。如果原方法的指令空间、
寄存器数量或 `try/catch` 指令边界无法容纳安全的返回桩，就保留原实现，并计入“有代码但
未保护”

`ART verifier` 不只检查返回值，还会检查完整指令流、寄存器类型、分支目标和异常处理结构。
对于实例构造函数，方法入口的 `p0(this)` 被视为 `uninitialized-this`。只有执行以 p0 或其
别名为 receiver 的合法 `this.<init>` 或 `super.<init>` 调用后，`this` 才会被标记为`已初始化`；
任何尚未初始化就正常 `return-void` 的路径都会导致验证失败。因此当前版本会把完整原构造函数
保存到 Payload，但在 Hollow dex 中保留从入口到初始化调用结束的必要前缀（`super/this`），
只抽空初始化完成后的主体（其余代码）。被调用的、位于业务 dex 中的其他构造函数仍会作为独立方
法继续尝试保护

理论上可以研究对 verifier 输入或结果进行定向干预，从而进一步抽空构造函数前缀，但
不能简单让 verifier 无条件返回成功。完全绕过验证可能让非法寄存器类型、错误控制流
或损坏的异常表进入`解释器/JIT`，影响整个进程的`稳定性`，因此当前版本选择**保守**地保留必
要初始化前缀

## Android 13 启动入口

Android 13 的 `LoadedApk` 大致按下面的顺序工作：

```text
用 apk 根 classes.dex 创建默认 PathClassLoader
    ↓
创建 Manifest 声明的 AppComponentFactory
    ↓
调用 factory.instantiateClassLoader()
    ↓
保存返回的 ClassLoader
    ↓
创建 Application、Provider、Activity 等组件
```

因此壳的最早公开入口是 `ShellComponentFactory.instantiateClassLoader()`。如果等到
`Application.attachBaseContext()` 才准备 dex，原 AppComponentFactory 和某些 Provider 已经太早需要
业务类

## Loader 的实际顺序

1. `NativeBridge` 通过 PathClassLoader 加载 `libdexhollow13_shell.so`
2. 从固定入口 `assets/.d13/0.dat` 读取并解密启动索引
3. 索引给出原 Application、原 AppComponentFactory 和所有随机 `.dat` 资源的对应关系
4. 密文 asset 用 64 KiB 缓冲流式提取到应用私有 `code_cache`，避免占用巨大 Java heap
5. Hollow dex 由 Native 直接从输入 mmap 解密到临时文件。Java 映射后马上
   `unlink`，目录中不留明文 dex
6. Payload 保持密文 mmap。Native 验证整份元数据后建立“dex signature + method_idx”索引
7. 安装 `ClassLinker::LoadMethod` Hook
8. 用 `InMemoryDexClassLoader(ByteBuffer[])` 一次打开全部 Hollow dex
9. 创建原 AppComponentFactory，之后 Application 和四大组件实例化都继续委托给它

Hook 必须在构造 `InMemoryDexClassLoader` 之前安装。大型 apk 中，ART 可能在打开
InMemory dex 期间就开始定义启动类；如果 Hook 晚一步，那些 `ArtMethod` 会永久
保留 Hollow CodeItem 指针

## verifier 和真实方法体为什么不冲突

`ClassAccessor::Method` 是 dex 中 `encoded_method` 的视图，`ArtMethod` 是 ART 建立的运行时
对象。两条路径读的不是同一个指针：

```text
verifier
    └── ClassAccessor::Method.GetCodeItem() -> Hollow dex 默认桩

方法执行
    └── ArtMethod.GetCodeItem() -> ArtMethod.data_ -> Shadow CodeItem
```

Hook 先调用原 `LoadMethod`，等 ART 填好 `ArtMethod`，再核对 Hollow dex signature、
`method_idx` 和原 `code_off` 地址。三者都正确时，才认证并解密该方法的
CodeItem，把 `ArtMethod.data_` 指向新内存

受保护方法会增加 r84 的 `kAccCompileDontBother`，避免 JIT 在后续调用中跳离
Shadow CodeItem 路径。项目不修改 quick entrypoint，解释器/nterp 的选择仍由 ART 自己完成

## Native 库搜索路径

`InMemoryDexClassLoader` 的 Java parent 不会自动拷贝父 Loader 的 Native 库搜索目录。
如果不显式传入 `librarySearchPath`，业务类的 `System.loadLibrary()` 会找不到明明已经
在 apk 中的 so。Loader 同时加入：

- `ApplicationInfo.nativeLibraryDir`：适用于 `extractNativeLibs=true`
- `sourceDir!/lib/<当前 ABI>`：适用于 apk 内直接加载 so

## 内存与文件生命周期

| 数据       | 处理方式                                            |
| ---------- | --------------------------------------------------- |
| 启动索引   | 小 byte array 解密，解析完立即填零                  |
| Hollow dex | 解密到临时文件，只读 mmap 后 unlink，映射随进程存活 |
| Payload    | 磁盘和 mmap 均保持密文                              |
| 未加载方法 | code_item 始终保持密文                              |
| 已加载方法 | Shadow CodeItem 在 Native 内存中保留到进程结束      |
| 临时密钥   | 用完后调用 `crypto_wipe()`                          |

已发布 Shadow CodeItem 不能在方法返回后释放，因为 `ArtMethod.data_` 是没有引用
计数的原始指针。并发加载同一方法时，只有一个解密副本会通过 CAS 发布，
竞争失败的副本会被擦除并释放

## Android 版本边界

下面的内容都不是 NDK 稳定 API：

- `ClassLinker::LoadMethod` 的 C++ 符号与参数 ABI
- `DexFile::begin_` 的对象偏移
- `ArtMethod::data_` 和 access flags 的偏移
- verifier、nterp、JIT 和 `LinkCode()` 的时序

迁移 Android 14 或其他 Android 13 ROM 时，不能只改 API level 判断。需要重新对照
相应 AOSP tag、检查真机 `libart.so`，再重跑 ARM64/ARM32 全部回归
