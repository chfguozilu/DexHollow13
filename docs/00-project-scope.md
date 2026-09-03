# 00：项目范围与标准

## 1. 成品完成的闭环

```text
输入未加固 apk
    ↓
读取 AndroidManifest.xml 与所有 classes*.dex
    ↓
保存原 Application、AppComponentFactory 和 dex 启动信息
    ↓
抽取所有受支持方法的完整 code_item
    ↓
生成类型正确、可通过 verifier 的 Hollow dex
    ↓
写入 Loader dex、Native so、Hollow dex、Payload 和 bootstrap.bin
    ↓
重新生成未签名 apk
    ↓
Android 13 启动 ShellApplication
    ↓
安装包含全部 Hollow dex 的目标 ClassLoader
    ↓
Native Runtime 将受保护 ArtMethod 导向 Shadow CodeItem
    ↓
原 Application、Provider、Activity 和业务方法正常工作
```

## 2. 不可破坏的 Runtime 约束

Hollow dex 是 ART 用来定义类、建立类型关系和通过校验的数据源。它的 `insns[]` 中只有
返回默认值的桩代码。Payload 中保存原始 `code_item`，运行时在 Native 匿名内存中建立
Shadow CodeItem，并让受保护方法从这块独立内存执行

## 4. 支持边界

成品目标支持：

- 单个 base apk，以及 base apk 内的多个标准 dex
- Android 13 / API 33
- ARM64 与 ARM32 应用进程
- 自定义 Application 与常见 AppComponentFactory
- direct/virtual/static/instance 方法
- 常见构造方法、类初始化方法、异常处理、switch 和复杂控制流
- apk 自带 Native 库

这里的“常见构造方法”有明确含义：Host 能解析 `this/super.<init>` 前的全部指令、跟踪
p0 的 move-object 别名，并证明 if/goto 目标不能绕过初始化调用；异常区间也不能覆盖该
前缀。无法证明桩合法的构造器会保留原实现并出现在未保护报告中，而不会冒险生成可能被
verifier 拒绝的 dex

对于自带 Native 库的 apk，支持的含义还包括保持原 ARM ABI 集合：不能因为壳自身同时有
32/64 位版本，就给 arm64-only App 新增一个 32 位目录。若输入含项目未支持的 Native ABI，
Host 会终止并要求先生成 ARM-only base apk

v1 的另一个明确边界是保留原 `encoded_method.code_off`。原 `insns[]` 若短于类型正确的
默认返回桩，Host 不会扩大 CodeItem 或让相邻 data item 被覆盖，而是把该方法列为
`skipped_stub_too_large`。解决它需要追加新 CodeItem 并重写 class_data 中的 ULEB128
`code_off`，属于后续格式版本，不能靠越界写入伪装成“全部保护”

## 5. 失败策略

加壳器不能在不知道结果是否正确时继续生成 apk。遇到格式错误、越界、不支持的 dex
变体或资源冲突时，必须终止。对于单个无法证明可生成合法桩的方法，保留它的原实现，
并在报告中给出 dex、类、方法、offset 和原因；“跳过”必须明确表示该方法没有受到保护

Runtime 会检查 API level、目标符号、dex magic/signature、method_idx 和原 code_off 对应的
Hollow 地址。检查失败时输出明确日志并中止或拒绝绑定。由于实现读取 r84 私有 C++ 对象
字段，布局被厂商改变的 Android 13 仍可能在检查之前崩溃；因此不能把“API 33”理解为
对所有 ROM 的通用 ABI 承诺
