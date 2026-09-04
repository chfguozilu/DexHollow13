# 安全边界

## 加密方案

- Host 每次打包调用 OpenSSL `RAND_bytes` 生成 256-bit master key 和所有 nonce
- keyed BLAKE2b 负责根据资源类型、dex identity 和固定 domain 派生子密钥
- XChaCha20-Poly1305 负责加密和单资源/单方法认证
- keyed BLAKE2b metadata tag 负责在启动阶段认证整份 Payload 结构
- 临时 master key 和子密钥用完后调用 Monocypher `crypto_wipe()`

如果 CSPRNG 失败，Host 会终止打包，不会降级成时间戳或其他弱随机数

## Runtime so 中的密钥

每个 Runtime so 模板包含一个唯一占位符。Host 打包时为当前 apk 生成随机 mask，
然后写入：

```text
mask[32] || (master_key XOR mask)[32]
```

这样做可以避免 so 中直接出现连续的 32 字节明文 key，并且让每个 apk、每个 ABI
的表面密钥材料都不一样

但它不是硬件密钥保护。Runtime 必须能离线恢复 key，所以了解函数逻辑的静态分析者
也可以做相同的 XOR。这层的作用是增加提取成本，不是让密钥在客户端永久不可得

## 低辨识度文件名的作用

`assets/.d13/r/` 中的 `.dat` 名称每次打包都随机，而且 dex/Payload 使用同一规则。
这能避免解压后直接出现 `classes21.dex` 或 `payload21.bin` 这种过于明显的名字

文件名隐藏不是密码学保护。攻击者可以枚举 apk entry、查看大小和分析 Runtime。
所以这项改动只是减少显眼特征，核心安全性仍然来自认证加密和方法体抽取

## 明文何时存在

| 内容                  | 明文时间                                           |
| --------------------- | -------------------------------------------------- |
| 启动索引              | Loader 最早阶段，解析完立即填零                    |
| Hollow dex            | 创建 ClassLoader 前解密；临时文件映射后立即 unlink |
| 未加载方法的 CodeItem | 不会解密                                           |
| 已加载方法的 CodeItem | 首次 LoadMethod 命中时解密，保留到进程结束         |

`unlink` 只代表文件不再出现在目录中，不代表这段 mmap 已经从内存消失。
有权限读取进程内存的人仍然能取得当前正在使用的明文

## 失败时怎么处理

资源 Header、长度、kind、ordinal、dex signature、method_idx、CodeItem 大小和认证 tag
都要检查。对一个已经在保护索引中命中的方法，任何认证、分配或 ART 不变量
失败都会终止当前进程

这里不能选择“记一条日志然后继续”，因为那会让方法安静地执行 Hollow 默认返回桩，
最后表现成一个很难排查的业务错误

## 它没有解决什么

- root/调试器下的进程内存 dump
- 对 Native Runtime 的仔细静态逆向
- 在解密函数或 ART Hook 上再次加 Hook
- 防调试、防 Frida、防 root、OLLVM 或商业级白盒密码
- apk 安装包的真实性；这需要使用者自己的 apk 签名和发布链

项目的定位是一个可以解释清楚的 dex 抽取与 ART 运行时绑定方案，不是对商业加固
产品的无限强度承诺

## 体积变化

Hollow dex 保留类型/索引/桩，Payload 又保留真实 CodeItem，这本来就是用空间换静态
抽取。加密后的内容还几乎无法被 zip 再压缩，所以产物会比输入 apk 大很多

Hollow dex 密文在 zip 中使用 STORE，避免浪费 deflate CPU。Payload 的 Record 表仍可压缩，
所以 Payload entry 使用 deflate。如果后续可能会继续缩小体积，可能设计为“先压缩单个 CodeItem，
再独立 AEAD”的新 Payload 版本
