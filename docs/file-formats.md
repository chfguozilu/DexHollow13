# 内部文件格式

这份文档用于排查 Host 和 Runtime 格式不一致。所有多字节整数均为小端序，
所有 offset 都是相对于当前文件开头

## apk 资源命名

```text
assets/.d13/0.dat
assets/.d13/r/0123456789abcdef0123456789abcdef.dat
assets/.d13/r/<另一个 128-bit 随机名>.dat
```

`0.dat` 是固定的加密启动索引。其他名称由 Host CSPRNG 每次打包生成，dex 和
Payload 使用同一命名规则，外部不根据名称判断类型。它们的关系保存在启动
索引内

## `DH13SEAL` 整体资源

启动索引和 Hollow dex 共用这个容器。Header 为 72 字节：

| Offset |           Size | 内容                                     |
| -----: | -------------: | ---------------------------------------- |
|      0 |              8 | magic：`DH13SEAL`                        |
|      8 |              4 | version：1                               |
|     12 |              4 | header_size：72                          |
|     16 |              4 | kind：1=启动索引，2=Hollow dex           |
|     20 |              4 | ordinal：启动索引为 0，dex 从 0 连续排列 |
|     24 |              4 | plaintext_size                           |
|     28 |              4 | reserved：0                              |
|     32 |             24 | XChaCha20 nonce                          |
|     56 |             16 | Poly1305 tag                             |
|     72 | plaintext_size | ciphertext                               |

前 56 字节 Header 作为 AEAD associated data。改动 kind、ordinal、长度或 nonce 都会导致
认证失败。Runtime 调用解密函数时还必须给出预期 kind/ordinal，防止合法密文被
用在错误位置

资源密钥不直接等于 apk master key。Host 和 Runtime 用 keyed BLAKE2b 对固定 domain、
kind 和 ordinal 做派生，得到每份资源独立的 256-bit key

## 启动索引明文

`0.dat` 解密后是 `DH13BOOT` v1。它保存：

- package name
- 原 Application 类名
- 原 AppComponentFactory 类名，可以为空
- dex 数量和连续 ordinal
- 每份 dex 的原/Hollow SHA-1 signature
- 每份 Hollow dex 和 Payload 的随机 asset 名称
- 保护方法数量

内层还保留 CRC32，用于区分内层字段编码错误；密码学完整性来自外层
`DH13SEAL` 的 Poly1305，不来自 CRC32

## `DH13EPAY` 加密 Payload

Payload 不做整体解密。它的 Header/Record 可以在启动时建立索引，每个 CodeItem
保持独立密文

### Header（144 字节）

| Offset | Size | 内容                             |
| -----: | ---: | -------------------------------- |
|      0 |    8 | magic：`DH13EPAY`                |
|      8 |    4 | version：1                       |
|     12 |    4 | header_size：144                 |
|     16 |    4 | endian_tag：`0x12345678`         |
|     20 |    4 | flags：1，逐方法 AEAD            |
|     24 |    4 | dex_ordinal                      |
|     28 |    4 | method_count                     |
|     32 |    4 | record_size：48                  |
|     36 |    4 | records_offset：144              |
|     40 |    4 | ciphertext data_offset           |
|     44 |    4 | file_size                        |
|     48 |    8 | reserved：0                      |
|     56 |   20 | 原 dex SHA-1 signature           |
|     76 |   20 | Hollow dex SHA-1 signature       |
|     96 |   16 | 这份 Payload 的随机 nonce_prefix |
|    112 |   32 | keyed BLAKE2b metadata tag       |

metadata tag 覆盖 Header 前 112 字节、所有 Method Record 和所有 ciphertext，不包含
tag 字段本身。Runtime 在安装 Hook 之前验证它，文件被截断、重排或替换时会直接
拒绝

### Method Record（48 字节）

| Offset | Size | 内容                        |
| -----: | ---: | --------------------------- |
|      0 |    4 | method_idx                  |
|      4 |    4 | 原 code_off                 |
|      8 |    4 | code_item_size              |
|     12 |    4 | ciphertext_offset           |
|     16 |    4 | insns_size                  |
|     20 |    4 | access_flags                |
|     24 |    4 | stub_kind                   |
|     28 |    4 | method flags                |
|     32 |   16 | 该 CodeItem 的 Poly1305 tag |

记录表为了建立 method_idx 索引而保持可读，但它被 metadata tag 和单方法 AEAD
同时绑定。它不存储类名、方法名或 descriptor

单方法 nonce 为：

```text
nonce_prefix[16] || little_endian(method_idx)[4] || little_endian(original_code_off)[4]
```

AEAD associated data 还绑定 dex ordinal、两个 dex signature、Record 中的所有 32 字节
元数据和格式 domain。因此不能把某个方法的密文换到另一条记录下使用

## 开发用明文 Payload

`dex-hollow --transform-dex` 是单 dex 调试入口，会生成 `DH13PAY\0` 明文 Payload v1，
便于单独检查 CodeItem 大小、对齐和转换结果。正式的单参数 apk 流程不会把这份
中间格式写入 apk
