# Go 配置说明

[English](./CONFIGURATION.md)

ETP/1 在包装现有 `net.Conn` 时通过 `enigma.Config` 配置。当前包没有 JSON 配置文件，
也不区分客户端或服务端角色：两端使用相同 API，每个连接方向独立初始化。

## 最小配置

```go
cfg := enigma.Config{
	Key: sharedKey, // 至少 32 字节随机密钥
}

conn, err := enigma.NewConn(rawConn, cfg)
if err != nil {
	return err
}
```

该配置关闭记录填充和 cover 填充，使用默认可打印字母表，每条记录最多承载 16 KiB
数据。

## 均衡示例

```go
cfg := enigma.Config{
	Key: sharedKey,

	MinPadding: 4,
	MaxPadding: 64,

	MinCoverPadding: 2,
	MaxCoverPadding: 32,

	MaxPayload: 16 * 1024,
}
```

填充值表示每条记录的字节/字符数量，不是百分比。增大范围会增加线开销，但不会隐藏
时序或连接总长度。

## 字段说明

### Key

`Key` 必填且至少为 32 字节。应使用 `crypto/rand` 生成，并通过已认证的安全渠道分发。
ETP/1 不负责将口令强化为密钥，也不协商密钥。

```go
key := make([]byte, 32)
if _, err := rand.Read(key); err != nil {
	return err
}
```

### CoverAlphabet

`CoverAlphabet` 必须由 `0x21` 到 `0x7e` 范围内 64 个互不重复的可打印 ASCII 字节
组成。

默认值：

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_
```

字母表顺序属于线 profile，两端必须一致。修改它只会改变可打印字符，不会增强加密。

### PaddingAlphabet

`PaddingAlphabet` 列出解码器允许在编码符号间忽略的字节。每个字节必须是可打印
ASCII 或 tab/CR/LF，并且不能出现在 `CoverAlphabet` 中。重复 padding 字节会被归一化。

字段为空时，ETP/1 使用默认的空白与标点集合。遇到两个字母表都不包含的字节时，
解码器返回 `ErrUnexpectedCoverByte`。

### MinPadding 与 MaxPadding

这两个字段限定每条记录认证明文末尾追加的随机字节数。

- 默认值：`0`、`0`；
- 有效范围：`0` 到 `8192`；
- `MinPadding` 不能大于 `MaxPadding`。

接收端会先认证这些字节再丢弃。接收端的 `MaxPadding` 必须不小于发送端可能产生的
记录填充。

### MinCoverPadding 与 MaxCoverPadding

这两个字段限定每个编码后 session salt 或帧中插入的可忽略字符数。

- 默认值：`0`、`0`；
- 有效范围：`0` 到 `8192`；
- `MinCoverPadding` 不能大于 `MaxCoverPadding`。

cover 填充在转子解码前被过滤，不属于 AEAD 记录。解码器只忽略明确配置的 padding
字符。

### MaxPayload

`MaxPayload` 是一条认证记录可以承载的最大 payload。

- 默认值：`16384` 字节；
- 有效范围：`1` 到 `32768` 字节；
- 更大的 `Write` 会自动拆分为多条记录。

接收端使用自己的 `MaxPayload` 作为内存分配和结构校验硬限制，建议两端使用相同值。

## 互操作要求

| 配置 | 是否必须一致 | 原因 |
| --- | --- | --- |
| `Key` | 是 | 派生 AEAD 密钥、转子、掩码和 nonce |
| `CoverAlphabet` | 是 | 定义符号到索引的解码 |
| `PaddingAlphabet` | 是 | 定义允许忽略的非 cover 字节 |
| `MaxPayload` | 建议一致 | 接收端拒绝超过自身限制的记录 |
| `MaxPadding` | 接收端需容纳发送端 | 接收端拒绝过大的内部填充 |
| 各最小填充值 | 否 | 只影响本地发送选择 |
| cover 填充范围 | 否 | 解码按字母表过滤，而非按数量过滤 |

两端使用完全相同的 `Config` 是最简单的互操作方式。

## 配置校验

`enigma.NewConn` 会在执行网络 I/O 前校验配置。短密钥、非法字母表、cover/padding
重叠、反向填充范围和越界限制都会直接返回错误。

配置错误是普通的上下文错误；线错误还可以通过 `errors.Is` 判断
`ErrAuthentication`、`ErrInvalidFrame` 和 `ErrUnexpectedCoverByte`。

