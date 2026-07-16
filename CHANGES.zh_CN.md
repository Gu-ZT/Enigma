# 变更日志

[English](./CHANGES.md)

本文记录 Enigma Traffic Protocol 的用户可见变更。`0.1.0` 是首个实验版本，
ETP/1 和 ETPH/1 尚未承诺长期线格式兼容性。

## 0.2.0 - 2026-07-17

### 新增

- 可配置的 `standard`、`balanced`、`compact` 和 `high-padding` 流量 profile。
- 独立于包内部实现的公共 API 互操作矩阵。

### 变更

- 完成初始实现计划，并将线格式不兼容的 cover 改进移入 ETP/2 路线图。
- 更新协议与架构文档，以反映 mux/UoT 和 HTTP/TLS 集成现状。

## 0.1.0 - 2026-07-17

### 新增

- `pkg/enigma` 中的 ETP/1 认证可打印流编码器：
  - 使用 AES-256-GCM 提供记录机密性和认证；
  - 每个方向使用独立的 salt、密钥、序列号和状态；
  - 受 Enigma 启发的插线板、转子、步进和反射器变换；
  - 带随机变体的 64 符号可打印 cover 编码；
  - 可配置的认证记录 padding 和可忽略 cover padding；
  - 有界记录、长度校验、部分读取和 `net.Conn` 语义。
- `internal/tunnel` 中的 ETPH/1 认证隧道建立：
  - PSK 保护的临时 X25519 密钥协商；
  - 用于 ETP/1 的前向保密会话密钥；
  - 时间偏差校验；
  - 有界的内存客户端 nonce 重放保护；
  - 认证的目标请求和响应消息。
- `cmd/enigma` 命令行应用：
  - `keygen` 生成 32 字节随机 PSK；
  - 固定目标 TCP 转发；
  - 无认证本地 SOCKS5 `CONNECT`；
  - HTTP CONNECT 本地目标选择；
  - 在一条隧道上承载多条 TCP 逻辑流的 mux 模式；
  - 通过 mux 流承载固定目标 UDP/UoT；
  - 精确、通配域名和 CIDR 目标允许规则；
  - 可选 TLS 和 HTTP/1.1 伪装传输包装。
- 内部传输组件：
  - 有界的 mux `OPEN`/`DATA`/`CLOSE`/`RESET` 帧；
  - 有界的可靠流之上 UDP 数据报分帧；
  - 基于标准库的 TLS 握手包装；
  - 能保留已缓冲 ETPH/1 字节的有界 HTTP 前导伪装。
- 协议兼容性向量、fuzz 目标、benchmark、loopback 集成测试，以及面向协议和
  应用行为的覆盖率测试。
- 双语协议、握手、配置、命令、架构、mux、UoT 和传输文档。
- 面向 Linux、macOS 和 Windows 的 GitHub Actions CI 与 release workflow，
  以及可复现的 bug 报告模板。

### 安全与行为说明

- 转子变换只负责混淆，不提供密码学保护。payload 安全性来自 Go 标准库中维护的
  AEAD 原语。
- 认证失败、结构错误或不可信长度错误会终止受影响的流方向；实现不会尝试重新同步。
- 直接使用 `pkg/enigma.NewConn` 不提供前向保密或重放缓存。接受不可信对端的应用应
  使用 ETPH/1，或提供等价的认证握手。
- 客户端默认启用 TLS 证书校验。`-tls-insecure-skip-verify` 是显式的不安全测试旁路。

### 已知限制

- 当前版本为实验版本，不承诺 ETP/1 或 ETPH/1 的长期线格式兼容性。
- mux session 是一次性的，共享连接失败后不会自动重连。
- UDP/UoT 只支持固定目标，并把响应发送给最近活跃的本地 UDP 对端；它不是动态目标
  SOCKS UDP association。
- 重放保护只保存在进程内，服务重启后不会持久化。
- 不包含 TUN、防御性 fallback、动态流量形状隐藏和更广泛的代理 profile。
- 可打印 cover 格式在 padding 之前每个变换字节需要两个符号，存在基础带宽开销。

### 验证

发布门禁计划执行：

```bash
go test ./...
go vet ./...
go build ./cmd/enigma
```

在具备可用 CGO 编译器的平台上运行 `go test -race ./...`。
