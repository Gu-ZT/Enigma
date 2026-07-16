# 架构与参考路径对照

[English](./ARCHITECTURE.md)

本仓库有意保持比 `ref/sudoku-main` 更小。参考项目只用于架构研究；其 GPL
授权源码、协议文字和线格式都没有复制或导入到本项目。

## 本仓库路径

| 路径 | 职责 | 边界 |
| --- | --- | --- |
| `pkg/enigma/` | ETP/1 流编码器：AES-GCM 记录、转子混淆、cover 编码、padding 和 `net.Conn` 语义 | 可复用公共包，不依赖命令或代理代码 |
| `internal/tunnel/` | ETPH/1 认证 X25519 握手、重放保护、目标请求/响应 | 应用私有的隧道控制面 |
| `internal/app/` | 监听器生命周期、目标策略、外连拨号、SOCKS5、HTTP CONNECT 和双向 relay | 运行时组装，依赖 `internal/tunnel` 与 `pkg/enigma` |
| `cmd/enigma/` | `keygen`、`server`、`client` 命令行解析和进程启动 | 可执行入口，不承载协议核心行为 |
| `docs/` | 线格式规范、命令/配置指南和架构决策 | 面向使用者的契约与运维说明 |
| `pkg/enigma/testdata/` | 稳定的 ETP/1 派生向量 | 兼容性夹具，不是运行时配置 |
| `internal/tunnel/testdata/` | 稳定的 ETPH/1 握手向量 | 握手兼容性夹具 |
| `PLAN.md` | 里程碑、安全边界和剩余协议工作 | 变更范围记录 |
| `AGENTS.md` | 仓库工作流和不变量 | 必须遵守的工程规则 |

## 参考项目路径映射

下面说明查看参考项目各路径时要回答的问题，以及它们在 ETP 中对应的
职责。它们不是本项目的代码依赖。

| 参考路径 | 可借鉴的架构问题 | ETP 对应位置 |
| --- | --- | --- |
| `apis/` | 哪些契约应保持公开且低依赖？ | `pkg/enigma` 公共 API 与 `docs/` 契约 |
| `pkg/obfs/sudoku/` | 如何把有状态的可打印变换与传输代码隔离？ | `pkg/enigma/rotor.go` 与 `cover.go` |
| `pkg/crypto/record_conn.go` | 记录分帧、认证和流语义应放在哪里？ | `pkg/enigma/conn.go` |
| `internal/tunnel/` | 会话、握手和连接所有权如何分离？ | `internal/tunnel/handshake.go`、`target.go` 与 `internal/app/relay.go` |
| `internal/app/` | 监听器和协议相关本地适配器如何组合？ | `internal/app/` 与 `cmd/enigma/` |
| `internal/config/` | 哪些校验应在配置边界执行？ | `pkg/enigma/config.go` 与 `cmd/enigma/main.go` 的 CLI 校验 |
| `cmd/` | 哪些内容应放入口程序而不是库？ | `cmd/enigma/main.go` |
| `tests/` 与 `*_test.go` | 哪些行为需要端到端和竞态敏感测试？ | 包测试、loopback 测试、fuzz 目标和向量 |

## 依赖方向

```text
cmd/enigma
    |
internal/app ----> internal/tunnel ----> pkg/enigma
    |                    |
    +---- net.Listener    +---- ETPH/1 控制消息
```

`pkg/enigma` 必须继续独立于命令代码和代理协议。mux 和 UoT 已遵循该规则运行在
流编码器之上，并具有独立规范和测试。线格式不兼容的 codec 仍必须使用新的协议标识。

## 变更指引

1. 记录字段、派生过程、cover 符号或失败行为的变化都属于 ETP/1 协议变化，
   必须同步更新 `docs/PROTOCOL.md`、向量、测试和 `PLAN.md`。
2. 新增本地代理模式应放在 `internal/app/` 和 `cmd/enigma/`，尽量复用现有
   目标协商与 relay 边界。
3. mux 或 UDP 等新传输模式必须先明确分帧和生命周期设计，不能把未文档化的
   扩展直接塞进现有 ETP/1 字节流。
