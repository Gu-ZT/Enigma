# ETP 多路复用层（实验性）

[English](./MUX.md)

`internal/mux` 是建立在已经完成 ETPH/ETP 认证的可靠连接之上的应用层逻辑流
多路复用器。它不修改 ETP/1 记录，目前也没有作为稳定公共 API 暴露。

## 帧格式

每个 mux 帧由 8 字节头部和有界 payload 组成：

```text
version[1] || type[1] || stream_id[4] || payload_length[2] || payload
```

当前帧类型：

| 类型 | Payload | 含义 |
| --- | --- | --- |
| `OPEN` | 空 | 创建一条逻辑流 |
| `DATA` | 不超过 `MaxFramePayload` 字节 | 传递有序流数据 |
| `CLOSE` | 空 | 半关闭远端读方向 |
| `RESET` | 有界 UTF-8 原因 | 中止逻辑流 |

客户端分配奇数 stream ID，服务端分配偶数 stream ID。会话会拒绝重复 ID、错误
发起方奇偶性、未知流上的 `DATA`、非法版本以及超过配置上限的长度。非法 mux
帧会使底层会话终止。

## 资源上限

`Config.MaxStreams`、`Config.MaxFramePayload` 和 `Config.StreamBuffer` 分别限制
逻辑流数量、单帧分配和入站帧队列。背压是有意设计：不读取某条流的对端最终会
阻塞会话读取器，而不是让内存无限增长。

## 生命周期

`Session.Open` 发送 `OPEN` 并返回兼容 `net.Conn` 的逻辑流，`Session.Accept` 返回
对端打开的逻辑流。目标协商仍然是每条流上的应用 payload，mux 层不理解 TCP、
SOCKS5 或 HTTP CONNECT 目标。

CLI 可在服务端和客户端同时使用 `-mux` 启用该功能。session 是一次性的：共享
连接失败后不会自动重连。目标打开确认仍通过每条逻辑流上的现有目标协议完成。
