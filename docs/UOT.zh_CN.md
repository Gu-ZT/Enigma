# 可靠传输之上的 UDP（UoT，实验性）

[English](./UOT.md)

`internal/uot` 在 ETP/1 或 mux 逻辑流等经过认证的可靠连接之上承载带地址的
数据报。它只负责数据报分帧，不替代 UDP 拥塞控制、NAT 穿透或认证。

## 帧格式

```text
version[1] || flags[1] || address_length[2] || payload_length[4] ||
address[address_length] || payload[payload_length]
```

版本 `1` 当前要求 `flags == 0`。地址以有界的 `host:port` 字符串传输，payload
受 `Config.MaxPacket` 限制，默认上限为 65535 字节。非法长度或截断帧会终止数据
报连接；读取器不会在不可信边界上重新同步。

`ReadFrom` 返回网络类型为 `udp` 的 `net.Addr`。如果调用者提供的缓冲区小于数据
报，数据报会被消费，只复制前缀并返回 `io.ErrShortBuffer`，保持本实验层明确的
有界行为。

该包本身不会创建操作系统 UDP socket。`internal/app` 已把固定目标本地 UDP 监听器
连接到一条 UoT mux 流，CLI 两端使用 `-mux -udp` 启用。当前适配器把响应发送给最近
活跃的本地对端，不实现动态 SOCKS UDP association。
