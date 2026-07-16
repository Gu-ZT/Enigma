# 命令行使用说明

[English](./COMMANDS.md)

`cmd/enigma` 提供实验性的固定目标、无认证 SOCKS5 和 HTTP CONNECT TCP 隧道。它使用
ETPH/1 完成认证 X25519 密钥建立，再使用 ETP/1 传输受保护的可打印记录。

它不是通用 HTTP 代理。固定目标模式把所有本地连接转发到一个目标，SOCKS5 和 HTTP
CONNECT 模式则为每条本地连接单独选择目标。

## 编译

```bash
go build -o enigma ./cmd/enigma
```

Windows 下一般输出为 `enigma.exe`。

## 1. 生成密钥

```bash
enigma keygen > enigma.key
```

文件中包含一个 64 字符十六进制 PSK。应通过安全渠道把同一文件分发到客户端和服务端，
并限制文件权限。CLI 也支持 `-key HEX`，但命令行密钥可能暴露在 shell 历史和进程列表
中。

## 2. 启动服务端

```bash
enigma server \
  -listen :8443 \
  -key-file enigma.key \
  -allow-target example.com:80
```

`-allow-target` 可以重复使用，支持三种规则：精确的规范化 `host:port`、例如
`*.example.com:443` 的子域名模式，以及例如 `192.0.2.0/24:*` 的 IP CIDR（端口可用 `*`）：

```bash
enigma server \
  -key-file enigma.key \
  -allow-target example.com:80 \
  -allow-target '*.example.com:443' \
  -allow-target '192.0.2.0/24:*'
```

不设置 `-allow-target` 时，任何持有 PSK 的客户端都能请求服务端可访问的任意 TCP
目标。`-allow-target '*'` 是该无限制模式的显式写法。

## 3. 启动客户端

```bash
enigma client \
  -listen 127.0.0.1:1080 \
  -server server.example.com:8443 \
  -target example.com:80 \
  -key-file enigma.key
```

每个连接到 `127.0.0.1:1080` 的 TCP 连接都会建立一条新认证隧道，并请求服务端连接
`example.com:80`。

该 HTTP 目标可以这样测试：

```bash
curl -H "Host: example.com" http://127.0.0.1:1080/
```

本地端口直接承载目标协议，应用必须发送目标本身能够理解的数据。

## SOCKS5 模式

```bash
enigma client \
  -socks5 \
  -listen 127.0.0.1:1080 \
  -server server.example.com:8443 \
  -key-file enigma.key
```

本地监听器接受无认证 SOCKS5 `CONNECT`，每个请求可以选择域名、IPv4 或 IPv6 目标。
只有在服务端完成隧道认证、目标策略检查并成功建立目标 TCP 连接后，才会返回 SOCKS5
成功响应。

## HTTP CONNECT 模式

```bash
enigma client \
  -http-connect \
  -listen 127.0.0.1:1080 \
  -server server.example.com:8443 \
  -key-file enigma.key
```

本地监听器接受不带代理认证的 `CONNECT host:port HTTP/1.x`。只有远端目标打开后才返回
`200 Connection Established`，远端失败时返回通用的 `502 Bad Gateway`。它不接受普通
HTTP 方法，也不是 HTTP 应用代理。

## Mux 模式

在服务端和客户端同时加入 `-mux`，可以让多条本地 TCP 连接复用一条已经认证的
ETPH/ETP 连接。每条逻辑流仍然独立进行目标协商和 relay。当前 session 是一次性的：
共享连接失败后，进程不会自动重连。

## UDP/UoT 模式

服务端和客户端同时使用 `-mux -udp`，客户端配置一个固定 `-target`：

```bash
enigma server -mux -udp -listen :8443 -key-file enigma.key \
  -allow-target 192.0.2.53:53

enigma client -mux -udp -listen 127.0.0.1:1053 \
  -server server.example.com:8443 -target 192.0.2.53:53 \
  -key-file enigma.key
```

客户端监听器为 UDP。数据报边界通过一条 mux 流上的 UoT 保留。当前模式只支持一个
固定目标，并把响应发送给最近活跃的本地 UDP 对端；它不是通用 SOCKS UDP association。

## TLS 与 HTTP 伪装

两端必须启用相同包装。同时启用时，HTTP 运行在 TLS 内：

```bash
enigma server -tls -tls-cert server.crt -tls-key server.key \
  -http-camouflage -http-host edge.example.com -http-path /sync \
  -key-file enigma.key

enigma client -tls -tls-server-name edge.example.com \
  -http-camouflage -http-host edge.example.com -http-path /sync \
  -server edge.example.com:8443 -target example.com:443 \
  -key-file enigma.key
```

客户端默认使用系统根证书，也可以通过 `-tls-ca-file` 指定 CA。
`-tls-insecure-skip-verify` 会关闭证书校验，只应在隔离测试环境使用。

## 通用 Codec 参数

服务端和客户端都支持下列参数，两端配置必须兼容。

| 参数 | 默认值 | 用途 |
| --- | --- | --- |
| `-key HEX` | 无 | 十六进制 PSK，主要用于本地测试 |
| `-key-file PATH` | 无 | 包含十六进制 PSK 的文件，推荐使用 |
| `-padding-min` | `0` | 最小认证记录填充 |
| `-padding-max` | `0` | 最大认证记录填充 |
| `-cover-padding-min` | `0` | 最小可打印 cover 填充 |
| `-cover-padding-max` | `0` | 最大可打印 cover 填充 |
| `-max-payload` | `16384` | 每条 ETP/1 记录的最大 payload |
| `-handshake-timeout` | `10s` | ETPH/1 读写超时 |
| `-clock-skew` | `1m` | 允许的客户端时间差 |

`-key` 与 `-key-file` 只能选择一个。

## 服务端参数

| 参数 | 默认值 | 用途 |
| --- | --- | --- |
| `-listen` | `:8443` | 公网 TCP 监听地址 |
| `-dial-timeout` | `10s` | 目标 TCP 拨号超时 |
| `-replay-capacity` | `65536` | 同时存活的客户端 nonce 上限 |
| `-replay-ttl` | `2m` | nonce 保留时间，至少为 `-clock-skew` 的两倍 |
| `-allow-target` | 无限制 | 精确主机、`*.domain` 或 CIDR 目标规则，可重复使用 |
| `-mux` | `false` | 为多条逻辑流复用一条认证连接 |
| `-udp` | `false` | 处理固定目标 UoT 流，需要 `-mux` |
| `-tls` | `false` | 为接收连接启用 TLS 包装 |
| `-tls-cert` | 无 | TLS 服务端证书 PEM，需要 `-tls` |
| `-tls-key` | 无 | TLS 服务端私钥 PEM，需要 `-tls` |
| `-http-camouflage` | `false` | 在 ETPH/1 前接收 HTTP/1.1 前导 |
| `-http-host` | 无 | 期望的 HTTP 伪装 Host 头 |
| `-http-path` | `/` | 期望的 HTTP 伪装请求路径 |

重放缓存满时会拒绝新的认证握手，不会提前淘汰仍有效的 nonce。

## 客户端参数

| 参数 | 默认值 | 用途 |
| --- | --- | --- |
| `-listen` | `127.0.0.1:1080` | 本地 TCP 转发地址 |
| `-server` | 无 | 必填，ETPH/1 服务端 `host:port` |
| `-target` | 无 | 固定目标 `host:port`，使用 `-socks5` 或 `-http-connect` 时省略 |
| `-socks5` | `false` | 开启无认证 SOCKS5 目标选择 |
| `-http-connect` | `false` | 开启 HTTP CONNECT 目标选择 |
| `-tls` | `false` | 为服务端连接启用 TLS 包装 |
| `-tls-ca-file` | 无 | 用于验证 TLS 服务端的 PEM CA 包 |
| `-tls-server-name` | 服务端主机 | TLS SNI 和证书名称 |
| `-tls-insecure-skip-verify` | `false` | 关闭 TLS 校验，危险且必须显式启用 |
| `-http-camouflage` | `false` | 在 ETPH/1 前发送 HTTP/1.1 前导 |
| `-http-host` | 服务端主机 | HTTP 伪装 Host 头 |
| `-http-path` | `/` | HTTP 伪装请求路径 |
| `-dial-timeout` | `10s` | 服务端 TCP 拨号超时 |
| `-local-handshake-timeout` | `10s` | 本地 SOCKS5/HTTP 请求超时 |
| `-mux` | `false` | 为多个本地连接复用一条认证连接 |
| `-udp` | `false` | 为一个固定目标监听 UDP，需要 `-mux` |

## 关闭与错误

`Ctrl+C` 或 `SIGTERM` 会停止监听，已经建立的转发可以独立结束。单个连接的握手、目标
或转发错误只写入标准错误，不会停止整个监听器。

服务端只向客户端返回通用目标拒绝原因，完整的外连错误保留在服务端日志中。

## 当前限制

- 没有 TUN 或动态目标 SOCKS UDP association；
- 没有 JSON 配置和自动服务安装；
- 重启后不会保留重放数据库；
- 没有防御性 fallback；
- mux 共享连接失败后不会自动重连；
- UDP 模式只支持一个固定目标和一个活跃本地对端 association；
