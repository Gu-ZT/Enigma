# 可选传输包装（实验性）

[English](./TRANSPORT.md)

`internal/transport` 提供可放在 ETPH/1 下面的包装器，故意与 ETP/1 编码器、mux、
UoT 和目标策略解耦。

## HTTP/1.1 前导

`ClientHTTP` 发送带空 body 的有界 `POST path HTTP/1.1` 请求；`ServerHTTP` 校验方法、
路径、可选 Host 头和空 body 后返回 `200 OK`。两端都会保留头部结束符之后已经被
缓冲的字节，因此随后可以立即启动 ETPH/1。

这只是表示层伪装。明文 HTTP 不提供机密性、证书认证或抵抗主动协议探测的能力。
包装器会拒绝非空 body、传输编码、格式错误的头部以及超过配置上限的头部。

## TLS 包装

`ClientTLS` 和 `ServerTLS` 使用 Go 维护的 `crypto/tls`，并在可选 deadline 下完成
显式握手。调用者通过 `tls.Config` 提供证书、信任根、SNI 和验证策略。库不会静默
开启 `InsecureSkipVerify`；没有公有证书时应使用私有 CA 或证书固定。

CLI 可通过 `-tls` 和/或 `-http-camouflage` 启用这两个包装器。
服务端模式需要证书和私钥；客户端使用系统根证书或 `-tls-ca-file` 校验，
`-tls-insecure-skip-verify` 是必须显式指定的不安全旁路选项。同时启用两个模式时，
先建立 TLS，再在 TLS 内运行 HTTP 前导。
