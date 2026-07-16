# ETP Multiplexing Layer (experimental)

[中文说明](./MUX.zh_CN.md)

`internal/mux` is an application-layer logical-stream multiplexer over one
already authenticated ETPH/ETP reliable connection. It does not modify ETP/1
records and is not exposed as a stable public API yet.

## Frame Format

Each mux frame has an 8-byte header followed by a bounded payload:

```text
version[1] || type[1] || stream_id[4] || payload_length[2] || payload
```

The current frame types are:

| Type | Payload | Meaning |
| --- | --- | --- |
| `OPEN` | empty | Create one logical stream |
| `DATA` | up to `MaxFramePayload` bytes | Deliver ordered stream bytes |
| `CLOSE` | empty | Half-close the remote read direction |
| `RESET` | bounded UTF-8 reason | Abort the logical stream |

Clients allocate odd stream IDs and servers allocate even stream IDs. A session
rejects duplicate IDs, wrong initiator parity, unknown `DATA`, invalid versions,
and lengths above its configured limit. The underlying session is terminal on a
malformed mux frame.

## Resource Bounds

`Config.MaxStreams`, `Config.MaxFramePayload`, and `Config.StreamBuffer` bound
the number of logical streams, frame allocations, and queued inbound frames.
Backpressure is intentional: a peer that does not read a stream can eventually
block the session reader instead of causing unbounded memory growth.

## Lifecycle

`Session.Open` sends `OPEN` and returns a `net.Conn`-compatible logical stream.
`Session.Accept` returns streams opened by the peer. Target negotiation remains
an application payload on each stream; the mux layer does not know about TCP,
SOCKS5, or HTTP CONNECT targets.

The CLI enables mux with `-mux` on both `server` and `client`. The session is
single-shot: if the shared connection fails, the process does not reconnect it
automatically. Target-open acknowledgements are carried by the existing target
protocol on each logical stream.
