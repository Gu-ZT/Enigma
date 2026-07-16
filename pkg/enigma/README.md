# ETP/1 raw-stream API

`pkg/enigma` wraps an existing ordered, reliable `net.Conn`. Callers read and
write their original bytes while the underlying wire carries AES-256-GCM
records transformed by the ETP/1 rotor machine and printable cover codec.

The package intentionally does not provide proxy destination negotiation,
SOCKS/HTTP listeners, multiplexing, fallback routing, a replay cache, or an
ephemeral-key handshake.

```go
cfg := enigma.Config{
	Key: sharedKey, // at least 32 cryptographically random bytes
}

rawClient, err := net.Dial("tcp", serverAddress)
if err != nil {
	return err
}
conn, err := enigma.NewConn(rawClient, cfg)
if err != nil {
	rawClient.Close()
	return err
}
```

Wrap the accepted connection with a compatible configuration on the other side:

```go
conn, err := enigma.NewConn(rawAcceptedConn, cfg)
```

There are no client/server roles at the codec layer. Each side lazily creates an
independent salt when it first writes, and consumes the peer's salt when it first
reads.

## Concurrency

- one reader and one writer may block concurrently;
- multiple writes are serialized into complete records;
- a read never returns bytes from a record before AEAD authentication succeeds;
- protocol errors are terminal for the read direction;
- deadlines and addresses are inherited from the embedded connection.

If the underlying connection does not implement `CloseRead` or `CloseWrite`, the
corresponding ETP/1 method closes the entire connection.

See the root [README](../../README.md), [configuration guide](../../docs/CONFIGURATION.md),
and [wire protocol](../../docs/PROTOCOL.md) for details.

