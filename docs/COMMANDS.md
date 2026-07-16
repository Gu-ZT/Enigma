# Command-line Guide

[中文说明](./COMMANDS.zh_CN.md)

The `cmd/enigma` program provides an experimental fixed-target TCP tunnel. It
uses ETPH/1 for authenticated X25519 key establishment and ETP/1 for protected,
printable traffic records.

It is not a SOCKS or HTTP proxy. Every client process forwards its local listen
port to one configured target.

## Build

```bash
go build -o enigma ./cmd/enigma
```

On Windows, the output is normally named `enigma.exe`.

## 1. Generate a Key

```bash
enigma keygen > enigma.key
```

The file contains one 64-character hexadecimal PSK. Copy the same file to the
client and server through a secure channel and restrict its filesystem
permissions. The CLI also accepts `-key HEX`, but command-line secrets may be
visible in shell history and process listings.

## 2. Start the Server

```bash
enigma server \
  -listen :8443 \
  -key-file enigma.key \
  -allow-target example.com:80
```

`-allow-target` is repeatable and matches canonical `host:port` values exactly:

```bash
enigma server \
  -key-file enigma.key \
  -allow-target example.com:80 \
  -allow-target example.com:443
```

If no `-allow-target` is supplied, every holder of the PSK may request any TCP
target reachable by the server. Use `-allow-target '*'` only as an explicit
equivalent of that unrestricted mode.

## 3. Start the Client

```bash
enigma client \
  -listen 127.0.0.1:1080 \
  -server server.example.com:8443 \
  -target example.com:80 \
  -key-file enigma.key
```

Every TCP connection to `127.0.0.1:1080` creates a new authenticated tunnel and
requests `example.com:80` from the server.

For this HTTP target, a simple local check is:

```bash
curl -H "Host: example.com" http://127.0.0.1:1080/
```

The local port transports the target protocol directly. Applications must speak
the protocol expected by the configured target.

## Common Codec Flags

These flags are available on both `server` and `client` and must be compatible
at both ends.

| Flag | Default | Purpose |
| --- | --- | --- |
| `-key HEX` | none | Hex PSK, mainly for local testing |
| `-key-file PATH` | none | File containing the hex PSK; preferred |
| `-padding-min` | `0` | Minimum authenticated record padding |
| `-padding-max` | `0` | Maximum authenticated record padding |
| `-cover-padding-min` | `0` | Minimum printable cover padding |
| `-cover-padding-max` | `0` | Maximum printable cover padding |
| `-max-payload` | `16384` | Maximum payload bytes per ETP/1 record |
| `-handshake-timeout` | `10s` | ETPH/1 read/write deadline |
| `-clock-skew` | `1m` | Accepted client timestamp difference |

Use only one of `-key` and `-key-file`.

## Server Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-listen` | `:8443` | Public TCP listen address |
| `-dial-timeout` | `10s` | Target TCP dial timeout |
| `-replay-capacity` | `65536` | Maximum simultaneously live client nonces |
| `-replay-ttl` | `2m` | Nonce retention; must be at least twice `-clock-skew` |
| `-allow-target` | unrestricted | Exact target allow-list entry; repeatable |

A full replay cache rejects new authenticated handshakes until entries expire;
it never evicts a live nonce early.

## Client Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-listen` | `127.0.0.1:1080` | Local TCP forwarding address |
| `-server` | none | Required ETPH/1 server `host:port` |
| `-target` | none | Required fixed target `host:port` |
| `-dial-timeout` | `10s` | Server TCP dial timeout |

## Shutdown and Errors

`Ctrl+C` or `SIGTERM` stops the listener. Existing relays are allowed to finish
independently. Per-connection handshake, target, and relay failures are written
to standard error without stopping the listener.

The current server sends only generic target rejection reasons to clients; full
outbound dial errors remain in server logs.

## Current Limitations

- no SOCKS, HTTP CONNECT, TUN, UDP, or multiplexing;
- no JSON configuration or automatic service installation;
- no persistent replay database across restarts;
- no HTTP/TLS camouflage or defensive fallback;
- target allow-list entries are exact strings, not CIDR or domain patterns.

