# Command-line Guide

[中文说明](./COMMANDS.zh_CN.md)

The `cmd/enigma` program provides experimental fixed-target, no-auth SOCKS5,
and HTTP CONNECT TCP tunnels. It uses ETPH/1 for authenticated X25519 key
establishment and ETP/1 for protected, printable traffic records.

It is not a general HTTP proxy. Fixed-target mode forwards every local
connection to one configured target; SOCKS5 and HTTP CONNECT modes select a
target per local connection.

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

`-allow-target` is repeatable. Rules may be an exact canonical `host:port`, a
subdomain pattern such as `*.example.com:443`, or an IP CIDR with a port such
as `192.0.2.0/24:*`:

```bash
enigma server \
  -key-file enigma.key \
  -allow-target example.com:80 \
  -allow-target '*.example.com:443' \
  -allow-target '192.0.2.0/24:*'
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

## SOCKS5 Mode

```bash
enigma client \
  -socks5 \
  -listen 127.0.0.1:1080 \
  -server server.example.com:8443 \
  -key-file enigma.key
```

The local listener accepts SOCKS5 `CONNECT` with no authentication. Each request
chooses its own domain, IPv4, or IPv6 target. The SOCKS5 success reply is sent
only after the server has authenticated the tunnel, passed the target policy,
and opened the target TCP connection.

## HTTP CONNECT Mode

```bash
enigma client \
  -http-connect \
  -listen 127.0.0.1:1080 \
  -server server.example.com:8443 \
  -key-file enigma.key
```

The local listener accepts `CONNECT host:port HTTP/1.x` without proxy
authentication. It returns `200 Connection Established` only after the remote
target is open, and returns a generic `502 Bad Gateway` on remote failure. It
does not accept ordinary HTTP methods or implement an HTTP application proxy.

## Mux Mode

Add `-mux` to both `server` and `client` to reuse one authenticated ETPH/ETP
connection for multiple local TCP connections. Each logical stream performs its
own target negotiation and relay. The current session is single-shot: if the
shared connection fails, the process does not reconnect it automatically.

## UDP/UoT Mode

Use `-mux -udp` on both sides and configure one fixed `-target` on the client:

```bash
enigma server -mux -udp -listen :8443 -key-file enigma.key \
  -allow-target 192.0.2.53:53

enigma client -mux -udp -listen 127.0.0.1:1053 \
  -server server.example.com:8443 -target 192.0.2.53:53 \
  -key-file enigma.key
```

The client listener is UDP. Datagram boundaries are preserved through UoT on
one mux stream. This mode currently supports one fixed target and routes replies
to the most recently active local UDP peer; it is not a general SOCKS UDP
association implementation.

## TLS and HTTP Camouflage

Both sides must enable the same wrappers. When both are enabled, HTTP runs
inside TLS:

```bash
enigma server -tls -tls-cert server.crt -tls-key server.key \
  -http-camouflage -http-host edge.example.com -http-path /sync \
  -key-file enigma.key

enigma client -tls -tls-server-name edge.example.com \
  -http-camouflage -http-host edge.example.com -http-path /sync \
  -server edge.example.com:8443 -target example.com:443 \
  -key-file enigma.key
```

The client uses system roots unless `-tls-ca-file` is supplied. The
`-tls-insecure-skip-verify` option disables certificate verification and should
only be used for isolated testing.

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
| `-allow-target` | unrestricted | Exact host, `*.domain`, or CIDR target rule; repeatable |
| `-mux` | `false` | Reuse one authenticated connection for multiple streams |
| `-udp` | `false` | Handle fixed-target UoT streams; requires `-mux` |
| `-tls` | `false` | Wrap accepted connections with TLS |
| `-tls-cert` | none | TLS server certificate PEM; requires `-tls` |
| `-tls-key` | none | TLS server private key PEM; requires `-tls` |
| `-http-camouflage` | `false` | Expect an HTTP/1.1 prelude before ETPH/1 |
| `-http-host` | none | Expected HTTP camouflage Host header |
| `-http-path` | `/` | Expected HTTP camouflage request path |

A full replay cache rejects new authenticated handshakes until entries expire;
it never evicts a live nonce early.

## Client Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-listen` | `127.0.0.1:1080` | Local TCP forwarding address |
| `-server` | none | Required ETPH/1 server `host:port` |
| `-target` | none | Fixed target `host:port`; omit with `-socks5` or `-http-connect` |
| `-socks5` | false | Enable no-auth SOCKS5 target selection |
| `-http-connect` | false | Enable HTTP CONNECT target selection |
| `-tls` | `false` | Wrap the server connection with TLS |
| `-tls-ca-file` | none | PEM CA bundle for TLS server verification |
| `-tls-server-name` | server host | TLS SNI and certificate name |
| `-tls-insecure-skip-verify` | `false` | Disable TLS verification; unsafe and explicit |
| `-http-camouflage` | `false` | Send an HTTP/1.1 prelude before ETPH/1 |
| `-http-host` | server host | HTTP camouflage Host header |
| `-http-path` | `/` | HTTP camouflage request path |
| `-dial-timeout` | `10s` | Server TCP dial timeout |
| `-local-handshake-timeout` | `10s` | Local SOCKS5/HTTP request deadline |
| `-mux` | `false` | Reuse one authenticated connection for multiple local connections |
| `-udp` | `false` | Listen on UDP for one fixed target; requires `-mux` |

## Shutdown and Errors

`Ctrl+C` or `SIGTERM` stops the listener. Existing relays are allowed to finish
independently. Per-connection handshake, target, and relay failures are written
to standard error without stopping the listener.

The current server sends only generic target rejection reasons to clients; full
outbound dial errors remain in server logs.

## Current Limitations

- no TUN or dynamic-target SOCKS UDP association;
- no JSON configuration or automatic service installation;
- no persistent replay database across restarts;
- no defensive fallback;
- mux sessions do not automatically reconnect after the shared connection fails;
- UDP mode supports one fixed target and one active local peer association;
