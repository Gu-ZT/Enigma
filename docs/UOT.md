# UDP over Reliable Transport (UoT, experimental)

[中文说明](./UOT.zh_CN.md)

`internal/uot` carries address-bearing datagrams over an authenticated reliable
stream such as ETP/1 or a mux logical stream. It is a packet framing layer, not
a replacement for UDP congestion control, NAT traversal, or authentication.

## Frame Format

```text
version[1] || flags[1] || address_length[2] || payload_length[4] ||
address[address_length] || payload[payload_length]
```

Version `1` currently requires `flags == 0`. Addresses are carried as bounded
`host:port` strings and payloads are limited by `Config.MaxPacket` (default
65535 bytes). A malformed length or truncated frame terminates the packet
connection; the reader does not resynchronize on untrusted boundaries.

`ReadFrom` returns a packet source as a `net.Addr` with network `udp`. If the
caller provides a buffer smaller than the packet, the packet is consumed and
`io.ErrShortBuffer` is returned after the copied prefix, matching the explicit
bounded-stream behavior of this experimental layer.

The package itself does not create OS UDP sockets. `internal/app` connects a
fixed-target local UDP listener to one UoT mux stream, enabled with `-mux -udp`
on both CLI sides. The current adapter routes replies to the most recently
active local peer and does not implement dynamic SOCKS UDP associations.
