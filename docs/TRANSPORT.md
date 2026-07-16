# Optional Transport Wrappers (experimental)

[中文说明](./TRANSPORT.zh_CN.md)

`internal/transport` contains wrappers that may run below ETPH/1. They are
deliberately independent from the ETP/1 codec, mux, UoT, and target policy.

## HTTP/1.1 Prelude

`ClientHTTP` sends a bounded `POST path HTTP/1.1` request with an empty body;
`ServerHTTP` validates the method, path, optional Host header, and empty-body
headers before returning `200 OK`. Both sides preserve bytes already buffered
after the header terminator, so ETPH/1 can start immediately afterward.

This is representation camouflage only. Cleartext HTTP does not provide
confidentiality, certificate authentication, or resistance to active protocol
inspection. The wrapper rejects non-empty bodies, transfer encoding, malformed
headers, and headers above the configured limit.

## TLS Wrapper

`ClientTLS` and `ServerTLS` use Go's maintained `crypto/tls` implementation and
perform an explicit handshake with an optional deadline. The caller supplies
certificates, trust roots, SNI, and verification policy through `tls.Config`.
The library does not silently enable `InsecureSkipVerify`; callers should use a
private CA or pinned certificate for deployments without public certificates.

The CLI enables these wrappers with `-tls` and/or
`-http-camouflage`. Server mode requires a certificate and key; client
verification uses system roots or `-tls-ca-file`, with
`-tls-insecure-skip-verify` as an explicit unsafe escape hatch. When both modes
are enabled, TLS is established first and the HTTP prelude runs inside TLS.
