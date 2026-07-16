# Changelog

This file records user-visible changes for Enigma Traffic Protocol. Version
`0.1.0` is the first experimental release. ETP/1 and ETPH/1 are not yet stable
compatibility commitments.

## 0.1.0 - 2026-07-17

### Added

- ETP/1 authenticated printable stream codec in `pkg/enigma`:
  - AES-256-GCM record confidentiality and authentication;
  - independent directional salts, keys, sequences, and state;
  - Enigma-inspired plugboard, rotors, stepping, and reflector transform;
  - printable 64-symbol cover encoding with randomized variants;
  - configurable authenticated padding and ignorable cover padding;
  - bounded records, length validation, partial reads, and `net.Conn` behavior.
- ETPH/1 authenticated tunnel setup in `internal/tunnel`:
  - PSK-protected ephemeral X25519 key agreement;
  - forward-secret session keys for ETP/1;
  - timestamp skew validation;
  - bounded in-memory client-nonce replay protection;
  - authenticated target request and response messages.
- Command-line application in `cmd/enigma`:
  - `keygen` for 32-byte random PSKs;
  - fixed-target TCP forwarding;
  - unauthenticated local SOCKS5 `CONNECT`;
  - HTTP CONNECT local target selection;
  - mux mode for multiple TCP logical streams over one tunnel;
  - fixed-target UDP/UoT mode over a mux stream;
  - exact, wildcard-domain, and CIDR target allow rules;
  - optional TLS and HTTP/1.1 camouflage transport wrappers.
- Internal transport components:
  - bounded mux `OPEN`/`DATA`/`CLOSE`/`RESET` frames;
  - bounded UDP-over-reliable-stream packet framing;
  - standard-library TLS handshake wrappers;
  - bounded HTTP prelude camouflage that preserves buffered ETPH/1 bytes.
- Compatibility vectors, fuzz targets, benchmarks, loopback integration tests,
  and coverage-oriented unit tests for protocol and application behavior.
- Bilingual protocol, handshake, configuration, command, architecture, mux,
  UoT, and transport documentation.
- GitHub Actions CI and release workflows for Linux, macOS, and Windows builds,
  plus a reproducible bug-report template.

### Security and behavior notes

- The rotor transform is obfuscation, not cryptographic protection. Payload
  security comes from maintained AEAD primitives in the Go standard library.
- Authentication, structural, or untrusted-length failures are terminal for the
  affected stream direction; the implementation does not resynchronize.
- Direct `pkg/enigma.NewConn` use provides no forward secrecy or replay cache.
  Applications that accept untrusted peers should use ETPH/1 or provide an
  equivalent authenticated handshake.
- TLS certificate verification is enabled by default on the client. The
  `-tls-insecure-skip-verify` option is an explicit unsafe testing override.

### Known limitations

- The release is experimental and does not promise long-term ETP/1 or ETPH/1
  wire compatibility.
- Mux sessions are single-shot and do not automatically reconnect after the
  shared connection fails.
- UDP/UoT is fixed-target and routes replies to the most recently active local
  UDP peer; it is not a dynamic-target SOCKS UDP association.
- Replay protection is process-local and is not persisted across restarts.
- TUN support, defensive fallback, dynamic traffic-shape hiding, and broader
  proxy profiles are not included.
- The printable cover format has two-symbol-per-byte base overhead before
  optional padding.

### Verification

The release gate is intended to run:

```bash
go test ./...
go vet ./...
go build ./cmd/enigma
```

Run `go test -race ./...` on platforms with a working CGO compiler.
