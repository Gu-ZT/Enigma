# Enigma Traffic Protocol (ETP/1) Implementation Plan

## 1. Goal

Build a reusable Go traffic-obfuscation layer inspired by the operating model of
an Enigma machine. The first milestone is a `net.Conn` wrapper that can carry an
arbitrary reliable byte stream while providing:

- per-direction session state;
- a plugboard, multiple rotors, stepping, and a reflector;
- authenticated encryption independent of the Enigma transform;
- a printable, configurable wire alphabet;
- ignorable padding inserted at arbitrary encoded positions;
- bounded frames and predictable memory use.

The implementation takes architectural lessons from `ref/sudoku-main`: keep the
obfuscator as an independent transport layer, make padding self-identifying, and
test the wrapper through real stream semantics. No source code or wire format is
copied from that GPL-licensed reference.

## 2. Security Boundary

The Enigma transform is **not encryption**. It only changes the representation
and state evolution of already encrypted records. ETP/1 uses AES-256-GCM for
confidentiality, integrity, and per-record authentication.

ETP/1 v1 is a pre-shared-key transport codec, not a complete proxy protocol:

- it does not negotiate destinations or implement SOCKS; those behaviors and
  mux/UoT are separate application protocols above ETP/1;
- it does not provide forward secrecy;
- it does not hide timing, total byte count, or connection endpoints;
- it does not prevent replay of an entire captured connection by itself;
- it assumes an ordered, reliable underlying stream such as TCP;
- authentication failure is terminal for that direction.

Direct `pkg/enigma` callers that accept untrusted peers must add an authenticated
application handshake and replay cache above ETP/1. The optional internal
ETPH/1 layer now provides ephemeral X25519 key establishment and bounded replay
protection without changing the codec package's role.

## 3. ETP/1 Wire Model

Each direction is a separate half-stream. Its sender creates an independent
16-byte random salt on first use. There is no shared mutable read/write state.

```text
direction := Cover(session_salt) || Cover(frame_0) || Cover(frame_1) || ...

frame_n := Enigma_n(masked_length || aead_ciphertext)

plaintext := version || payload_length || payload || random_padding
```

### 3.1 Key derivation

Domain-separated HMAC-SHA-256 derives independent values from the PSK and the
direction's session salt:

- an AES-256-GCM traffic key;
- a rotor construction seed;
- per-frame starting positions and ring settings;
- a two-byte length mask.

Every derivation includes the exact `enigma/etp/v1/...` context string. Keys and
salts are never used directly as rotor tables.

### 3.2 Authenticated record

- Payloads are split into records of at most 16 KiB by default.
- The inner plaintext stores protocol version, payload length, payload, and
  random padding.
- The AES-GCM nonce is derived from the session-specific traffic key and the
  monotonically increasing 64-bit frame sequence.
- The sequence, protocol context, and encoded ciphertext length are AEAD
  associated data.
- The two-byte ciphertext length is masked, then transformed together with the
  ciphertext. The receiver rejects lengths outside strict configured bounds
  before allocating.
- Sequence numbers are implicit on the wire and strictly ordered by the stream.

### 3.3 Enigma-inspired transform

ETP/1 operates on an alphabet of all 256 byte values:

1. step the fast rotor, carrying at derived notch positions;
2. apply the plugboard;
3. traverse three derived rotors in the forward direction;
4. apply a fixed-point-free derived reflector;
5. traverse the inverse rotor mappings in reverse order;
6. apply the plugboard again.

The transform is involutive for identical initial state. Rotor wiring is derived
with deterministic Fisher-Yates shuffles. Every frame resets its starting state
from the session salt and frame sequence so one malformed frame cannot silently
shift all later rotor positions. On a reliable stream, malformed frames still
terminate the connection because record boundaries can no longer be trusted.

### 3.4 Printable cover encoding and padding

The default cover alphabet contains 64 unique printable ASCII bytes. Each
transformed byte is encoded as two symbols:

- the low four bits of each symbol index carry one nibble;
- the upper two bits are chosen with `crypto/rand`, giving four wire variants
  for every nibble;
- bytes outside the configured cover alphabet are padding and are ignored by
  the decoder;
- padding count is selected per frame from a configured inclusive range and
  padding bytes are distributed among encoded symbols.

This design favors simple, unambiguous stream recovery over bandwidth efficiency;
the base overhead is 2x before AEAD and padding. A framed base64-like 4:3 codec
would be wire-incompatible and is therefore reserved for a future ETP/2
identifier rather than treated as an unfinished ETP/1 feature.

## 4. Package Layout

```text
pkg/enigma/
  config.go       configuration, validation, limits, public constructor
  derive.go       domain-separated deterministic derivation helpers
  rotor.go        plugboard/rotor/reflector construction and transform
  cover.go        printable symbol encoding and padding filtering
  conn.go         framed AEAD net.Conn implementation
  *_test.go       unit, stream, duplex, tamper, and edge-case tests
internal/tunnel/  ETPH/1 X25519 handshake and replay protection
internal/mux/     bounded logical-stream multiplexing above ETP/1
internal/uot/     bounded UDP-over-stream packet framing
internal/transport/ optional HTTP/TLS connection wrappers below ETPH/1
internal/app/     TCP/UDP listeners, target policy, and relay assembly
cmd/enigma/       CLI configuration and process entry point
```

The initial public API is intentionally small:

```go
type Config struct { /* PSK, profile, padding, frame limit */ }
func NewConn(net.Conn, Config) (*Conn, error)
```

`Conn` must preserve ordinary `net.Conn` deadlines and addresses by embedding
the underlying connection. Concurrent one-reader/one-writer use is supported;
concurrent writes are serialized into records.

## 5. Delivery Stages

Current status:

| Stage | Status |
| --- | --- |
| A: protocol core | Complete |
| B: secure stream wrapper | Complete |
| C: hardening | Complete |
| D: integration | Complete |

### Stage A: protocol core

- configuration validation and bounded defaults;
- deterministic KDF and rotor construction;
- involutive rotor transform tests with frame-specific state;
- printable cover codec with ignored padding tests.

### Stage B: secure stream wrapper

- independent lazy salt prelude for each direction;
- AES-256-GCM record sealing/opening;
- partial reads, large writes, empty writes, EOF, and deadline behavior;
- full-duplex operation over `net.Pipe` and loopback TCP.

### Stage C: hardening

- tampered tag, malformed length, wrong key, truncated stream tests;
- fuzz targets for cover decoding and frame parsing;
- benchmarks for allocation rate, throughput, and padding overhead;
- stable protocol test vectors and a compatibility policy; the current
  experimental wire specification lives in `docs/PROTOCOL.md`.

### Stage D: integration (complete)

- authenticated X25519 handshake and bounded replay guard (complete);
- client/server command with explicit target negotiation (complete);
- exact, wildcard-domain, and CIDR target policy rules (complete);
- no-auth SOCKS5 local target selection (complete);
- HTTP CONNECT local target selection (complete);
- bounded mux session and logical-stream core (complete; CLI integration complete);
- bounded UoT packet framing and fixed-target UDP listener integration (complete);
- HTTP/1.1 and standard-library TLS transport wrappers (complete; CLI integration complete);
- CLI mux, fixed-target UDP/UoT, and HTTP/TLS transport flags (complete);
- configurable `standard`, `balanced`, `compact`, and `high-padding` traffic profiles (complete);
- public-API interoperability matrix independent of implementation internals (complete).

## 6. Acceptance Criteria For The First Coding Pass (complete)

- `go test ./...` passes.
- `go vet ./...` passes.
- Rotor transform round-trips all byte values across multiple keys/sequences.
- The cover decoder recovers data across arbitrary read fragmentation and
  ignores only configured non-alphabet padding.
- Two wrapped connections exchange binary payloads concurrently in both
  directions, including payloads larger than one frame.
- Wrong keys and modified ciphertext return errors and never return unauthenticated
  plaintext.
- Frame and padding settings are validated before network I/O or allocation.

All criteria above are covered by unit, black-box interoperability, loopback,
fuzz, vector, or application integration tests in the current tree.

## 7. Future Roadmap

The following work is intentionally outside the completed ETP/1 implementation
plan and requires separate design or a new compatibility identifier:

- ETP/2 negotiation and a more efficient framed 4:3 printable cover codec;
- mux session pooling, health checks, and automatic reconnect;
- dynamic-target SOCKS UDP associations and multi-peer UDP routing;
- persistent replay storage across process restarts;
- TUN integration and defensive HTTP/TLS fallback behavior;
- independent implementations for cross-language wire interoperability.
