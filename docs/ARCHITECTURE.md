# Architecture and Reference Map

[中文说明](./ARCHITECTURE.zh_CN.md)

This repository is intentionally smaller than `ref/sudoku-main`. The reference
project is architecture research only; its GPL-licensed source, protocol text,
and wire format are not copied or imported here.

## This Repository

| Path | Responsibility | Boundary |
| --- | --- | --- |
| `pkg/enigma/` | ETP/1 stream codec: AES-GCM records, rotor transform, cover encoding, padding, and `net.Conn` semantics | Reusable public package; no command or proxy dependency |
| `internal/tunnel/` | ETPH/1 authenticated X25519 handshake, replay guard, target request/response | Application-private tunnel control plane |
| `internal/app/` | Listener lifecycle, target policy, outbound dialing, SOCKS5, HTTP CONNECT, and bidirectional relay | Runtime assembly; depends on `internal/tunnel` and `pkg/enigma` |
| `cmd/enigma/` | `keygen`, `server`, and `client` CLI parsing and process startup | Executable entry point; must not contain codec behavior |
| `docs/` | Wire specifications, command/configuration guides, and architecture decisions | Human-facing contract and operational guidance |
| `pkg/enigma/testdata/` | Stable ETP/1 derivation vectors | Compatibility fixtures, not runtime configuration |
| `internal/tunnel/testdata/` | Stable ETPH/1 handshake vectors | Handshake compatibility fixtures |
| `PLAN.md` | Milestones, security boundaries, and remaining protocol work | Change-scope record |
| `AGENTS.md` | Repository workflow and invariants | Required engineering rules |

## Reference Project Mapping

The following paths explain why the reference project was inspected and what
kind of design information they provide. They are not implementation
dependencies.

| Reference path | Useful architectural question | ETP equivalent |
| --- | --- | --- |
| `apis/` | Which contracts should be public and dependency-light? | `pkg/enigma` public API and `docs/` contracts |
| `pkg/obfs/sudoku/` | How can a stateful printable transform be isolated from transport code? | `pkg/enigma/rotor.go` and `cover.go` |
| `pkg/crypto/record_conn.go` | Where should record framing, authentication, and stream semantics live? | `pkg/enigma/conn.go` |
| `internal/tunnel/` | How are sessions, handshakes, and connection ownership separated? | `internal/tunnel/handshake.go`, `target.go`, and `internal/app/relay.go` |
| `internal/app/` | How are listeners and protocol-specific local adapters composed? | `internal/app/` plus `cmd/enigma/` |
| `internal/config/` | Which validation belongs at configuration boundaries? | `pkg/enigma/config.go` and CLI validation in `cmd/enigma/main.go` |
| `cmd/` | What belongs in process entry points versus libraries? | `cmd/enigma/main.go` |
| `tests/` and `*_test.go` | Which behaviors need end-to-end and race-sensitive coverage? | Package tests, loopback tests, fuzz targets, and vectors |

## Dependency Direction

```text
cmd/enigma
    |
internal/app ----> internal/tunnel ----> pkg/enigma
    |                    |
    +---- net.Listener    +---- ETPH/1 control messages
```

`pkg/enigma` must remain independent of command code and proxy protocols. A
future mux or UDP profile should therefore be introduced above the stream codec
or under a new protocol identifier, with its own tests and specification.

## Change Guidance

1. A change to record fields, derivation, cover symbols, or failure behavior is
   an ETP/1 protocol change and must update `docs/PROTOCOL.md`, vectors, tests,
   and `PLAN.md`.
2. A new local proxy mode belongs in `internal/app/` and `cmd/enigma/`; it must
   use the existing target negotiation and relay boundaries where possible.
3. A new transport mode such as mux or UDP needs an explicit framing and
   lifecycle design before code is added. It must not be smuggled into the
   existing ETP/1 byte stream as an undocumented extension.
