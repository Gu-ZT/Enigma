---
name: Bug report
about: Report a reproducible problem in the Enigma implementation
title: "[Bug] "
labels: [bug]
assignees: []
---

## Summary

Describe the observed behavior and the behavior you expected.

## Reproduction

List the smallest command sequence or Go test that reproduces the problem.

## Configuration

- Enigma version or commit:
- OS and architecture:
- Go version:
- Mode: fixed TCP / SOCKS5 / HTTP CONNECT / mux / UDP-UoT
- Transport: plain / TLS / HTTP camouflage / TLS plus HTTP camouflage
- Relevant limits: `MaxPayload`, padding ranges, mux or UoT limits

Do not include PSKs, private keys, certificates with private material, or full
wire captures containing application data.

## Logs and failure

Paste the smallest relevant log or error. Redact addresses, tokens, and payloads
that should not be public.

## Additional context

Include whether the failure is deterministic, whether both peers use the same
configuration, and whether `go test ./...` or `go test -race ./...` changes it.
