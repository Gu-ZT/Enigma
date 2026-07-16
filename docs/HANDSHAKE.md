# Enigma Tunnel Handshake 1 (ETPH/1)

Status: **experimental**

ETPH/1 is the authenticated key-establishment layer implemented by
`internal/tunnel`. It runs before ETP/1 on the same ordered, reliable
`net.Conn`, derives a forward-secret 32-byte session key, and then supplies that
key to `pkg/enigma`.

ETPH/1 authenticates a pre-shared-key group. It does not distinguish individual
users that share the same PSK.

## 1. Parameters

- PSK: at least 32 high-entropy bytes;
- key agreement: ephemeral X25519;
- handshake protection: AES-256-GCM;
- hash and KDF primitive: HMAC-SHA-256;
- client nonce: 16 random bytes;
- server nonce: 16 random bytes;
- outer GCM nonce: 12 random bytes per packet;
- default handshake timeout: 10 seconds;
- default accepted client clock skew: 60 seconds.

The derivation prefix is:

```text
enigma/etph/v1/
```

## 2. Packet Protection

The handshake key is:

```text
handshake_key = HMAC-SHA-256(
    PSK,
    ASCII("enigma/etph/v1/handshake-key")
)
```

Each packet is encoded as:

```text
packet := outer_nonce[12] || AES-256-GCM-Seal(
    key = handshake_key,
    nonce = outer_nonce,
    plaintext,
    associated_data
)
```

The 16-byte GCM tag is appended by `Seal`. No plaintext magic or version bytes
appear outside authenticated encryption.

## 3. Client Hello

The client generates an ephemeral X25519 key pair and sends an 86-byte packet.

```text
client_plaintext :=
    version[1]          = 0x01
    type[1]             = 0x01
    unix_timestamp[8]   = signed Unix seconds encoded as two's-complement BE
    client_nonce[16]
    client_public[32]

client_aad := ASCII("enigma/etph/v1/client")
```

The server authenticates the packet before parsing its timestamp, nonce, or
public key. It then:

1. requires the timestamp to fall within `now +/- MaxClockSkew`;
2. atomically inserts `client_nonce` into the configured replay guard;
3. rejects a nonce already present and unexpired;
4. validates the X25519 public key during key agreement.

The replay guard TTL must be at least twice `MaxClockSkew`, covering the full
time in which a hello can remain valid. The implementation caps
`MaxClockSkew` at 10 minutes.

## 4. Server Hello

The server generates its own ephemeral X25519 key pair and nonce, then sends a
94-byte response.

```text
server_plaintext :=
    version[1]          = 0x01
    type[1]             = 0x02
    echoed_client_nonce[16]
    server_nonce[16]
    server_public[32]

client_packet_hash := SHA-256(exact_client_packet)
server_aad := ASCII("enigma/etph/v1/server") || client_packet_hash
```

Binding the exact encrypted client packet into server AAD prevents a response
from being detached from the initiating transcript. The echoed nonce gives the
client an additional explicit request/response check.

## 5. Session Key

Both peers compute:

```text
shared = X25519(local_ephemeral_private, peer_ephemeral_public)

extract_input =
    ASCII("enigma/etph/v1/extract") || client_nonce || server_nonce

extract_salt = HMAC-SHA-256(PSK, extract_input)
prk          = HMAC-SHA-256(extract_salt, shared)

session_context =
    ASCII("enigma/etph/v1/session-key") ||
    client_public || server_public

session_key = HMAC-SHA-256(prk, session_context)
```

The 32-byte `session_key` replaces `enigma.Config.Key` when the underlying
stream is upgraded to ETP/1. ETP/1 then creates independent directional salts,
traffic keys, nonces, and rotor state from this session key.

Assuming ephemeral private keys are not retained, later disclosure of the PSK
does not reveal captured ETP/1 traffic keys because the X25519 shared secret
cannot be reconstructed from public keys alone.

## 6. API and Deadlines

```go
guard, err := tunnel.NewReplayGuard(4096, 2*time.Minute)

serverConn, err := tunnel.NewServerConn(rawServer, tunnel.Config{
    Codec:      codecConfig,
    ReplayGuard: guard,
})

clientConn, err := tunnel.NewClientConn(rawClient, tunnel.Config{
    Codec: codecConfig,
})
```

Servers must share a `ReplayGuard` across accepted connections. Creating one
guard per connection provides no replay protection.

`NewClientConn` and `NewServerConn` set a whole-connection deadline for the
handshake and clear it after a successful upgrade. Callers remain responsible
for closing failed raw connections and setting application traffic deadlines.

`internal/tunnel` is internal to this Go module. A stable external facade will
be added when the client/server application layer is introduced.

## 7. Failure Behavior

- GCM failure: `ErrAuthentication`;
- wrong version, message type, nonce echo, or X25519 input: `ErrProtocol`;
- duplicate authenticated client nonce: `ErrReplay`;
- replay cache at live-entry capacity: `ErrReplayCacheFull`;
- timestamp outside the configured window: `ErrClockSkew`;
- short reads, deadlines, and closed connections: wrapped transport errors.

Handshake failure is terminal for that raw connection. The implementation does
not send distinguishable protocol error responses.

## 8. Security and Traffic Considerations

- The PSK must be random and securely distributed. Passwords are not stretched.
- All holders of one PSK can authenticate as either side.
- The replay cache is bounded and in-memory; it does not survive process restart.
- A full replay cache rejects new authenticated hellos until entries expire;
  it never evicts a live nonce early. Size the cache for the expected connection
  rate and TTL to avoid availability loss.
- Fixed packet lengths and handshake timing are observable even though packet
  contents have no plaintext magic.
- The handshake packets are binary high-entropy data. HTTP/TLS camouflage and
  fallback behavior are separate future transport features.
- ETPH/1 does not negotiate protocol versions. Future incompatible handshakes
  require an out-of-band selection or a separately designed negotiation layer.

## 9. Compatibility Vector

The [machine-readable ETPH/1 vector](../internal/tunnel/testdata/etph1-vectors.json)
fixes representative private/public keys, nonces, plaintexts, complete encrypted
packets, shared secret, intermediate KDF values, and final session key. Protocol
optimizations must preserve these outputs. Intentional incompatible changes
require a new handshake identifier and derivation prefix.
