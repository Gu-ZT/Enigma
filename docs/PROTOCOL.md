# Enigma Traffic Protocol 1 (ETP/1)

Status: **experimental, wire behavior locked by test vectors**

This document describes the wire behavior implemented by `pkg/enigma`. It is
the protocol reference for the current repository, while `PLAN.md` describes
future work. ETP/1 has no assigned standard identifier.

## 1. Scope and Requirements

ETP/1 carries an arbitrary byte stream over an ordered, reliable transport. It
requires a pre-shared key (PSK) of at least 32 bytes and compatible cover
settings at both peers.

The protocol provides:

- per-record confidentiality and integrity with AES-256-GCM;
- independent cryptographic and rotor state in each direction;
- an Enigma-inspired involutive representation transform;
- printable wire symbols with ignorable configured padding;
- bounded record parsing.

It does not define peer roles, target addresses, application authentication,
forward secrecy, cross-connection replay prevention, multiplexing, or traffic
timing protection.

All integers below use unsigned big-endian encoding. Byte arithmetic in the
rotor machine is modulo 256.

## 2. Directional Stream

Each connection direction is an independent half-stream. The first non-empty
write in a direction generates a random 16-byte `session_salt`. Sequence numbers
start at zero and increase by one for every successfully written record.

```text
direction := Cover(session_salt) || Cover(frame_0) || Cover(frame_1) || ...

frame_n := Enigma_n(masked_length || ciphertext)
```

The salt is cover-encoded but is not passed through the rotor machine. Cover
padding may appear in the salt encoding, so a receiver reads 16 decoded bytes
rather than a fixed number of wire characters.

The all-ones `uint64` sequence value is reserved as the exhaustion boundary and
is not used for a record.

## 3. Domain-separated Derivation

The derivation prefix is the ASCII string:

```text
enigma/etp/v1/
```

The 32-byte master value is:

```text
master = HMAC-SHA-256(PSK, "enigma/etp/v1/master")
```

ETP/1 uses the following expansion function, where `i` starts at 1:

```text
block_i = HMAC-SHA-256(
    key,
    ASCII("enigma/etp/v1/" || label) ||
    U32BE(len(context)) || context || U32BE(i)
)

Expand(key, label, context, size) =
    first size bytes of (block_1 || block_2 || ...)
```

For each directional `session_salt`:

```text
traffic_key = Expand(master, "traffic-key", session_salt, 32)
rotor_seed  = Expand(master, "rotor-seed",  session_salt, 32)
length_key  = Expand(master, "length-key", session_salt, 32)
nonce_head  = Expand(master, "nonce-prefix", session_salt, 4)
```

AES-256-GCM is initialized with `traffic_key`.

## 4. Authenticated Record

### 4.1 Plaintext

```text
plaintext := version[1] || payload_length[2] || payload || random_padding
```

- `version` is `0x01`;
- `payload_length` is the number of payload bytes and must be non-zero;
- `payload` is at most the configured `MaxPayload`;
- `random_padding` is locally selected within the configured record-padding
  range and filled from `crypto/rand`.

The default maximum payload is 16384 bytes. Implementations in this repository
reject configured payload limits above 32768 bytes and record padding above
8192 bytes.

### 4.2 Nonce and associated data

For sequence `seq`:

```text
nonce = nonce_head[4] || U64BE(seq)

ciphertext_length = len(plaintext) + 16

aad = ASCII("enigma/etp/v1/frame") ||
      U64BE(seq) || U16BE(ciphertext_length)
```

`ciphertext` is the AES-GCM seal of `plaintext` under `nonce` and `aad`. The
16-byte GCM tag is included in `ciphertext_length`.

### 4.3 Masked length

```text
length_mask = Expand(length_key, "length-mask", U64BE(seq), 2)
masked_length = U16BE(ciphertext_length) XOR length_mask
```

`masked_length || ciphertext` is transformed by the frame-specific rotor
machine as one continuous byte sequence. The receiver transforms the first two
bytes, removes the mask, validates the resulting length, and only then reads and
allocates the ciphertext body.

The decoded ciphertext length must be at least 20 bytes (one payload byte,
three inner-header bytes, and a 16-byte GCM tag) and no larger than:

```text
3 + configured MaxPayload + configured MaxPadding + 16
```

## 5. Rotor Machine

The machine alphabet contains all byte values `0..255`. A directional rotor set
contains three rotor permutations and their inverses, three turnover notches, a
plugboard involution, and a fixed-point-free reflector involution.

### 5.1 Deterministic table stream

Table construction uses this deterministic stream:

```text
table_key = HMAC-SHA-256(rotor_seed, "enigma/etp/v1/table-prng")
stream_i  = HMAC-SHA-256(table_key, U64BE(i)), i = 0, 1, 2, ...
stream    = stream_0 || stream_1 || ...
```

`nextUint32` consumes consecutive four-byte big-endian values from `stream`.
`intn(n)` is `nextUint32 mod n`.

A permutation is built by initializing `[0, 1, ..., 255]`, then applying
Fisher-Yates from index 255 down to 1 with `j = intn(i+1)`.

Construction consumes the deterministic stream in this order:

1. one permutation and one `intn(256)` notch for each of three rotors;
2. one permutation whose adjacent values are paired to form the plugboard;
3. one permutation whose adjacent values are paired to form the reflector.

Pairing shuffled values `(a,b)` sets both `map[a]=b` and `map[b]=a`. The rotor
inverse tables are constructed from their forward permutations.

### 5.2 Per-frame state

```text
state_key = Expand(rotor_seed, "rotor-state-key", empty, 32)
state     = Expand(state_key, "frame-rotor-state", U64BE(seq), 6)

positions = state[0:3]
rings     = state[3:6]
```

The machine is reset to this state at the start of every frame.

### 5.3 Stepping

Before transforming every byte:

1. increment fast rotor position 0;
2. if position 0 equals notch 0, increment position 1;
3. if position 1 then equals notch 1, increment position 2.

This is an Enigma-inspired odometer step, not an exact reproduction of a
historical machine's double-stepping behavior.

### 5.4 Signal path

For rotor `r`, position `p`, and ring `g`:

```text
Forward(r, x, p, g) = r.forward[x + p - g] - p + g
Reverse(r, x, p, g) = r.inverse[x + p - g] - p + g
```

After stepping, a byte follows this path:

```text
plugboard
-> rotor 0 forward -> rotor 1 forward -> rotor 2 forward
-> reflector
-> rotor 2 reverse -> rotor 1 reverse -> rotor 0 reverse
-> plugboard
```

Because the plugboard and reflector are involutions and the return path uses
inverse rotor maps, applying the same stepping state a second time recovers the
input.

## 6. Printable Cover Codec

The cover alphabet contains exactly 64 unique printable ASCII bytes. Its order
defines symbol indices `0..63`. The default is:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_
```

For transformed byte `b`, one random byte `r` selects synonym bits:

```text
high_index = (b >> 4)   | ((r & 0x03) << 4)
low_index  = (b & 0x0f) | (((r >> 2) & 0x03) << 4)

encoded_byte = alphabet[high_index] || alphabet[low_index]
```

The decoder looks up each symbol index and uses only its low four bits. Thus
every nibble has four possible printable representations.

For every encoded salt or frame, the sender independently chooses a configured
number of cover-padding characters. Each character is placed into a randomly
selected one of the `2*decoded_length + 1` slots before, between, or after cover
symbols. Padding characters must come from a configured alphabet disjoint from
the cover alphabet.

The decoder ignores configured padding bytes. Any byte in neither alphabet is a
terminal `ErrUnexpectedCoverByte`. EOF after only one symbol of a byte is a
truncated stream.

## 7. Receiver Validation and Failure

A receiver performs these checks before returning payload bytes:

1. decode exactly 16 session-salt bytes;
2. transform, unmask, and bound-check the record length;
3. read and transform the complete ciphertext;
4. authenticate AES-GCM with the implicit sequence and decoded length;
5. verify inner version `0x01`;
6. verify non-zero payload length and configured payload limit;
7. verify that remaining inner padding does not exceed `MaxPadding`.

AEAD failure maps to `ErrAuthentication`. Invalid length, version, payload, or
padding maps to `ErrInvalidFrame`. These errors are terminal for the read
direction; ETP/1 does not scan for a new record boundary after failure.

## 8. Security Considerations

- Rotor tables and cover alphabets do not add cryptographic strength beyond
  AES-256-GCM.
- A fresh random directional salt makes traffic keys independent with collision
  probability bounded by the 128-bit salt space.
- Nonces are unique within a direction while the salt is unique and sequence
  numbers do not repeat.
- The salt is public. Its purpose is key separation, not secrecy.
- The current protocol has no transcript handshake or salt replay cache, so a
  complete directional stream can be replayed.
- Wrong-key input can fail at the masked-length check before reaching GCM. If a
  wrong decoded length is within bounds, transport deadlines remain necessary
  to limit how long a receiver waits for the claimed body.
- Printable encoding and padding alter representation but do not hide timing,
  endpoints, or traffic volume.

## 9. Versioning

ETP/1 carries its version only inside authenticated plaintext and has no public
magic prefix or negotiation message. Incompatible peers fail length validation
or record authentication.

The derivation functions, table construction, stepping, record fields, and cover
encoding documented here are the ETP/1 compatibility contract. The
[machine-readable vector](../pkg/enigma/testdata/etp1-vectors.json) locks
representative outputs. Bug fixes and optimizations must preserve those outputs.

Any intentional incompatible change must use a new protocol identifier such as
ETP/2 and a distinct derivation prefix. Because ETP/1 has no in-band negotiation,
applications must select future versions out of band rather than probing on the
same stream.

The machine-readable derivation vector and the external-package public API
interoperability matrix form the current compatibility gate. Complete-record
cross-language vectors remain future work because sender randomness is visible
in salts, padding, and cover variants.
