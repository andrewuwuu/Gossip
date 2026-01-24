# Meshnet: C++ Network Layer

The core networking engine for the Gossip P2P chat.

## Architecture

The network layer is built as a shared/static C++ library (`libgossipnet`) that provides a C-compatible API for Go to consume.

### Components

1. **Connection**: Handles individual TCP sockets, non-blocking I/O, and packet parsing.
2. **ConnectionManager**: Tracks all active peer connections using `epoll` for event multiplexing.
3. **MeshNode**: Manages peer discovery (UDP), connection initiation, and packet routing.
4. **Packet**: Binary serialization/deserialization (Big Endian).
5. **Crypto**: Ed25519 signatures, X25519 key exchange, SHA-256, and HKDF-SHA256.
6. **Session**: Manages derived XChaCha20-Poly1305 keys, strict directional nonces, and replay protection.
7. **Handshake**: Implements the `HELLO` -> `AUTH` exchange state machine.
8. **TrustStore**: Manages pinned peer identities (TOFU).

## Protocol Detail

### Packet Header (12 bytes)

| Offset | Field | Size | Type | Description |
|---|---|---|---|---|
| 0 | Magic | 1 | uint8 | Always `0x47` ('G') |
| 1 | Version | 1 | uint8 | Protocol version |
| 2 | Type | 1 | uint8 | Packet type (MESSAGE, DISCOVER, etc) |
| 3 | Flags | 1 | uint8 | Option flags |
| 4 | Payload Len | 2 | uint16 | Length of the following data |
| 6 | Sequence | 4 | uint32 | Unique ID for the packet |
| 10 | Source ID | 2 | uint16 | Originating node ID |

### Handshake Protocol (v1.0)

Encryption is negotiated via an ephemeral handshake:

1.  **HELLO (0x01)**: Peers exchange ephemeral X25519 public keys.
2.  **Key Derivation**: Session keys (`K_init`, `K_resp`) are derived using HKDF-SHA256.
3.  **AUTH (0x02)**: Peers exchange their static Ed25519 public key and a signature over the handshake transcript.
4.  **Verification**: The signature is verified. If the peer is known, the public key is checked against the TrustStore (pinning).

### UDP Discovery (v1.0)

Nodes broadcast a signed beacon every 5 seconds on the discovery port.

**Format**: `[ Magic(2) | Version(1) | IK_pub(32) | Timestamp(8) | Signature(64) | Port(2) ]`

- **Signature**: Ed25519 signature covering the beacon content.
- **Timestamp**: Replay protection (valid for ±60 seconds).

### Packet Types
- `0x01` HELLO
- `0x02` AUTH
- `0x10` MSG (Application Data)
- `0x20` PING (Heartbeat)
- `0xFF` ERR (Error)

## CGo Integration

The C++ layer exposes a flat C API in `include/gossip_net.h`.
Critically, the `GossipEvent` struct uses **naturally aligned 64-bit fields** to ensure memory layout parity between C++ and Go across different architectures (x86_64 vs aarch64). This avoids the performance penalty of `#pragma pack(1)` while maintaining identical field offsets for CGo.

## Build System

Uses CMake to produce:
- `libgossipnet.so`: Shared library for dynamic linking.
- `libgossipnet.a`: Static library for integrated builds.

**Build Options:**
- `-DSTATIC_LIBSODIUM=ON`: Link libsodium statically (for portable builds)
- `-DBUILD_TESTS=ON`: Build unit tests

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

### Dependencies

- **libsodium**: Required for cryptographic operations
  - Ubuntu/Debian: `apt install libsodium-dev`
  - Termux: `pkg install libsodium`

