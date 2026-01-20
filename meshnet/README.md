# Meshnet: C++ Network Layer

The core networking engine for the Gossip P2P chat.

## Architecture

The network layer is built as a shared/static C++ library (`libgossipnet`) that provides a C-compatible API for Go to consume.

### Components

1. **Connection**: Handles individual TCP sockets, non-blocking I/O, and packet parsing.
2. **ConnectionManager**: Tracks all active peer connections using `epoll` for event multiplexing.
3. **MeshNode**: Manages peer discovery (UDP), connection initiation, and packet routing.
4. **Packet**: Binary serialization/deserialization with Big Endian enforcement.

## Protocol Detail

### Packet Header (14 bytes)

| Offset | Field | Size | Type | Description |
|---|---|---|---|---|
| 0 | Magic | 1 | uint8 | Always `0x47` ('G') |
| 1 | Version | 1 | uint8 | Protocol version |
| 2 | Type | 1 | uint8 | Packet type (MESSAGE, DISCOVER, etc) |
| 3 | Flags | 1 | uint8 | Option flags |
| 4 | Payload Len | 2 | uint16 | Length of the following data |
| 6 | Sequence | 4 | uint32 | Unique ID for the packet |
| 10 | Source ID | 2 | uint16 | Originating node ID |
| 12 | Dest ID | 2 | uint16 | Destination node ID |

### Packet Types
- `0x01` PING / `0x02` PONG
- `0x10` DISCOVER / `0x11` ANNOUNCE
- `0x20` MESSAGE / `0x21` MESSAGE_ACK
- `0x31` FORWARD (Mesh routing)

## CGo Integration

The C++ layer exposes a flat C API in `include/gossip_net.h`.
Critically, the `GossipEvent` struct uses `#pragma pack(1)` to ensure memory layout parity between C++ and Go across different architectures (x86_64 vs aarch64).

## Build System

Uses CMake to produce:
- `libgossipnet.so`: Shared library for dynamic linking.
- `libgossipnet.a`: Static library for integrated builds.

```bash
mkdir build && cd build
cmake ..
make
```
