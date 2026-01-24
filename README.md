# Gossip: P2P Mesh Chat

A private, peer-to-peer mesh chat application built with Go and C++.

## Overview

Gossip uses a hybrid architecture:
- **C++ Network Layer**: High-performance networking using TCP/UDP, manual binary serialization, and `epoll` for efficient I/O.
- **Go Application Layer**: Robust application logic, CLI interface, and peer management using CGo to bridge with the network layer.

## Features

- [x] **Automatic Peer Discovery**: Uses UDP broadcasting (Signed Beacons) to find other nodes on the local network.
- [x] **Mesh Routing**: Nodes automatically forward messages to reach peers not in direct range.
- [x] **Reliable Transport**: TCP-based connections with custom v1.0 packet framing and heartbeat.
- [x] **Cross-Platform Support**: Optimized for Linux (WSL2), Linux (Native), and Android (Termux).
- [x] **Secure Handshake**: Ephemeral X25519 key exchange with HKDF-SHA256 session derivation (Gossip Protocol v1.0).
- [x] **Identity Trust**: Ed25519 signatures and TOFU (Trust On First Use) identity pinning.

## Project Structure

```text
Gossip/
├── internal/            # Go application logic
│   ├── chat/            # CLI and message handling
│   ├── config/          # Environment configuration
│   └── meshnet/         # CGo bindings and Go network adapter
├── meshnet/             # C++ Network Layer (Shared Library)
│   ├── include/         # Header files
│   └── src/             # Implementation
├── main.go              # Application entry point
├── Makefile             # Root build system
└── .env                 # Configuration file
```

## Getting Started

### Prerequisites

- **Go**: 1.21+
- **C++ Compiler**: GCC 14+ or Clang equivalent
- **Build Tools**: CMake, Make
- **Architecture**: Linux (x86_64, aarch64)

### Build & Run (Linux/WSL2)

1. Clone the repository.
2. Build the project:
   ```bash
   make build
   ```
3. Run the application:
   ```bash
   make run
   ```

### Configuration

Configuration is managed via the `.env` file:
```env
NODE_PORT=19000
DISCOVERY_PORT=19001
USERNAME=anonymous

# Optional: Enable encryption (64-char hex, generate with: openssl rand -hex 32)
# GOSSIP_SESSION_KEY=your_64_char_hex_key_here
```

### Identity & Encryption

Gossip now uses a zero-configuration PKI system (Protocol v1.0).

1.  **Identity Generation**: The first time you run the app, it will generate a secure Ed25519 keypair.
2.  **Public Key**: Your Node ID is derived from your public key.
3.  **Trust**: When connecting to a peer for the first time, their public key is pinned. Subsequent connections MUST match this key or they will be rejected (TOFU).
4.  **Encryption**: All sessions are encrypted with forward-secret XChaCha20-Poly1305 keys derived from an ephemeral X25519 handshake.

Manual key configuration (via `GOSSIP_SESSION_KEY`) is considered legacy and deprecated.

## Protocol Specification

See [meshnet/README.md](./meshnet/README.md) for detailed networking technicals.

## Troubleshooting

### Connection Drops
If you see frequent disconnects, ensure both nodes are using the latest version as byte alignment and endianness are critical for connectivity.

### Building on Android (Termux)
Full instructions are available in [ANDROID_GUIDE.md](./ANDROID_GUIDE.md).
Quick start:
```bash
./build_android.sh
```
