# Gossip: P2P Mesh Chat

A private, peer-to-peer mesh chat application built with Go and C++.

## Overview

Gossip uses a hybrid architecture:
- **C++ Network Layer**: High-performance networking using TCP/UDP, manual binary serialization, and `epoll` for efficient I/O.
- **Go Application Layer**: Robust application logic, CLI interface, and peer management using CGo to bridge with the network layer.

## Features

- [x] **Automatic Peer Discovery**: Uses UDP broadcasting to find other nodes on the local network.
- [x] **Mesh Routing**: Nodes automatically forward messages to reach peers not in direct range.
- [x] **Reliable Transport**: TCP-based connections with custom packet framing and heartbeat.
- [x] **Cross-Platform Support**: Optimized for Linux (WSL2), Linux (Native), and Android (Termux).
- [x] **Encryption**: XChaCha20-Poly1305 AEAD encryption with replay protection (Gossip Protocol v0.1).

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

### Enabling Encryption

To enable encrypted messaging between peers:

1. Generate a shared key:
   ```bash
   openssl rand -hex 32
   ```

2. Set the key on all peers (via `.env` or environment):
   ```bash
   export GOSSIP_SESSION_KEY=<your_64_char_hex_key>
   ```

All peers must use the same key to communicate. Without a key, messages are sent unencrypted.

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
