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
- [ ] **Encryption**: (Planned) P2P encryption using ChaCha20-Poly1305.

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
```

## Protocol Specification

See [meshnet/README.md](./meshnet/README.md) for detailed networking technicals.

## Troubleshooting

### Connection Drops
If you see frequent disconnects, ensure both nodes are using the latest version as byte alignment and endianness are critical for connectivity.

### Building on Android (Termux)
Use the provided `build_android.sh` script in the root directory. Refer to [ANDROID_GUIDE.md](./ANDROID_GUIDE.md) for detailed steps.
