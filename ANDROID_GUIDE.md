# Gossip Android Guide

This guide details how to build and run Gossip on Android devices using Termux.

## Prerequisites

1.  **Install Termux**: Get it from F-Droid (Google Play version is deprecated).
2.  **Update Packages**:
    ```bash
    pkg update && pkg upgrade
    ```
3.  **Install Build Tools**:
    ```bash
    pkg install git cmake golang build-essential
    ```

## Building

We provide a dedicated build script for Android/Termux environments that handles CGo linking and library paths.

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/andrewuwuu/Gossip.git
    cd Gossip
    ```

2.  **Run Build Script**:
    ```bash
    ./build_android.sh
    ```

    *If you encounter permission errors, make the script executable:*
    ```bash
    chmod +x build_android.sh
    ```

## Running

To run the application, you must set the `LD_LIBRARY_PATH` so the runtime can find the C++ shared library.

```bash
export LD_LIBRARY_PATH=$(pwd)/meshnet/build
./gossip
```

### Shortcuts

You can add an alias to your `.bashrc` or `.zshrc` in Termux:

```bash
echo 'alias run-gossip="export LD_LIBRARY_PATH=$HOME/Gossip/meshnet/build && $HOME/Gossip/gossip"' >> ~/.bashrc
source ~/.bashrc
```

Then just type `run-gossip`.

## Troubleshooting

### "Shared object not found"
If you see an error about `libgossipnet.so` not being found, ensure you have exported `LD_LIBRARY_PATH`:
```bash
export LD_LIBRARY_PATH=$(pwd)/meshnet/build
```

### Port Permission Denied
Android blocks ports under 1024. Use ports above 1024 (default 19000/19001 are safe).

### "Wait for more data" hangs
If the application hangs on startup, it might be due to slow entropy generation or network interface enumeration on some devices. Give it a few seconds.

### Display Issues
If the TUI looks broken (characters misaligned), ensure your Termux font supports UTF-8 line drawing characters. The TUI automatically adjusts to screen size, but very small screens might clip the interface.
