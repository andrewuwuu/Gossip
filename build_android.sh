#!/bin/bash
# Build script specifically for Android (Termux) environment

echo "=== Android/Termux Build Script ==="

# Check for required tools
if ! command -v cmake &> /dev/null; then
    echo "Error: cmake is not installed. Run: pkg install cmake"
    exit 1
fi

if ! command -v go &> /dev/null; then
    echo "Error: go is not installed. Run: pkg install golang"
    exit 1
fi

# Clean previous build
echo "Cleaning previous builds..."
rm -rf meshnet/build
rm -f gossip

# Build C++ library
echo "Building C++ library..."
mkdir -p meshnet/build
cd meshnet/build

# Standard CMake build (Termux usually sets up paths correctly)
cmake .. -DCMAKE_BUILD_TYPE=Release
if [ $? -ne 0 ]; then
    echo "Error: CMake configuration failed."
    exit 1
fi

make -j$(nproc)
if [ $? -ne 0 ]; then
    echo "Error: C++ library build failed."
    exit 1
fi

cd ../..

# Build Go application
echo "Building Go application..."
# Set CGo environment variables for Termux
export CGO_ENABLED=1
export LD_LIBRARY_PATH=$(pwd)/meshnet/build

go build -o gossip .
if [ $? -ne 0 ]; then
    echo "Error: Go build failed."
    exit 1
fi

echo "=== Build Success! ==="
echo "To run:"
echo "export LD_LIBRARY_PATH=$(pwd)/meshnet/build"
echo "./gossip"
