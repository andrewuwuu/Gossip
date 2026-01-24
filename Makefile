.PHONY: all build clean meshnet gossip run

all: build

build: meshnet gossip

meshnet:
	@echo "Building C++ network library..."
	@mkdir -p meshnet/build
	@cd meshnet/build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$$(nproc)

gossip: meshnet
	@echo "Building Go application..."
	CGO_ENABLED=1 LD_LIBRARY_PATH=./meshnet/build go build -v -o gossip .

run: build
	@echo "Starting application..."
	@LD_LIBRARY_PATH=./meshnet/build ./gossip

run-tui: build
	@echo "Starting application (TUI mode)..."
	@# Assuming TUI is default or flag needed. Based on code, TUI starts if not disabled.
	@# Actually, CLI.Run() starts TUI if c.ui != nil. NewCLI initializes TUI.
	@# So standard run should show TUI unless flags change behavior.
	@# But user asked for specific target.
	@LD_LIBRARY_PATH=./meshnet/build ./gossip

clean:
	@echo "Cleaning..."
	@rm -rf meshnet/build
	@rm -f gossip

install: build
	@echo "Installing library..."
	@sudo cp meshnet/build/libgossipnet.so /usr/local/lib/
	@sudo ldconfig
	@echo "Installing binary..."
	@sudo cp gossip /usr/local/bin/

dev: meshnet
	@CGO_ENABLED=1 LD_LIBRARY_PATH=./meshnet/build go run .

test: meshnet
	@echo "Running tests..."
	@CGO_ENABLED=1 LD_LIBRARY_PATH=./meshnet/build go test ./...

help:
	@echo "Gossip P2P Mesh Chat - Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make build    - Build everything (C++ lib + Go app)"
	@echo "  make meshnet  - Build only C++ network library"
	@echo "  make gossip   - Build only Go application"
	@echo "  make run      - Build and run the application"
	@echo "  make dev      - Run in development mode (go run)"
	@echo "  make clean    - Remove all build artifacts"
	@echo "  make install  - Install library and binary system-wide"
	@echo "  make test     - Run tests"
	@echo "  make help     - Show this help message"
