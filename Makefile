# Build variables
BINARY_NAME=depscanity
SRC=./cmd/depscanity

# Default target
all: build

# Release build (stripped, optimized)
# -s: disable symbol table
# -w: disable DWARF generation
build:
	@echo "Building release binary..."
	go build -ldflags "-s -w" -o $(BINARY_NAME) $(SRC)

# Debug build (optimizations disabled for Delve)
# -N: disable optimizations
# -l: disable inlining
debug:
	@echo "Building debug binary..."
	go build -gcflags "all=-N -l" -o $(BINARY_NAME)-debug $(SRC)

# Run unit tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-debug
	rm -rf depscanity_out/

.PHONY: all build debug test clean
