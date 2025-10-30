#!/bin/bash
# Build script for LCP-ABE (Ubuntu/Linux)

echo "=========================================="
echo "Building PQ-ABL LCP-ABE System"
echo "=========================================="

# Check for required tools
command -v cmake >/dev/null 2>&1 || { echo "Error: cmake not found. Install with: sudo apt-get install cmake"; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo "Error: gcc not found. Install with: sudo apt-get install build-essential"; exit 1; }

# Check for OpenSSL (optional but recommended)
if command -v pkg-config >/dev/null 2>&1; then
    if pkg-config --exists openssl; then
        echo "✓ OpenSSL found"
        USE_OPENSSL=ON
    else
        echo "⚠ OpenSSL not found - using stub AES-GCM (NOT SECURE)"
        echo "  Install with: sudo apt-get install libssl-dev"
        USE_OPENSSL=OFF
    fi
else
    echo "⚠ pkg-config not found - assuming OpenSSL available"
    USE_OPENSSL=ON
fi

# Create build directory
echo ""
echo "Creating build directory..."
rm -rf build
mkdir -p build
cd build

# Configure
echo ""
echo "Configuring with CMake..."
cmake .. -DUSE_OPENSSL=$USE_OPENSSL

# Build
echo ""
echo "Building..."
make -j$(nproc)

# Check if build succeeded
if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "✓ Build successful!"
    echo "=========================================="
    echo "Libraries created:"
    ls -lh liblcp_abe.a libmodule_bfrs.a 2>/dev/null || echo "  (check build directory)"
    echo ""
    echo "Next steps:"
    echo "1. Generate log.json file (see logs/log_sample.json)"
    echo "2. Create test programs in test/ directory"
    echo "3. Run: ./test_setup, ./test_keygen, ./test_encrypt, ./test_decrypt"
    echo "=========================================="
else
    echo ""
    echo "=========================================="
    echo "✗ Build failed!"
    echo "=========================================="
    echo "Check error messages above"
    exit 1
fi
