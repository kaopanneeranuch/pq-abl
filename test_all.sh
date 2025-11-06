#!/bin/bash
# Quick test script for LCP-ABE implementation
# Run this on Ubuntu/Linux

set -e  # Exit on error

echo "=========================================="
echo "LCP-ABE Testing Script"
echo "Module-LWE Based CP-ABE Implementation"
echo "=========================================="
echo ""

# Navigate to project root
cd "$(dirname "$0")"

# 1. Clean build
echo ">>> Step 1: Building project..."
rm -rf build
mkdir -p build && cd build
cmake -DUSE_OPENSSL=ON ..
make -j$(nproc)
cd ..
echo "✓ Build complete"
echo ""

# 2. Generate logs
echo ">>> Step 2: Generating test logs..."
python3 gen_log.py -n 1000 --epoch-duration 60 --jitter-seconds 30
echo "✓ Generated logs/log.json"
echo ""

# 3. Create directories
echo ">>> Step 3: Creating output directories..."
mkdir -p keys out/encrypted out/decrypted
echo "✓ Directories created"
echo ""

# 4. Test Setup
echo ">>> Step 4: Testing Setup (Phase 1)..."
./build/test_setup
echo "✓ Setup complete - check keys/MPK.bin and keys/MSK.bin"
echo ""

# 5. Test KeyGen
echo ">>> Step 5: Testing KeyGen (Phase 2)..."
./build/test_keygen
echo "✓ KeyGen complete - check keys/SK_admin_storage.bin"
echo ""

# 6. Test Encrypt
echo ">>> Step 6: Testing Encrypt with Microbatching (Phase 3)..."
./build/test_encrypt
echo "✓ Encryption complete - check out/encrypted/"
echo ""

# 7. Test Decrypt
echo ">>> Step 7: Testing Decrypt (Phase 4)..."
./build/test_decrypt
echo "✓ Decrypt complete - check out/decrypted/"
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Keys generated:"
ls -lh keys/
echo ""
echo "Encrypted batches:"
ls -lh out/encrypted/ | head -10
echo ""
echo "Total batches: $(ls -1 out/encrypted/*.bin 2>/dev/null | wc -l)"
echo ""
echo "✓ All tests complete!"
echo "=========================================="
