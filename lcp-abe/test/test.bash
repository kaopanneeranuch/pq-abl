# Build libs (run once)
mkdir -p build && cd build
cmake -DUSE_OPENSSL=ON ..
make -j
cd ..

# Generate test log file (example)
python3 gen_log.py -n 1000 --epoch-duration 60 --jitter-seconds 30

# Create output/key dirs
mkdir -p keys out/encrypted out/decrypted

# Setup (produce MPK and MSK)
gcc -O3 -I. -I./lcp-abe -I./lcp-abe/common -I./lcp-abe/setup -I./lcp-abe/util \
  lcp-abe/test/setup.c \
  -L./build -llcp_abe -lmodule_bfrs -lssl -lcrypto -lm \
  -o lcp-abe/test/test_setup
# To run later: ./lcp-abe/test/test_setup
# expected: keys/MPK.bin keys/MSK.bin

# KeyGen (produce a user SK for an attribute set)
gcc -O3 -I. -I./lcp-abe -I./lcp-abe/common -I./lcp-abe/keygen -I./lcp-abe/util \
  lcp-abe/test/keygen.c \
  -L./build -llcp_abe -lmodule_bfrs -lssl -lcrypto -lm \
  -o lcp-abe/test/test_keygen
# To run later: ./lcp-abe/test/test_keygen
# expected: keys/SK_admin_storage.bin

# Encrypt (produce ciphertexts per epoch+policy)
gcc -O3 -I. -I./lcp-abe -I./lcp-abe/common -I./lcp-abe/encrypt -I./lcp-abe/util \
  lcp-abe/test/encrypt.c \
  -L./build -llcp_abe -lmodule_bfrs -lssl -lcrypto -lm \
  -o lcp-abe/test/test_encrypt
# To run later: ./lcp-abe/test/test_encrypt
# expected: out/encrypted/*.json

# Decrypt (recover logs for a user SK and ciphertext)
gcc -O3 -I. -I./lcp-abe -I./lcp-abe/common -I./lcp-abe/decrypt -I./lcp-abe/util \
  lcp-abe/test/decrypt.c \
  -L./build -llcp_abe -lmodule_bfrs -lssl -lcrypto -lm \
  -o lcp-abe/test/test_decrypt
# To run later: ./lcp-abe/test/test_decrypt
# expected: out/decrypted/*.json or plaintext files for each CT_obj