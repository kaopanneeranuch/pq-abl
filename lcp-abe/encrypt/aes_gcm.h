#ifndef AES_GCM_H
#define AES_GCM_H

#include "../common/lcp_params.h"
#include <stdint.h>
#include <stddef.h>

// ============================================================================
// AES-256-GCM Encryption/Decryption
// ============================================================================

// Encrypt data with AES-256-GCM
// Input:
//   - plaintext: data to encrypt
//   - plaintext_len: length of plaintext
//   - key: 256-bit encryption key
//   - nonce: 96-bit nonce
//   - aad: additional authenticated data (metadata)
//   - aad_len: length of AAD
// Output:
//   - ciphertext: encrypted data (same length as plaintext)
//   - tag: 128-bit authentication tag
// Returns: 0 on success, -1 on failure
int aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t key[AES_KEY_SIZE],
                    const uint8_t nonce[AES_NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *ciphertext,
                    uint8_t tag[AES_TAG_SIZE]);

// Decrypt data with AES-256-GCM
// Input:
//   - ciphertext: encrypted data
//   - ciphertext_len: length of ciphertext
//   - key: 256-bit decryption key
//   - nonce: 96-bit nonce
//   - aad: additional authenticated data (must match encryption AAD)
//   - aad_len: length of AAD
//   - tag: 128-bit authentication tag
// Output:
//   - plaintext: decrypted data
// Returns: 0 on success (authentication passed), -1 on failure
int aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t key[AES_KEY_SIZE],
                    const uint8_t nonce[AES_NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t tag[AES_TAG_SIZE],
                    uint8_t *plaintext);

#endif // AES_GCM_H
