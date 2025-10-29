#ifndef AES_GCM_H
#define AES_GCM_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pq_abl::crypto {

// AES-GCM helper stub interface. Replace implementations with a real crypto lib.
// key: 32 bytes (256-bit). nonce: 12 bytes recommended. aad: additional authenticated data.

int aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    std::vector<uint8_t> &ciphertext, // includes GCM tag appended
                    std::vector<uint8_t> &out_nonce);

int aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    std::vector<uint8_t> &out_plaintext);

} // namespace pq_abl::crypto

#endif // AES_GCM_H
