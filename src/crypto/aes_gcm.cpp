#include "../../include/crypto/aes_gcm.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>

namespace pq_abl::crypto {

int aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    std::vector<uint8_t> &ciphertext,
                    std::vector<uint8_t> &out_nonce) {
    if (!key || key_len != 32) return -1;

    // Use 12-byte nonce if not provided
    uint8_t iv[12];
    if (nonce && nonce_len == sizeof(iv)) {
        memcpy(iv, nonce, sizeof(iv));
    } else {
        if (RAND_bytes(iv, sizeof(iv)) != 1) return -2;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -3;

    int rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -4; }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(iv), NULL);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -5; }

    rc = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -6; }

    int outlen = 0;
    if (aad && aad_len > 0) {
        rc = EVP_EncryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len);
        if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -7; }
    }

    ciphertext.resize(plaintext_len);
    if (plaintext_len > 0) {
        rc = EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext, (int)plaintext_len);
        if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -8; }
        ciphertext.resize(outlen);
    } else {
        ciphertext.clear();
    }

    int tmplen = 0;
    rc = EVP_EncryptFinal_ex(ctx, NULL, &tmplen);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -9; }

    uint8_t tag[16];
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -10; }

    // append tag
    size_t old = ciphertext.size();
    ciphertext.resize(old + sizeof(tag));
    memcpy(ciphertext.data() + old, tag, sizeof(tag));

    out_nonce.assign(iv, iv + sizeof(iv));

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    std::vector<uint8_t> &out_plaintext) {
    if (!key || key_len != 32) return -1;
    if (!nonce || nonce_len != 12) return -2;
    if (!ciphertext || ciphertext_len < 16) return -3; // need at least tag

    size_t tag_len = 16;
    size_t ct_len = ciphertext_len - tag_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -4;

    int rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -5; }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, NULL);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -6; }

    rc = EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -7; }

    if (aad && aad_len > 0) {
        int outl = 0;
        rc = EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len);
        if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -8; }
    }

    out_plaintext.resize(ct_len);
    int outl = 0;
    if (ct_len > 0) {
        rc = EVP_DecryptUpdate(ctx, out_plaintext.data(), &outl, ciphertext, (int)ct_len);
        if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -9; }
        out_plaintext.resize(outl);
    } else {
        out_plaintext.clear();
    }

    // set expected tag
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)(ciphertext + ct_len));
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -10; }

    rc = EVP_DecryptFinal_ex(ctx, NULL, &outl);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -11; }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

} // namespace pq_abl::crypto
