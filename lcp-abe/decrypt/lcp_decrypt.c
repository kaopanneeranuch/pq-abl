#include "lcp_decrypt.h"
#include "../encrypt/aes_gcm.h"
#include "../policy/lcp_policy.h"
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Phase 4: LCP-ABE Decryption
// ============================================================================

int lcp_abe_decrypt(const ABECiphertext *ct_abe,
                    const UserSecretKey *usk,
                    const MasterPublicKey *mpk,
                    uint8_t key_out[AES_KEY_SIZE]) {
    printf("[Decrypt] LCP-ABE decrypting ciphertext...\n");
    
    // Check if user attributes satisfy policy
    if (!lsss_check_satisfaction(&ct_abe->policy, &usk->attr_set)) {
        fprintf(stderr, "Error: User attributes do not satisfy policy\n");
        return -1;
    }
    
    printf("[Decrypt] Policy satisfied! Computing reconstruction coefficients...\n");
    
    // Compute reconstruction coefficients
    scalar coefficients[MAX_ATTRIBUTES];
    uint32_t n_coeffs = 0;
    lsss_compute_coefficients(&ct_abe->policy, &usk->attr_set, coefficients, &n_coeffs);
    
    // Decrypt: compute Σ ω_i · (sk_i^T · C_i)
    poly partial_sum = (poly)calloc(PARAM_N, sizeof(scalar));
    
    for (uint32_t i = 0; i < n_coeffs && i < usk->n_components; i++) {
        // Compute sk_i^T · C_i
        poly temp = (poly)calloc(PARAM_N, sizeof(scalar));
        
        for (uint32_t j = 0; j < PARAM_D; j++) {
            poly sk_ij = poly_matrix_element(usk->sk_components[i], 1, j, 0);
            poly c_ij = ct_abe->C[i]; // Simplified
            poly prod = (poly)calloc(PARAM_N, sizeof(scalar));
            mul_poly_crt(prod, sk_ij, c_ij);
            add_poly(temp, temp, prod, PARAM_N);
            free(prod);
        }
        
        // Multiply by coefficient ω_i
        for (uint32_t k = 0; k < PARAM_N; k++) {
            temp[k] = ((uint64_t)temp[k] * coefficients[i]) % PARAM_Q;
        }
        
        // Add to partial sum
        add_poly(partial_sum, partial_sum, temp, PARAM_N);
        free(temp);
    }
    
    // Subtract from ct_key to recover encoded key
    poly recovered = (poly)calloc(PARAM_N, sizeof(scalar));
    sub_poly(recovered, ct_abe->ct_key, partial_sum, PARAM_N);
    
    // Extract key bytes from polynomial coefficients
    for (uint32_t i = 0; i < AES_KEY_SIZE && i < PARAM_N; i++) {
        key_out[i] = (uint8_t)(recovered[i] % 256);
    }
    
    free(partial_sum);
    free(recovered);
    
    printf("[Decrypt] Key recovered successfully\n");
    return 0;
}

// ============================================================================
// Symmetric Decryption
// ============================================================================

int decrypt_log_symmetric(const SymmetricCiphertext *ct_sym,
                         const uint8_t key[AES_KEY_SIZE],
                         const LogMetadata *metadata,
                         uint8_t **plaintext_out,
                         size_t *plaintext_len) {
    // Allocate plaintext buffer
    *plaintext_out = (uint8_t*)malloc(ct_sym->ct_len);
    if (!*plaintext_out) {
        return -1;
    }
    *plaintext_len = ct_sym->ct_len;
    
    // Reconstruct AAD
    uint8_t aad[512];
    size_t aad_len = snprintf((char*)aad, sizeof(aad),
                             "%s|%s|%s|%s|%s",
                             metadata->timestamp,
                             metadata->user_id,
                             metadata->resource_id,
                             metadata->action_type,
                             metadata->service_name);
    
    // Decrypt with AES-GCM
    int result = aes_gcm_decrypt(ct_sym->ciphertext, ct_sym->ct_len,
                                key, ct_sym->nonce,
                                aad, aad_len,
                                ct_sym->tag,
                                *plaintext_out);
    
    if (result != 0) {
        free(*plaintext_out);
        *plaintext_out = NULL;
        fprintf(stderr, "Error: AES-GCM decryption or authentication failed\n");
        return -1;
    }
    
    return 0;
}

// ============================================================================
// Combined Decryption
// ============================================================================

int decrypt_log_entry(const EncryptedLogObject *encrypted_log,
                     const UserSecretKey *usk,
                     const MasterPublicKey *mpk,
                     uint8_t **log_data_out,
                     size_t *log_len) {
    // Decrypt K_log with ABE
    uint8_t k_log[AES_KEY_SIZE];
    if (lcp_abe_decrypt(&encrypted_log->ct_abe, usk, mpk, k_log) != 0) {
        fprintf(stderr, "Error: ABE decryption failed\n");
        return -1;
    }
    
    // Decrypt log data with AES-GCM
    if (decrypt_log_symmetric(&encrypted_log->ct_sym, k_log,
                             &encrypted_log->metadata,
                             log_data_out, log_len) != 0) {
        fprintf(stderr, "Error: Symmetric decryption failed\n");
        return -1;
    }
    
    // Verify hash
    uint8_t computed_hash[SHA3_DIGEST_SIZE];
    sha3_256_log_object(encrypted_log, computed_hash);
    
    if (memcmp(computed_hash, encrypted_log->hash, SHA3_DIGEST_SIZE) != 0) {
        fprintf(stderr, "Warning: Hash verification failed\n");
    }
    
    return 0;
}

int decrypt_microbatch(const Microbatch *batch,
                      const UserSecretKey *usk,
                      const MasterPublicKey *mpk) {
    printf("[Decrypt] Decrypting microbatch: %d logs\n", batch->n_logs);
    
    for (uint32_t i = 0; i < batch->n_logs; i++) {
        printf("[Decrypt]   Decrypting log %d/%d...\n", i + 1, batch->n_logs);
        
        uint8_t *log_data;
        size_t log_len;
        
        if (decrypt_log_entry(&batch->logs[i], usk, mpk, &log_data, &log_len) == 0) {
            printf("[Decrypt]   Log %d: %.*s\n", i, (int)log_len, log_data);
            free(log_data);
        } else {
            fprintf(stderr, "[Decrypt]   Failed to decrypt log %d\n", i);
        }
    }
    
    return 0;
}

int load_and_decrypt_batch(const char *filename,
                          const UserSecretKey *usk,
                          const MasterPublicKey *mpk) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    // Read batch header
    uint64_t epoch_id;
    uint32_t n_logs;
    char epoch_start[32], epoch_end[32];
    char policy_expr[MAX_POLICY_SIZE];
    
    fread(&epoch_id, sizeof(uint64_t), 1, fp);
    fread(&n_logs, sizeof(uint32_t), 1, fp);
    fread(epoch_start, 32, 1, fp);
    fread(epoch_end, 32, 1, fp);
    fread(policy_expr, MAX_POLICY_SIZE, 1, fp);
    
    printf("[Load] Batch: epoch %lu, %d logs, policy: %s\n", epoch_id, n_logs, policy_expr);
    
    // Read and decrypt each log
    for (uint32_t i = 0; i < n_logs; i++) {
        EncryptedLogObject log;
        encrypted_log_init(&log);
        
        // Read metadata
        fread(&log.metadata, sizeof(LogMetadata), 1, fp);
        
        // Read symmetric ciphertext
        fread(&log.ct_sym.ct_len, sizeof(uint32_t), 1, fp);
        log.ct_sym.ciphertext = (uint8_t*)malloc(log.ct_sym.ct_len);
        fread(log.ct_sym.ciphertext, log.ct_sym.ct_len, 1, fp);
        fread(log.ct_sym.nonce, AES_NONCE_SIZE, 1, fp);
        fread(log.ct_sym.tag, AES_TAG_SIZE, 1, fp);
        
        // Read hash
        fread(log.hash, SHA3_DIGEST_SIZE, 1, fp);
        
        // Decrypt (ABE part needs to be loaded separately or cached)
        // This is simplified - in practice, batch would share ABE ciphertext
        
        encrypted_log_free(&log);
    }
    
    fclose(fp);
    return 0;
}
