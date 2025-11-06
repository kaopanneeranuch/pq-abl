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
    
    printf("[Decrypt] Using %d attributes for decryption\n", n_coeffs);
    
    // ========================================================================
    // Decryption Algorithm:
    // For the new scheme with B+, B-, β structure:
    // 1. Compute partial decryption using ω_i vectors
    // 2. Use ω_A and reconstruction coefficients
    // 3. Recover K_log from ct_key using β relationship
    // ========================================================================
    
    // Simplified decryption (basic implementation)
    // TODO: Full decryption needs proper lattice trapdoor inversion
    // For now, use a simplified approach for testing
    
    poly recovered = (poly)calloc(PARAM_N, sizeof(scalar));
    
    // Copy ct_key as base
    memcpy(recovered, ct_abe->ct_key, PARAM_N * sizeof(scalar));
    
    // Compute sum of contributions from user's attributes
    poly partial_sum = (poly)calloc(PARAM_N, sizeof(scalar));
    
    for (uint32_t i = 0; i < n_coeffs && i < usk->n_components; i++) {
        // For each matching attribute, compute contribution
        // Using ω_i vectors (m-dimensional)
        
        poly temp = (poly)calloc(PARAM_N, sizeof(scalar));
        
        // Compute inner product: ω_i^T · C_i
        // C_i is m×1 column vector, ω_i is m×1 column vector
        // Loop over all m=PARAM_M components
        for (uint32_t j = 0; j < PARAM_M; j++) {
            // Both omega_i and C[i] are m×1 column vectors, so nb_col=1
            poly omega_ij = poly_matrix_element(usk->omega_i[i], 1, j, 0);
            poly c_i_j = poly_matrix_element(ct_abe->C[i], 1, j, 0);
            
            // Multiply in CRT domain (produces 2*PARAM_N result)
            double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            mul_crt_poly(prod, omega_ij, c_i_j, LOG_R);
            
            // Reduce double_poly to poly (stays in CRT domain)
            poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            reduce_double_crt_poly(prod_reduced, prod, LOG_R);
            
            add_poly(temp, temp, prod_reduced, PARAM_N - 1);
            free(prod);
            free(prod_reduced);
        }
        
        // Multiply by reconstruction coefficient
        for (uint32_t k = 0; k < PARAM_N; k++) {
            temp[k] = ((uint64_t)temp[k] * coefficients[i]) % PARAM_Q;
        }
        
        // Add to partial sum
        add_poly(partial_sum, partial_sum, temp, PARAM_N - 1);
        free(temp);
    }
    
    // Subtract partial sum from ct_key (both in CRT domain)
    sub_poly(recovered, recovered, partial_sum, PARAM_N - 1);
    
    // Convert recovered from CRT back to coefficient representation
    coeffs_representation(recovered, LOG_R);
    
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
        
        // Read symmetric ciphertext (CT_sym)
        fread(&log.ct_sym.ct_len, sizeof(uint32_t), 1, fp);
        log.ct_sym.ciphertext = (uint8_t*)malloc(log.ct_sym.ct_len);
        fread(log.ct_sym.ciphertext, log.ct_sym.ct_len, 1, fp);
        fread(log.ct_sym.nonce, AES_NONCE_SIZE, 1, fp);
        fread(log.ct_sym.tag, AES_TAG_SIZE, 1, fp);
        
        // Read ABE ciphertext (CT_ABE)
        fread(log.ct_abe.policy.expression, MAX_POLICY_SIZE, 1, fp);
        fread(&log.ct_abe.n_components, sizeof(uint32_t), 1, fp);
        
        // Allocate and read C0
        size_t c0_size = PARAM_M * PARAM_N;
        log.ct_abe.C0 = (poly_matrix)malloc(c0_size * sizeof(scalar));
        fread(log.ct_abe.C0, sizeof(scalar), c0_size, fp);
        
        // Allocate and read C[i] components
        log.ct_abe.C = (poly_matrix*)malloc(log.ct_abe.n_components * sizeof(poly_matrix));
        for (uint32_t j = 0; j < log.ct_abe.n_components; j++) {
            log.ct_abe.C[j] = (poly_matrix)malloc(c0_size * sizeof(scalar));
            fread(log.ct_abe.C[j], sizeof(scalar), c0_size, fp);
        }
        
        // Allocate and read ct_key
        log.ct_abe.ct_key = (poly)malloc(PARAM_N * sizeof(scalar));
        fread(log.ct_abe.ct_key, sizeof(scalar), PARAM_N, fp);
        
        // Read rho
        uint32_t matrix_rows;
        fread(&matrix_rows, sizeof(uint32_t), 1, fp);
        if (matrix_rows > 0) {
            log.ct_abe.policy.matrix_rows = matrix_rows;
            log.ct_abe.policy.rho = (uint32_t*)malloc(matrix_rows * sizeof(uint32_t));
            fread(log.ct_abe.policy.rho, sizeof(uint32_t), matrix_rows, fp);
        }
        
        // Read hash
        fread(log.hash, SHA3_DIGEST_SIZE, 1, fp);
        
        // Now decrypt the log using ABE + AES-GCM
        printf("[Load]   Log %d: %s\n", i + 1, log.metadata.timestamp);
        
        // TODO: Call decryption function here
        // decrypt_log_entry(&log, usk, mpk, ...);
        
        encrypted_log_free(&log);
    }
    
    fclose(fp);
    return 0;
}
