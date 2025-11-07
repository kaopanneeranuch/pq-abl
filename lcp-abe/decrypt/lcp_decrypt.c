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
    printf("\n[Decrypt] LCP-ABE Decryption Start \n");
    printf("[Decrypt] CT_ABE Policy: '%s'\n", ct_abe->policy.expression);
    printf("[Decrypt] CT_ABE Components: %u\n", ct_abe->n_components);
    printf("[Decrypt] User has %u attributes\n", usk->attr_set.count);
    
    // Check if user attributes satisfy policy
    printf("[Decrypt] Checking policy satisfaction...\n");
    if (!lsss_check_satisfaction(&ct_abe->policy, &usk->attr_set)) {
        fprintf(stderr, "[Decrypt] Error: User attributes do not satisfy policy\n");
        return -1;
    }
    printf("[Decrypt] Policy satisfied!\n");
    
    printf("[Decrypt] Computing reconstruction coefficients...\n");
    
    // Compute reconstruction coefficients
    scalar coefficients[MAX_ATTRIBUTES];
    uint32_t n_coeffs = 0;
    lsss_compute_coefficients(&ct_abe->policy, &usk->attr_set, coefficients, &n_coeffs);
    
    printf("[Decrypt] Using %d attributes for decryption\n", n_coeffs);
    for (uint32_t i = 0; i < n_coeffs && i < 5; i++) {
        printf("[Decrypt]   Coefficient[%d] = %u\n", i, coefficients[i]);
    }
    
    // ========================================================================
    // Decryption Algorithm (Proper Lattice-Based):
    // 
    // Given:
    //   ct_key = β·s[0] + e_key + encode(K_log)
    //   C0[i] = s[i] + e0[i] for i < PARAM_D
    //   C[j] = B_plus[ρ(j)]·s[0] + e_j + λ_j·g
    //   A·ω_A ≈ β - Σ(B_plus[user_attrs]·ω[user_attrs])
    //
    // Decryption computes:
    //   ω_A·C0 + Σ(coeff[j]·ω[ρ(j)]·C[j])
    //   ≈ ω_A·s + Σ(coeff[j]·ω[ρ(j)]·B_plus[ρ(j)]·s[0])
    //   ≈ β·s[0]  (using the trapdoor relationship)
    //
    // Then: ct_key - (β·s[0]) ≈ e_key + encode(K_log)
    // Extract K_log from high bits (errors don't affect high 8 bits)
    // ========================================================================
    
    // ========================================================================
    // PROPER LCP-ABE DECRYPTION (following paper specification):
    // 
    // Encryption: ct_key = e_key + β·s[0] + encode(K_log)  (in COEFF domain)
    // Decryption: Compute ω_A·C0 + Σ(coeff[j]·ω[ρ(j)]·C[j]) ≈ β·s[0]
    //             Then: ct_key - (β·s[0]) ≈ e_key + encode(K_log)
    //             Extract K_log from high 8 bits
    // ========================================================================
    
    poly recovered = (poly)calloc(PARAM_N, sizeof(scalar));
    
    // Copy ct_key - it's already in COEFFICIENT domain from encryption
    // (encryption encodes K_log in COEFF domain and keeps it there)
    memcpy(recovered, ct_abe->ct_key, PARAM_N * sizeof(scalar));
    printf("[Decrypt]   DEBUG: ct_key (already COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           recovered[0], recovered[1], recovered[2], recovered[3]);
    
    // Compute the decryption term IN CRT DOMAIN, then convert to COEFF once
    // This matches how ct_key was created: (e_key + β·s[0]) in CRT, then converted to COEFF
    poly decryption_term_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    
    // Step 1: Compute ω_A · C0 (inner product over all M polynomials) in CRT
    printf("\n[Decrypt]   Step 1: Computing ω_A · C0 (inner product) in CRT\n");
    
    for (uint32_t j = 0; j < PARAM_M; j++) {
        poly omega_A_j = poly_matrix_element(usk->omega_A, 1, j, 0);
        poly c0_j = poly_matrix_element(ct_abe->C0, 1, j, 0);
        
        double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        mul_crt_poly(prod, omega_A_j, c0_j, LOG_R);
        
        poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
        reduce_double_crt_poly(prod_reduced, prod, LOG_R);
        
        // Add in CRT domain (NOT converting to COEFF yet)
        add_poly(decryption_term_crt, decryption_term_crt, prod_reduced, PARAM_N - 1);
        
        free(prod);
        free(prod_reduced);
    }
    
    printf("[Decrypt]   ω_A · C0 (CRT, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           decryption_term_crt[0], decryption_term_crt[1], decryption_term_crt[2], decryption_term_crt[3]);
    
    // Step 2: Add Σ(coeff[j]·ω[ρ(j)]·C[j]) in CRT domain
    printf("\n[Decrypt]   Step 2: Computing Σ(coeff[j]·ω[ρ(j)]·C[j]) in CRT\n");
    
    for (uint32_t i = 0; i < n_coeffs && i < ct_abe->policy.matrix_rows; i++) {
        uint32_t policy_attr_idx = ct_abe->policy.rho[i];
        printf("[Decrypt]   Processing policy row %d (attr idx %d, coeff=%u)\n", 
               i, policy_attr_idx, coefficients[i]);
        
        // Find corresponding omega_i in user's key
        int omega_idx = -1;
        for (uint32_t j = 0; j < usk->attr_set.count; j++) {
            if (usk->attr_set.attrs[j].index == policy_attr_idx) {
                omega_idx = j;
                break;
            }
        }
        
        if (omega_idx == -1) {
            fprintf(stderr, "[Decrypt] ERROR: Policy requires attr %d but user doesn't have it!\n", 
                    policy_attr_idx);
            free(decryption_term_crt);
            free(recovered);
            return -1;
        }
        
        // Compute ω[ρ(i)]·C[i] as inner product in CRT
        poly temp_sum_crt = (poly)calloc(PARAM_N, sizeof(scalar));
        
        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly omega_ij = poly_matrix_element(usk->omega_i[omega_idx], 1, j, 0);
            poly c_i_j = poly_matrix_element(ct_abe->C[i], 1, j, 0);
            
            double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            mul_crt_poly(prod, omega_ij, c_i_j, LOG_R);
            
            poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            reduce_double_crt_poly(prod_reduced, prod, LOG_R);
            
            // Add in CRT domain (NOT converting to COEFF yet)
            add_poly(temp_sum_crt, temp_sum_crt, prod_reduced, PARAM_N - 1);
            
            free(prod);
            free(prod_reduced);
        }
        
        // Multiply by reconstruction coefficient in CRT (scalar multiplication)
        for (uint32_t k = 0; k < PARAM_N; k++) {
            temp_sum_crt[k] = ((uint64_t)temp_sum_crt[k] * coefficients[i]) % PARAM_Q;
        }
        
        // Add to decryption_term in CRT
        add_poly(decryption_term_crt, decryption_term_crt, temp_sum_crt, PARAM_N - 1);
        
        free(temp_sum_crt);
    }
    
    printf("[Decrypt]   decryption_term (CRT, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           decryption_term_crt[0], decryption_term_crt[1], decryption_term_crt[2], decryption_term_crt[3]);
    
    // NOW convert decryption_term from CRT to COEFF (matching how ct_key was created)
    coeffs_representation(decryption_term_crt, LOG_R);
    
    printf("[Decrypt]   decryption_term (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           decryption_term_crt[0], decryption_term_crt[1], decryption_term_crt[2], decryption_term_crt[3]);
    
    // Step 3: Subtract decryption_term from ct_key to recover encode(K_log) + small_error
    printf("\n[Decrypt]   Step 3: Subtracting to extract K_log\n");
    
    for (uint32_t i = 0; i < PARAM_N; i++) {
        recovered[i] = (recovered[i] + PARAM_Q - decryption_term_crt[i]) % PARAM_Q;
    }
    
    printf("[Decrypt]   After subtraction (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           recovered[0], recovered[1], recovered[2], recovered[3]);
    printf("[Decrypt]   In HEX: [0]=0x%08x, [1]=0x%08x, [2]=0x%08x, [3]=0x%08x\n",
           recovered[0], recovered[1], recovered[2], recovered[3]);
    
    // Extract K_log by rounding to nearest byte value
    // Decoding inverts the encoding: K_log[i] = round(recovered[i] / 2^22)
    printf("[Decrypt]   Extracting K_log using rounding (recovered >> %d):\n", PARAM_K - 8);
    printf("[Decrypt]   ");
    const uint32_t shift = PARAM_K - 8;  // 30 - 8 = 22 bits
    for (int i = 0; i < 8; i++) {
        // Round to nearest: add 2^(shift-1) before right-shifting
        uint64_t rounded = ((uint64_t)recovered[i] + (1ULL << (shift - 1))) >> shift;
        printf("%02x ", (uint8_t)(rounded & 0xFF));
    }
    printf("\n");
    
    // Extract full K_log using proper rounding
    for (uint32_t i = 0; i < AES_KEY_SIZE && i < PARAM_N; i++) {
        uint64_t rounded = ((uint64_t)recovered[i] + (1ULL << (shift - 1))) >> shift;
        key_out[i] = (uint8_t)(rounded & 0xFF);
    }
    
    free(recovered);
    free(decryption_term_crt);
    
    printf("[Decrypt] K_log recovered successfully (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", key_out[i]);
    }
    printf("\n");
    printf("[Decrypt] LCP-ABE Decryption End \n\n");
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
    printf("[Decrypt AES] Decrypting symmetric ciphertext (length: %u)\n", ct_sym->ct_len);
    
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
    
    printf("[Decrypt AES] AAD: %.*s\n", (int)aad_len, aad);
    printf("[Decrypt AES] Key (full 32 bytes): ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    printf("[Decrypt AES] Nonce (12 bytes): ");
    for (int i = 0; i < 12; i++) {
        printf("%02x", ct_sym->nonce[i]);
    }
    printf("\n");
    printf("[Decrypt AES] Tag (16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", ct_sym->tag[i]);
    }
    printf("\n");
    printf("[Decrypt AES] Ciphertext (first 32 bytes): ");
    for (int i = 0; i < 32 && i < ct_sym->ct_len; i++) {
        printf("%02x", ct_sym->ciphertext[i]);
    }
    printf("\n");
    
    // Decrypt with AES-GCM
    int result = aes_gcm_decrypt(ct_sym->ciphertext, ct_sym->ct_len,
                                key, ct_sym->nonce,
                                aad, aad_len,
                                ct_sym->tag,
                                *plaintext_out);
    
    if (result != 0) {
        free(*plaintext_out);
        *plaintext_out = NULL;
        fprintf(stderr, "[Decrypt AES] Error: AES-GCM decryption or authentication failed\n");
        return -1;
    }
    
    printf("[Decrypt AES] AES-GCM decryption successful\n");
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

// ============================================================================
// Load individual CT_obj file
// ============================================================================

int load_ctobj_file(const char *filename, EncryptedLogObject *log) {
    printf("[Load] Opening CT_obj file: %s\n", filename);
    
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "[Load] Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    encrypted_log_init(log);
    
    // Read metadata
    if (fread(&log->metadata, sizeof(LogMetadata), 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read metadata\n");
        fclose(fp);
        return -1;
    }
    printf("[Load] Loaded metadata\n");
    
    // Read symmetric ciphertext (CT_sym)
    if (fread(&log->ct_sym.ct_len, sizeof(uint32_t), 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read ct_len\n");
        fclose(fp);
        return -1;
    }
    
    log->ct_sym.ciphertext = (uint8_t*)malloc(log->ct_sym.ct_len);
    fread(log->ct_sym.ciphertext, log->ct_sym.ct_len, 1, fp);
    fread(log->ct_sym.nonce, AES_NONCE_SIZE, 1, fp);
    fread(log->ct_sym.tag, AES_TAG_SIZE, 1, fp);
    printf("[Load] Loaded CT_sym (size: %u bytes)\n", log->ct_sym.ct_len);
    
    // Read ABE ciphertext (CT_ABE)
    fread(log->ct_abe.policy.expression, MAX_POLICY_SIZE, 1, fp);
    fread(&log->ct_abe.n_components, sizeof(uint32_t), 1, fp);
    printf("[Load] Loaded CT_ABE policy: '%s' (%u components)\n", 
           log->ct_abe.policy.expression, log->ct_abe.n_components);
    
    // Parse the policy to extract attribute indices
    policy_parse(log->ct_abe.policy.expression, &log->ct_abe.policy);
    
    // Allocate and read C0
    size_t c0_size = PARAM_M * PARAM_N;
    log->ct_abe.C0 = (poly_matrix)malloc(c0_size * sizeof(scalar));
    fread(log->ct_abe.C0, sizeof(scalar), c0_size, fp);
    
    // Allocate and read C[i] components
    log->ct_abe.C = (poly_matrix*)malloc(log->ct_abe.n_components * sizeof(poly_matrix));
    for (uint32_t j = 0; j < log->ct_abe.n_components; j++) {
        log->ct_abe.C[j] = (poly_matrix)malloc(c0_size * sizeof(scalar));
        fread(log->ct_abe.C[j], sizeof(scalar), c0_size, fp);
    }
    
    // Allocate and read ct_key
    log->ct_abe.ct_key = (poly)malloc(PARAM_N * sizeof(scalar));
    fread(log->ct_abe.ct_key, sizeof(scalar), PARAM_N, fp);
    
    // Read rho
    uint32_t matrix_rows;
    fread(&matrix_rows, sizeof(uint32_t), 1, fp);
    if (matrix_rows > 0) {
        log->ct_abe.policy.matrix_rows = matrix_rows;
        log->ct_abe.policy.rho = (uint32_t*)malloc(matrix_rows * sizeof(uint32_t));
        fread(log->ct_abe.policy.rho, sizeof(uint32_t), matrix_rows, fp);
    }
    
    fclose(fp);
    printf("[Load] Successfully loaded complete CT_obj\n");
    return 0;
}

// ============================================================================
// Batch Decryption with Policy Reuse Optimization
// ============================================================================

typedef struct {
    char policy[MAX_POLICY_SIZE];
    uint8_t k_log[AES_KEY_SIZE];
    int valid;
} PolicyKeyCache;

int decrypt_ctobj_batch(const char **filenames,
                       uint32_t n_files,
                       const UserSecretKey *usk,
                       const MasterPublicKey *mpk,
                       const char *output_dir) {
    printf("\n=== Batch Decryption with Policy Reuse ===\n");
    printf("[Decrypt] Processing %d CT_obj files\n", n_files);
    
    // Cache for policy-key pairs (optimization from Phase 6 spec)
    PolicyKeyCache cache[100];  // Support up to 100 unique policies
    uint32_t n_cached = 0;
    
    uint32_t success_count = 0;
    uint32_t cache_hits = 0;
    uint32_t abe_decryptions = 0;
    
    for (uint32_t i = 0; i < n_files; i++) {
        printf("[Decrypt] File %d/%d: %s\n", i + 1, n_files, filenames[i]);
        
        // Load CT_obj
        EncryptedLogObject log;
        if (load_ctobj_file(filenames[i], &log) != 0) {
            fprintf(stderr, "[Decrypt] Failed to load file\n");
            continue;
        }
        
        printf("[Decrypt]   Policy: %s\n", log.ct_abe.policy.expression);
        printf("[Decrypt]   User: %s, Timestamp: %s\n", 
               log.metadata.user_id, log.metadata.timestamp);
        
        // CRITICAL FIX: Each log has UNIQUE K_log encoded in ct_key
        // Cannot cache K_log by policy alone - must decrypt each ct_key independently
        // The batch optimization shares C0/C[i], but ct_key is unique per log!
        uint8_t k_log[AES_KEY_SIZE];
        int found_in_cache = 0;  // DISABLED: Force decryption for each unique ct_key
        
        // CACHE DISABLED - Each file has unique K_log
        // for (uint32_t c = 0; c < n_cached; c++) {
        //     if (strcmp(cache[c].policy, log.ct_abe.policy.expression) == 0 && cache[c].valid) {
        //         memcpy(k_log, cache[c].k_log, AES_KEY_SIZE);
        //         found_in_cache = 1;
        //         cache_hits++;
        //         printf("[Decrypt]   Cache HIT! Reusing K_log from policy cache\n");
        //         break;
        //     }
        // }
        
        if (!found_in_cache) {  // Always true now
            // Cache miss - perform LCP-ABE decryption
            printf("[Decrypt]   Cache MISS - Performing LCP-ABE decryption...\n");
            
            int decrypt_result = lcp_abe_decrypt(&log.ct_abe, usk, mpk, k_log);
            printf("[Decrypt]   LCP-ABE decrypt returned: %d\n", decrypt_result);
            
            if (decrypt_result != 0) {
                fprintf(stderr, "[Decrypt]   FAILED: Policy not satisfied or decryption error\n");
                fprintf(stderr, "[Decrypt]   Skipping this file and continuing...\n");
                encrypted_log_free(&log);
                continue;
            }
            
            printf("[Decrypt]   LCP-ABE decryption succeeded!\n");
            abe_decryptions++;
            
            // Add to cache
            if (n_cached < 100) {
                strncpy(cache[n_cached].policy, log.ct_abe.policy.expression, MAX_POLICY_SIZE);
                memcpy(cache[n_cached].k_log, k_log, AES_KEY_SIZE);
                cache[n_cached].valid = 1;
                n_cached++;
                printf("[Decrypt]   Added policy to cache (total cached: %d)\n", n_cached);
            }
        }
        
        // Decrypt symmetric ciphertext using K_log
        uint8_t *log_data = NULL;
        size_t log_len = 0;
        
        printf("[Decrypt]   Attempting AES-GCM decryption...\n");
        int sym_result = decrypt_log_symmetric(&log.ct_sym, k_log, &log.metadata, 
                                               &log_data, &log_len);
        printf("[Decrypt]   AES-GCM decrypt returned: %d\n", sym_result);
        
        if (sym_result != 0) {
            fprintf(stderr, "[Decrypt]   FAILED: AES-GCM decryption or authentication failed\n");
            fprintf(stderr, "[Decrypt]   Skipping this file and continuing...\n");
            encrypted_log_free(&log);
            continue;
        }
        
        printf("[Decrypt]   Decrypted successfully (%zu bytes)\n", log_len);
        printf("[Decrypt]   \n");
        printf("%.*s\n", (int)log_len, log_data);
        printf("[Decrypt]   \n");
        
        // Save decrypted log
        if (output_dir) {
            char output_filename[512];
            snprintf(output_filename, sizeof(output_filename), 
                    "%s/decrypted_log_%d.json", output_dir, i + 1);
            
            FILE *out_fp = fopen(output_filename, "w");
            if (out_fp) {
                fwrite(log_data, 1, log_len, out_fp);
                fclose(out_fp);
                printf("[Decrypt]   Saved to: %s\n", output_filename);
            }
        }
        
        free(log_data);
        encrypted_log_free(&log);
        success_count++;
    }
    
    // Print statistics
    printf("\n");
    printf("=== Decryption Statistics ===\n");
    printf("Total CT_obj files processed: %d\n", n_files);
    printf("Successfully decrypted: %d\n", success_count);
    printf("Failed (policy mismatch): %d\n", n_files - success_count);
    
    if (success_count > 0) {
        printf("Saved %d decrypted logs to: %s/\n", success_count, output_dir);
    }
    
    printf("\n--- Policy Reuse Optimization ---\n");
    printf("LCP-ABE decryptions performed: %d\n", abe_decryptions);
    printf("Cache hits (reused K_log): %d\n", cache_hits);
    printf("Unique policies encountered: %d\n", n_cached);
    if (n_files > 0) {
        printf("Efficiency gain: %.1f%% reduction in ABE operations\n", 
               100.0 * cache_hits / n_files);
    }
    
    return 0;
}
