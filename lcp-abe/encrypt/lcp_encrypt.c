#include "lcp_encrypt.h"
#include "aes_gcm.h"
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "../../module_gaussian_lattice/Module_BFRS/sampling.h"
#include "../keygen/lcp_keygen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

// ============================================================================
// LCP-ABE Encryption
// ============================================================================

int lcp_abe_encrypt(const uint8_t key[AES_KEY_SIZE],
                    const AccessPolicy *policy,
                    const MasterPublicKey *mpk,
                    ABECiphertext *ct_abe) {
    printf("[Encrypt] LCP-ABE encrypting key under policy: %s\n", policy->expression);
    
    // Initialize ciphertext
    abe_ct_init(ct_abe);
    ct_abe->policy = *policy;
    
    // Step 1: Convert policy to LSSS matrix (should be done already)
    if (!policy->share_matrix) {
        fprintf(stderr, "Error: Policy LSSS matrix not initialized\n");
        return -1;
    }
    
    uint32_t n_rows = policy->matrix_rows;
    
    // Allocate ciphertext components
    ct_abe->C0 = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    ct_abe->C = (poly_matrix*)calloc(n_rows, sizeof(poly_matrix));
    for (uint32_t i = 0; i < n_rows; i++) {
        ct_abe->C[i] = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    }
    ct_abe->ct_key = (poly)calloc(PARAM_N, sizeof(scalar));
    ct_abe->n_components = n_rows;
    
    // Step 2: Sample random secret vector s ∈ R_q^d
    poly_matrix s = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    for (uint32_t i = 0; i < PARAM_D; i++) {
        poly s_i = poly_matrix_element(s, 1, i, 0);
        random_poly(s_i, PARAM_N);
    }
    
    // Step 3: Generate LSSS shares
    scalar secret_scalar = rand() % PARAM_Q;
    scalar *shares = (scalar*)calloc(n_rows, sizeof(scalar));
    lsss_generate_shares(policy, secret_scalar, shares);
    
    // Step 4: Compute C_0 = A^T · s + e_0
    poly_matrix e0 = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    SampleR_matrix_centered((signed_poly_matrix)e0, PARAM_D, 1, PARAM_SIGMA);
    
    // C_0 = A^T · s
    poly_matrix A_T = (poly_matrix)calloc(PARAM_D * PARAM_D * PARAM_N, sizeof(scalar));
    // Transpose A (simplified: assume A is symmetric for now)
    memcpy(A_T, mpk->A, PARAM_D * PARAM_D * PARAM_N * sizeof(scalar));
    multiply_by_A(ct_abe->C0, A_T, s);
    
    // Add error e_0
    for (uint32_t i = 0; i < PARAM_D; i++) {
        poly c0_i = poly_matrix_element(ct_abe->C0, 1, i, 0);
        poly e0_i = poly_matrix_element(e0, 1, i, 0);
        add_poly(c0_i, c0_i, e0_i, PARAM_N);
    }
    
    // Step 5: For each row i of LSSS matrix
    for (uint32_t i = 0; i < n_rows; i++) {
        uint32_t attr_idx = policy->rho[i]; // Attribute for row i
        
        // Get u_{ρ(i)} from MPK
        poly_matrix u_attr = poly_matrix_element(mpk->U, mpk->n_attributes, 0, attr_idx);
        
        // Sample error e_i
        poly_matrix e_i = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
        SampleR_matrix_centered((signed_poly_matrix)e_i, PARAM_D, 1, PARAM_SIGMA);
        
        // C_i = u_{ρ(i)}^T · s + e_i + λ_i · g
        // where g is gadget vector [1, 2, 4, ..., 2^(k-1)]
        
        // Compute u^T · s (simplified: dot product)
        poly temp = (poly)calloc(PARAM_N, sizeof(scalar));
        for (uint32_t j = 0; j < PARAM_D; j++) {
            poly u_j = poly_matrix_element(u_attr, 1, j, 0);
            poly s_j = poly_matrix_element(s, 1, j, 0);
            poly prod = (poly)calloc(PARAM_N, sizeof(scalar));
            mul_poly_crt(prod, u_j, s_j);
            add_poly(temp, temp, prod, PARAM_N);
            free(prod);
        }
        
        // Add error
        poly e_i_0 = poly_matrix_element(e_i, 1, 0, 0);
        add_poly(temp, temp, e_i_0, PARAM_N);
        
        // Add share λ_i encoded as polynomial (first coefficient)
        temp[0] = (temp[0] + shares[i]) % PARAM_Q;
        
        // Store in C[i]
        memcpy(ct_abe->C[i], temp, PARAM_N * sizeof(scalar));
        
        free(temp);
        free(e_i);
    }
    
    // Step 6: Encrypt the key K_log
    // ct_key = s^T · u_0 + e + encode(K_log)
    poly_matrix u_0 = poly_matrix_element(mpk->U, mpk->n_attributes, 0, 0);
    poly e_key = (poly)calloc(PARAM_N, sizeof(scalar));
    SampleR_centered((signed_poly)e_key, PARAM_SIGMA);
    
    // Compute s^T · u_0
    for (uint32_t j = 0; j < PARAM_D; j++) {
        poly u_j = poly_matrix_element(u_0, 1, j, 0);
        poly s_j = poly_matrix_element(s, 1, j, 0);
        poly prod = (poly)calloc(PARAM_N, sizeof(scalar));
        mul_poly_crt(prod, u_j, s_j);
        add_poly(ct_abe->ct_key, ct_abe->ct_key, prod, PARAM_N);
        free(prod);
    }
    
    // Add error
    add_poly(ct_abe->ct_key, ct_abe->ct_key, e_key, PARAM_N);
    
    // Encode K_log into polynomial (pack bytes into coefficients)
    for (uint32_t i = 0; i < AES_KEY_SIZE && i < PARAM_N; i++) {
        ct_abe->ct_key[i] = (ct_abe->ct_key[i] + key[i]) % PARAM_Q;
    }
    
    // Cleanup
    free(s);
    free(shares);
    free(e0);
    free(A_T);
    free(e_key);
    
    printf("[Encrypt] LCP-ABE ciphertext generated: %d components\n", n_rows);
    return 0;
}

// ============================================================================
// Symmetric Encryption (AES-GCM)
// ============================================================================

int encrypt_log_symmetric(const uint8_t *log_data, size_t log_len,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t nonce[AES_NONCE_SIZE],
                         const LogMetadata *metadata,
                         SymmetricCiphertext *ct_sym) {
    // Allocate ciphertext buffer
    ct_sym->ciphertext = (uint8_t*)malloc(log_len);
    if (!ct_sym->ciphertext) {
        return -1;
    }
    ct_sym->ct_len = log_len;
    
    // Copy nonce
    memcpy(ct_sym->nonce, nonce, AES_NONCE_SIZE);
    
    // Prepare AAD (additional authenticated data) from metadata
    uint8_t aad[512];
    size_t aad_len = snprintf((char*)aad, sizeof(aad),
                             "%s|%s|%s|%s|%s",
                             metadata->timestamp,
                             metadata->user_id,
                             metadata->resource_id,
                             metadata->action_type,
                             metadata->service_name);
    
    // Encrypt with AES-GCM
    int result = aes_gcm_encrypt(log_data, log_len, key, nonce,
                                aad, aad_len,
                                ct_sym->ciphertext, ct_sym->tag);
    
    if (result != 0) {
        free(ct_sym->ciphertext);
        ct_sym->ciphertext = NULL;
        return -1;
    }
    
    return 0;
}

// ============================================================================
// Combined Log Encryption
// ============================================================================

int encrypt_log_entry(const JsonLogEntry *log_entry,
                     const AccessPolicy *policy,
                     const MasterPublicKey *mpk,
                     EncryptedLogObject *encrypted_log) {
    // Initialize encrypted log object
    encrypted_log_init(encrypted_log);
    
    // Copy metadata
    strncpy(encrypted_log->metadata.timestamp, log_entry->timestamp, 32);
    strncpy(encrypted_log->metadata.user_id, log_entry->user_id, 64);
    strncpy(encrypted_log->metadata.user_role, log_entry->user_role, 32);
    strncpy(encrypted_log->metadata.team, log_entry->team, 32);
    strncpy(encrypted_log->metadata.action_type, log_entry->action_type, 32);
    strncpy(encrypted_log->metadata.resource_id, log_entry->resource_id, 64);
    strncpy(encrypted_log->metadata.resource_type, log_entry->resource_type, 32);
    strncpy(encrypted_log->metadata.service_name, log_entry->service_name, 32);
    strncpy(encrypted_log->metadata.region, log_entry->region, 32);
    
    // Generate fresh K_log and nonce
    uint8_t k_log[AES_KEY_SIZE];
    uint8_t nonce[AES_NONCE_SIZE];
    rng_key(k_log);
    rng_nonce(nonce);
    
    // Encrypt log data with AES-GCM
    size_t log_len = strlen(log_entry->log_data);
    if (encrypt_log_symmetric((const uint8_t*)log_entry->log_data, log_len,
                             k_log, nonce, &encrypted_log->metadata,
                             &encrypted_log->ct_sym) != 0) {
        fprintf(stderr, "Error: Symmetric encryption failed\n");
        return -1;
    }
    
    // Encrypt K_log with LCP-ABE
    if (lcp_abe_encrypt(k_log, policy, mpk, &encrypted_log->ct_abe) != 0) {
        fprintf(stderr, "Error: ABE encryption failed\n");
        return -1;
    }
    
    // Compute hash of CT_obj
    sha3_256_log_object(encrypted_log, encrypted_log->hash);
    
    return 0;
}

// ============================================================================
// Microbatch Processing
// ============================================================================

int encrypt_microbatch(const JsonLogEntry *logs,
                      uint32_t n_logs,
                      const AccessPolicy *policy,
                      const MasterPublicKey *mpk,
                      uint64_t epoch_id,
                      Microbatch *batch) {
    printf("[Microbatch] Processing %d logs for policy: %s (epoch %lu)\n",
           n_logs, policy->expression, epoch_id);
    
    // Initialize microbatch
    microbatch_init(batch, n_logs);
    batch->policy = *policy;
    batch->epoch_id = epoch_id;
    
    // Set epoch timestamps
    if (n_logs > 0) {
        strncpy(batch->epoch_start, logs[0].timestamp, 32);
        strncpy(batch->epoch_end, logs[n_logs - 1].timestamp, 32);
    }
    
    // Encrypt each log in the batch
    for (uint32_t i = 0; i < n_logs; i++) {
        printf("[Microbatch]   Encrypting log %d/%d...\n", i + 1, n_logs);
        
        if (encrypt_log_entry(&logs[i], policy, mpk, &batch->logs[i]) != 0) {
            fprintf(stderr, "Error: Failed to encrypt log %d\n", i);
            return -1;
        }
    }
    
    printf("[Microbatch] Batch encryption complete: %d logs\n", n_logs);
    return 0;
}

int process_logs_microbatch(const JsonLogArray *logs,
                            const AccessPolicy *policies,
                            uint32_t n_policies,
                            const MasterPublicKey *mpk,
                            Microbatch **batches,
                            uint32_t *n_batches) {
    printf("[Process] Processing %d logs with %d policies...\n", logs->count, n_policies);
    
    // Group logs by epoch and policy
    // Simplified: allocate max possible batches
    *batches = (Microbatch*)calloc(logs->count, sizeof(Microbatch));
    *n_batches = 0;
    
    // For each epoch
    // Find unique epochs
    uint64_t epochs[1000];
    uint32_t n_epochs = 0;
    
    for (uint32_t i = 0; i < logs->count; i++) {
        uint64_t ts = parse_timestamp(logs->entries[i].timestamp);
        uint64_t epoch = get_epoch_id(ts);
        
        // Check if epoch already seen
        int found = 0;
        for (uint32_t j = 0; j < n_epochs; j++) {
            if (epochs[j] == epoch) {
                found = 1;
                break;
            }
        }
        
        if (!found && n_epochs < 1000) {
            epochs[n_epochs++] = epoch;
        }
    }
    
    printf("[Process] Found %d unique epochs\n", n_epochs);
    
    // For each epoch and policy combination
    for (uint32_t e = 0; e < n_epochs; e++) {
        for (uint32_t p = 0; p < n_policies; p++) {
            // Find logs matching this epoch and policy
            JsonLogEntry matching_logs[1000];
            uint32_t n_matching = 0;
            
            for (uint32_t i = 0; i < logs->count && n_matching < 1000; i++) {
                uint64_t ts = parse_timestamp(logs->entries[i].timestamp);
                uint64_t epoch = get_epoch_id(ts);
                
                if (epoch == epochs[e] && policy_match_log(&logs->entries[i], &policies[p])) {
                    matching_logs[n_matching++] = logs->entries[i];
                }
            }
            
            if (n_matching > 0) {
                printf("[Process] Epoch %lu, Policy %d: %d logs\n", epochs[e], p, n_matching);
                
                // Encrypt this microbatch
                if (encrypt_microbatch(matching_logs, n_matching, &policies[p],
                                      mpk, epochs[e], &(*batches)[*n_batches]) == 0) {
                    (*n_batches)++;
                }
            }
        }
    }
    
    printf("[Process] Created %d microbatches\n", *n_batches);
    return 0;
}

// ============================================================================
// Save Encrypted Batch
// ============================================================================

int save_encrypted_batch(const Microbatch *batch, const char *output_dir) {
    // Create output directory if needed
#ifdef _WIN32
    _mkdir(output_dir);
#else
    mkdir(output_dir, 0755);
#endif
    
    // Create filename
    char filename[512];
    snprintf(filename, sizeof(filename), "%s/batch_epoch%lu_policy%u.bin",
             output_dir, batch->epoch_id, (uint32_t)batch->policy.attr_count);
    
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    // Write batch header
    fwrite(&batch->epoch_id, sizeof(uint64_t), 1, fp);
    fwrite(&batch->n_logs, sizeof(uint32_t), 1, fp);
    fwrite(batch->epoch_start, 32, 1, fp);
    fwrite(batch->epoch_end, 32, 1, fp);
    
    // Write policy
    fwrite(batch->policy.expression, MAX_POLICY_SIZE, 1, fp);
    
    // Write each encrypted log
    for (uint32_t i = 0; i < batch->n_logs; i++) {
        const EncryptedLogObject *log = &batch->logs[i];
        
        // Write metadata
        fwrite(&log->metadata, sizeof(LogMetadata), 1, fp);
        
        // Write symmetric ciphertext
        fwrite(&log->ct_sym.ct_len, sizeof(uint32_t), 1, fp);
        fwrite(log->ct_sym.ciphertext, log->ct_sym.ct_len, 1, fp);
        fwrite(log->ct_sym.nonce, AES_NONCE_SIZE, 1, fp);
        fwrite(log->ct_sym.tag, AES_TAG_SIZE, 1, fp);
        
        // Write hash
        fwrite(log->hash, SHA3_DIGEST_SIZE, 1, fp);
    }
    
    fclose(fp);
    printf("[Save] Batch saved to %s\n", filename);
    
    // Save hashes to separate file
    char hash_filename[512];
    snprintf(hash_filename, sizeof(hash_filename), "%s/batch_epoch%lu_policy%u_hashes.txt",
             output_dir, batch->epoch_id, (uint32_t)batch->policy.attr_count);
    
    fp = fopen(hash_filename, "w");
    if (fp) {
        for (uint32_t i = 0; i < batch->n_logs; i++) {
            fprintf(fp, "Log %d: ", i);
            for (int j = 0; j < SHA3_DIGEST_SIZE; j++) {
                fprintf(fp, "%02x", batch->logs[i].hash[j]);
            }
            fprintf(fp, "\n");
        }
        fclose(fp);
    }
    
    return 0;
}
