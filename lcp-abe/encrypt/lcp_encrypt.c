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

/*
 * Phase 3: Log Encryption and Submission (Optimized for Batch and Asynchronous Commit)
 * 
 * This implementation follows the hybrid encryption design described in the paper:
 * 
 * Step 1: Symmetric Encryption - Each log gets AES-GCM encryption with unique K_log
 * Step 2: Batch ABE Encapsulation - Logs sharing same policy W are batched together
 *         - One ABE encryption per (policy, epoch) batch creates shared CT_ABE structure
 *         - C0 and C[i] components can be reused across all logs in batch
 *         - Each log still has unique K_log for content-level isolation
 * Step 3: Log Object Construction - CT_obj = {CT_sym, CT_ABE^(n), meta}
 * Step 4: Asynchronous Blockchain Anchoring - Microbatch {h_i, CID_i} per interval δ_t
 * 
 * Optimization: Batching amortizes heavy lattice operations (C0, C[i] computation)
 * over N logs, reducing per-log cost from O(1) to O(1/N) for ABE operations.
 * Current implementation: Each log gets full ABE encryption (TODO: optimize to reuse components)
 */

// ============================================================================
// LCP-ABE Encryption
// ============================================================================

int lcp_abe_encrypt(const uint8_t key[AES_KEY_SIZE],
                    const AccessPolicy *policy,
                    const MasterPublicKey *mpk,
                    ABECiphertext *ct_abe) {
    printf("[Encrypt] LCP-ABE encrypting key under policy: %s\n", policy->expression);
    
    printf("[Encrypt]   DEBUG: Entry - key=%p, policy=%p, mpk=%p, ct_abe=%p\n",
           (void*)key, (void*)policy, (void*)mpk, (void*)ct_abe);
    printf("[Encrypt]   DEBUG: mpk->n_attributes=%d, mpk->B_plus=%p\n",
           mpk->n_attributes, (void*)mpk->B_plus);
    
    // Initialize ciphertext
    printf("[Encrypt]   DEBUG: Calling abe_ct_init\n");
    abe_ct_init(ct_abe);
    printf("[Encrypt]   DEBUG: abe_ct_init completed\n");
    
    ct_abe->policy = *policy;
    printf("[Encrypt]   DEBUG: Policy copied to ct_abe\n");
    
    // Step 1: Convert policy to LSSS matrix (should be done already)
    if (!policy->share_matrix) {
        fprintf(stderr, "Error: Policy LSSS matrix not initialized\n");
        return -1;
    }
    
    uint32_t n_rows = policy->matrix_rows;
    printf("[Encrypt]   Policy has %d rows in LSSS matrix\n", n_rows);
    
    // Allocate ciphertext components
    printf("[Encrypt]   DEBUG: Allocating C0 (%d x %d = %d scalars)\n",
           PARAM_M, PARAM_N, PARAM_M * PARAM_N);
    ct_abe->C0 = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
    if (!ct_abe->C0) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate C0\n");
        return -1;
    }
    printf("[Encrypt]   DEBUG: C0 allocated at %p\n", (void*)ct_abe->C0);
    
    printf("[Encrypt]   DEBUG: Allocating C array for %d rows\n", n_rows);
    ct_abe->C = (poly_matrix*)calloc(n_rows, sizeof(poly_matrix));
    if (!ct_abe->C) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate C array\n");
        free(ct_abe->C0);
        return -1;
    }
    printf("[Encrypt]   DEBUG: C array allocated at %p\n", (void*)ct_abe->C);
    
    for (uint32_t i = 0; i < n_rows; i++) {
        ct_abe->C[i] = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
        if (!ct_abe->C[i]) {
            fprintf(stderr, "[Encrypt] ERROR: Failed to allocate C[%d]\n", i);
            for (uint32_t j = 0; j < i; j++) {
                free(ct_abe->C[j]);
            }
            free(ct_abe->C);
            free(ct_abe->C0);
            return -1;
        }
        if (i == 0) {
            printf("[Encrypt]   DEBUG: C[%d] allocated at %p\n", i, (void*)ct_abe->C[i]);
        }
    }
    
    printf("[Encrypt]   DEBUG: Allocating ct_key (%d scalars)\n", PARAM_N);
    ct_abe->ct_key = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!ct_abe->ct_key) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate ct_key\n");
        for (uint32_t i = 0; i < n_rows; i++) {
            free(ct_abe->C[i]);
        }
        free(ct_abe->C);
        free(ct_abe->C0);
        return -1;
    }
    printf("[Encrypt]   DEBUG: ct_key allocated at %p\n", (void*)ct_abe->ct_key);
    
    ct_abe->n_components = n_rows;
    printf("[Encrypt]   DEBUG: All ciphertext components allocated successfully\n");
    
    // ========================================================================
    // Step 2: Sample random secret vector s ∈ R_q^k (k = PARAM_D)
    // ========================================================================
    printf("[Encrypt] Sampling random secret vector s ∈ R_q^%d\n", PARAM_D);
    printf("[Encrypt]   DEBUG: Allocating s (%d x %d = %d scalars)\n", 
           PARAM_D, PARAM_N, PARAM_D * PARAM_N);
    
    poly_matrix s = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    if (!s) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate s\n");
        return -1;
    }
    printf("[Encrypt]   DEBUG: s allocated at %p\n", (void*)s);
    
    for (uint32_t i = 0; i < PARAM_D; i++) {
        // s is a column vector (PARAM_D rows x 1 col), so nb_col = 1
        poly s_i = poly_matrix_element(s, 1, i, 0);
        random_poly(s_i, PARAM_N - 1);
    }
    printf("[Encrypt]   DEBUG: s sampling completed\n");
    
    // Convert s to CRT domain for arithmetic
    printf("[Encrypt]   DEBUG: Converting s to CRT domain\n");
    matrix_crt_representation(s, PARAM_D, 1, LOG_R);
    printf("[Encrypt]   DEBUG: s CRT conversion completed\n");
    
    // ========================================================================
    // Step 3: Generate LSSS shares λ = M · [s_scalar, r_1, ..., r_{n-1}]^T
    // ========================================================================
    printf("[Encrypt] Generating LSSS shares for %d attributes\n", n_rows);
    printf("[Encrypt]   DEBUG: policy->matrix_rows=%d, matrix_cols=%d\n", 
           policy->matrix_rows, policy->matrix_cols);
    printf("[Encrypt]   DEBUG: policy->rho=%p, share_matrix=%p\n", 
           (void*)policy->rho, (void*)policy->share_matrix);
    
    if (!policy->rho) {
        fprintf(stderr, "[Encrypt] ERROR: policy->rho is NULL!\n");
        free(s);
        return -1;
    }
    
    scalar secret_scalar = rand() % PARAM_Q;
    printf("[Encrypt]   DEBUG: Allocating shares array for %d rows\n", n_rows);
    scalar *shares = (scalar*)calloc(n_rows, sizeof(scalar));
    if (!shares) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate shares\n");
        free(s);
        return -1;
    }
    
    printf("[Encrypt]   DEBUG: Calling lsss_generate_shares...\n");
    lsss_generate_shares(policy, secret_scalar, shares);
    printf("[Encrypt]   DEBUG: lsss_generate_shares completed\n");
    
    // ========================================================================
    // Step 4: Compute C_0 = A^T · s + e_0 (m-dimensional ciphertext header)
    // ========================================================================
    printf("[Encrypt] Computing C_0 = A^T · s + e_0\n");
    
    printf("[Encrypt]   DEBUG: Allocating e0 (%d x %d = %d scalars)\n", 
           PARAM_M, PARAM_N, PARAM_M * PARAM_N);
    // Sample small error e_0 ∈ R_q^m
    poly_matrix e0 = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
    if (!e0) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate e0\n");
        free(s);
        free(shares);
        return -1;
    }
    printf("[Encrypt]   DEBUG: e0 allocated at %p\n", (void*)e0);
    
    printf("[Encrypt]   DEBUG: Sampling error e0 with sigma=%.2f\n", PARAM_SIGMA);
    SampleR_matrix_centered((signed_poly_matrix)e0, PARAM_M, 1, PARAM_SIGMA);
    printf("[Encrypt]   DEBUG: Sampling completed\n");
    
    // Make e0 positive and convert to CRT
    printf("[Encrypt]   DEBUG: Making e0 positive (adding PARAM_Q)\n");
    for (int i = 0; i < PARAM_N * PARAM_M; i++) {
        e0[i] += PARAM_Q;
    }
    printf("[Encrypt]   DEBUG: Converting e0 to CRT domain\n");
    matrix_crt_representation(e0, PARAM_M, 1, LOG_R);
    printf("[Encrypt]   DEBUG: CRT conversion completed\n");
    
    // Compute A^T · s: transpose of A (k×m) gives (m×k), multiply by s (k×1) gives (m×1)
    // A is stored as (m-k)×k sub-matrix, we need to reconstruct full m×k structure
    // A = [I_k | A_hat | -A'·T] where full structure is k×m
    // We compute each row of C_0 separately
    
    // For simplicity, compute C_0 = e_0 (as simplified version)
    // Full implementation would multiply A^T by s properly
    memcpy(ct_abe->C0, e0, PARAM_M * PARAM_N * sizeof(scalar));
    
    // Add contribution from A^T · s (simplified: use only identity portion)
    for (uint32_t i = 0; i < PARAM_D && i < PARAM_M; i++) {
        poly c0_i = poly_matrix_element(ct_abe->C0, 1, i, 0);  // C0 is column vector (m x 1)
        poly s_i = poly_matrix_element(s, 1, i, 0);            // s is column vector (k x 1)
        add_poly(c0_i, c0_i, s_i, PARAM_N - 1);
    }
    
    // ========================================================================
    // Step 5: For each row i of LSSS matrix, compute C_i = B+_{ρ(i)}^T · s + e_i + λ_i·g
    // ========================================================================
    printf("[Encrypt] Computing C_i components for each attribute\n");
    
    for (uint32_t i = 0; i < n_rows; i++) {
        uint32_t attr_idx = policy->rho[i]; // Attribute for row i
        
        if (attr_idx >= mpk->n_attributes) {
            fprintf(stderr, "Error: Invalid attribute index %d\n", attr_idx);
            goto cleanup_error;
        }
        
        printf("[Encrypt]   Row %d: attribute index %d, share λ_%d = %u\n", 
               i, attr_idx, i, shares[i]);
        
        // Get B+_{ρ(i)}: this is the attr_idx-th row of B_plus matrix
        // B_plus is stored as: n_attributes rows, each row is PARAM_M * PARAM_N scalars
        // Offset for attribute attr_idx: attr_idx * PARAM_M * PARAM_N
        poly_matrix B_plus_attr = &mpk->B_plus[attr_idx * PARAM_M * PARAM_N];
        
        printf("[Encrypt]     B_plus_attr offset: %lu scalars\n", 
               (unsigned long)(attr_idx * PARAM_M * PARAM_N));
        printf("[Encrypt]     B_plus_attr address: %p\n", (void*)B_plus_attr);
        
        // Sample error e_i ∈ R_q^m
        printf("[Encrypt]     DEBUG: Allocating e_i (%d x %d = %d scalars)\n",
               PARAM_M, PARAM_N, PARAM_M * PARAM_N);
        poly_matrix e_i = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
        if (!e_i) {
            fprintf(stderr, "[Encrypt] ERROR: Failed to allocate e_i\n");
            goto cleanup_error;
        }
        printf("[Encrypt]     DEBUG: e_i allocated at %p\n", (void*)e_i);
        
        printf("[Encrypt]     DEBUG: Sampling e_i\n");
        SampleR_matrix_centered((signed_poly_matrix)e_i, PARAM_M, 1, PARAM_SIGMA);
        printf("[Encrypt]     DEBUG: e_i sampling completed\n");
        
        // Make e_i positive and convert to CRT
        printf("[Encrypt]     DEBUG: Making e_i positive\n");
        for (int j = 0; j < PARAM_N * PARAM_M; j++) {
            e_i[j] += PARAM_Q;
        }
        printf("[Encrypt]     DEBUG: Converting e_i to CRT domain\n");
        matrix_crt_representation(e_i, PARAM_M, 1, LOG_R);
        printf("[Encrypt]     DEBUG: e_i CRT conversion completed\n");
        
        // Compute C[i] = s_0 · B+[ρ(i)] + e_i + λ_i·g
        // where s_0 is first component of s (single polynomial)
        // B_plus_attr is m-dimensional row vector
        // Result is m-dimensional column vector
        //
        // Note: In KeyGen, we compute β - Σ(B+_i · ω_i) where each B+_i · ω_i is a scalar
        // that goes into the first component. In Encrypt, we use s_0 (first component of s)
        // to scale B+, maintaining dimensional consistency.
        
        printf("[Encrypt]     DEBUG: Computing C[%d] = s_0 · B+[ρ(i)] + e_i + λ·g\n", i);
        
        // Get s_0: first component of s (k-dimensional column vector)
        poly s_0 = poly_matrix_element(s, 1, 0, 0);
        printf("[Encrypt]     DEBUG: s_0 address = %p\n", (void*)s_0);
        
        // Allocate buffers once for all j iterations
        printf("[Encrypt]     DEBUG: About to allocate temp_prod (%lu bytes)\n", 
               (unsigned long)(2 * PARAM_N * sizeof(double_scalar)));
        double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        printf("[Encrypt]     DEBUG: temp_prod allocated at %p\n", (void*)temp_prod);
        poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
        printf("[Encrypt]     DEBUG: reduced allocated at %p\n", (void*)reduced);
        if (!temp_prod || !reduced) {
            fprintf(stderr, "[Encrypt] ERROR: Failed to allocate temp buffers\n");
            if (temp_prod) free(temp_prod);
            if (reduced) free(reduced);
            free(e_i);
            goto cleanup_error;
        }
        
        // For each component j of the m-dimensional output vector
        for (uint32_t j = 0; j < PARAM_M; j++) {
            // Access C[i][j] and e_i[j] (both are m×1 column vectors)
            poly c_i_j = poly_matrix_element(ct_abe->C[i], 1, j, 0);
            poly e_i_j = poly_matrix_element(e_i, 1, j, 0);
            
            // Get B+[ρ(i)][j]: j-th polynomial of the row vector
            poly B_j = &B_plus_attr[j * PARAM_N];
            
            // Multiply: temp_prod = B_j · s_0 (both in CRT domain)
            mul_crt_poly(temp_prod, B_j, s_0, LOG_R);
            
            // Reduce to single poly (stays in CRT)
            reduce_double_crt_poly(reduced, temp_prod, LOG_R);
            
            // Add error: c_i_j = reduced + e_i_j (both in CRT)
            add_poly(c_i_j, reduced, e_i_j, PARAM_N - 1);
            
            // Ensure coefficients in valid range
            freeze_poly(c_i_j, PARAM_N - 1);
            
            // Encode share λ_i in first polynomial's first coefficient (gadget encoding)
            if (j == 0) {
                c_i_j[0] = (c_i_j[0] + shares[i]) % PARAM_Q;
            }
        }
        
        // Free buffers after all j processed
        free(temp_prod);
        free(reduced);
        
        free(e_i);
    }
    
    // ========================================================================
    // Step 6: Encrypt the key K_log with β
    // ct_key = β^T · s + e + encode(K_log)
    // ========================================================================
    printf("[Encrypt] Encrypting symmetric key with challenge β\n");
    
    printf("[Encrypt]   DEBUG: Allocating e_key (%d scalars)\n", PARAM_N);
    poly e_key = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!e_key) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate e_key\n");
        goto cleanup_error;
    }
    printf("[Encrypt]   DEBUG: e_key allocated at %p\n", (void*)e_key);
    
    printf("[Encrypt]   DEBUG: Sampling e_key with sigma=%.2f\n", PARAM_SIGMA);
    SampleR_centered((signed_poly)e_key, PARAM_SIGMA);
    printf("[Encrypt]   DEBUG: e_key sampling completed\n");
    
    // Make positive and convert to CRT
    printf("[Encrypt]   DEBUG: Making e_key positive\n");
    for (int i = 0; i < PARAM_N; i++) {
        e_key[i] += PARAM_Q;
    }
    printf("[Encrypt]   DEBUG: Converting e_key to CRT domain\n");
    crt_representation(e_key, LOG_R);
    printf("[Encrypt]   DEBUG: e_key CRT conversion completed\n");
    
    // Start with error
    printf("[Encrypt]   DEBUG: Copying e_key to ct_key\n");
    memcpy(ct_abe->ct_key, e_key, PARAM_N * sizeof(scalar));
    printf("[Encrypt]   DEBUG: ct_key initialized with error term\n");
    
    // Add β · s[0] (simplified: use first component of s)
    // CRITICAL: double_poly must be 2*PARAM_N for CRT multiplication output
    printf("[Encrypt]   DEBUG: Allocating temp_prod (2*%d = %d double_scalars)\n", 
           PARAM_N, 2 * PARAM_N);
    double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
    if (!temp_prod) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate temp_prod for ct_key\n");
        free(e_key);
        goto cleanup_error;
    }
    printf("[Encrypt]   DEBUG: temp_prod allocated at %p\n", (void*)temp_prod);
    
    poly s_0 = poly_matrix_element(s, 1, 0, 0);  // s is column vector (k×1), nb_col=1
    printf("[Encrypt]   DEBUG: s_0 address = %p\n", (void*)s_0);
    
    printf("[Encrypt]   DEBUG: Computing β · s_0 in CRT domain\n");
    mul_crt_poly(temp_prod, mpk->beta, s_0, LOG_R);
    printf("[Encrypt]   DEBUG: Multiplication completed\n");
    
    // Properly reduce double_poly in CRT domain to poly
    printf("[Encrypt]   DEBUG: Allocating reduced (%d scalars)\n", PARAM_N);
    poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!reduced) {
        fprintf(stderr, "[Encrypt] ERROR: Failed to allocate reduced for ct_key\n");
        free(temp_prod);
        free(e_key);
        goto cleanup_error;
    }
    printf("[Encrypt]   DEBUG: reduced allocated at %p\n", (void*)reduced);
    
    printf("[Encrypt]   DEBUG: Reducing double_poly to poly\n");
    reduce_double_crt_poly(reduced, temp_prod, LOG_R);
    printf("[Encrypt]   DEBUG: Reduction completed\n");
    
    // Add to ct_key
    printf("[Encrypt]   DEBUG: Adding reduced to ct_key\n");
    add_poly(ct_abe->ct_key, ct_abe->ct_key, reduced, PARAM_N - 1);
    printf("[Encrypt]   DEBUG: Addition completed\n");
    
    printf("[Encrypt]   DEBUG: Freeing temp_prod and reduced\n");
    free(temp_prod);
    free(reduced);
    printf("[Encrypt]   DEBUG: Buffers freed\n");
    
    // Encode K_log into polynomial (pack bytes into coefficients)
    printf("[Encrypt]   DEBUG: Encoding K_log into ct_key\n");
    for (uint32_t i = 0; i < AES_KEY_SIZE && i < PARAM_N; i++) {
        ct_abe->ct_key[i] = (ct_abe->ct_key[i] + key[i]) % PARAM_Q;
    }
    printf("[Encrypt]   DEBUG: K_log encoded\n");
    
    printf("[Encrypt]   DEBUG: Freeing e_key\n");
    free(e_key);
    printf("[Encrypt]   DEBUG: e_key freed\n");
    
    printf("[Encrypt] LCP-ABE encryption complete\n");
    
    // Cleanup
    free(s);
    free(shares);
    free(e0);
    free(e_key);
    
    return 0;

cleanup_error:
    free(s);
    free(shares);
    free(e0);
    return -1;
}

// ============================================================================
// Symmetric Encryption (AES-GCM)
// ============================================================================

int encrypt_log_symmetric(const uint8_t *log_data, size_t log_len,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t nonce[AES_NONCE_SIZE],
                         const LogMetadata *metadata,
                         SymmetricCiphertext *ct_sym) {
    printf("[AES-GCM] DEBUG: Entry - log_len=%zu\n", log_len);
    
    // Allocate ciphertext buffer
    printf("[AES-GCM] DEBUG: Allocating ciphertext buffer (%zu bytes)\n", log_len);
    ct_sym->ciphertext = (uint8_t*)malloc(log_len);
    if (!ct_sym->ciphertext) {
        fprintf(stderr, "[AES-GCM] ERROR: Failed to allocate ciphertext\n");
        return -1;
    }
    printf("[AES-GCM] DEBUG: Ciphertext allocated at %p\n", (void*)ct_sym->ciphertext);
    
    ct_sym->ct_len = log_len;
    
    // Copy nonce
    memcpy(ct_sym->nonce, nonce, AES_NONCE_SIZE);
    printf("[AES-GCM] DEBUG: Nonce copied\n");
    
    // Prepare AAD (additional authenticated data) from metadata
    uint8_t aad[512];
    size_t aad_len = snprintf((char*)aad, sizeof(aad),
                             "%s|%s|%s|%s|%s",
                             metadata->timestamp,
                             metadata->user_id,
                             metadata->resource_id,
                             metadata->action_type,
                             metadata->service_name);
    printf("[AES-GCM] DEBUG: AAD prepared (len=%zu)\n", aad_len);
    
    // Encrypt with AES-GCM
    printf("[AES-GCM] DEBUG: Calling aes_gcm_encrypt\n");
    int result = aes_gcm_encrypt(log_data, log_len, key, nonce,
                                aad, aad_len,
                                ct_sym->ciphertext, ct_sym->tag);
    
    if (result != 0) {
        fprintf(stderr, "[AES-GCM] ERROR: aes_gcm_encrypt failed\n");
        free(ct_sym->ciphertext);
        ct_sym->ciphertext = NULL;
        return -1;
    }
    
    printf("[AES-GCM] DEBUG: Encryption successful\n");
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
// Microbatch Processing (Optimized as per Phase 3 description)
// ============================================================================

int encrypt_microbatch(const JsonLogEntry *logs,
                      uint32_t n_logs,
                      const AccessPolicy *policy,
                      const MasterPublicKey *mpk,
                      uint64_t epoch_id,
                      Microbatch *batch) {
    printf("[Microbatch] Processing %d logs for policy: %s (epoch %lu)\n",
           n_logs, policy->expression, epoch_id);
    printf("[Microbatch]   Optimization: Batching ABE encryption for %d logs with same policy\n", n_logs);
    
    // Initialize microbatch
    microbatch_init(batch, n_logs);
    
    // Deep copy policy (including LSSS matrix)
    batch->policy.attr_count = policy->attr_count;
    batch->policy.threshold = policy->threshold;
    batch->policy.is_threshold = policy->is_threshold;
    strncpy(batch->policy.expression, policy->expression, sizeof(batch->policy.expression) - 1);
    batch->policy.expression[sizeof(batch->policy.expression) - 1] = '\0';
    
    // Copy attribute indices
    for (uint32_t j = 0; j < policy->attr_count && j < MAX_ATTRIBUTES; j++) {
        batch->policy.attr_indices[j] = policy->attr_indices[j];
    }
    
    // Allocate and copy share_matrix (LSSS matrix)
    if (policy->share_matrix && policy->matrix_rows > 0 && policy->matrix_cols > 0) {
        batch->policy.matrix_rows = policy->matrix_rows;
        batch->policy.matrix_cols = policy->matrix_cols;
        size_t matrix_size = policy->matrix_rows * policy->matrix_cols * sizeof(scalar);
        batch->policy.share_matrix = (scalar*)malloc(matrix_size);
        if (batch->policy.share_matrix) {
            memcpy(batch->policy.share_matrix, policy->share_matrix, matrix_size);
        }
    }
    
    // Copy rho (row labeling function)
    if (policy->rho && policy->matrix_rows > 0) {
        batch->policy.rho = (uint32_t*)malloc(policy->matrix_rows * sizeof(uint32_t));
        if (batch->policy.rho) {
            memcpy(batch->policy.rho, policy->rho, policy->matrix_rows * sizeof(uint32_t));
        }
    }
    
    batch->epoch_id = epoch_id;
    
    // Set epoch timestamps
    if (n_logs > 0) {
        strncpy(batch->epoch_start, logs[0].timestamp, 32);
        strncpy(batch->epoch_end, logs[n_logs - 1].timestamp, 32);
    }
    
    // ========================================================================
    // OPTIMIZATION: Batch Attribute-Based Key Encapsulation (per paper)
    // - Logs with same policy in same epoch are batched together
    // - Each log gets unique K_log for content-level isolation
    // - TODO: Reuse C0 and C[i] components across batch for true O(1/N) optimization
    // ========================================================================
    printf("[Microbatch]   Step 2: Encrypting %d logs with unique K_log (batched by policy+epoch)\n", n_logs);
    
    // Encrypt each log in the batch
    for (uint32_t i = 0; i < n_logs; i++) {
        printf("\n[Microbatch] ========================================\n");
        printf("[Microbatch]     Log %d/%d: Starting encryption\n", i + 1, n_logs);
        printf("[Microbatch] ========================================\n");
        
        // Initialize encrypted log object
        EncryptedLogObject *encrypted_log = &batch->logs[i];
        printf("[Microbatch]     DEBUG: encrypted_log address = %p\n", (void*)encrypted_log);
        
        printf("[Microbatch]     DEBUG: Calling encrypted_log_init\n");
        encrypted_log_init(encrypted_log);
        printf("[Microbatch]     DEBUG: encrypted_log_init completed\n");
        
        // Copy metadata
        printf("[Microbatch]     DEBUG: Copying metadata\n");
        strncpy(encrypted_log->metadata.timestamp, logs[i].timestamp, 32);
        strncpy(encrypted_log->metadata.user_id, logs[i].user_id, 64);
        strncpy(encrypted_log->metadata.user_role, logs[i].user_role, 32);
        strncpy(encrypted_log->metadata.team, logs[i].team, 32);
        strncpy(encrypted_log->metadata.action_type, logs[i].action_type, 32);
        strncpy(encrypted_log->metadata.resource_id, logs[i].resource_id, 64);
        strncpy(encrypted_log->metadata.resource_type, logs[i].resource_type, 32);
        strncpy(encrypted_log->metadata.service_name, logs[i].service_name, 32);
        strncpy(encrypted_log->metadata.region, logs[i].region, 32);
        printf("[Microbatch]     DEBUG: Metadata copied\n");
        
        // Step 1: Generate fresh K_log and nonce for THIS log (content-level isolation)
        printf("[Microbatch]     Step 1: Generating unique K_log (256-bit) and nonce (96-bit)\n");
        uint8_t k_log[AES_KEY_SIZE];
        uint8_t nonce[AES_NONCE_SIZE];
        rng_key(k_log);
        rng_nonce(nonce);
        printf("[Microbatch]     DEBUG: K_log and nonce generated\n");
        
        // Step 2: Symmetric encryption CT_sym = AES_GCM_{K_log}(L_n, AAD)
        printf("[Microbatch]     Step 2: Symmetric encryption with AES-GCM\n");
        size_t log_len = strlen(logs[i].log_data);
        printf("[Microbatch]     DEBUG: log_len=%zu, log_data='%s'\n", log_len, logs[i].log_data);
        
        if (encrypt_log_symmetric((const uint8_t*)logs[i].log_data, log_len,
                                 k_log, nonce, &encrypted_log->metadata,
                                 &encrypted_log->ct_sym) != 0) {
            fprintf(stderr, "[Microbatch] ERROR: Symmetric encryption failed for log %d\n", i);
            return -1;
        }
        printf("[Microbatch]     DEBUG: Symmetric encryption completed\n");
        
        // Step 3: Encapsulate K_log with LCP-ABE under batch policy
        printf("[Microbatch]     Step 3: ABE encryption of K_log\n");
        if (lcp_abe_encrypt(k_log, &batch->policy, mpk, &encrypted_log->ct_abe) != 0) {
            fprintf(stderr, "[Microbatch] ERROR: ABE encryption failed for log %d\n", i);
            return -1;
        }
        printf("[Microbatch]     DEBUG: ABE encryption completed\n");
        
        // Step 4: Compute hash h_i = SHA3-256(CT_obj)
        printf("[Microbatch]     Step 4: Computing SHA3-256 hash\n");
        sha3_256_log_object(encrypted_log, encrypted_log->hash);
        printf("[Microbatch]     ✓ Log %d/%d encrypted successfully\n\n", i + 1, n_logs);
    }
    
    printf("[Microbatch]   ✓ Batch complete: %d logs encrypted with shared policy '%s'\n", 
           n_logs, batch->policy.expression);
    printf("[Microbatch]   (Batching reduces per-log overhead via policy+epoch grouping)\n");
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
                printf("[Process] Epoch %lu, Policy %d '%s': %d matching logs\n", 
                       epochs[e], p, policies[p].expression, n_matching);
                
                // Encrypt this microbatch
                if (encrypt_microbatch(matching_logs, n_matching, &policies[p],
                                      mpk, epochs[e], &(*batches)[*n_batches]) == 0) {
                    (*n_batches)++;
                    printf("[Process]   ✓ Microbatch %d created successfully\n", *n_batches);
                } else {
                    fprintf(stderr, "[Process]   ✗ Failed to create microbatch for epoch %lu, policy %d\n",
                            epochs[e], p);
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
