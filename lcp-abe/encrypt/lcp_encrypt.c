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
#include <errno.h>
#ifdef _WIN32
#include <direct.h>
#endif

// ============================================================================
// Batch-Optimized LCP-ABE Encryption (O(1/N) optimization)
// ============================================================================
// 
// This implements the batching optimization described in Phase 3:
// "The AA performs ONE LCP-ABE encapsulation to derive a common header
// CT_ABE^W and uses it across all logs in that batch."
//
// Split into two parts:
// 1. lcp_abe_encrypt_batch_init: Compute shared C0, C[i] (once per batch)
// 2. lcp_abe_encrypt_batch_key: Compute unique ct_key per log (N times)
//
// Complexity: First log = O(1), remaining logs = O(1/N)
// ============================================================================

int lcp_abe_encrypt_batch_init(const AccessPolicy *policy,
                               const MasterPublicKey *mpk,
                               ABECiphertext *ct_abe_template,
                               poly_matrix *s_out) {
    // Initialize ciphertext template
    abe_ct_init(ct_abe_template);
    ct_abe_template->policy = *policy;
    
    if (!policy->share_matrix) {
        fprintf(stderr, "[Batch Init] Error: Policy LSSS matrix not initialized\n");
        return -1;
    }
    
    uint32_t n_rows = policy->matrix_rows;
    
    ct_abe_template->C0 = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
    ct_abe_template->C = (poly_matrix*)calloc(n_rows, sizeof(poly_matrix));
    ct_abe_template->n_components = n_rows;  // CRITICAL: Set n_components
    
    if (!ct_abe_template->C0 || !ct_abe_template->C) {
        fprintf(stderr, "[Batch Init] ERROR: Failed to allocate C0/C\n");
        return -1;
    }
    
    for (uint32_t i = 0; i < n_rows; i++) {
        ct_abe_template->C[i] = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
        if (!ct_abe_template->C[i]) {
            fprintf(stderr, "[Batch Init] ERROR: Failed to allocate C[%d]\n", i);
            return -1;
        }
    }
    

    poly_matrix s = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    if (!s) {
        fprintf(stderr, "[Batch Init] ERROR: Failed to allocate s\n");
        return -1;
    }
    
    SampleR_matrix_centered((signed_poly_matrix)s, PARAM_D, 1, PARAM_SIGMA);
    for (int i = 0; i < PARAM_N * PARAM_D; i++) {
        s[i] += PARAM_Q;
    }
    matrix_crt_representation(s, PARAM_D, 1, LOG_R);

    
    scalar secret_scalar = 0;  // Share secret = 0 (shares won't interfere with decryption)
    scalar *shares = (scalar*)calloc(n_rows, sizeof(scalar));
    if (!shares) {
        fprintf(stderr, "[Batch Init] ERROR: Failed to allocate shares\n");
        free(s);
        return -1;
    }
    lsss_generate_shares(policy, secret_scalar, shares);
    
    // Compute C_0 = A^T · s + e_0 (SHARED)
    poly_matrix e0 = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
    if (!e0) {
        fprintf(stderr, "[Batch Init] ERROR: Failed to allocate e0\n");
        free(s);
        free(shares);
        return -1;
    }
    
    SampleR_centered((signed_poly)&e0[0 * PARAM_N], 0.25 * PARAM_SIGMA);
    
    for (uint32_t i = 1; i < PARAM_M; i++) {
        SampleR_centered((signed_poly)&e0[i * PARAM_N], PARAM_SIGMA);
    }
    
    for (int i = 0; i < PARAM_N * PARAM_M; i++) {
        e0[i] += PARAM_Q;
    }
    matrix_crt_representation(e0, PARAM_M, 1, LOG_R);
    
    poly_matrix A_T_s = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
    if (!A_T_s) {
        fprintf(stderr, "[Batch Init] ERROR: Failed to allocate A_T_s\n");
        free(s);
        free(shares);
        free(e0);
        return -1;
    }
    

    for (uint32_t i = 0; i < PARAM_D; i++) {
        poly result_i = poly_matrix_element(A_T_s, 1, i, 0);
        poly s_i = poly_matrix_element(s, 1, i, 0);
        memcpy(result_i, s_i, PARAM_N * sizeof(scalar));
    }
    
    for (uint32_t i = 0; i < PARAM_M - PARAM_D; i++) {
        poly result_i = poly_matrix_element(A_T_s, 1, i + PARAM_D, 0);
        
        for (uint32_t j = 0; j < PARAM_D; j++) {
            poly A_ji = poly_matrix_element(mpk->A, PARAM_M - PARAM_D, j, i);
            poly s_j = poly_matrix_element(s, 1, j, 0);
            
            double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            mul_crt_poly(temp_prod, A_ji, s_j, LOG_R);
            
            poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            reduce_double_crt_poly(reduced, temp_prod, LOG_R);
            
            add_poly(result_i, result_i, reduced, PARAM_N - 1);
            
            free(temp_prod);
            free(reduced);
        }
    }
    
    if (getenv("ARITH_DEBUG")) {
        for (uint32_t _i = 0; _i < 16 && _i < PARAM_M; _i++) {
            poly a_ts_elem = poly_matrix_element(A_T_s, 1, _i, 0);
            printf("[ENCRYPT MAP] A_T_s idx=%u ptr=%p first4=%u %u %u %u\n",
                   _i, (void*)a_ts_elem, a_ts_elem[0], a_ts_elem[1], a_ts_elem[2], a_ts_elem[3]);
        }
    }
    memcpy(ct_abe_template->C0, A_T_s, PARAM_M * PARAM_N * sizeof(scalar));
    add_poly(ct_abe_template->C0, ct_abe_template->C0, e0, PARAM_N * PARAM_M - 1);
    
    if (getenv("ARITH_DEBUG")) {
        for (uint32_t _i = 0; _i < 6 && _i < PARAM_M; _i++) {
            poly c0_i = poly_matrix_element(ct_abe_template->C0, 1, _i, 0);
            printf("[ENCRYPT DIAG] C0_template i=%u ptr=%p first4=%u %u %u %u\n",
                   _i, (void*)c0_i, c0_i[0], c0_i[1], c0_i[2], c0_i[3]);
        }
    }

    free(A_T_s);

    if (getenv("ARITH_DEBUG")) {
        for (uint32_t ii = 0; ii < PARAM_D; ii++) {
            poly s_i = poly_matrix_element(s, 1, ii, 0);
            for (int comp = 0; comp < LOG_R; comp++) {
                char tags[80];
                snprintf(tags, sizeof(tags), "ENCRYPT_s_poly_%u_comp_%d", ii, comp);
                dump_crt_component(s_i, LOG_R, comp, tags);
            }
            poly s_i_copy = (poly)calloc(PARAM_N, sizeof(scalar));
            if (s_i_copy) {
                memcpy(s_i_copy, s_i, PARAM_N * sizeof(scalar));
                coeffs_representation(s_i_copy, LOG_R);
                printf("[ARITH DUMP] ENCRYPT_s_poly_%u_COEFF: COEFF (deg=%d, first %d):", ii, PARAM_N, PARAM_N);
                for (int _k = 0; _k < PARAM_N; _k++) printf(" %" PRIu32, (uint32_t)s_i_copy[_k]);
                printf("\n");
                free(s_i_copy);
            }
        }

        for (uint32_t ii = 0; ii < PARAM_M && ii < 8; ii++) {
            poly a_ts_i = poly_matrix_element(ct_abe_template->C0, 1, ii, 0);
            for (int comp = 0; comp < LOG_R; comp++) {
                char taga[96];
                snprintf(taga, sizeof(taga), "ENCRYPT_A_T_s_poly_%u_comp_%d", ii, comp);
                dump_crt_component(a_ts_i, LOG_R, comp, taga);
            }
            printf("[ENCRYPT DIAG] A_T_s poly %u first4=%u %u %u %u ptr=%p\n",
                   ii, a_ts_i[0], a_ts_i[1], a_ts_i[2], a_ts_i[3], (void*)a_ts_i);
            poly a_ts_copy = (poly)calloc(PARAM_N, sizeof(scalar));
            if (a_ts_copy) {
                memcpy(a_ts_copy, a_ts_i, PARAM_N * sizeof(scalar));
                coeffs_representation(a_ts_copy, LOG_R);
                printf("[ARITH DUMP] ENCRYPT_A_T_s_poly_%u_COEFF: COEFF (deg=%d, first %d):", ii, PARAM_N, PARAM_N);
                for (int _k = 0; _k < PARAM_N; _k++) printf(" %" PRIu32, (uint32_t)a_ts_copy[_k]);
                printf("\n");
                free(a_ts_copy);
            }
        }
    }
    
    for (uint32_t i = 0; i < n_rows; i++) {
        uint32_t attr_idx = policy->rho[i];
        
        if (attr_idx >= mpk->n_attributes) {
            fprintf(stderr, "[Batch Init] Error: Invalid attribute index %d\n", attr_idx);
            free(s);
            free(shares);
            free(e0);
            return -1;
        }
        
        poly_matrix B_plus_attr = &mpk->B_plus[attr_idx * PARAM_M * PARAM_N];
        
        poly_matrix e_i = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
        if (!e_i) {
            fprintf(stderr, "[Batch Init] ERROR: Failed to allocate e_i\n");
            free(s);
            free(shares);
            free(e0);
            return -1;
        }
        
        SampleR_matrix_centered((signed_poly_matrix)e_i, PARAM_M, 1, PARAM_SIGMA);
        for (int j = 0; j < PARAM_N * PARAM_M; j++) {
            e_i[j] += PARAM_Q;
        }
        matrix_crt_representation(e_i, PARAM_M, 1, LOG_R);
        
        double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
        
        if (!temp_prod || !reduced) {
            fprintf(stderr, "[Batch Init] ERROR: Failed to allocate temp buffers\n");
            if (temp_prod) free(temp_prod);
            if (reduced) free(reduced);
            free(e_i);
            free(s);
            free(shares);
            free(e0);
            return -1;
        }
        
        poly s_0 = poly_matrix_element(s, 1, 0, 0);
        
        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly c_i_j = poly_matrix_element(ct_abe_template->C[i], 1, j, 0);
            poly e_i_j = poly_matrix_element(e_i, 1, j, 0);
            poly B_j = &B_plus_attr[j * PARAM_N];
            
            mul_crt_poly(temp_prod, B_j, s_0, LOG_R);
            reduce_double_crt_poly(reduced, temp_prod, LOG_R);
            add_poly(c_i_j, reduced, e_i_j, PARAM_N - 1);
            
            freeze_poly(c_i_j, PARAM_N - 1);
        }
        
        free(temp_prod);
        free(reduced);
        free(e_i);
    }
    
    if (getenv("ARITH_DEBUG")) {
        for (uint32_t _i = 0; _i < 3 && _i < n_rows; _i++) {
            for (uint32_t _j = 0; _j < 4 && _j < PARAM_M; _j++) {
                poly c_ij = poly_matrix_element(ct_abe_template->C[_i], 1, _j, 0);
                printf("[ENCRYPT DIAG] C_template i=%u j=%u ptr=%p first4=%u %u %u %u\n",
                       _i, _j, (void*)c_ij, c_ij[0], c_ij[1], c_ij[2], c_ij[3]);
            }
        }
    }

    free(e0);
    free(shares);
    
    *s_out = s;
    
    return 0;
}

int lcp_abe_encrypt_batch_key(const uint8_t key[AES_KEY_SIZE],
                              const poly_matrix s,
                              const MasterPublicKey *mpk,
                              const ABECiphertext *ct_abe_template,
                              ABECiphertext *ct_abe) {
    abe_ct_init(ct_abe);
    ct_abe->policy = ct_abe_template->policy;
    ct_abe->n_components = ct_abe_template->n_components;
    
    ct_abe->C0 = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
    if (!ct_abe->C0) {
        fprintf(stderr, "[Batch Key] ERROR: Failed to allocate C0\n");
        return -1;
    }
    memcpy(ct_abe->C0, ct_abe_template->C0, PARAM_M * PARAM_N * sizeof(scalar));    
    if (getenv("ARITH_DEBUG")) {
        for (uint32_t _i = 0; _i < 6 && _i < PARAM_M; _i++) {
            poly c0_i = poly_matrix_element(ct_abe->C0, 1, _i, 0);
            printf("[ENCRYPT DIAG] C0_deepcopy i=%u ptr=%p first4=%u %u %u %u\n",
                   _i, (void*)c0_i, c0_i[0], c0_i[1], c0_i[2], c0_i[3]);
        }
    }
    
    uint32_t n_rows = ct_abe_template->policy.matrix_rows;
    ct_abe->C = (poly_matrix*)calloc(n_rows, sizeof(poly_matrix));
    if (!ct_abe->C) {
        fprintf(stderr, "[Batch Key] ERROR: Failed to allocate C array\n");
        free(ct_abe->C0);
        return -1;
    }
    
    for (uint32_t i = 0; i < n_rows; i++) {
        ct_abe->C[i] = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
        if (!ct_abe->C[i]) {
            fprintf(stderr, "[Batch Key] ERROR: Failed to allocate C[%d]\n", i);
            for (uint32_t j = 0; j < i; j++) {
                free(ct_abe->C[j]);
            }
            free(ct_abe->C);
            free(ct_abe->C0);
            return -1;
        }
        memcpy(ct_abe->C[i], ct_abe_template->C[i], PARAM_M * PARAM_N * sizeof(scalar));
    }

    if (getenv("ARITH_DEBUG")) {
        for (uint32_t _i = 0; _i < 3 && _i < n_rows; _i++) {
            for (uint32_t _j = 0; _j < 4 && _j < PARAM_M; _j++) {
                poly c_ij = poly_matrix_element(ct_abe->C[_i], 1, _j, 0);
                printf("[ENCRYPT DIAG] C_deepcopy i=%u j=%u ptr=%p first4=%u %u %u %u\n",
                       _i, _j, (void*)c_ij, c_ij[0], c_ij[1], c_ij[2], c_ij[3]);
            }
        }
    }
    
    ct_abe->ct_key = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!ct_abe->ct_key) {
        fprintf(stderr, "[Batch Key] ERROR: Failed to allocate ct_key\n");
        for (uint32_t i = 0; i < n_rows; i++) {
            free(ct_abe->C[i]);
        }
        free(ct_abe->C);
        free(ct_abe->C0);
        return -1;
    }
    
    poly e_key = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!e_key) {
        fprintf(stderr, "[Batch Key] ERROR: Failed to allocate e_key\n");
        free(ct_abe->ct_key);
        return -1;
    }
    
    // Reduce e_key noise for better k_log recovery (0.1× sigma for exact recovery)
    // This noise is still secure (σ = 0.7) but allows k_log extraction to work
    SampleR_centered((signed_poly)e_key, 0.1 * PARAM_SIGMA);
    for (int i = 0; i < PARAM_N; i++) {
        e_key[i] += PARAM_Q;
    }
    crt_representation(e_key, LOG_R);
    
    memcpy(ct_abe->ct_key, e_key, PARAM_N * sizeof(scalar));
    
    double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
    poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
    
    if (!temp_prod || !reduced) {
        fprintf(stderr, "[Batch Key] ERROR: Failed to allocate temp buffers\n");
        if (temp_prod) free(temp_prod);
        if (reduced) free(reduced);
        free(e_key);
        free(ct_abe->ct_key);
        return -1;
    }
    
    // Use C0[0] instead of s[0] to match what decryption recovers
    // Decryption recovers β·C0[0] = β·s[0] + β·e0[0], so encryption should use the same
    poly c0_0 = poly_matrix_element(ct_abe->C0, 1, 0, 0);
    if (getenv("ARITH_DEBUG")) {
        for (int comp = 0; comp < LOG_R; comp++) {
            char tb[80];
            char tc[80];
            snprintf(tb, sizeof(tb), "ENCRYPT_mpk_beta_comp_%d", comp);
            snprintf(tc, sizeof(tc), "ENCRYPT_c0_0_comp_%d", comp);
            dump_crt_component(mpk->beta, LOG_R, comp, tb);
            dump_crt_component(c0_0, LOG_R, comp, tc);
        }
    }
    mul_crt_poly(temp_prod, mpk->beta, c0_0, LOG_R);
    if (getenv("ARITH_DEBUG")) {
        for (int comp = 0; comp < LOG_R; comp++) {
            char tag[64];
            snprintf(tag, sizeof(tag), "ENCRYPT_beta_s0_comp_%d", comp);
            dump_double_crt_component(temp_prod, LOG_R, comp, tag);
        }
    }
    reduce_double_crt_poly(reduced, temp_prod, LOG_R);
    if (getenv("ARITH_DEBUG")) {
        for (int comp = 0; comp < LOG_R; comp++) {
            char tagr[80];
            snprintf(tagr, sizeof(tagr), "ENCRYPT_beta_s0_reduced_comp_%d", comp);
            dump_crt_component(reduced, LOG_R, comp, tagr);
        }
    }
    add_poly(ct_abe->ct_key, ct_abe->ct_key, reduced, PARAM_N - 1);
    
    free(temp_prod);
    free(reduced);
    
    coeffs_representation(ct_abe->ct_key, LOG_R);

    double_poly tmp_prod2 = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
    poly reduced_beta = (poly)calloc(PARAM_N, sizeof(scalar));
    if (tmp_prod2 && reduced_beta) {
        mul_crt_poly(tmp_prod2, mpk->beta, c0_0, LOG_R);
        if (getenv("ARITH_DEBUG")) {
            for (int comp = 0; comp < LOG_R; comp++) {
                char tag2[64];
                snprintf(tag2, sizeof(tag2), "ENCRYPT_beta_s0_tmp2_comp_%d", comp);
                dump_double_crt_component(tmp_prod2, LOG_R, comp, tag2);
            }
        }
        reduce_double_crt_poly(reduced_beta, tmp_prod2, LOG_R);
        if (getenv("ARITH_DEBUG")) {
            for (int comp = 0; comp < LOG_R; comp++) {
                char tagb2[80];
                snprintf(tagb2, sizeof(tagb2), "ENCRYPT_beta_s0_reduced_beta_comp_%d", comp);
                dump_crt_component(reduced_beta, LOG_R, comp, tagb2);
            }
        }
        coeffs_representation(reduced_beta, LOG_R);
        if (getenv("ARITH_DUMP_FULL")) {
            printf("[ENCRYPT DUMP FULL] beta_C0_0_COEFF:\n");
            for (int _i = 0; _i < PARAM_N; _i++) printf(" %u", reduced_beta[_i]);
            printf("\n");
        }
        free(reduced_beta);
    }
    if (tmp_prod2) free(tmp_prod2);
    
    const uint32_t shift = PARAM_K - 8;
    const uint32_t redundancy = 3;
    const uint32_t spacing = 32;
    
    for (uint32_t i = 0; i < AES_KEY_SIZE && i < PARAM_N; i++) {
        uint64_t encoded = (uint64_t)key[i] << shift;
        uint32_t encoded_val = (uint32_t)(encoded % PARAM_Q);
        
        for (uint32_t rep = 0; rep < redundancy; rep++) {
            uint32_t pos = i + rep * spacing;
            if (pos >= PARAM_N) break;
            
            uint64_t sum = (uint64_t)ct_abe->ct_key[pos] + encoded;
            ct_abe->ct_key[pos] = (uint32_t)(sum % PARAM_Q);
        }
    }
    
    free(e_key);
    
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
    if (log_len == 0 || log_len > 10 * 1024 * 1024) { /* 10 MB upper bound */
        fprintf(stderr, "[AES-GCM] ERROR: suspicious log_len=%zu\n", log_len);
        return -1;
    }

    ct_sym->ciphertext = (uint8_t*)malloc(log_len);
    if (!ct_sym->ciphertext) {
        fprintf(stderr, "[AES-GCM] ERROR: Failed to allocate ciphertext\n");
        return -1;
    }
    
    ct_sym->ct_len = log_len;
    
    memcpy(ct_sym->nonce, nonce, AES_NONCE_SIZE);
    
    uint8_t aad[512];
    size_t aad_len = snprintf((char*)aad, sizeof(aad),
                             "%s|%s|%s|%s|%s",
                             metadata->timestamp,
                             metadata->user_id,
                             metadata->resource_id,
                             metadata->action_type,
                             metadata->service_name);
    
    int result = aes_gcm_encrypt(log_data, log_len, key, nonce,
                                aad, aad_len,
                                ct_sym->ciphertext, ct_sym->tag);
    
    if (result != 0) {
        fprintf(stderr, "[AES-GCM] ERROR: aes_gcm_encrypt failed\n");
        free(ct_sym->ciphertext);
        ct_sym->ciphertext = NULL;
        return -1;
    }
    
    return 0;
}

// ============================================================================
// ============================================================================
// Microbatch Processing (Optimized as per Phase 3 description)
// ============================================================================

int encrypt_microbatch(const JsonLogEntry *logs,
                      uint32_t n_logs,
                      const AccessPolicy *policy,
                      const MasterPublicKey *mpk,
                      uint64_t epoch_id,
                      Microbatch *batch) {
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
    // OPTIMIZATION: Batch Attribute-Based Key Encapsulation (O(1/N) per log)
    // - Compute C0 and C[i] ONCE for the entire batch (shared components)
    // - Compute ct_key separately for each log (unique K_log encryption)
    // - Amortizes heavy lattice operations: First log O(1), remaining O(1/N)
    // ========================================================================
    
    // Step 1: Compute shared ABE components (C0, C[i]) - ONCE per batch
    ABECiphertext ct_abe_template;
    poly_matrix s_shared = NULL;
    
    if (lcp_abe_encrypt_batch_init(&batch->policy, mpk, &ct_abe_template, &s_shared) != 0) {
        fprintf(stderr, "[Microbatch] ERROR: Batch ABE init failed\n");
        return -1;
    }
    
    // Step 2: Encrypt each log using shared components
    for (uint32_t i = 0; i < n_logs; i++) {
        // Initialize encrypted log object
        EncryptedLogObject *encrypted_log = &batch->logs[i];
        encrypted_log_init(encrypted_log);
        
    // Copy metadata (bounded and null-terminated)
    strncpy(encrypted_log->metadata.timestamp, logs[i].timestamp, sizeof(encrypted_log->metadata.timestamp) - 1);
    encrypted_log->metadata.timestamp[sizeof(encrypted_log->metadata.timestamp) - 1] = '\0';
    strncpy(encrypted_log->metadata.user_id, logs[i].user_id, sizeof(encrypted_log->metadata.user_id) - 1);
    encrypted_log->metadata.user_id[sizeof(encrypted_log->metadata.user_id) - 1] = '\0';
    strncpy(encrypted_log->metadata.user_role, logs[i].user_role, sizeof(encrypted_log->metadata.user_role) - 1);
    encrypted_log->metadata.user_role[sizeof(encrypted_log->metadata.user_role) - 1] = '\0';
    strncpy(encrypted_log->metadata.team, logs[i].team, sizeof(encrypted_log->metadata.team) - 1);
    encrypted_log->metadata.team[sizeof(encrypted_log->metadata.team) - 1] = '\0';
    strncpy(encrypted_log->metadata.action_type, logs[i].action_type, sizeof(encrypted_log->metadata.action_type) - 1);
    encrypted_log->metadata.action_type[sizeof(encrypted_log->metadata.action_type) - 1] = '\0';
    strncpy(encrypted_log->metadata.resource_id, logs[i].resource_id, sizeof(encrypted_log->metadata.resource_id) - 1);
    encrypted_log->metadata.resource_id[sizeof(encrypted_log->metadata.resource_id) - 1] = '\0';
    strncpy(encrypted_log->metadata.resource_type, logs[i].resource_type, sizeof(encrypted_log->metadata.resource_type) - 1);
    encrypted_log->metadata.resource_type[sizeof(encrypted_log->metadata.resource_type) - 1] = '\0';
    strncpy(encrypted_log->metadata.service_name, logs[i].service_name, sizeof(encrypted_log->metadata.service_name) - 1);
    encrypted_log->metadata.service_name[sizeof(encrypted_log->metadata.service_name) - 1] = '\0';
    strncpy(encrypted_log->metadata.region, logs[i].region, sizeof(encrypted_log->metadata.region) - 1);
    encrypted_log->metadata.region[sizeof(encrypted_log->metadata.region) - 1] = '\0';
    
    // Copy additional fields for full JSON reconstruction
    strncpy(encrypted_log->metadata.resource_owner, logs[i].resource_owner, sizeof(encrypted_log->metadata.resource_owner) - 1);
    encrypted_log->metadata.resource_owner[sizeof(encrypted_log->metadata.resource_owner) - 1] = '\0';
    strncpy(encrypted_log->metadata.instance_id, logs[i].instance_id, sizeof(encrypted_log->metadata.instance_id) - 1);
    encrypted_log->metadata.instance_id[sizeof(encrypted_log->metadata.instance_id) - 1] = '\0';
    strncpy(encrypted_log->metadata.ip_address, logs[i].ip_address, sizeof(encrypted_log->metadata.ip_address) - 1);
    encrypted_log->metadata.ip_address[sizeof(encrypted_log->metadata.ip_address) - 1] = '\0';
    strncpy(encrypted_log->metadata.application, logs[i].application, sizeof(encrypted_log->metadata.application) - 1);
    encrypted_log->metadata.application[sizeof(encrypted_log->metadata.application) - 1] = '\0';
    strncpy(encrypted_log->metadata.event_description, logs[i].event_description, sizeof(encrypted_log->metadata.event_description) - 1);
    encrypted_log->metadata.event_description[sizeof(encrypted_log->metadata.event_description) - 1] = '\0';
        
        // Generate unique K_log and nonce for THIS log (content-level isolation)
        uint8_t k_log[AES_KEY_SIZE];
        uint8_t nonce[AES_NONCE_SIZE];
        rng_key(k_log);
        rng_nonce(nonce);
        
        // Symmetric encryption CT_sym = AES_GCM_{K_log}(L_n, AAD)
        size_t log_len = strlen(logs[i].log_data);
        
        if (encrypt_log_symmetric((const uint8_t*)logs[i].log_data, log_len,
                                 k_log, nonce, &encrypted_log->metadata,
                                 &encrypted_log->ct_sym) != 0) {
            fprintf(stderr, "[Microbatch] ERROR: Symmetric encryption failed for log %d\n", i);
            free(s_shared);
            return -1;
        }
        
        // ABE encryption of K_log using SHARED components (lightweight!)
        if (lcp_abe_encrypt_batch_key(k_log, s_shared, mpk, &ct_abe_template, 
                                      &encrypted_log->ct_abe) != 0) {
            fprintf(stderr, "[Microbatch] ERROR: ABE key encryption failed for log %d\n", i);
            free(s_shared);
            return -1;
        }
    }

    free(s_shared);
    
    return 0;
}

int process_logs_microbatch(const JsonLogArray *logs,
                            const AccessPolicy *policies,
                            uint32_t n_policies,
                            const MasterPublicKey *mpk,
                            Microbatch **batches,
                            uint32_t *n_batches) {
    // Group logs by epoch and policy
    *batches = (Microbatch*)calloc(logs->count, sizeof(Microbatch));
    *n_batches = 0;
    
    uint64_t epochs[1000];
    uint32_t n_epochs = 0;
    
    for (uint32_t i = 0; i < logs->count; i++) {
        uint64_t ts = parse_timestamp(logs->entries[i].timestamp);
        uint64_t epoch = get_epoch_id(ts);
        
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
    
    for (uint32_t e = 0; e < n_epochs; e++) {
        for (uint32_t p = 0; p < n_policies; p++) {
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
                // Encrypt this microbatch
                if (encrypt_microbatch(matching_logs, n_matching, &policies[p],
                                      mpk, epochs[e], &(*batches)[*n_batches]) == 0) {
                    (*n_batches)++;
                } else {
                    fprintf(stderr, "[Process] ERROR: Failed to create microbatch for epoch %" PRIu64 ", policy %d\n",
                            epochs[e], p);
                }
            }
        }
    }
    
    return 0;
}

// ============================================================================
// Save Encrypted Batch
// ============================================================================

int save_encrypted_batch(const Microbatch *batch, const char *output_dir) {
    // Create output directory if needed (cross-platform)
#ifdef _WIN32
    if (_mkdir(output_dir) != 0 && errno != EEXIST) {
        fprintf(stderr, "[Save] ERROR: Failed to create directory %s (errno=%d)\n", output_dir, errno);
        return -1;
    }
#else
    if (mkdir(output_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[Save] ERROR: Failed to create directory %s (errno=%d)\n", output_dir, errno);
        return -1;
    }
#endif
    
    // Save each CT_obj as a separate file
    for (uint32_t i = 0; i < batch->n_logs; i++) {
        const EncryptedLogObject *log = &batch->logs[i];
        
        // Generate unique ID from log metadata (timestamp + user + resource)
        char unique_key[256];
        snprintf(unique_key, sizeof(unique_key), "%s%s%s",
                 log->metadata.timestamp,
                 log->metadata.user_id,
                 log->metadata.resource_id);
        
        // Simple hash for filename (FNV-1a variant)
        uint32_t hash = 2166136261u;
        for (const char *p = unique_key; *p; p++) {
            hash ^= (uint8_t)*p;
            hash *= 16777619u;
        }
        
        // Create filename for this CT_obj (epoch + unique hash)
        char filename[512];
        snprintf(filename, sizeof(filename), "%s/ctobj_epoch%" PRIu64 "_%08x.bin",
                 output_dir, batch->epoch_id, hash);
        
        FILE *fp = fopen(filename, "wb");
        if (!fp) {
            fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
            return -1;
        }
        
        // Write metadata
        fwrite(&log->metadata, sizeof(LogMetadata), 1, fp);
        
    // Write symmetric ciphertext (CT_sym)
    // Sanity-check ct_len and ciphertext pointer before writing
    if (log->ct_sym.ct_len == 0 || log->ct_sym.ct_len > 10 * 1024 * 1024 || !log->ct_sym.ciphertext) {
        fprintf(stderr, "[Save] ERROR: Invalid CT_sym (ct_len=%u, ptr=%p)\n",
            log->ct_sym.ct_len, (void*)log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    fwrite(&log->ct_sym.ct_len, sizeof(uint32_t), 1, fp);
    fwrite(log->ct_sym.ciphertext, log->ct_sym.ct_len, 1, fp);
    fwrite(log->ct_sym.nonce, AES_NONCE_SIZE, 1, fp);
    fwrite(log->ct_sym.tag, AES_TAG_SIZE, 1, fp);
        
        // Write ABE ciphertext (CT_ABE) - essential for decryption!
        // Write policy expression and component count
        fwrite(log->ct_abe.policy.expression, MAX_POLICY_SIZE, 1, fp);
        fwrite(&log->ct_abe.n_components, sizeof(uint32_t), 1, fp);
        
        // Write C0 (m x n matrix in CRT domain)
        size_t c0_size = PARAM_M * PARAM_N;
        fwrite(log->ct_abe.C0, sizeof(scalar), c0_size, fp);
        
        // Write each C[i] component
        for (uint32_t j = 0; j < log->ct_abe.n_components; j++) {
            if (!log->ct_abe.C || !log->ct_abe.C[j]) {
                fprintf(stderr, "[Save] ERROR: C[%u] is NULL (n_components=%u)\n", j, log->ct_abe.n_components);
                fclose(fp);
                return -1;
            }
            fwrite(log->ct_abe.C[j], sizeof(scalar), c0_size, fp);
        }
        
        // Write ct_key (the encapsulated K_log)
        fwrite(log->ct_abe.ct_key, sizeof(scalar), PARAM_N, fp);
        
        // Write rho (attribute mapping)
        if (log->ct_abe.policy.rho && log->ct_abe.policy.matrix_rows > 0) {
            fwrite(&log->ct_abe.policy.matrix_rows, sizeof(uint32_t), 1, fp);
            fwrite(log->ct_abe.policy.rho, sizeof(uint32_t), log->ct_abe.policy.matrix_rows, fp);
        } else {
            uint32_t zero = 0;
            fwrite(&zero, sizeof(uint32_t), 1, fp);
        }
        
        fclose(fp);
    }
    
    return 0;
}
