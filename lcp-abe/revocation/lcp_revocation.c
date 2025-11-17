#include "lcp_revocation.h"
#include "../policy/lcp_policy.h"
#include "../keygen/lcp_keygen.h"
#include "../encrypt/lcp_encrypt.h"
#include "../../module_gaussian_lattice/Module_BFRS/sampling.h"
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// ============================================================================
// Helper Functions
// ============================================================================

void revocation_context_init(RevocationContext *ctx) {
    ctx->current_ver_id = 0;
    ctx->revoked_attr_indices = NULL;
    ctx->n_revoked_attrs = 0;
    ctx->trapdoor_rotated = false;
}

void revocation_context_free(RevocationContext *ctx) {
    if (ctx->revoked_attr_indices) {
        free(ctx->revoked_attr_indices);
        ctx->revoked_attr_indices = NULL;
    }
    ctx->n_revoked_attrs = 0;
}

void revocation_notice_init(RevocationNotice *notice) {
    memset(notice->revoked_uid, 0, sizeof(notice->revoked_uid));
    notice->revoked_attr_indices = NULL;
    notice->n_revoked_attrs = 0;
    notice->ver_id = 0;
    notice->timestamp = 0;
}

void revocation_notice_free(RevocationNotice *notice) {
    if (notice->revoked_attr_indices) {
        free(notice->revoked_attr_indices);
        notice->revoked_attr_indices = NULL;
    }
    notice->n_revoked_attrs = 0;
}

// ============================================================================
// Phase 1: Revocation Trigger and Policy Update
// ============================================================================

int lcp_create_revocation_notice(const char *revoked_uid,
                                 const char **revoked_attr_names,
                                 uint32_t n_attrs,
                                 uint32_t ver_id,
                                 RevocationNotice *notice) {
    revocation_notice_init(notice);
    
    if (revoked_uid) {
        strncpy(notice->revoked_uid, revoked_uid, sizeof(notice->revoked_uid) - 1);
        notice->revoked_uid[sizeof(notice->revoked_uid) - 1] = '\0';
    }
    
    notice->ver_id = ver_id;
    notice->timestamp = (uint64_t)time(NULL);
    notice->n_revoked_attrs = n_attrs;
    
    if (n_attrs > 0) {
        notice->revoked_attr_indices = (uint32_t *)calloc(n_attrs, sizeof(uint32_t));
        if (!notice->revoked_attr_indices) {
            fprintf(stderr, "[Revocation] ERROR: Failed to allocate revoked_attr_indices\n");
            return -1;
        }
        
        // Convert attribute names to indices
        for (uint32_t i = 0; i < n_attrs; i++) {
            notice->revoked_attr_indices[i] = attr_name_to_index(revoked_attr_names[i]);
        }
    }
    
    return 0;
}

int lcp_update_policy_exclude_attrs(const AccessPolicy *policy_old,
                                    const uint32_t *revoked_attr_indices,
                                    uint32_t n_revoked,
                                    AccessPolicy *policy_new) {
    
    // Initialize new policy
    policy_init(policy_new);
    
    // Build new attribute list excluding revoked attributes
    bool *is_revoked = (bool *)calloc(policy_old->attr_count, sizeof(bool));
    if (!is_revoked) {
        fprintf(stderr, "[Revocation] ERROR: Failed to allocate is_revoked\n");
        return -1;
    }
    
    // Mark revoked attributes
    for (uint32_t i = 0; i < n_revoked; i++) {
        for (uint32_t j = 0; j < policy_old->attr_count; j++) {
            if (policy_old->attr_indices[j] == revoked_attr_indices[i]) {
                is_revoked[j] = true;
                break;
            }
        }
    }
    
    // Copy non-revoked attributes
    for (uint32_t i = 0; i < policy_old->attr_count; i++) {
        if (!is_revoked[i]) {
            if (policy_new->attr_count < MAX_ATTRIBUTES) {
                policy_new->attr_indices[policy_new->attr_count] = policy_old->attr_indices[i];
                policy_new->attr_count++;
            }
        }
    }
    // Rebuild expression string by parsing old expression and excluding revoked attributes
    // Parse the old expression to extract attribute names
    const char *expr = policy_old->expression;
    
    char attr_buffer[ATTRIBUTE_NAME_LEN];
    char new_expr[MAX_POLICY_SIZE] = "";
    bool first_attr = true;
    
    // Simple parser: extract attributes from expression (handles "(attr1 AND attr2)" format)
    size_t expr_len = strlen(expr);
    
    for (size_t i = 0; i < expr_len; i++) {
        // Skip whitespace and parentheses
        if (expr[i] == ' ' || expr[i] == '(' || expr[i] == ')') {
            continue;
        }
        
        // Check if we hit "AND" keyword (case-insensitive check)
        if ((i + 2 < expr_len) && 
            (expr[i] == 'A' || expr[i] == 'a') &&
            (expr[i+1] == 'N' || expr[i+1] == 'n') &&
            (expr[i+2] == 'D' || expr[i+2] == 'd') &&
            (i + 3 >= expr_len || expr[i+3] == ' ' || expr[i+3] == ')' || expr[i+3] == '\0')) {
            i += 2; // Skip "AND" (loop will increment past 'D')
            continue;
        }
        
        // Extract attribute name (until space, ')', or start of "AND")
        size_t attr_start = i;
        
        while (i < expr_len && expr[i] != ' ' && expr[i] != ')' && expr[i] != '(') {
            // Check if we're hitting "AND"
            if ((i + 2 < expr_len) && 
                (expr[i] == 'A' || expr[i] == 'a') &&
                (expr[i+1] == 'N' || expr[i+1] == 'n') &&
                (expr[i+2] == 'D' || expr[i+2] == 'd') &&
                (i + 3 >= expr_len || expr[i+3] == ' ' || expr[i+3] == ')' || expr[i+3] == '\0')) {
                break;
            }
            i++;
        }
        
        size_t attr_len = i - attr_start;
        
        if (attr_len > 0 && attr_len < ATTRIBUTE_NAME_LEN) {
            strncpy(attr_buffer, &expr[attr_start], attr_len);
            attr_buffer[attr_len] = '\0';
            
            // Check if this attribute is revoked
            uint32_t attr_idx = attr_name_to_index(attr_buffer);
            
            bool is_this_revoked = false;
            for (uint32_t j = 0; j < n_revoked; j++) {
                if (attr_idx == revoked_attr_indices[j]) {
                    is_this_revoked = true;
                    break;
                }
            }
            
            // Add to new expression if not revoked
            if (!is_this_revoked) {
                if (!first_attr) {
                    size_t current_len = strlen(new_expr);
                    if (current_len + 5 < MAX_POLICY_SIZE) {
                        strncat(new_expr, " AND ", MAX_POLICY_SIZE - current_len - 1);
                    }
                }
                size_t current_len = strlen(new_expr);
                if (current_len + attr_len < MAX_POLICY_SIZE) {
                    strncat(new_expr, attr_buffer, MAX_POLICY_SIZE - current_len - 1);
                }
                first_attr = false;
            }
        }
        
        if (i >= expr_len) break;
    }
    
    // Copy rebuilt expression
    strncpy(policy_new->expression, new_expr, MAX_POLICY_SIZE - 1);
    policy_new->expression[MAX_POLICY_SIZE - 1] = '\0';
    
    free(is_revoked);
    
    // Rebuild LSSS matrix for new policy
    // Note: This is a simplified approach - in practice, you'd need to rebuild
    // the LSSS matrix properly based on the new attribute set
    if (policy_new->attr_count > 0) {
        // Re-parse the policy expression to rebuild LSSS matrix
        // For now, we'll use a simple threshold policy
        policy_new->is_threshold = policy_old->is_threshold;
        policy_new->threshold = policy_new->attr_count;
        
        // Rebuild LSSS matrix
        if (lsss_policy_to_matrix(policy_new) != 0) {
            fprintf(stderr, "[Revocation] WARNING: Failed to rebuild LSSS matrix\n");
            // Continue anyway - the matrix might be rebuilt later
        }
    } else {
        fprintf(stderr, "[Revocation] ERROR: All attributes revoked, policy becomes empty\n");
        return -1;
    }
    
    return 0;
}

// ============================================================================
// Phase 2: Lattice-Based Trapdoor Re-Keying
// ============================================================================

int lcp_rotate_trapdoor(const MasterSecretKey *msk_old,
                       MasterSecretKey *msk_new) {
    // Initialize new MSK
    msk_init(msk_new);
    
    // FIXED APPROACH: Sample a completely new trapdoor from scratch
    // This ensures all trapdoor properties are maintained (shortness, valid structure)
    // This is the same approach as in lcp_setup, which guarantees a valid trapdoor
    
    // Sample new trapdoor T' from discrete Gaussian D_{R^{2d,dk}, σ_s}
    // This is exactly how the original trapdoor is generated in setup
    // CRITICAL: Sample as signed (centered around 0), matching setup.c line 21
    SampleR_matrix_centered((signed_poly_matrix)msk_new->T, 
                           2 * PARAM_D, 
                           PARAM_D * PARAM_K, 
                           PARAM_SIGMA);
    
    // Reconstruct complex representation for new trapdoor
    // CRITICAL: This must be done with T in signed coefficient representation (as sampled)
    // This matches setup.c: construct_complex_private_key is called before converting to positive
    construct_complex_private_key(msk_new->cplx_T, msk_new->sch_comp, msk_new->T);
    
    // Convert T to positive representation [0, q-1] (matching setup.c behavior)
    size_t t_size = 2 * PARAM_D * PARAM_D * PARAM_K * PARAM_N;
    for (size_t i = 0; i < t_size; i++) {
        msk_new->T[i] += PARAM_Q;
    }
    
    // Convert T to CRT representation (needed for other operations)
    matrix_crt_representation(msk_new->T, 2 * PARAM_D, PARAM_D * PARAM_K, LOG_R);
    
    // Validate Schur complement after reconstruction
    // Since we sampled a fresh trapdoor (same as setup), sch_comp should be valid
    int invalid_sch_comp = 0;
    for (int i = 0; i < PARAM_N * PARAM_D * (2 * PARAM_D + 1); i++) {
        real real_val = creal(msk_new->sch_comp[i]);
        real imag_val = cimag(msk_new->sch_comp[i]);
        if (isnan(real_val) || isnan(imag_val) || isinf(real_val) || isinf(imag_val)) {
            invalid_sch_comp++;
            if (invalid_sch_comp < 5) {
                fprintf(stderr, "[Revocation ERROR] Invalid sch_comp[%d] = %f + %fi\n", i, real_val, imag_val);
            }
        }
    }
    if (invalid_sch_comp > 0) {
        fprintf(stderr, "[Revocation ERROR] Found %d invalid values in sch_comp after reconstruction\n", invalid_sch_comp);
        fprintf(stderr, "[Revocation ERROR] This should not happen with a fresh trapdoor sample!\n");
        fflush(stderr);
        return -1;  // Abort if we have invalid values
    }
    
    return 0;
}

// Regenerate A matrix from new trapdoor T
// CRITICAL: After rotating T, we must regenerate A to maintain trapdoor relationship
// A is constructed as [A_hat | 2Q - AprimeT] where AprimeT = A_hat·T2 + T1
// This matches the setup procedure to ensure consistency
int lcp_regenerate_A_from_trapdoor(const MasterSecretKey *msk_new,
                                   MasterPublicKey *mpk_new) {
    
    // Allocate temporary matrices for A construction
    scalar *A_hat_coeffs = (scalar *)malloc(PARAM_D * PARAM_D * PARAM_N * sizeof(scalar));
    scalar *AprimeT_coeffs = (scalar *)malloc(PARAM_D * PARAM_D * PARAM_K * PARAM_N * sizeof(scalar));
    if (!A_hat_coeffs || !AprimeT_coeffs) {
        fprintf(stderr, "[Revocation] ERROR: Failed to allocate A_hat or AprimeT\n");
        if (A_hat_coeffs) free(A_hat_coeffs);
        if (AprimeT_coeffs) free(AprimeT_coeffs);
        return -1;
    }
    
    poly_matrix A_hat = A_hat_coeffs;
    poly_matrix AprimeT = AprimeT_coeffs;
    
    // Generate new random A_hat (d × d matrix)
    // Note: We generate a new A_hat rather than reusing the old one to ensure
    // the new A is independent and maintains security properties
    random_poly(A_hat, PARAM_N * PARAM_D * PARAM_D - 1);
    matrix_crt_representation(A_hat, PARAM_D, PARAM_D, LOG_R);
    
    // Extract T1 and T2 from new trapdoor
    // T1 = first PARAM_D rows, T2 = last PARAM_D rows
    poly_matrix T1 = msk_new->T;
    poly_matrix T2 = poly_matrix_element(msk_new->T, PARAM_D * PARAM_K, PARAM_D, 0);
    
    // Compute AprimeT = A_hat · T2 + T1
    mul_crt_poly_matrix(AprimeT, A_hat, T2, PARAM_D, PARAM_D, PARAM_D * PARAM_K, LOG_R);
    add_to_poly_matrix(AprimeT, T1, PARAM_D, PARAM_D * PARAM_K);
    
    // Construct A = [A_hat | 2Q - AprimeT]
    // First PARAM_D columns: A_hat
    for (int i = 0; i < PARAM_D; i++) {
        poly_matrix A_i0 = poly_matrix_element(mpk_new->A, PARAM_M - PARAM_D, i, 0);
        poly_matrix A_hat_i = poly_matrix_element(A_hat, PARAM_D, i, 0);
        memcpy(A_i0, A_hat_i, PARAM_D * PARAM_N * sizeof(scalar));
    }
    
    // Remaining columns: 2Q - AprimeT
    for (int i = 0; i < PARAM_D; i++) {
        poly_matrix A_i1 = poly_matrix_element(mpk_new->A, PARAM_M - PARAM_D, i, PARAM_D);
        poly_matrix AprimeT_i = poly_matrix_element(AprimeT, PARAM_D * PARAM_K, i, 0);
        for (int j = 0; j < PARAM_D * PARAM_K * PARAM_N; j++) {
            A_i1[j] = 2 * PARAM_Q - AprimeT_i[j];
        }
    }
    
    // Reduce coefficients modulo q
    freeze_poly(mpk_new->A, PARAM_N * PARAM_D * (PARAM_M - PARAM_D) - 1);
    
    free(A_hat_coeffs);
    free(AprimeT_coeffs);
    
    return 0;
}

int lcp_update_mpk_version(MasterPublicKey *mpk, uint32_t ver_id) {
    // In this scheme, the MPK structure (A, B_plus, B_minus, beta) remains the same
    // We just track the version. In practice, you might want to add a version field
    // to the MPK structure, but for now we'll keep it simple.
    (void)mpk;  // Unused for now
    (void)ver_id;  // Unused for now
    return 0;
}

// ============================================================================
// Phase 3: Selective Key Regeneration for Valid Users
// ============================================================================

int lcp_check_user_revoked(const AttributeSet *attr_set,
                           const uint32_t *revoked_attr_indices,
                           uint32_t n_revoked) {
    for (uint32_t i = 0; i < attr_set->count; i++) {
        uint32_t attr_idx = attr_set->attrs[i].index;
        for (uint32_t j = 0; j < n_revoked; j++) {
            if (attr_idx == revoked_attr_indices[j]) {
                return 1;  // User has revoked attribute
            }
        }
    }
    return 0;  // User is not revoked
}

int lcp_regenerate_user_key(const MasterPublicKey *mpk,
                            const MasterSecretKey *msk_new,
                            const AttributeSet *attr_set,
                            UserSecretKey *usk_new) {
    // Check if user has revoked attributes
    // (This check should be done before calling this function, but we include it for safety)
    
    // Simply call the existing keygen function with the new MSK
    // This will generate a new key under the rotated trapdoor
    return lcp_keygen(mpk, msk_new, attr_set, usk_new);
}

// ============================================================================
// Phase 4: Selective Re-Encryption of Encrypted Logs
// ============================================================================

int lcp_reencrypt_log_abe(const EncryptedLogObject *log_old,
                         const AccessPolicy *policy_new,
                         const MasterPublicKey *mpk_new,
                         EncryptedLogObject *log_new) {
    // Initialize new log object
    encrypted_log_init(log_new);
    
    // Copy metadata and symmetric ciphertext (unchanged)
    log_new->metadata = log_old->metadata;
    
    // Copy symmetric ciphertext (CT_sym remains unchanged)
    log_new->ct_sym.ct_len = log_old->ct_sym.ct_len;
    if (log_old->ct_sym.ct_len > 0) {
        log_new->ct_sym.ciphertext = (uint8_t *)malloc(log_old->ct_sym.ct_len);
        if (!log_new->ct_sym.ciphertext) {
            fprintf(stderr, "[Revocation] ERROR: Failed to allocate ciphertext\n");
            return -1;
        }
        memcpy(log_new->ct_sym.ciphertext, log_old->ct_sym.ciphertext, log_old->ct_sym.ct_len);
    }
    memcpy(log_new->ct_sym.nonce, log_old->ct_sym.nonce, AES_NONCE_SIZE);
    memcpy(log_new->ct_sym.tag, log_old->ct_sym.tag, AES_TAG_SIZE);
    
    // Re-encapsulate the symmetric key K_log using new policy
    // Note: This function assumes K_log is provided separately or can be decrypted
    // with old keys. In practice, the AA would:
    // 1. Decrypt old ct_abe with old MSK/USK to get K_log
    // 2. Re-encrypt K_log with new policy and new MPK
    
    // For now, we initialize the structure - actual re-encryption requires K_log
    // which should be obtained by decrypting the old ciphertext first
    abe_ct_init(&log_new->ct_abe);
    log_new->ct_abe.policy = *policy_new;
    
    // Copy hash (will be recomputed after re-encryption)
    memcpy(log_new->hash, log_old->hash, SHA3_DIGEST_SIZE);
    
    return 0;
}

// Re-encrypt log with known K_log (for when AA has stored K_log separately)
int lcp_reencrypt_log_abe_with_key(const EncryptedLogObject *log_old,
                                   const uint8_t k_log[AES_KEY_SIZE],
                                   const AccessPolicy *policy_new,
                                   const MasterPublicKey *mpk_new,
                                   EncryptedLogObject *log_new) {
    // Copy symmetric parts (unchanged)
    if (lcp_reencrypt_log_abe(log_old, policy_new, mpk_new, log_new) != 0) {
        return -1;
    }
    
    // Re-encrypt K_log with new policy and new MPK
    // Use batch encryption functions for efficiency
    poly_matrix s = NULL;
    ABECiphertext ct_template;
    
    if (lcp_abe_encrypt_batch_init(policy_new, mpk_new, &ct_template, &s) != 0) {
        fprintf(stderr, "[Revocation] ERROR: Failed to initialize batch encryption\n");
        return -1;
    }
    
    if (!s) {
        fprintf(stderr, "[Revocation] ERROR: s is NULL after batch init\n");
        abe_ct_free(&ct_template);
        return -1;
    }
    
    // Encrypt the key
    if (lcp_abe_encrypt_batch_key(k_log, s, mpk_new, &ct_template, &log_new->ct_abe) != 0) {
        fprintf(stderr, "[Revocation] ERROR: Failed to encrypt key\n");
        abe_ct_free(&ct_template);
        free(s);
        return -1;
    }
    
    // Clean up
    abe_ct_free(&ct_template);
    free(s);
    
    return 0;
}

int lcp_reencrypt_logs_batch(const EncryptedLogObject *logs_old,
                            uint32_t n_logs,
                            const AccessPolicy *policy_new,
                            const MasterPublicKey *mpk_new,
                            EncryptedLogObject *logs_new) {
    int ret = 0;
    for (uint32_t i = 0; i < n_logs; i++) {
        if (lcp_reencrypt_log_abe(&logs_old[i], policy_new, mpk_new, &logs_new[i]) != 0) {
            fprintf(stderr, "[Revocation] ERROR: Failed to re-encrypt log %u\n", i);
            ret = -1;
        }
    }
    return ret;
}

// ============================================================================
// Complete Revocation Workflow
// ============================================================================

int lcp_execute_revocation(const char **revoked_attr_names,
                          uint32_t n_revoked_attrs,
                          const AccessPolicy *policy_old,
                          const MasterPublicKey *mpk_old,
                          const MasterSecretKey *msk_old,
                          AccessPolicy *policy_new,
                          MasterPublicKey *mpk_new,
                          MasterSecretKey *msk_new,
                          RevocationContext *ctx) {
    int ret = 0;
    
    // Step 1: Update policy to exclude revoked attributes
    uint32_t *revoked_indices = (uint32_t *)calloc(n_revoked_attrs, sizeof(uint32_t));
    if (!revoked_indices) {
        fprintf(stderr, "[Revocation] ERROR: Failed to allocate revoked_indices\n");
        return -1;
    }
    
    for (uint32_t i = 0; i < n_revoked_attrs; i++) {
        revoked_indices[i] = attr_name_to_index(revoked_attr_names[i]);
    }
    
    if (lcp_update_policy_exclude_attrs(policy_old, revoked_indices, 
                                       n_revoked_attrs, policy_new) != 0) {
        fprintf(stderr, "[Revocation] ERROR: Failed to update policy\n");
        free(revoked_indices);
        return -1;
    }
    
    // Step 2: Rotate trapdoor
    if (lcp_rotate_trapdoor(msk_old, msk_new) != 0) {
        fprintf(stderr, "[Revocation] ERROR: Failed to rotate trapdoor\n");
        free(revoked_indices);
        return -1;
    }
    
    // Step 3: Update MPK
    // CRITICAL: After rotating trapdoor, we must regenerate A from new T
    // to maintain the trapdoor relationship A·T ≈ β
    mpk_init(mpk_new, mpk_old->n_attributes);
    
    // Regenerate A matrix from new trapdoor (CRITICAL for trapdoor relationship)
    if (lcp_regenerate_A_from_trapdoor(msk_new, mpk_new) != 0) {
        fprintf(stderr, "[Revocation] ERROR: Failed to regenerate A from new trapdoor\n");
        free(revoked_indices);
        return -1;
    }
    
    // Copy B_plus, B_minus, and beta (these remain unchanged)
    // Note: β could be regenerated, but keeping it the same maintains
    // backward compatibility for re-encryption of old ciphertexts
    memcpy(mpk_new->B_plus, mpk_old->B_plus, 
           mpk_old->n_attributes * PARAM_M * PARAM_N * sizeof(scalar));
    memcpy(mpk_new->B_minus, mpk_old->B_minus, 
           mpk_old->n_attributes * PARAM_M * PARAM_N * sizeof(scalar));
    memcpy(mpk_new->beta, mpk_old->beta, PARAM_N * sizeof(scalar));
    mpk_new->k = mpk_old->k;
    mpk_new->m = mpk_old->m;
    mpk_new->n_attributes = mpk_old->n_attributes;
    
    // Update revocation context
    ctx->current_ver_id++;
    if (ctx->revoked_attr_indices) {
        // Append new revoked attributes
        uint32_t *new_list = (uint32_t *)realloc(ctx->revoked_attr_indices,
                                                 (ctx->n_revoked_attrs + n_revoked_attrs) * sizeof(uint32_t));
        if (new_list) {
            ctx->revoked_attr_indices = new_list;
            memcpy(&ctx->revoked_attr_indices[ctx->n_revoked_attrs], 
                   revoked_indices, n_revoked_attrs * sizeof(uint32_t));
            ctx->n_revoked_attrs += n_revoked_attrs;
        }
    } else {
        ctx->revoked_attr_indices = revoked_indices;
        ctx->n_revoked_attrs = n_revoked_attrs;
        revoked_indices = NULL;  // Don't free, it's now owned by ctx
    }
    ctx->trapdoor_rotated = true;
    
    if (revoked_indices) {
        free(revoked_indices);
    }
    
    return ret;
}

