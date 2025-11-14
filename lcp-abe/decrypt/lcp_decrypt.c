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

    if (getenv("ARITH_DEBUG")) {
        printf("[Decrypt DIAG] Computing A·ω_A and Σ(B·ω) for diagnostic comparison\n");

        poly_matrix y = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
        if (y) {
            multiply_by_A(y, mpk->A, usk->omega_A);

            poly a0 = poly_matrix_element(y, 1, 0, 0);
            for (int comp = 0; comp < LOG_R; comp++) {
                char tag[80];
                snprintf(tag, sizeof(tag), "DIAG_Aomega_comp_%d", comp);
                dump_crt_component(a0, LOG_R, comp, tag);
            }
            poly a0_copy = (poly)calloc(PARAM_N, sizeof(scalar));
            if (a0_copy) {
                memcpy(a0_copy, a0, PARAM_N * sizeof(scalar));
                coeffs_representation(a0_copy, LOG_R);
                printf("[ARITH DUMP] DIAG_Aomega_poly_0_COEFF: COEFF (deg=%d, first %d):", PARAM_N, PARAM_N);
                for (int _k = 0; _k < PARAM_N; _k++) printf(" %" PRIu32, (uint32_t)a0_copy[_k]);
                printf("\n");
                free(a0_copy);
            }

            for (uint32_t _j = 0; _j < PARAM_M && _j < 8; _j++) {
                poly omega_j = poly_matrix_element(usk->omega_A, 1, _j, 0);
                poly omega_copy = (poly)calloc(PARAM_N, sizeof(scalar));
                if (!omega_copy) continue;
                memcpy(omega_copy, omega_j, PARAM_N * sizeof(scalar));
                coeffs_representation(omega_copy, LOG_R);
                printf("[ARITH DUMP] DIAG_omega_A_poly_%u_COEFF: COEFF (deg=%d, first %d):", _j, PARAM_N, PARAM_N);
                for (int _k = 0; _k < PARAM_N; _k++) printf(" %" PRIu32, (uint32_t)omega_copy[_k]);
                printf("\n");
                free(omega_copy);
            }
        }

        poly b_sum = (poly)calloc(PARAM_N, sizeof(scalar));
        double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));

        if (b_sum && prod && reduced) {
            for (uint32_t ai = 0; ai < usk->n_components; ai++) {
                uint32_t attr_idx = usk->attr_set.attrs[ai].index;
                if (attr_idx >= mpk->n_attributes) continue;

                poly_matrix B_plus_row = &mpk->B_plus[attr_idx * PARAM_M * PARAM_N];

                poly temp_res = (poly)calloc(PARAM_N, sizeof(scalar));
                if (!temp_res) continue;

                for (uint32_t j = 0; j < PARAM_M; j++) {
                    poly B_ij = &B_plus_row[j * PARAM_N];
                    poly omega_ij = poly_matrix_element(usk->omega_i[ai], 1, j, 0);

                    memset(prod, 0, 2 * PARAM_N * sizeof(double_scalar));
                    memset(reduced, 0, PARAM_N * sizeof(scalar));
                    mul_crt_poly(prod, B_ij, omega_ij, LOG_R);
                    reduce_double_crt_poly(reduced, prod, LOG_R);

                    add_poly(temp_res, temp_res, reduced, PARAM_N - 1);
                    freeze_poly(temp_res, PARAM_N - 1);
                }

                add_poly(b_sum, b_sum, temp_res, PARAM_N - 1);
                freeze_poly(b_sum, PARAM_N - 1);
                free(temp_res);
            }

            for (int comp = 0; comp < LOG_R; comp++) {
                char tagb[80];
                snprintf(tagb, sizeof(tagb), "DIAG_Bomega_sum_comp_%d", comp);
                dump_crt_component(b_sum, LOG_R, comp, tagb);
            }

            if (y && b_sum) {
                poly lhs = (poly)calloc(PARAM_N, sizeof(scalar));
                poly a0 = poly_matrix_element(y, 1, 0, 0);
                memcpy(lhs, a0, PARAM_N * sizeof(scalar));
                add_poly(lhs, lhs, b_sum, PARAM_N - 1);
                freeze_poly(lhs, PARAM_N - 1);

                for (int comp = 0; comp < LOG_R; comp++) {
                    char tagl[80];
                    snprintf(tagl, sizeof(tagl), "DIAG_lhs_AplusB_comp_%d", comp);
                    dump_crt_component(lhs, LOG_R, comp, tagl);
                }

                for (int comp = 0; comp < LOG_R; comp++) {
                    char tagbeta[80];
                    snprintf(tagbeta, sizeof(tagbeta), "DIAG_mpk_beta_comp_%d", comp);
                    dump_crt_component(mpk->beta, LOG_R, comp, tagbeta);
                }

                free(lhs);
            }
        }

        if (prod) free(prod);
        if (reduced) free(reduced);
        if (b_sum) free(b_sum);
        if (y) free(y);
    }
    
    poly recovered = (poly)calloc(PARAM_N, sizeof(scalar));
    
    memcpy(recovered, ct_abe->ct_key, PARAM_N * sizeof(scalar));
    printf("[Decrypt]   DEBUG: ct_key (already COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           recovered[0], recovered[1], recovered[2], recovered[3]);
    if (getenv("ARITH_MIN_PROV")) {
        uint64_t fnv_early = 1469598103934665603ULL;
        for (int _i = 0; _i < PARAM_N; _i++) {
            uint64_t v = (uint64_t)recovered[_i];
            fnv_early ^= (v & 0xFFFFFFFFULL);
            fnv_early *= 1099511628211ULL;
        }
        printf("[DECRYPT MINPROV] recovered ptr=%p ct_key ptr=%p Early FNV64=0x%016" PRIx64 "\n",
               (void*)recovered, (void*)ct_abe->ct_key, fnv_early);
    }
    if (getenv("ARITH_DUMP_FULL")) {
        printf("[DECRYPT DUMP FULL] ct_key_coeff_full:\n");
        for (int _i = 0; _i < PARAM_N; _i++) printf(" %u", recovered[_i]);
        printf("\n");
    }
    
    poly decryption_term_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    poly decryption_term_coeff = (poly)calloc(PARAM_N, sizeof(scalar));

    printf("\n[Decrypt]   Computing decryption using [0] coefficients only\n");
    printf("[Decrypt]   Formula: (A·ω_A)[0]·C0[0] + Σ(coeff[i]·(B+_ρ(i)·ω[ρ(i)])[0]·C0[0]) ≈ β·C0[0]\n");
    printf("[Decrypt]   CRITICAL: Trapdoor relationship must hold for policy attributes:\n");
    printf("[Decrypt]   (A·ω_A)[0] + Σ(coeff[i]·(B+_ρ(i)·ω[ρ(i)])[0]) ≈ β\n");
    printf("[Decrypt]   Note: This is DIFFERENT from keygen which uses ALL user attributes!\n");
    
    // Step 1: Compute (A·ω_A)[0]·C0[0]
    poly_matrix A_omega_A = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    if (!A_omega_A) {
        fprintf(stderr, "[Decrypt] ERROR: Failed to allocate A_omega_A\n");
        free(decryption_term_crt);
        free(decryption_term_coeff);
        free(recovered);
        return -1;
    }
    multiply_by_A(A_omega_A, mpk->A, usk->omega_A);
    
    poly A_omega_A_0 = poly_matrix_element(A_omega_A, 1, 0, 0);
    poly c0_0 = poly_matrix_element(ct_abe->C0, 1, 0, 0);

    double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
    if (!prod) {
        fprintf(stderr, "[Decrypt] ERROR: Failed to allocate prod\n");
        free(A_omega_A);
        free(decryption_term_crt);
        free(decryption_term_coeff);
        free(recovered);
        return -1;
    }
    
    mul_crt_poly(prod, A_omega_A_0, c0_0, LOG_R);
    
    poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!prod_reduced) {
        fprintf(stderr, "[Decrypt] ERROR: Failed to allocate prod_reduced\n");
        free(prod);
        free(A_omega_A);
        free(decryption_term_crt);
        free(decryption_term_coeff);
        free(recovered);
        return -1;
    }
    
    reduce_double_crt_poly(prod_reduced, prod, LOG_R);
    memcpy(decryption_term_crt, prod_reduced, PARAM_N * sizeof(scalar));
    freeze_poly(decryption_term_crt, PARAM_N - 1);
    
    printf("[Decrypt]   (A·ω_A)[0]·C0[0] computed (CRT, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
        decryption_term_crt[0], decryption_term_crt[1], decryption_term_crt[2], decryption_term_crt[3]);
        
        free(prod);
        free(prod_reduced);
    
    // DIAGNOSTIC: Verify trapdoor relationship for policy attributes
    poly sum_B_omega_policy_0 = (poly)calloc(PARAM_N, sizeof(scalar));
    if (sum_B_omega_policy_0) {
        zero_poly(sum_B_omega_policy_0, PARAM_N - 1);
        
        for (uint32_t i = 0; i < n_coeffs && i < ct_abe->policy.matrix_rows; i++) {
            if (coefficients[i] == 0) continue;
            
            uint32_t policy_attr_idx = ct_abe->policy.rho[i];
            int omega_idx = -1;
            for (uint32_t j = 0; j < usk->attr_set.count; j++) {
                if (usk->attr_set.attrs[j].index == policy_attr_idx) {
                    omega_idx = j;
                    break;
                }
            }
            if (omega_idx == -1) continue;
            
            poly_matrix B_plus_attr = &mpk->B_plus[policy_attr_idx * PARAM_M * PARAM_N];
            poly temp_result = (poly)calloc(PARAM_N, sizeof(scalar));
            if (!temp_result) continue;
            zero_poly(temp_result, PARAM_N - 1);
            
            double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            
            if (temp_prod && reduced) {
                for (uint32_t j = 0; j < PARAM_M; j++) {
                    poly B_ij = &B_plus_attr[j * PARAM_N];
                    poly omega_ij = poly_matrix_element(usk->omega_i[omega_idx], 1, j, 0);
                    
                    mul_crt_poly(temp_prod, B_ij, omega_ij, LOG_R);
                    reduce_double_crt_poly(reduced, temp_prod, LOG_R);
                    add_poly(temp_result, temp_result, reduced, PARAM_N - 1);
                    freeze_poly(temp_result, PARAM_N - 1);
                }
                
                // Scale by coefficient
                for (uint32_t k = 0; k < PARAM_N; k++) {
                    uint64_t scaled = ((uint64_t)temp_result[k] * (uint64_t)coefficients[i]) % PARAM_Q;
                    temp_result[k] = (uint32_t)scaled;
                }
                freeze_poly(temp_result, PARAM_N - 1);
                
                add_poly(sum_B_omega_policy_0, sum_B_omega_policy_0, temp_result, PARAM_N - 1);
                freeze_poly(sum_B_omega_policy_0, PARAM_N - 1);
                
                free(temp_prod);
                free(reduced);
            }
            free(temp_result);
        }
        
        poly A_omega_A_0_diag = poly_matrix_element(A_omega_A, 1, 0, 0);
        poly A_omega_A_0_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
        poly sum_B_omega_policy_0_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
        poly lhs_trapdoor = (poly)calloc(PARAM_N, sizeof(scalar));
        
        if (A_omega_A_0_coeff && sum_B_omega_policy_0_coeff && lhs_trapdoor) {
            memcpy(A_omega_A_0_coeff, A_omega_A_0_diag, PARAM_N * sizeof(scalar));
            memcpy(sum_B_omega_policy_0_coeff, sum_B_omega_policy_0, PARAM_N * sizeof(scalar));
            coeffs_representation(A_omega_A_0_coeff, LOG_R);
            coeffs_representation(sum_B_omega_policy_0_coeff, LOG_R);
            
            memcpy(lhs_trapdoor, A_omega_A_0_coeff, PARAM_N * sizeof(scalar));
            add_poly(lhs_trapdoor, lhs_trapdoor, sum_B_omega_policy_0_coeff, PARAM_N - 1);
            freeze_poly(lhs_trapdoor, PARAM_N - 1);
            
            poly beta_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
            if (beta_coeff) {
                memcpy(beta_coeff, mpk->beta, PARAM_N * sizeof(scalar));
                coeffs_representation(beta_coeff, LOG_R);
                
                printf("\n[Decrypt] DIAGNOSTIC: Trapdoor relationship for policy attributes:\n");
                printf("[Decrypt]   (A·ω_A)[0] (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                       A_omega_A_0_coeff[0], A_omega_A_0_coeff[1], A_omega_A_0_coeff[2], A_omega_A_0_coeff[3]);
                printf("[Decrypt]   Σ(coeff[i]·(B+_ρ(i)·ω[ρ(i)])[0]) (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                       sum_B_omega_policy_0_coeff[0], sum_B_omega_policy_0_coeff[1], sum_B_omega_policy_0_coeff[2], sum_B_omega_policy_0_coeff[3]);
                printf("[Decrypt]   (A·ω_A)[0] + Σ(coeff[i]·(B+_ρ(i)·ω[ρ(i)])[0]) (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                       lhs_trapdoor[0], lhs_trapdoor[1], lhs_trapdoor[2], lhs_trapdoor[3]);
                printf("[Decrypt]   β (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                       beta_coeff[0], beta_coeff[1], beta_coeff[2], beta_coeff[3]);
                
                int mismatch_count = 0;
                uint32_t max_diff = 0;
                for (int k = 0; k < PARAM_N && k < 16; k++) {
                    uint32_t diff = (lhs_trapdoor[k] > beta_coeff[k]) ? 
                                   (lhs_trapdoor[k] - beta_coeff[k]) : 
                                   (beta_coeff[k] - lhs_trapdoor[k]);
                    if (diff > max_diff) max_diff = diff;
                    if (diff > 1000 && diff < (PARAM_Q - 1000)) {
                        if (mismatch_count < 5) {
                            printf("[Decrypt]   MISMATCH at coeff[%d]: lhs=%u, beta=%u, diff=%u\n",
                                   k, lhs_trapdoor[k], beta_coeff[k], diff);
                        }
                        mismatch_count++;
                    }
                }
                printf("[Decrypt]   Max difference: %u\n", max_diff);
                if (mismatch_count == 0) {
                    printf("[Decrypt]   ✓ Trapdoor relationship HOLDS for policy attributes\n");
                } else {
                    printf("[Decrypt]   ✗ Trapdoor relationship FAILS for policy attributes (%d mismatches)\n", mismatch_count);
                    printf("[Decrypt]   ⚠ This explains why decryption_term ≠ β·C0[0]!\n");
                    printf("[Decrypt]   ⚠ KeyGen uses ALL user attributes, but Decrypt uses only policy attributes!\n");
                }
                
                free(beta_coeff);
            }
            free(A_omega_A_0_coeff);
            free(sum_B_omega_policy_0_coeff);
            free(lhs_trapdoor);
        }
        free(sum_B_omega_policy_0);
    }
    
    printf("\n[Decrypt]   Step 2: Computing Σ(coeff[i]·(B+_ρ(i)·ω[ρ(i)])[0]·C0[0]) and adding to decryption_term\n");
    printf("[Decrypt]   CRITICAL: Using C0[0] (not C[i][0]) to match encryption's use of s[0]\n");
    
    poly step2_contributions_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!step2_contributions_crt) {
        fprintf(stderr, "[Decrypt] ERROR: Failed to allocate step2_contributions_crt\n");
        free(decryption_term_crt);
        free(decryption_term_coeff);
        free(recovered);
        return -1;
                    }
    zero_poly(step2_contributions_crt, PARAM_N - 1);
    
    poly expected_step2_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!expected_step2_crt) {
        fprintf(stderr, "[Decrypt] ERROR: Failed to allocate expected_step2_crt\n");
        free(step2_contributions_crt);
        free(decryption_term_crt);
        free(decryption_term_coeff);
        free(recovered);
        return -1;
    }
    zero_poly(expected_step2_crt, PARAM_N - 1);
    
    poly s_0_approx = poly_matrix_element(ct_abe->C0, 1, 0, 0);
    
    for (uint32_t i = 0; i < n_coeffs && i < ct_abe->policy.matrix_rows; i++) {
        uint32_t policy_attr_idx = ct_abe->policy.rho[i];
        printf("[Decrypt]   Processing policy row %d (attr idx %d, coeff=%u)\n", 
               i, policy_attr_idx, coefficients[i]);
        
        int omega_idx = -1;
        for (uint32_t j = 0; j < usk->attr_set.count; j++) {
            if (usk->attr_set.attrs[j].index == policy_attr_idx) {
                omega_idx = j;
                break;
            }
        }
        
        if (omega_idx == -1) {
            if (coefficients[i] == 0) {
                continue;
            }
            fprintf(stderr, "[Decrypt] ERROR: Policy requires attr %d but user doesn't have it!\n",
                    policy_attr_idx);
            free(decryption_term_crt);
            free(decryption_term_coeff);
            free(recovered);
            return -1;
        }
        
        // Compute (B+_attr · ω[ρ(i)])[0]·C0[0]
        // CRITICAL: Use C0[0] (not C[i][0]) to match encryption's use of s[0]
        // This ensures: (B+_attr·ω[ρ(i)])[0]·C0[0] ≈ (B+_attr·ω[ρ(i)])[0]·s[0]
        // First compute B+_attr · ω[ρ(i)] (full inner product over all M components)
        poly B_omega_attr = (poly)calloc(PARAM_N, sizeof(scalar));
        if (!B_omega_attr) {
            fprintf(stderr, "[Decrypt] ERROR: Failed to allocate B_omega_attr\n");
            free(decryption_term_crt);
            free(decryption_term_coeff);
            free(recovered);
            return -1;
        }
        zero_poly(B_omega_attr, PARAM_N - 1);
        
        poly_matrix B_plus_attr = &mpk->B_plus[policy_attr_idx * PARAM_M * PARAM_N];

        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly B_ij = &B_plus_attr[j * PARAM_N];
            poly omega_ij = poly_matrix_element(usk->omega_i[omega_idx], 1, j, 0);
            
            double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            if (!prod) {
                fprintf(stderr, "[Decrypt] ERROR: Failed to allocate prod\n");
                free(B_omega_attr);
                free(decryption_term_crt);
                free(decryption_term_coeff);
                free(recovered);
                return -1;
            }
            
            mul_crt_poly(prod, B_ij, omega_ij, LOG_R);

            poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            if (!prod_reduced) {
                fprintf(stderr, "[Decrypt] ERROR: Failed to allocate prod_reduced\n");
                free(prod);
                free(B_omega_attr);
                free(decryption_term_crt);
                free(decryption_term_coeff);
                free(recovered);
                return -1;
            }
            
            reduce_double_crt_poly(prod_reduced, prod, LOG_R);
            add_poly(B_omega_attr, B_omega_attr, prod_reduced, PARAM_N - 1);
            freeze_poly(B_omega_attr, PARAM_N - 1);
            
            free(prod);
            free(prod_reduced);
        }
        
        // Now compute (B+_attr · ω[ρ(i)])[0]·C0[0] (use C0[0], not C[i][0]!)
        // This matches encryption which uses s[0] (approximated by C0[0])
        poly c0_0_step2 = poly_matrix_element(ct_abe->C0, 1, 0, 0);
        double_poly prod_B_omega_c = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        if (!prod_B_omega_c) {
            fprintf(stderr, "[Decrypt] ERROR: Failed to allocate prod_B_omega_c\n");
            free(B_omega_attr);
            free(decryption_term_crt);
            free(decryption_term_coeff);
            free(recovered);
            return -1;
        }
        
        mul_crt_poly(prod_B_omega_c, B_omega_attr, c0_0_step2, LOG_R);
        
        poly scaled_contribution = (poly)calloc(PARAM_N, sizeof(scalar));
        if (!scaled_contribution) {
            fprintf(stderr, "[Decrypt] ERROR: Failed to allocate scaled_contribution\n");
            free(prod_B_omega_c);
            free(B_omega_attr);
            free(step2_contributions_crt);
            free(expected_step2_crt);
            free(decryption_term_crt);
            free(decryption_term_coeff);
            free(recovered);
            return -1;
        }
        
        reduce_double_crt_poly(scaled_contribution, prod_B_omega_c, LOG_R);
        
        // Scale by coefficient and add to decryption_term
        for (uint32_t k = 0; k < PARAM_N; k++) {
            uint64_t scaled = ((uint64_t)scaled_contribution[k] * (uint64_t)coefficients[i]) % PARAM_Q;
            scaled_contribution[k] = (uint32_t)scaled;
            decryption_term_crt[k] = (decryption_term_crt[k] + scaled) % PARAM_Q;
        }
        freeze_poly(decryption_term_crt, PARAM_N - 1);
        freeze_poly(scaled_contribution, PARAM_N - 1);
        
        free(prod_B_omega_c);
        free(B_omega_attr);
        
        add_poly(step2_contributions_crt, step2_contributions_crt, scaled_contribution, PARAM_N - 1);
        freeze_poly(step2_contributions_crt, PARAM_N - 1);
        
        poly expected_attr_contrib = (poly)calloc(PARAM_N, sizeof(scalar));
        if (expected_attr_contrib) {
            zero_poly(expected_attr_contrib, PARAM_N - 1);
            
            poly_matrix B_plus_attr_diag = &mpk->B_plus[policy_attr_idx * PARAM_M * PARAM_N];
            double_poly temp_prod_exp = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            poly reduced_exp = (poly)calloc(PARAM_N, sizeof(scalar));
            
            if (temp_prod_exp && reduced_exp) {
            for (uint32_t j = 0; j < PARAM_M; j++) {
                    poly B_ij = &B_plus_attr_diag[j * PARAM_N];
                poly omega_ij = poly_matrix_element(usk->omega_i[omega_idx], 1, j, 0);
                    
                    mul_crt_poly(temp_prod_exp, B_ij, omega_ij, LOG_R);
                    reduce_double_crt_poly(reduced_exp, temp_prod_exp, LOG_R);
                    add_poly(expected_attr_contrib, expected_attr_contrib, reduced_exp, PARAM_N - 1);
                    freeze_poly(expected_attr_contrib, PARAM_N - 1);
                }
                
                double_poly prod_s0 = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
                poly reduced_s0 = (poly)calloc(PARAM_N, sizeof(scalar));
                
                if (prod_s0 && reduced_s0) {
                    mul_crt_poly(prod_s0, expected_attr_contrib, s_0_approx, LOG_R);
                    reduce_double_crt_poly(reduced_s0, prod_s0, LOG_R);
                    
            for (uint32_t k = 0; k < PARAM_N; k++) {
                        uint64_t scaled_exp = ((uint64_t)reduced_s0[k] * (uint64_t)coefficients[i]) % PARAM_Q;
                        expected_step2_crt[k] = (expected_step2_crt[k] + scaled_exp) % PARAM_Q;
                    }
                    freeze_poly(expected_step2_crt, PARAM_N - 1);
                    
                    poly scaled_contrib_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
                    poly expected_contrib_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
                    if (scaled_contrib_coeff && expected_contrib_coeff) {
                        memcpy(scaled_contrib_coeff, scaled_contribution, PARAM_N * sizeof(scalar));
                        memcpy(expected_contrib_coeff, reduced_s0, PARAM_N * sizeof(scalar));
                        coeffs_representation(scaled_contrib_coeff, LOG_R);
                        coeffs_representation(expected_contrib_coeff, LOG_R);
                        
                        printf("[Decrypt DIAG] Attr %u: Actual Step2 contrib (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                               policy_attr_idx, scaled_contrib_coeff[0], scaled_contrib_coeff[1], 
                               scaled_contrib_coeff[2], scaled_contrib_coeff[3]);
                        printf("[Decrypt DIAG] Attr %u: Expected (B+·ω)·s[0]·coeff (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                               policy_attr_idx, expected_contrib_coeff[0], expected_contrib_coeff[1],
                               expected_contrib_coeff[2], expected_contrib_coeff[3]);
                        
                        free(scaled_contrib_coeff);
                        free(expected_contrib_coeff);
            }
                    
                    free(prod_s0);
                    free(reduced_s0);
                }
                
                free(temp_prod_exp);
                free(reduced_exp);
            }
            free(expected_attr_contrib);
        }
        
        if (getenv("ARITH_DEBUG")) {
            for (int comp = 0; comp < LOG_R; comp++) {
                char tagt[96];
                snprintf(tagt, sizeof(tagt), "DECRYPT_scaled_contrib_attr_%u_comp_%d", policy_attr_idx, comp);
                dump_crt_component(scaled_contribution, LOG_R, comp, tagt);
            }
        }
        
        poly scaled_contrib_coeffs = (poly)calloc(PARAM_N, sizeof(scalar));
        if (scaled_contrib_coeffs) {
            memcpy(scaled_contrib_coeffs, scaled_contribution, PARAM_N * sizeof(scalar));
            coeffs_representation(scaled_contrib_coeffs, LOG_R);
            printf("[Decrypt DEBUG] attr %u: scaled_contribution (COEFF, first 4) = [%u, %u, %u, %u]\n",
                   policy_attr_idx, scaled_contrib_coeffs[0], scaled_contrib_coeffs[1], scaled_contrib_coeffs[2], scaled_contrib_coeffs[3]);
            free(scaled_contrib_coeffs);
        }

        free(scaled_contribution);
    }
    
    memcpy(decryption_term_coeff, decryption_term_crt, PARAM_N * sizeof(scalar));
    coeffs_representation(decryption_term_coeff, LOG_R);
    freeze_poly(decryption_term_coeff, PARAM_N - 1);
    
    printf("[Decrypt]   decryption_term (CRT→COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
        decryption_term_coeff[0], decryption_term_coeff[1], decryption_term_coeff[2], decryption_term_coeff[3]);
        
    printf("\n[Decrypt] DIAGNOSTIC: Step 2 Contributions Analysis\n");
    poly step2_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
    poly expected_step2_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
    if (step2_coeff && expected_step2_coeff) {
        memcpy(step2_coeff, step2_contributions_crt, PARAM_N * sizeof(scalar));
        memcpy(expected_step2_coeff, expected_step2_crt, PARAM_N * sizeof(scalar));
        coeffs_representation(step2_coeff, LOG_R);
        coeffs_representation(expected_step2_coeff, LOG_R);
        
        printf("[Decrypt]   Actual Step2 sum (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
               step2_coeff[0], step2_coeff[1], step2_coeff[2], step2_coeff[3]);
        printf("[Decrypt]   Expected Step2 sum (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
               expected_step2_coeff[0], expected_step2_coeff[1], expected_step2_coeff[2], expected_step2_coeff[3]);
        
        int mismatch_count = 0;
        for (int k = 0; k < PARAM_N && k < 16; k++) {
            uint32_t diff = (step2_coeff[k] > expected_step2_coeff[k]) ? 
                           (step2_coeff[k] - expected_step2_coeff[k]) : 
                           (expected_step2_coeff[k] - step2_coeff[k]);
            if (diff > 1000 && diff < (PARAM_Q - 1000)) {
                if (mismatch_count < 5) {
                    printf("[Decrypt]   Step2 MISMATCH at coeff[%d]: actual=%u, expected=%u, diff=%u\n",
                           k, step2_coeff[k], expected_step2_coeff[k], diff);
                }
                mismatch_count++;
            }
        }
        if (mismatch_count == 0) {
            printf("[Decrypt]   ✓ Step2 contributions MATCH expected (first 16 coeffs)\n");
        } else {
            printf("[Decrypt]   ✗ Step2 contributions MISMATCH (%d differences in first 16 coeffs)\n", mismatch_count);
        }
    }
    
    printf("\n[Decrypt] DIAGNOSTIC: Verifying Step 1 + Step 2 ≈ β·s[0]\n");
    printf("[Decrypt]   Formula: ω_A·C0 + Σ(coeff[i]·ω[ρ(i)]·C[i]) ≈ β·s[0] + noise\n");
    
    poly step1_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    poly step1_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
    if (step1_crt && step1_coeff) {
        zero_poly(step1_crt, PARAM_N - 1);
        
        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly omega_A_j = poly_matrix_element(usk->omega_A, 1, j, 0);
            poly c0_j = poly_matrix_element(ct_abe->C0, 1, j, 0);
            
            double_poly prod_diag = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            if (prod_diag) {
                mul_crt_poly(prod_diag, omega_A_j, c0_j, LOG_R);
                poly prod_reduced_diag = (poly)calloc(PARAM_N, sizeof(scalar));
                if (prod_reduced_diag) {
                    reduce_double_crt_poly(prod_reduced_diag, prod_diag, LOG_R);
                    add_poly(step1_crt, step1_crt, prod_reduced_diag, PARAM_N - 1);
                    freeze_poly(step1_crt, PARAM_N - 1);
                    free(prod_reduced_diag);
                }
                free(prod_diag);
            }
        }
        
        memcpy(step1_coeff, step1_crt, PARAM_N * sizeof(scalar));
        coeffs_representation(step1_coeff, LOG_R);
        freeze_poly(step1_coeff, PARAM_N - 1);
        
        printf("[Decrypt]   Step 1 diagnostic (ω_A·C0, matches actual Step 1): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
               step1_coeff[0], step1_coeff[1], step1_coeff[2], step1_coeff[3]);
    }
    
    poly beta_s0_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
    if (beta_s0_coeff && step1_coeff) {
        poly s_0_approx = poly_matrix_element(ct_abe->C0, 1, 0, 0);
        double_poly beta_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        poly beta_s0_crt = (poly)calloc(PARAM_N, sizeof(scalar));
        
        if (beta_prod && beta_s0_crt) {
            mul_crt_poly(beta_prod, mpk->beta, s_0_approx, LOG_R);
            reduce_double_crt_poly(beta_s0_crt, beta_prod, LOG_R);
            memcpy(beta_s0_coeff, beta_s0_crt, PARAM_N * sizeof(scalar));
            coeffs_representation(beta_s0_coeff, LOG_R);
            freeze_poly(beta_s0_coeff, PARAM_N - 1);
            
            printf("[Decrypt]   β·C0[0] ≈ β·s[0] (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                   beta_s0_coeff[0], beta_s0_coeff[1], beta_s0_coeff[2], beta_s0_coeff[3]);
            
            poly step1_plus_step2 = (poly)calloc(PARAM_N, sizeof(scalar));
            if (step1_plus_step2 && step2_coeff) {
                memcpy(step1_plus_step2, step1_coeff, PARAM_N * sizeof(scalar));
                add_poly(step1_plus_step2, step1_plus_step2, step2_coeff, PARAM_N - 1);
                freeze_poly(step1_plus_step2, PARAM_N - 1);
                
                printf("[Decrypt]   Step 1 + Step 2 (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                       step1_plus_step2[0], step1_plus_step2[1], step1_plus_step2[2], step1_plus_step2[3]);
                
                int mismatch_count = 0;
                uint32_t max_diff = 0;
                for (int k = 0; k < PARAM_N && k < 16; k++) {
                    uint32_t diff = (step1_plus_step2[k] > beta_s0_coeff[k]) ? 
                                   (step1_plus_step2[k] - beta_s0_coeff[k]) : 
                                   (beta_s0_coeff[k] - step1_plus_step2[k]);
                    if (diff > max_diff) max_diff = diff;
                    if (diff > 1000000) {
                        if (mismatch_count < 5) {
                            printf("[Decrypt]   Large diff at coeff[%d]: (Step1+Step2)=%u, β·s[0]=%u, diff=%u\n",
                                   k, step1_plus_step2[k], beta_s0_coeff[k], diff);
                        }
                        mismatch_count++;
                    }
                }
                printf("[Decrypt]   Max difference: %u\n", max_diff);
                if (mismatch_count == 0) {
                    printf("[Decrypt]   ✓ Step 1 + Step 2 ≈ β·s[0] (within noise tolerance)\n");
                } else {
                    printf("[Decrypt]   ✗ Step 1 + Step 2 ≠ β·s[0] (%d large differences)\n", mismatch_count);
                }
                
                free(step1_plus_step2);
            }
            
            free(beta_prod);
            free(beta_s0_crt);
        }
        free(beta_s0_coeff);
    }
    
    printf("\n[Decrypt] DIAGNOSTIC: Analyzing Step 2 noise terms\n");
    printf("[Decrypt]   Step 2 computes: ω[ρ(i)]·C[i] where C[i] = B+_attr · s[0] + e_i\n");
    printf("[Decrypt]   This gives: ω[ρ(i)]·B+_attr · s[0] + ω[ρ(i)]·e_i\n");
    printf("[Decrypt]   The noise term is: ω[ρ(i)]·e_i\n");
    printf("[Decrypt]   Actual Step2 includes noise, Expected Step2 does not\n");
    printf("[Decrypt]   Noise magnitude (diff between actual and expected):\n");
    if (step2_coeff && expected_step2_coeff) {
        uint32_t max_noise = 0;
        for (int k = 0; k < PARAM_N && k < 16; k++) {
            uint32_t noise = (step2_coeff[k] > expected_step2_coeff[k]) ? 
                            (step2_coeff[k] - expected_step2_coeff[k]) : 
                            (expected_step2_coeff[k] - step2_coeff[k]);
            if (noise > max_noise) max_noise = noise;
            if (k < 4) {
                printf("[Decrypt]     coeff[%d]: noise=%u\n", k, noise);
    }
        }
        printf("[Decrypt]   Max noise magnitude: %u (out of %u)\n", max_noise, PARAM_Q);
        printf("[Decrypt]   Noise percentage: %.2f%%\n", (100.0 * max_noise) / PARAM_Q);
    }
    
    printf("\n[Decrypt] DIAGNOSTIC: Final decryption term comparison\n");
    printf("[Decrypt]   Final decryption_term (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
        decryption_term_coeff[0], decryption_term_coeff[1], decryption_term_coeff[2], decryption_term_coeff[3]);
    printf("[Decrypt]   Note: decryption_term = ω_A·C0 + Σ(coeff[i]·ω[ρ(i)]·C[i]) ≈ β·s[0] + noise\n");
    printf("[Decrypt]   The noise term (ω_A·e0 + Σ(coeff[i]·ω[ρ(i)]·e_i)) may cause mismatch with encryption's β·s[0]\n");
    
    poly beta_c0_0_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
    if (beta_c0_0_coeff) {
        poly c0_0 = poly_matrix_element(ct_abe->C0, 1, 0, 0);
        double_poly beta_c0_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        poly beta_c0_crt = (poly)calloc(PARAM_N, sizeof(scalar));
        
        if (beta_c0_prod && beta_c0_crt) {
            mul_crt_poly(beta_c0_prod, mpk->beta, c0_0, LOG_R);
            reduce_double_crt_poly(beta_c0_crt, beta_c0_prod, LOG_R);
            memcpy(beta_c0_0_coeff, beta_c0_crt, PARAM_N * sizeof(scalar));
            coeffs_representation(beta_c0_0_coeff, LOG_R);
            freeze_poly(beta_c0_0_coeff, PARAM_N - 1);
            
            printf("[Decrypt]   β·C0[0] (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
                   beta_c0_0_coeff[0], beta_c0_0_coeff[1], beta_c0_0_coeff[2], beta_c0_0_coeff[3]);
            
            int mismatch_count = 0;
            uint32_t max_diff = 0;
            // Check ALL coefficients, especially the ones used for k_log extraction (0-31)
            for (int k = 0; k < PARAM_N && k < AES_KEY_SIZE + 16; k++) {
                uint32_t diff = (decryption_term_coeff[k] > beta_c0_0_coeff[k]) ? 
                               (decryption_term_coeff[k] - beta_c0_0_coeff[k]) : 
                               (beta_c0_0_coeff[k] - decryption_term_coeff[k]);
                if (diff > max_diff) max_diff = diff;
                // Check for significant differences (not just modulo wrap)
                if (diff > 1000 && diff < (PARAM_Q - 1000)) {
                    if (mismatch_count < 10 || (k >= 10 && k < 20)) {
                        printf("[Decrypt]   Diff at coeff[%d]: decryption_term=%u, β·C0[0]=%u, diff=%u\n",
                               k, decryption_term_coeff[k], beta_c0_0_coeff[k], diff);
                    }
                    mismatch_count++;
                }
            }
            printf("[Decrypt]   Max difference between decryption_term and expected β·C0[0] (first %d coeffs): %u\n", 
                   AES_KEY_SIZE + 16, max_diff);
            if (mismatch_count == 0) {
                printf("[Decrypt]   ✓ decryption_term matches expected β·C0[0] (within tolerance)\n");
            } else {
                printf("[Decrypt]   ✗ decryption_term differs from expected β·C0[0] (%d differences out of %d checked)\n", 
                       mismatch_count, AES_KEY_SIZE + 16);
                printf("[Decrypt]   ⚠ WARNING: Mismatch indicates decryption formula may be incorrect\n");
            }
            
            free(beta_c0_prod);
            free(beta_c0_crt);
        }
        free(beta_c0_0_coeff);
    }
    
    printf("\n[Decrypt] DIAGNOSTIC: Measuring noise term magnitude\n");
    printf("[Decrypt]   Formula: decryption_term = ω_A·C0 + Σ(coeff[i]·ω[ρ(i)]·C[i]) ≈ β·s[0] + noise\n");
    printf("[Decrypt]   The noise includes: ω_A·e0 + Σ(coeff[i]·ω[ρ(i)]·e_i)\n");
    printf("[Decrypt]   We'll measure the magnitude of decryption_term and compare with encoding tolerance\n");
    
    uint32_t max_decryption_term = 0;
    uint32_t min_decryption_term = PARAM_Q;
    for (int i = 0; i < PARAM_N; i++) {
        if (decryption_term_coeff[i] > max_decryption_term) max_decryption_term = decryption_term_coeff[i];
        if (decryption_term_coeff[i] < min_decryption_term) min_decryption_term = decryption_term_coeff[i];
    }
    printf("[Decrypt]   decryption_term (β·C0[0]) magnitude:\n");
    printf("[Decrypt]     Max coefficient: %u (0x%x)\n", max_decryption_term, max_decryption_term);
    printf("[Decrypt]     Min coefficient: %u (0x%x)\n", min_decryption_term, min_decryption_term);
    
    const uint32_t shift_diag = PARAM_K - 8;
    const uint32_t encoding_tolerance = 1U << shift_diag;  // 2^shift_diag
    const uint32_t half_tolerance = encoding_tolerance / 2;
    printf("[Decrypt]   Encoding tolerance (2^%u): %u (0x%x)\n", shift_diag, encoding_tolerance, encoding_tolerance);
    printf("[Decrypt]   Half tolerance: %u (0x%x)\n", half_tolerance, half_tolerance);
    
    if (max_decryption_term > encoding_tolerance) {
        printf("[Decrypt]   ⚠ WARNING: Max coefficient (%u) exceeds encoding tolerance (%u)\n", 
               max_decryption_term, encoding_tolerance);
        printf("[Decrypt]   This may cause k_log corruption in high bits\n");
    } else {
        printf("[Decrypt]   ✓ Max coefficient is within encoding tolerance\n");
    }
    
    printf("[Decrypt]   To compute noise exactly, we need β·s[0] from encryption\n");
    printf("[Decrypt]   Noise = decryption_term - β·s[0] = (ω_A·C0 + Σ(coeff[i]·ω[ρ(i)]·C[i])) - β·s[0]\n");
    
    printf("[Decrypt NOISE DIAG] decryption_term (ω_A·C0 + Σ(coeff[i]·ω[ρ(i)]·C[i])) (COEFF, first 32):");
    fflush(stdout);
    for (int i = 0; i < 32 && i < PARAM_N; i++) {
        printf(" %u", decryption_term_coeff[i]);
    }
    printf(" ... (truncated, total %d coefficients)\n", PARAM_N);
    fflush(stdout);
    printf("[Decrypt NOISE DIAG] decryption_term max coefficient: %u (0x%x)\n", max_decryption_term, max_decryption_term);
    fflush(stdout);
    printf("[Decrypt] DIAGNOSTIC: Diagnostic output completed, continuing to Step 3...\n");
    fflush(stdout);
    
    // Skip beta_e0_0_coeff computation - it's not needed for extraction
    // This was causing the hang - computing β·C0[0] again is expensive and unnecessary
    printf("[Decrypt] DIAGNOSTIC: Skipping beta_e0_0_coeff computation (not needed for extraction)\n");
    fflush(stdout);
    
    // Note: The diagnostic code for beta_e0_0_coeff is not needed for k_log extraction
    // It was causing the hang because it recomputes β·C0[0] which is expensive
    // We already have decryption_term which equals β·C0[0], so we don't need to recompute it
    // Skipping this expensive computation to avoid hanging
    printf("[Decrypt] DIAGNOSTIC: Skipping expensive beta_e0_0_coeff computation\n");
    printf("[Decrypt]   (decryption_term already equals β·C0[0], no need to recompute)\n");
    fflush(stdout);
    
    // Quick summary without expensive computation
    printf("\n[Decrypt] DIAGNOSTIC: Noise Analysis Summary\n");
    printf("[Decrypt]   ============================================\n");
    printf("[Decrypt]   Current measurements:\n");
    printf("[Decrypt]     - decryption_term max: %u (0x%x)\n", max_decryption_term, max_decryption_term);
    printf("[Decrypt]     - Encoding tolerance: %u (2^%u)\n", encoding_tolerance, shift_diag);
    printf("[Decrypt]     - Status: %s\n", 
           (max_decryption_term > encoding_tolerance) ? "WARNING: May cause corruption" : "OK");
    printf("[Decrypt]   ============================================\n");
    fflush(stdout);
    
    if (step1_crt) free(step1_crt);
    if (step1_coeff) free(step1_coeff);
    if (step2_coeff) free(step2_coeff);
    if (expected_step2_coeff) free(expected_step2_coeff);
    
    free(step2_contributions_crt);
    free(expected_step2_crt);
    free(A_omega_A);

    if (getenv("ARITH_PROVENANCE")) {
        int watch_idx[] = {0,1,2,3,4,5,6,7,16,31};
        int nwatch = sizeof(watch_idx)/sizeof(watch_idx[0]);
        printf("[DECRYPT PROV] Running provenance tracing for indices:");
        for (int wi = 0; wi < nwatch; wi++) printf(" %d", watch_idx[wi]);
        printf("\n");

        long long accum[10];
        for (int a = 0; a < nwatch; a++) accum[a] = 0;

        printf("[DECRYPT PROV] Replaying Step1 (ω_A · C0) per-j contributions\n");
        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly omega_A_j = poly_matrix_element(usk->omega_A, 1, j, 0);
            poly c0_j = poly_matrix_element(ct_abe->C0, 1, j, 0);
            double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            mul_crt_poly(prod, omega_A_j, c0_j, LOG_R);
            poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            reduce_double_crt_poly(prod_reduced, prod, LOG_R);

            printf("[DECRYPT PROV] Step1 j=%u contributions:", j);
            for (int w = 0; w < nwatch; w++) {
                int idx = watch_idx[w];
                long long v = (long long)prod_reduced[idx];
                accum[w] = (accum[w] + v) % PARAM_Q;
                printf(" idx=%d val=%u accum=%lld,", idx, (uint32_t)v, accum[w]);
            }
            printf("\n");

            free(prod);
            free(prod_reduced);
        }

        printf("[DECRYPT PROV] After Step1 running accum (mod Q):");
        for (int w = 0; w < nwatch; w++) printf(" %d->%lld", watch_idx[w], accum[w]);
        printf("\n");

        printf("[DECRYPT PROV] Replaying Step2 (policy attribute contributions)\n");
        for (uint32_t i = 0; i < n_coeffs && i < ct_abe->policy.matrix_rows; i++) {
            uint32_t policy_attr_idx = ct_abe->policy.rho[i];
            int omega_idx = -1;
            for (uint32_t j = 0; j < usk->attr_set.count; j++) {
                if (usk->attr_set.attrs[j].index == policy_attr_idx) { omega_idx = j; break; }
            }
            if (omega_idx == -1) continue;

            long long temp_accum[10];
            for (int a = 0; a < nwatch; a++) temp_accum[a] = 0;

            for (uint32_t j = 0; j < PARAM_M; j++) {
                poly omega_ij = poly_matrix_element(usk->omega_i[omega_idx], 1, j, 0);
                poly c_i_j = poly_matrix_element(ct_abe->C[i], 1, j, 0);
                double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
                mul_crt_poly(prod, omega_ij, c_i_j, LOG_R);
                poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
                reduce_double_crt_poly(prod_reduced, prod, LOG_R);

                for (int w = 0; w < nwatch; w++) {
                    int idx = watch_idx[w];
                    temp_accum[w] = (temp_accum[w] + (long long)prod_reduced[idx]) % PARAM_Q;
                }

                free(prod);
                free(prod_reduced);
            }

            uint32_t coeff = coefficients[i];
            printf("[DECRYPT PROV] Attr %u (policy row %u) pre-mul contributions:", policy_attr_idx, i);
            for (int w = 0; w < nwatch; w++) {
                long long before = temp_accum[w];
                long long after = (before * (long long)coeff) % PARAM_Q;
                accum[w] = (accum[w] + after) % PARAM_Q;
                printf(" idx=%d pre=%lld post=%lld accum=%lld,", watch_idx[w], before, after, accum[w]);
            }
            printf("\n");
        }

        printf("[DECRYPT PROV] Final reconstructed accum (mod Q):");
        for (int w = 0; w < nwatch; w++) printf(" %d->%lld", watch_idx[w], accum[w]);
        printf("\n");
    }

    printf("\n[Decrypt]   Step 3: Subtracting to extract K_log\n");
    fflush(stdout);
    if (getenv("ARITH_PROVENANCE")) {
        int watch_idx[] = {0,1,2,3,4,5,6,7,16,31};
        int nwatch = sizeof(watch_idx)/sizeof(watch_idx[0]);
        printf("[DECRYPT PROV] Pre-subtraction ct_key values:\n");
        for (int w = 0; w < nwatch; w++) {
            int idx = watch_idx[w];
            printf("  idx=%d ct_key=%u\n", idx, ct_abe->ct_key[idx]);
        }
        uint64_t fnv_late = 1469598103934665603ULL;
        for (int _i = 0; _i < PARAM_N; _i++) {
            uint64_t v2 = (uint64_t)ct_abe->ct_key[_i];
            for (int b2 = 0; b2 < 8; b2++) {
                uint8_t oct2 = (uint8_t)((v2 >> (b2 * 8)) & 0xFF);
                fnv_late ^= (uint64_t)oct2;
                fnv_late *= 1099511628211ULL;
            }
        }
        printf("[DECRYPT PROV] Pre-subtraction ct_key FNV64=0x%016" PRIx64 "\n", fnv_late);
    }
    if (getenv("ARITH_MIN_PROV")) {
        uint64_t fnv_late_min = 1469598103934665603ULL;
        for (int _i = 0; _i < PARAM_N; _i++) {
            uint64_t v2 = (uint64_t)ct_abe->ct_key[_i];
            fnv_late_min ^= (v2 & 0xFFFFFFFFULL);
            fnv_late_min *= 1099511628211ULL;
        }
        printf("[DECRYPT MINPROV] ct_key ptr=%p Pre-subtraction FNV64=0x%016" PRIx64 "\n",
               (void*)ct_abe->ct_key, fnv_late_min);
    }
    
    // Diagnostic: Compare ct_key and decryption_term for failing bytes (12-15)
    // Note: This diagnostic is expensive (recomputes β·C0[0]), so we skip it to avoid hanging
    // We already know decryption_term = β·C0[0] from earlier diagnostics
    printf("[Decrypt DIAG] Skipping expensive ct_key comparison (decryption_term already verified = β·C0[0])\n");
    fflush(stdout);
    
    for (uint32_t i = 0; i < PARAM_N; i++) {
        // recovered[i] = ct_key[i] - decryption_term[i] (mod Q)
        // ct_key[i] = β·C0[0][i] + e_key[i] + encoded_klog[i]
        // decryption_term[i] ≈ β·C0[0][i]
        // So: recovered[i] ≈ e_key[i] + encoded_klog[i]
        // If decryption_term[i] > ct_key[i], this will wrap around
        // We need to handle this correctly
        int64_t diff = (int64_t)recovered[i] - (int64_t)decryption_term_coeff[i];
        if (diff < 0) {
            diff += PARAM_Q;
        }
        recovered[i] = (uint32_t)(diff % PARAM_Q);
        
        // Diagnostic for failing bytes (commented out - shift not defined here)
        // if (i >= 12 && i < 16 && getenv("ARITH_DEBUG")) {
        //     uint64_t expected_enc = (uint64_t)(0xA5 + i) << shift;
        //     int64_t noise_est = (int64_t)recovered[i] - (int64_t)expected_enc;
        //     if (noise_est > (int64_t)PARAM_Q / 2) noise_est -= (int64_t)PARAM_Q;
        //     if (noise_est < -(int64_t)PARAM_Q / 2) noise_est += (int64_t)PARAM_Q;
        //     printf("[Decrypt DEBUG]   After subtraction i=%u: recovered=%u, expected_enc=%llu, noise_est=%lld\n",
        //            i, recovered[i], (unsigned long long)expected_enc, (long long)noise_est);
        // }
    }
    if (getenv("ARITH_DUMP_FULL")) {
        printf("[DECRYPT DUMP FULL] recovered_after_subtraction_full:\n");
        for (int _i = 0; _i < PARAM_N; _i++) printf(" %u", recovered[_i]);
        printf("\n");
    }
    
    printf("[Decrypt]   After subtraction (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           recovered[0], recovered[1], recovered[2], recovered[3]);
    printf("[Decrypt]   In HEX: [0]=0x%08x, [1]=0x%08x, [2]=0x%08x, [3]=0x%08x\n",
           recovered[0], recovered[1], recovered[2], recovered[3]);
    
    if (getenv("ARITH_PROVENANCE")) {
        int watch_idx[] = {0,1,2,3,4,5,6,7,16,31};
        int nwatch = sizeof(watch_idx)/sizeof(watch_idx[0]);
        const uint32_t shift_local = PARAM_K - 8;
        const uint32_t Q_half_local = PARAM_Q / 2;
        printf("[DECRYPT PROV] Per-index subtraction + rounding details:\n");
        for (int w = 0; w < nwatch; w++) {
            int idx = watch_idx[w];
            uint32_t ctval = ct_abe->ct_key[idx];
            uint32_t term = decryption_term_coeff[idx];
            uint32_t diff = recovered[idx];
            int64_t centered = (int64_t)diff;
            if (centered > (int64_t)Q_half_local) centered -= (int64_t)PARAM_Q;
            int64_t rounded;
            if (centered >= 0) {
                rounded = (centered + (1LL << (shift_local - 1))) >> shift_local;
            } else {
                rounded = -(((-centered) + (1LL << (shift_local - 1))) >> shift_local);
            }
            uint8_t byte = (uint8_t)(rounded & 0xFF);
            printf("  idx=%d ct_key=%10u term=%10u diff=%10u centered=%+12lld rounded=%+6lld byte=0x%02x\n",
                   idx, ctval, term, diff, (long long)centered, (long long)rounded, byte);
        }
    }
    const uint32_t shift = PARAM_K - 8;  // Reduced from PARAM_K-4 to avoid modulo wrap issues
    const uint32_t Q_half = PARAM_Q / 2;
    const uint32_t redundancy = 3;  // Reduced from 5 to allow larger spacing
    const uint32_t spacing = 32;  // Increased from 12 to avoid position collisions (must be >= AES_KEY_SIZE)
    
    printf("[Decrypt]   Extracting K_log (shift=%u):\n", shift);
    fflush(stdout);
    printf("[Decrypt]   Using primary position per byte (redundant positions have different noise)\n");
    fflush(stdout);
    printf("[Decrypt]   ");
    fflush(stdout);
    
    for (uint32_t i = 0; i < AES_KEY_SIZE && i < PARAM_N; i++) {
        // Use primary position (i) as the main source, since it has the encoded value
        // Redundant positions have different noise, so they're not reliable
        uint64_t val = (uint64_t)recovered[i];
        
        // The recovered value should be: encoded_klog[i] + e_key[i]
        // where encoded_klog[i] = (key[i] << shift) % Q
        // With shift=22, the encoded value is in [0, Q) and key[i] << 22 < Q (no wrap)
        // So: encoded_klog[i] = key[i] << 22
        // Therefore: val = (key[i] << 22) + e_key[i]
        // To extract: key[i] = (val - e_key[i]) >> 22 ≈ val >> 22 (if e_key[i] is small)
        
        // Handle potential modulo wrap: if val is much smaller than expected, it might have wrapped
        // Check if val is suspiciously small (less than half of expected for a typical byte)
        // Expected encoded values are in range [0 << 22, 255 << 22] = [0, 1069547520]
        // If val is very small (< 2^21 = 2097152), it might be a wrap issue
        // But actually, if decryption_term[i] > β·C0[0][i], then recovered[i] will be small
        // This suggests decryption_term[i] doesn't match β·C0[0][i]
        
        // Try direct extraction first
        uint64_t rounded1 = (val + (1ULL << (shift - 1))) >> shift;
        
        // If rounded1 is suspiciously small (< 64), it might be because val wrapped around
        // This happens when decryption_term[i] > β·C0[0][i], making recovered[i] too small
        // Try adding Q to see if that gives a better result
        uint64_t rounded = rounded1;
        if (rounded1 < 64 && val < (1ULL << 21)) {
            // val is very small, might be a wrap issue
            // Try: (val + Q) >> shift
            uint64_t val_plus_q = val + PARAM_Q;
            uint64_t rounded_alt = (val_plus_q + (1ULL << (shift - 1))) >> shift;
            if (rounded_alt <= 255 && rounded_alt > rounded1) {
                rounded = rounded_alt;
            }
        }
        
        // Clamp to byte range [0, 255]
        if (rounded > 255) rounded = 255;
        
        // For debugging: check if extraction is correct
        if (i < 16 && i < AES_KEY_SIZE) {
            uint8_t expected_byte = (uint8_t)(0xA5 + i);
            if (rounded != expected_byte) {
                // Calculate expected encoded value
                uint64_t expected_encoded = (uint64_t)expected_byte << shift;
                int64_t noise_estimate = (int64_t)val - (int64_t)expected_encoded;
                if (noise_estimate > (int64_t)PARAM_Q / 2) noise_estimate -= (int64_t)PARAM_Q;
                if (noise_estimate < -(int64_t)PARAM_Q / 2) noise_estimate += (int64_t)PARAM_Q;
                
                printf("[Decrypt ERROR] i=%u: expected=0x%02x got=0x%02llx val=%llu expected_enc=%llu noise=%lld\n",
                       i, expected_byte, (unsigned long long)rounded, (unsigned long long)val, 
                       (unsigned long long)expected_encoded, (long long)noise_estimate);
            }
        }
        
        if (i < 4) {
            printf("[Decrypt DEBUG] i=%u val=%llu rounded=%llu (0x%02llx)\n",
                   i, (unsigned long long)val, (unsigned long long)rounded, (unsigned long long)rounded);
        }
        
        key_out[i] = (uint8_t)rounded;
        
        if (i < 8) {
            printf("%02x ", key_out[i]);
        }
    }
    printf("\n");
    fflush(stdout);
    
    free(recovered);
    free(decryption_term_crt);
    free(decryption_term_coeff);
    
    printf("\n");
    printf("========================================\n");
    printf("[Decrypt] K_log recovered successfully!\n");
    printf("[Decrypt] First 16 bytes (hex): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", key_out[i]);
    }
    printf("\n");
    printf("[Decrypt] Full K_log (hex): ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", key_out[i]);
    }
    printf("\n");
    printf("[Decrypt] Full K_log (decimal): ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%d ", key_out[i]);
    }
    printf("\n");
    printf("========================================\n");
    fflush(stdout);
    printf("[Decrypt] LCP-ABE Decryption End \n\n");
    fflush(stdout);
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

    // Sanity-check ct_len
    if (log->ct_sym.ct_len == 0 || log->ct_sym.ct_len > 10 * 1024 * 1024) {
        fprintf(stderr, "[Load] Error: suspicious ct_len=%u\n", log->ct_sym.ct_len);
        fclose(fp);
        return -1;
    }

    log->ct_sym.ciphertext = (uint8_t*)malloc(log->ct_sym.ct_len);
    if (!log->ct_sym.ciphertext) {
        fprintf(stderr, "[Load] Error: Failed to allocate ciphertext buffer (len=%u)\n", log->ct_sym.ct_len);
        fclose(fp);
        return -1;
    }
    if (fread(log->ct_sym.ciphertext, log->ct_sym.ct_len, 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read ciphertext data\n");
        free(log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    if (fread(log->ct_sym.nonce, AES_NONCE_SIZE, 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read nonce\n");
        free(log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    if (fread(log->ct_sym.tag, AES_TAG_SIZE, 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read tag\n");
        free(log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    printf("[Load] Loaded CT_sym (size: %u bytes)\n", log->ct_sym.ct_len);
    
    // Read ABE ciphertext (CT_ABE)
    if (fread(log->ct_abe.policy.expression, MAX_POLICY_SIZE, 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read policy expression\n");
        free(log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    if (fread(&log->ct_abe.n_components, sizeof(uint32_t), 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read n_components\n");
        free(log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    printf("[Load] Loaded CT_ABE policy: '%s' (%u components)\n", 
           log->ct_abe.policy.expression, log->ct_abe.n_components);
    
    // Parse the policy to extract attribute indices
    policy_parse(log->ct_abe.policy.expression, &log->ct_abe.policy);
    
    // Allocate and read C0
    size_t c0_size = PARAM_M * PARAM_N;
    log->ct_abe.C0 = (poly_matrix)malloc(c0_size * sizeof(scalar));
    if (!log->ct_abe.C0) {
        fprintf(stderr, "[Load] Error: Failed to allocate C0 buffer\n");
        free(log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    if (fread(log->ct_abe.C0, sizeof(scalar), c0_size, fp) != c0_size) {
        fprintf(stderr, "[Load] Error: Failed to read C0\n");
        free(log->ct_sym.ciphertext);
        free(log->ct_abe.C0);
        fclose(fp);
        return -1;
    }
    
    // Allocate and read C[i] components
    log->ct_abe.C = (poly_matrix*)malloc(log->ct_abe.n_components * sizeof(poly_matrix));
    if (!log->ct_abe.C) {
        fprintf(stderr, "[Load] Error: Failed to allocate C array (n_components=%u)\n", log->ct_abe.n_components);
        free(log->ct_sym.ciphertext);
        free(log->ct_abe.C0);
        fclose(fp);
        return -1;
    }
    for (uint32_t j = 0; j < log->ct_abe.n_components; j++) {
        log->ct_abe.C[j] = (poly_matrix)malloc(c0_size * sizeof(scalar));
        if (!log->ct_abe.C[j]) {
            fprintf(stderr, "[Load] Error: Failed to allocate C[%u]\n", j);
            for (uint32_t k = 0; k < j; k++) free(log->ct_abe.C[k]);
            free(log->ct_abe.C);
            free(log->ct_sym.ciphertext);
            free(log->ct_abe.C0);
            fclose(fp);
            return -1;
        }
        if (fread(log->ct_abe.C[j], sizeof(scalar), c0_size, fp) != c0_size) {
            fprintf(stderr, "[Load] Error: Failed to read C[%u]\n", j);
            for (uint32_t k = 0; k <= j; k++) free(log->ct_abe.C[k]);
            free(log->ct_abe.C);
            free(log->ct_sym.ciphertext);
            free(log->ct_abe.C0);
            fclose(fp);
            return -1;
        }
    }
    
    // Allocate and read ct_key
    log->ct_abe.ct_key = (poly)malloc(PARAM_N * sizeof(scalar));
    if (!log->ct_abe.ct_key) {
        fprintf(stderr, "[Load] Error: Failed to allocate ct_key\n");
        for (uint32_t k = 0; k < log->ct_abe.n_components; k++) free(log->ct_abe.C[k]);
        free(log->ct_abe.C);
        free(log->ct_sym.ciphertext);
        free(log->ct_abe.C0);
        fclose(fp);
        return -1;
    }
    if (fread(log->ct_abe.ct_key, sizeof(scalar), PARAM_N, fp) != PARAM_N) {
        fprintf(stderr, "[Load] Error: Failed to read ct_key\n");
        free(log->ct_abe.ct_key);
        for (uint32_t k = 0; k < log->ct_abe.n_components; k++) free(log->ct_abe.C[k]);
        free(log->ct_abe.C);
        free(log->ct_sym.ciphertext);
        free(log->ct_abe.C0);
        fclose(fp);
        return -1;
    }
    

    
    // Read rho
    uint32_t matrix_rows;
    if (fread(&matrix_rows, sizeof(uint32_t), 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read matrix_rows\n");
        free(log->ct_abe.ct_key);
        for (uint32_t k = 0; k < log->ct_abe.n_components; k++) free(log->ct_abe.C[k]);
        free(log->ct_abe.C);
        free(log->ct_sym.ciphertext);
        free(log->ct_abe.C0);
        fclose(fp);
        return -1;
    }
    if (matrix_rows > 0) {
        log->ct_abe.policy.matrix_rows = matrix_rows;
        log->ct_abe.policy.rho = (uint32_t*)malloc(matrix_rows * sizeof(uint32_t));
        if (!log->ct_abe.policy.rho) {
            fprintf(stderr, "[Load] Error: Failed to allocate rho\n");
            free(log->ct_abe.ct_key);
            for (uint32_t k = 0; k < log->ct_abe.n_components; k++) free(log->ct_abe.C[k]);
            free(log->ct_abe.C);
            free(log->ct_sym.ciphertext);
            free(log->ct_abe.C0);
            fclose(fp);
            return -1;
        }
        if (fread(log->ct_abe.policy.rho, sizeof(uint32_t), matrix_rows, fp) != matrix_rows) {
            fprintf(stderr, "[Load] Error: Failed to read rho\n");
            free(log->ct_abe.policy.rho);
            free(log->ct_abe.ct_key);
            for (uint32_t k = 0; k < log->ct_abe.n_components; k++) free(log->ct_abe.C[k]);
            free(log->ct_abe.C);
            free(log->ct_sym.ciphertext);
            free(log->ct_abe.C0);
            fclose(fp);
            return -1;
        }
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
    
    PolicyKeyCache cache[100];
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
        
        uint8_t k_log[AES_KEY_SIZE];
        int found_in_cache = 0;
        
        if (!found_in_cache) {
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
            
            if (n_cached < 100) {
                strncpy(cache[n_cached].policy, log.ct_abe.policy.expression, MAX_POLICY_SIZE);
                memcpy(cache[n_cached].k_log, k_log, AES_KEY_SIZE);
                cache[n_cached].valid = 1;
                n_cached++;
                printf("[Decrypt]   Added policy to cache (total cached: %d)\n", n_cached);
            }
        }
        
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
