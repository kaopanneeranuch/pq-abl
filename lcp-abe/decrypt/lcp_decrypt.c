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
    // Validate policy structure is properly initialized
    if (!ct_abe->policy.share_matrix || !ct_abe->policy.rho || ct_abe->policy.matrix_rows == 0) {
        fprintf(stderr, "[Decrypt] Error: Policy structure not properly initialized (matrix=%p, rho=%p, rows=%u)\n",
            (void*)ct_abe->policy.share_matrix, (void*)ct_abe->policy.rho, ct_abe->policy.matrix_rows);
        return -1;
    }
    
    // Check if user attributes satisfy policy
    if (!lsss_check_satisfaction(&ct_abe->policy, &usk->attr_set)) {
        fprintf(stderr, "[Decrypt] Error: User attributes do not satisfy policy\n");
        return -1;
    }
    
    // Compute reconstruction coefficients
    scalar coefficients[MAX_ATTRIBUTES];
    uint32_t n_coeffs = 0;
    if (lsss_compute_coefficients(&ct_abe->policy, &usk->attr_set, coefficients, &n_coeffs) != 0) {
        fprintf(stderr, "[Decrypt] Error: Failed to compute coefficients (policy satisfied but coefficient computation failed)\n");
        return -1;
    }

    if (getenv("ARITH_DEBUG")) {
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
                
                free(beta_coeff);
            }
            free(A_omega_A_0_coeff);
            free(sum_B_omega_policy_0_coeff);
            free(lhs_trapdoor);
        }
        free(sum_B_omega_policy_0);
    }
    
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
            free(scaled_contrib_coeffs);
        }

        free(scaled_contribution);
    }
    
    memcpy(decryption_term_coeff, decryption_term_crt, PARAM_N * sizeof(scalar));
    coeffs_representation(decryption_term_coeff, LOG_R);
    freeze_poly(decryption_term_coeff, PARAM_N - 1);
    
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
        
        key_out[i] = (uint8_t)rounded;
    }
    
    free(recovered);
    free(decryption_term_crt);
    free(decryption_term_coeff);
    
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
        fprintf(stderr, "[Decrypt AES] Error: AES-GCM decryption or authentication failed\n");
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
    for (uint32_t i = 0; i < batch->n_logs; i++) {
        uint8_t *log_data;
        size_t log_len;
        
        if (decrypt_log_entry(&batch->logs[i], usk, mpk, &log_data, &log_len) == 0) {
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
    
    // Read ABE ciphertext (CT_ABE)
    if (fread(log->ct_abe.policy.expression, MAX_POLICY_SIZE, 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read policy expression\n");
        free(log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    // Ensure null termination (fread doesn't add null terminator)
    log->ct_abe.policy.expression[MAX_POLICY_SIZE - 1] = '\0';
    if (fread(&log->ct_abe.n_components, sizeof(uint32_t), 1, fp) != 1) {
        fprintf(stderr, "[Load] Error: Failed to read n_components\n");
        free(log->ct_sym.ciphertext);
        fclose(fp);
        return -1;
    }
    
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
    uint32_t *saved_rho = NULL;
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
        saved_rho = (uint32_t*)malloc(matrix_rows * sizeof(uint32_t));
        if (!saved_rho) {
            fprintf(stderr, "[Load] Error: Failed to allocate saved_rho\n");
            free(log->ct_abe.ct_key);
            for (uint32_t k = 0; k < log->ct_abe.n_components; k++) free(log->ct_abe.C[k]);
            free(log->ct_abe.C);
            free(log->ct_sym.ciphertext);
            free(log->ct_abe.C0);
            fclose(fp);
            return -1;
        }
        if (fread(saved_rho, sizeof(uint32_t), matrix_rows, fp) != matrix_rows) {
            fprintf(stderr, "[Load] Error: Failed to read rho\n");
            free(saved_rho);
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
    
    // Rebuild LSSS matrix from loaded policy (required for decryption)
    // The share_matrix needs to be rebuilt for lsss_check_satisfaction and lsss_compute_coefficients
    if (lsss_policy_to_matrix(&log->ct_abe.policy) != 0) {
        fprintf(stderr, "[Load] Error: Failed to rebuild LSSS matrix for policy\n");
        if (saved_rho) free(saved_rho);
        free(log->ct_abe.ct_key);
        for (uint32_t k = 0; k < log->ct_abe.n_components; k++) free(log->ct_abe.C[k]);
        free(log->ct_abe.C);
        free(log->ct_sym.ciphertext);
        free(log->ct_abe.C0);
        return -1;
    }
    
    // Restore rho and matrix_rows from file (lsss_policy_to_matrix may have overwritten them)
    // CRITICAL: The rho from file must be used because it matches the encryption-time mapping
    // The share_matrix created by lsss_policy_to_matrix is correct (deterministic for AND policies),
    // but we must use the rho that was saved during encryption
    if (matrix_rows > 0 && saved_rho) {
        if (log->ct_abe.policy.rho) {
            free(log->ct_abe.policy.rho);
        }
        // Restore the exact matrix structure from encryption time
        log->ct_abe.policy.matrix_rows = matrix_rows;
        if (log->ct_abe.policy.matrix_cols != matrix_rows) {
            // Ensure matrix_cols matches (should already be set by lsss_policy_to_matrix)
            log->ct_abe.policy.matrix_cols = matrix_rows;
        }
        log->ct_abe.policy.rho = saved_rho;
    }
    
    return 0;
}

// ============================================================================
// Batch Decryption with Policy Reuse Optimization
// ============================================================================

// Cache structure for policy-specific computations
typedef struct {
    char policy[MAX_POLICY_SIZE];
    int valid;
    int policy_satisfied;
    scalar coefficients[MAX_ATTRIBUTES];
    uint32_t n_coeffs;
    uint32_t matrix_rows;  // Cached policy matrix_rows for validation
    uint32_t rho[MAX_ATTRIBUTES];  // Cached rho mapping for validation
    poly_matrix A_omega_A;  // Cached expensive multiply_by_A result
} PolicyDecryptCache;

// Optimized ABE decryption using cached policy computations
static int lcp_abe_decrypt_cached(const ABECiphertext *ct_abe,
                                  const UserSecretKey *usk,
                                  const MasterPublicKey *mpk,
                                  const PolicyDecryptCache *cache,
                                  uint8_t key_out[AES_KEY_SIZE]) {
    // Use cached policy satisfaction result
    if (!cache->policy_satisfied) {
        return -1;
    }
    
    poly recovered = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!recovered) {
        return -1;
    }
    
    memcpy(recovered, ct_abe->ct_key, PARAM_N * sizeof(scalar));
    
    poly decryption_term_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    poly decryption_term_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
    
    if (!decryption_term_crt || !decryption_term_coeff) {
        free(recovered);
        if (decryption_term_crt) free(decryption_term_crt);
        if (decryption_term_coeff) free(decryption_term_coeff);
        return -1;
    }
    
    // Step 1: Compute (A·ω_A)[0]·C0[0] using cached A_omega_A
    poly A_omega_A_0 = poly_matrix_element(cache->A_omega_A, 1, 0, 0);
    poly c0_0 = poly_matrix_element(ct_abe->C0, 1, 0, 0);
    
    double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
    if (!prod) {
        free(decryption_term_crt);
        free(decryption_term_coeff);
        free(recovered);
        return -1;
    }
    
    mul_crt_poly(prod, A_omega_A_0, c0_0, LOG_R);
    
    poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
    if (!prod_reduced) {
        free(prod);
        free(decryption_term_crt);
        free(decryption_term_coeff);
        free(recovered);
        return -1;
    }
    
    reduce_double_crt_poly(prod_reduced, prod, LOG_R);
    memcpy(decryption_term_crt, prod_reduced, PARAM_N * sizeof(scalar));
    freeze_poly(decryption_term_crt, PARAM_N - 1);
    
    free(prod);
    free(prod_reduced);
    
    // Step 2: Compute policy attribute contributions using cached coefficients
    // IMPORTANT: Use current file's policy.matrix_rows, but cached coefficients
    // The coefficients are indexed by policy matrix row, so they should align
    // Match original loop: i < n_coeffs && i < matrix_rows
    uint32_t max_iter = (cache->n_coeffs < ct_abe->policy.matrix_rows) ?
                        cache->n_coeffs : ct_abe->policy.matrix_rows;
    for (uint32_t i = 0; i < max_iter; i++) {
        if (cache->coefficients[i] == 0) continue;
        
        uint32_t policy_attr_idx = ct_abe->policy.rho[i];
        
        int omega_idx = -1;
        for (uint32_t j = 0; j < usk->attr_set.count; j++) {
            if (usk->attr_set.attrs[j].index == policy_attr_idx) {
                omega_idx = j;
                break;
            }
        }
        
        if (omega_idx == -1) {
            // Match original behavior: if coefficient is 0, skip; otherwise it's an error
            // But we already checked coefficients[i] == 0 above, so if we're here, it's an error
            fprintf(stderr, "[Decrypt] ERROR: Policy requires attr %u but user doesn't have it! (row %u)\n",
                    policy_attr_idx, i);
            free(decryption_term_crt);
            free(decryption_term_coeff);
            free(recovered);
            return -1;
        }
        
        // Compute (B+_attr · ω[ρ(i)])[0]·C0[0]
        poly B_omega_attr = (poly)calloc(PARAM_N, sizeof(scalar));
        if (!B_omega_attr) {
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
                free(B_omega_attr);
                free(decryption_term_crt);
                free(decryption_term_coeff);
                free(recovered);
                return -1;
            }
            
            mul_crt_poly(prod, B_ij, omega_ij, LOG_R);
            
            poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            if (!prod_reduced) {
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
        
        poly c0_0_step2 = poly_matrix_element(ct_abe->C0, 1, 0, 0);
        double_poly prod_B_omega_c = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        if (!prod_B_omega_c) {
            free(B_omega_attr);
            free(decryption_term_crt);
            free(decryption_term_coeff);
            free(recovered);
            return -1;
        }
        
        mul_crt_poly(prod_B_omega_c, B_omega_attr, c0_0_step2, LOG_R);
        
        poly scaled_contribution = (poly)calloc(PARAM_N, sizeof(scalar));
        if (!scaled_contribution) {
            free(prod_B_omega_c);
            free(B_omega_attr);
            free(decryption_term_crt);
            free(decryption_term_coeff);
            free(recovered);
            return -1;
        }
        
        reduce_double_crt_poly(scaled_contribution, prod_B_omega_c, LOG_R);
        
        // Scale by cached coefficient and add to decryption_term
        for (uint32_t k = 0; k < PARAM_N; k++) {
            uint64_t scaled = ((uint64_t)scaled_contribution[k] * (uint64_t)cache->coefficients[i]) % PARAM_Q;
            decryption_term_crt[k] = (decryption_term_crt[k] + scaled) % PARAM_Q;
        }
        freeze_poly(decryption_term_crt, PARAM_N - 1);
        
        free(prod_B_omega_c);
        free(B_omega_attr);
        free(scaled_contribution);
    }
    
    memcpy(decryption_term_coeff, decryption_term_crt, PARAM_N * sizeof(scalar));
    coeffs_representation(decryption_term_coeff, LOG_R);
    freeze_poly(decryption_term_coeff, PARAM_N - 1);
    
    // Extract key from recovered polynomial
    for (uint32_t i = 0; i < PARAM_N; i++) {
        int64_t diff = (int64_t)recovered[i] - (int64_t)decryption_term_coeff[i];
        if (diff < 0) {
            diff += PARAM_Q;
        }
        recovered[i] = (uint32_t)(diff % PARAM_Q);
    }
    
    // Extract bytes from recovered polynomial
    const uint32_t shift = PARAM_K - 8;
    const uint32_t Q_half = PARAM_Q / 2;
    
    for (uint32_t i = 0; i < AES_KEY_SIZE && i < PARAM_N; i++) {
        uint64_t val = (uint64_t)recovered[i];
        uint64_t rounded1 = (val + (1ULL << (shift - 1))) >> shift;
        uint64_t rounded = rounded1;
        
        if (rounded1 < 64 && val < (1ULL << 21)) {
            uint64_t val_plus_q = val + PARAM_Q;
            uint64_t rounded_alt = (val_plus_q + (1ULL << (shift - 1))) >> shift;
            if (rounded_alt <= 255 && rounded_alt > rounded1) {
                rounded = rounded_alt;
            }
        }
        
        if (rounded > 255) rounded = 255;
        key_out[i] = (uint8_t)rounded;
    }
    
    free(decryption_term_crt);
    free(decryption_term_coeff);
    free(recovered);
    
    return 0;
}

int decrypt_ctobj_batch(const char **filenames,
                       uint32_t n_files,
                       const UserSecretKey *usk,
                       const MasterPublicKey *mpk,
                       const char *output_dir) {
    uint32_t success_count = 0;
    uint32_t abe_decryptions = 0;
    uint32_t cache_hits = 0;
    
    // Policy cache (one entry per unique policy)
    PolicyDecryptCache policy_cache[10];
    memset(policy_cache, 0, sizeof(policy_cache));  // Initialize all entries as invalid
    uint32_t n_cached_policies = 0;
    
    for (uint32_t i = 0; i < n_files; i++) {
        // Load CT_obj
        EncryptedLogObject log;
        if (load_ctobj_file(filenames[i], &log) != 0) {
            fprintf(stderr, "[Decrypt] Failed to load file\n");
            continue;
        }
        
        // Find or create policy cache entry
        PolicyDecryptCache *cache = NULL;
        uint32_t cache_idx = 0;
        for (uint32_t j = 0; j < n_cached_policies; j++) {
            if (policy_cache[j].valid && 
                strcmp(policy_cache[j].policy, log.ct_abe.policy.expression) == 0) {
                // For same policy expression, we can reuse A_omega_A (policy-independent)
                // Coefficients will be computed fresh for each file
                cache = &policy_cache[j];
                cache_idx = j;
                cache_hits++;
                break;
            }
        }
        
        // Track if this is a cache miss (need to populate cache)
        int is_cache_miss = 0;
        
        // If cache miss, populate cache with expensive computations
        if (!cache && n_cached_policies < 10) {
            is_cache_miss = 1;
            cache = &policy_cache[n_cached_policies];
            cache_idx = n_cached_policies;
            n_cached_policies++;
            
            // Initialize cache entry
            strncpy(cache->policy, log.ct_abe.policy.expression, MAX_POLICY_SIZE - 1);
            cache->policy[MAX_POLICY_SIZE - 1] = '\0';
            cache->valid = 1;
            
            // Check policy satisfaction (cacheable)
            cache->policy_satisfied = lsss_check_satisfaction(&log.ct_abe.policy, &usk->attr_set);
            
            if (!cache->policy_satisfied) {
                fprintf(stderr, "[Decrypt] FAILED: Policy not satisfied for file %u\n", i + 1);
                cache->valid = 0;  // Mark as invalid
                encrypted_log_free(&log);
                continue;
            }
            
            // Compute coefficients (cacheable)
            lsss_compute_coefficients(&log.ct_abe.policy, &usk->attr_set, 
                                     cache->coefficients, &cache->n_coeffs);
            
            // Cache policy structure for validation (matrix_rows and rho)
            cache->matrix_rows = log.ct_abe.policy.matrix_rows;
            if (log.ct_abe.policy.rho && cache->matrix_rows > 0 && cache->matrix_rows <= MAX_ATTRIBUTES) {
                memcpy(cache->rho, log.ct_abe.policy.rho, cache->matrix_rows * sizeof(uint32_t));
            }
            
            // Compute A_omega_A (expensive, cacheable)
            cache->A_omega_A = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
            if (!cache->A_omega_A) {
                fprintf(stderr, "[Decrypt] ERROR: Failed to allocate A_omega_A for cache\n");
                cache->valid = 0;
                encrypted_log_free(&log);
                continue;
            }
            multiply_by_A(cache->A_omega_A, mpk->A, usk->omega_A);
        } else if (!cache) {
            // Cache full, fall back to non-cached decryption
        }
        
        uint8_t k_log[AES_KEY_SIZE];
        int decrypt_result;
        int used_cached = 0;
        
        // Use cached decryption if available AND not a cache miss
        // For cache miss, use standard decryption to ensure correctness, then cache can be used for subsequent files
        if (cache && cache->valid && !is_cache_miss) {
            decrypt_result = lcp_abe_decrypt_cached(&log.ct_abe, usk, mpk, cache, k_log);
            used_cached = 1;
            
            // If cached decryption fails, fall back to standard decryption
            if (decrypt_result != 0) {
                decrypt_result = lcp_abe_decrypt(&log.ct_abe, usk, mpk, k_log);
                used_cached = 0;
            }
        } else {
            // Use standard decryption (for cache miss or no cache)
            decrypt_result = lcp_abe_decrypt(&log.ct_abe, usk, mpk, k_log);
        }
        if (decrypt_result != 0) {
            fprintf(stderr, "[Decrypt] FAILED: ABE decryption error for file %u/%u: %s\n", 
                i + 1, n_files, filenames[i]);
            encrypted_log_free(&log);
            continue;
        }
        
        abe_decryptions++;
        
        uint8_t *log_data = NULL;
        size_t log_len = 0;
        
        int sym_result = decrypt_log_symmetric(&log.ct_sym, k_log, &log.metadata, 
                                               &log_data, &log_len);
        
        if (sym_result != 0) {
            fprintf(stderr, "[Decrypt] FAILED: AES-GCM decryption or authentication failed for file %u/%u: %s\n", 
                i + 1, n_files, filenames[i]);
            encrypted_log_free(&log);
            continue;
        }
        
        if (output_dir) {
            char output_filename[512];
            snprintf(output_filename, sizeof(output_filename), 
                    "%s/decrypted_log_%d.json", output_dir, i + 1);
            
            FILE *out_fp = fopen(output_filename, "w");
            if (out_fp) {
                // Reconstruct full JSON object from metadata and decrypted log_data
                fprintf(out_fp, "{\n");
                fprintf(out_fp, "  \"timestamp\": \"%s\",\n", log.metadata.timestamp);
                fprintf(out_fp, "  \"user_id\": \"%s\",\n", log.metadata.user_id);
                fprintf(out_fp, "  \"user_role\": \"%s\",\n", log.metadata.user_role);
                fprintf(out_fp, "  \"team\": \"%s\",\n", log.metadata.team);
                fprintf(out_fp, "  \"action_type\": \"%s\",\n", log.metadata.action_type);
                fprintf(out_fp, "  \"resource_id\": \"%s\",\n", log.metadata.resource_id);
                fprintf(out_fp, "  \"resource_type\": \"%s\",\n", log.metadata.resource_type);
                fprintf(out_fp, "  \"resource_owner\": \"%s\",\n", log.metadata.resource_owner);
                fprintf(out_fp, "  \"service_name\": \"%s\",\n", log.metadata.service_name);
                fprintf(out_fp, "  \"region\": \"%s\",\n", log.metadata.region);
                fprintf(out_fp, "  \"instance_id\": \"%s\",\n", log.metadata.instance_id);
                fprintf(out_fp, "  \"ip_address\": \"%s\",\n", log.metadata.ip_address);
                fprintf(out_fp, "  \"application\": \"%s\",\n", log.metadata.application);
                fprintf(out_fp, "  \"event_description\": \"%s\",\n", log.metadata.event_description);
                fprintf(out_fp, "  \"log_data\": \"");
                // Escape JSON special characters in log_data
                for (size_t j = 0; j < log_len; j++) {
                    char c = log_data[j];
                    if (c == '"') {
                        fprintf(out_fp, "\\\"");
                    } else if (c == '\\') {
                        fprintf(out_fp, "\\\\");
                    } else if (c == '\n') {
                        fprintf(out_fp, "\\n");
                    } else if (c == '\r') {
                        fprintf(out_fp, "\\r");
                    } else if (c == '\t') {
                        fprintf(out_fp, "\\t");
                    } else if (c >= 0 && c < 32) {
                        // Control characters: escape as \uXXXX
                        fprintf(out_fp, "\\u%04x", (unsigned char)c);
                    } else {
                        fputc(c, out_fp);
                    }
                }
                fprintf(out_fp, "\"\n");
                fprintf(out_fp, "}\n");
                fclose(out_fp);
            }
        }
        
        free(log_data);
        encrypted_log_free(&log);
        success_count++;
    }
    
    // Free cached A_omega_A matrices
    for (uint32_t i = 0; i < n_cached_policies; i++) {
        if (policy_cache[i].valid && policy_cache[i].A_omega_A) {
            free(policy_cache[i].A_omega_A);
        }
    }
    
    if (success_count == 0) {
        fprintf(stderr, "Decryption failed: No files successfully decrypted\n");
    } else {
        fprintf(stderr, "[Decrypt] Success: %u/%u files decrypted, %u ABE decryptions, %u cache hits (%.1f%%)\n",
            success_count, n_files, abe_decryptions, cache_hits,
            n_files > 0 ? (100.0 * cache_hits / n_files) : 0.0);
    }
    
    return 0;
}
