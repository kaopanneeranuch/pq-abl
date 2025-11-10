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

    // ====================================================================
    // Option C Diagnostic: compute A * omega_A and Σ(B_plus[attr] * omega_i)
    // and compare (A·ωA + Σ B·ω) ?= β (all in CRT domain). Dump CRT
    // components for later per-component diffing with encryption-side dumps.
    // ====================================================================
    if (getenv("ARITH_DEBUG")) {
        printf("[Decrypt DIAG] Computing A·ω_A and Σ(B·ω) for diagnostic comparison\n");

        // Buffer for A * omega_A result (y is D-dimensional)
        poly_matrix y = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
        if (y) {
            // multiply_by_A expects y, A, x
            multiply_by_A(y, mpk->A, usk->omega_A);

            // Dump first component y[0] (A·ω_A first poly) as CRT components
            poly a0 = poly_matrix_element(y, 1, 0, 0);
            for (int comp = 0; comp < LOG_R; comp++) {
                char tag[80];
                snprintf(tag, sizeof(tag), "DIAG_Aomega_comp_%d", comp);
                dump_crt_component(a0, LOG_R, comp, tag);
            }
            /* Also dump full coefficient representation for a0 (COEFF) */
            poly a0_copy = (poly)calloc(PARAM_N, sizeof(scalar));
            if (a0_copy) {
                memcpy(a0_copy, a0, PARAM_N * sizeof(scalar));
                coeffs_representation(a0_copy, LOG_R);
                printf("[ARITH DUMP] DIAG_Aomega_poly_0_COEFF: COEFF (deg=%d, first %d):", PARAM_N, PARAM_N);
                for (int _k = 0; _k < PARAM_N; _k++) printf(" %" PRIu32, (uint32_t)a0_copy[_k]);
                printf("\n");
                free(a0_copy);
            }

            /* Dump a few omega_A polynomials (COEFF) from user's key for comparison */
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

        // Compute Σ(B_plus[attr] · omega_i) into b_sum (single poly)
        poly b_sum = (poly)calloc(PARAM_N, sizeof(scalar));
        double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));

        if (b_sum && prod && reduced) {
            // Iterate over user's ωi entries (as provided in USK)
            for (uint32_t ai = 0; ai < usk->n_components; ai++) {
                // Attribute index
                uint32_t attr_idx = usk->attr_set.attrs[ai].index;
                if (attr_idx >= mpk->n_attributes) continue;

                // B_plus row for this attribute
                poly_matrix B_plus_row = &mpk->B_plus[attr_idx * PARAM_M * PARAM_N];

                // temp accumulator for this attribute's dot product
                poly temp_res = (poly)calloc(PARAM_N, sizeof(scalar));
                if (!temp_res) continue;

                for (uint32_t j = 0; j < PARAM_M; j++) {
                    poly B_ij = &B_plus_row[j * PARAM_N];
                    poly omega_ij = poly_matrix_element(usk->omega_i[ai], 1, j, 0);

                    // mul and reduce
                    memset(prod, 0, 2 * PARAM_N * sizeof(double_scalar));
                    memset(reduced, 0, PARAM_N * sizeof(scalar));
                    mul_crt_poly(prod, B_ij, omega_ij, LOG_R);
                    reduce_double_crt_poly(reduced, prod, LOG_R);

                    add_poly(temp_res, temp_res, reduced, PARAM_N - 1);
                    freeze_poly(temp_res, PARAM_N - 1);
                }

                // Add attribute contribution to global b_sum
                add_poly(b_sum, b_sum, temp_res, PARAM_N - 1);
                freeze_poly(b_sum, PARAM_N - 1);
                free(temp_res);
            }

            // Dump b_sum components
            for (int comp = 0; comp < LOG_R; comp++) {
                char tagb[80];
                snprintf(tagb, sizeof(tagb), "DIAG_Bomega_sum_comp_%d", comp);
                dump_crt_component(b_sum, LOG_R, comp, tagb);
            }

            // Compute lhs = a0 + b_sum and dump
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

                // Also dump mpk->beta components for direct comparison
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

    /* Lightweight provenance mode: print only pointers and compact FNV64
     * hashes (early) to detect in-process mutation with minimal log output.
     * Controlled by ARITH_MIN_PROV environment var. This is intentionally
     * much lighter than the full ARITH_PROVENANCE path. */
    if (getenv("ARITH_MIN_PROV")) {
        uint64_t fnv_early = 1469598103934665603ULL;
        for (int _i = 0; _i < PARAM_N; _i++) {
            uint64_t v = (uint64_t)recovered[_i];
            /* mix 4 bytes per scalar (cheap) instead of 8-byte loop to keep
             * this fast while still producing a decent fingerprint */
            fnv_early ^= (v & 0xFFFFFFFFULL);
            fnv_early *= 1099511628211ULL;
        }
        printf("[DECRYPT MINPROV] recovered ptr=%p ct_key ptr=%p Early FNV64=0x%016" PRIx64 "\n",
               (void*)recovered, (void*)ct_abe->ct_key, fnv_early);
    }
    /* Optional full COEFF dump of the ciphertext's ct_key as observed by
     * the decryption routine. This will be compared against the encryption
     * side's ct_key_coeff_full to locate any divergence. */
    if (getenv("ARITH_DUMP_FULL")) {
        printf("[DECRYPT DUMP FULL] ct_key_coeff_full:\n");
        for (int _i = 0; _i < PARAM_N; _i++) printf(" %u", recovered[_i]);
        printf("\n");
    }
    
    // Compute the decryption term IN CRT DOMAIN, then convert to COEFF once
    // This matches how ct_key was created: (e_key + β·s[0]) in CRT, then converted to COEFF
    /* We'll compute the decryption term directly in the COEFFICIENT domain to
     * avoid subtle CRT <-> COEFF ordering/rounding differences. For each per-
     * polynomial product we reduce the CRT product and immediately convert it
     * to COEFF before accumulating into decryption_term_coeff. This keeps the
     * accumulated representation identical to how ct_key is produced in
     * encryption (which stores ct_key in COEFF domain). */
    poly decryption_term_coeff = (poly)calloc(PARAM_N, sizeof(scalar));

    // Step 1: Compute ω_A · C0 (inner product) and accumulate in COEFF
    printf("\n[Decrypt]   Step 1: Computing ω_A · C0 (inner product) and accumulating in COEFF\n");
    // DIAGNOSTIC: print addresses and first coefficients of first few C0 polynomials
    if (getenv("ARITH_DEBUG")) {
        printf("[DECRYPT DIAG] ct_abe->C0 ptr=%p PARAM_M=%u PARAM_N=%u\n", (void*)ct_abe->C0, (unsigned)PARAM_M, (unsigned)PARAM_N);
        for (uint32_t _i = 0; _i < 6 && _i < PARAM_M; _i++) {
            poly c0_i = poly_matrix_element(ct_abe->C0, 1, _i, 0);
            printf("[DECRYPT DIAG] C0_ct i=%u ptr=%p first4=%u %u %u %u\n",
                   _i, (void*)c0_i, c0_i[0], c0_i[1], c0_i[2], c0_i[3]);
        }
    }
    
    /* Accumulator for roundtrip-of-coeffs (CRT) to check linearity: sum of
     * (prod_reduced -> COEFF -> CRT) over j. If conversion is linear, this
     * accumulator converted to COEFF should equal the final decryption_term
     * COEFF produced by converting the CRT accumulator. */
    poly sum_roundtrip_crt = (poly)calloc(PARAM_N, sizeof(scalar));

    for (uint32_t j = 0; j < PARAM_M; j++) {
        poly omega_A_j = poly_matrix_element(usk->omega_A, 1, j, 0);
        poly c0_j = poly_matrix_element(ct_abe->C0, 1, j, 0);
        /* Diagnostic mapping: print per-j pointers and first4 coeffs to detect
         * ordering/layout mismatches between encrypt and decrypt. */
        if (getenv("ARITH_DEBUG") && j < 32) {
            printf("[DECRYPT MAP] j=%u omega_A_j ptr=%p first4=%u %u %u %u | c0_j ptr=%p first4=%u %u %u %u\n",
                   j, (void*)omega_A_j, omega_A_j[0], omega_A_j[1], omega_A_j[2], omega_A_j[3],
                   (void*)c0_j, c0_j[0], c0_j[1], c0_j[2], c0_j[3]);
        }

    double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
    mul_crt_poly(prod, omega_A_j, c0_j, LOG_R);
        /* Diagnostic: when ARITH_DEBUG is set, dump each reduced CRT component
         * for this product so we can later compare with encryption-side dumps. */
        if (getenv("ARITH_DEBUG")) {
            for (int comp = 0; comp < LOG_R; comp++) {
                char tag[64];
                snprintf(tag, sizeof(tag), "DECRYPT_step1_attr_%d_j_%d_comp_%d", j, (int)j, comp);
                dump_double_crt_component(prod, LOG_R, comp, tag);
            }
        }

    poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
    reduce_double_crt_poly(prod_reduced, prod, LOG_R);

    /* Convert this per-term reduced CRT product to COEFFICIENT domain and
     * add it immediately to the COEFF accumulator. This reduces reliance
     * on a large CRT accumulator and keeps the arithmetic consistent with
     * encryption (which keeps ct_key in COEFF). */
    coeffs_representation(prod_reduced, LOG_R);
    add_poly(decryption_term_coeff, decryption_term_coeff, prod_reduced, PARAM_N - 1);
    freeze_poly(decryption_term_coeff, PARAM_N - 1);

    /* Diagnostic: dump the reduced COEFF for this per-j product when enabled */
        if (getenv("ARITH_DEBUG")) {
            for (int comp = 0; comp < LOG_R; comp++) {
                char tagr[80];
                snprintf(tagr, sizeof(tagr), "DECRYPT_step1_prod_reduced_j_%u_comp_%d", j, comp);
                dump_crt_component(prod_reduced, LOG_R, comp, tagr);
            }
            /* Also dump a COEFF representation of this per-j reduced product for
             * direct comparison with encryption-side COEFF dumps. Print for ALL
             * j but limit to first 16 coefficients to keep logs manageable. */
            {
                poly prod_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
                if (prod_coeff) {
                    memcpy(prod_coeff, prod_reduced, PARAM_N * sizeof(scalar));
                    /* Normalize the copied CRT component before converting to
                     * COEFF. This makes the per-term conversion use the same
                     * canonical representative as the aggregated path. */
                    freeze_poly(prod_coeff, PARAM_N - 1);
                    coeffs_representation(prod_coeff, LOG_R);
                    printf("[DECRYPT DIAG] Step1_prod_j_%u_COEFF: COEFF (deg=%d, first %d):", j, PARAM_N, 16);
                    for (int _k = 0; _k < 16; _k++) printf(" %u", prod_coeff[_k]);
                    printf("\n");

                    /* Optional full CRT dump for exact-data harness */
                    if (getenv("ARITH_DUMP_FULL")) {
                        printf("[DECRYPT DUMP FULL] prod_reduced_j_%u_full:\n", j);
                        for (int _i = 0; _i < PARAM_N; _i++) {
                            printf(" %u", prod_reduced[_i]);
                        }
                        printf("\n");
                    }

                    /* Convert back to CRT (roundtrip) and add to sum_roundtrip_crt */
                    crt_representation(prod_coeff, LOG_R);
                    /* Optional: dump the CRT result of the COEFF->CRT roundtrip
                     * so we can later reconstruct exactly what was added into
                     * sum_roundtrip_crt. This helps trace upstream contributors
                     * to any divergence observed at higher combine nodes. */
                    if (getenv("ARITH_DUMP_FULL")) {
                        printf("[DECRYPT DUMP FULL] prod_roundtrip_crt_j_%u_full:\n", j);
                        for (int _i = 0; _i < PARAM_N; _i++) printf(" %u", prod_coeff[_i]);
                        printf("\n");
                    }
                    add_poly(sum_roundtrip_crt, sum_roundtrip_crt, prod_coeff, PARAM_N - 1);
                    free(prod_coeff);
                }
            }
        }

        // free per-term buffers
        if (getenv("ARITH_DEBUG")) {
            /* For traceability still show a small COEFF snapshot */
            poly prod_coeff_snap = prod_reduced; /* already COEFF */
            printf("[DECRYPT DIAG] Step1_prod_j_%u_COEFF (first 16):", j);
            for (int _k = 0; _k < 16; _k++) printf(" %u", prod_coeff_snap[_k]);
            printf("\n");
        }
        
        free(prod);
        free(prod_reduced);
    }
    
    /* Diagnostic B: print COEFF representation of Step 1 (ω_A · C0) so we can
     * directly compare encrypt-side ω_A·(A^T·s) COEFF vector with the value
     * computed during decryption BEFORE attribute contributions are added. */
    if (getenv("ARITH_DEBUG")) {
        poly step1_copy = (poly)calloc(PARAM_N, sizeof(scalar));
        if (step1_copy) {
            memcpy(step1_copy, decryption_term_coeff, PARAM_N * sizeof(scalar));
            /* Convert in-place to COEFF domain for human-readable comparison */
            coeffs_representation(step1_copy, LOG_R);
            printf("[DECRYPT DIAG] Step1 (COEFF, first 16):");
            for (int _k = 0; _k < 16; _k++) printf(" %u", step1_copy[_k]);
            printf("\n");
                /* Also dump full CRT array immediately after Step1 (before Step2) */
                if (getenv("ARITH_DUMP_FULL")) {
                    printf("[DECRYPT DUMP FULL] decryption_term_coeff_after_step1_full:\n");
                    for (int _i = 0; _i < PARAM_N; _i++) printf(" %u", decryption_term_coeff[_i]);
                    printf("\n");
                }
            free(step1_copy);
        }
    }

    printf("[Decrypt]   ω_A · C0 (COEFF accumulator, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
        decryption_term_coeff[0], decryption_term_coeff[1], decryption_term_coeff[2], decryption_term_coeff[3]);
    
    // Step 2: Add Σ(coeff[j]·ω[ρ(j)]·C[j]) in CRT domain
    printf("\n[Decrypt]   Step 2: Computing Σ(coeff[j]·ω[ρ(j)]·C[j]) and accumulating in COEFF\n");
    
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
            /* If the reconstruction coefficient for this policy row is zero
             * then the user's missing attribute does not contribute and we
             * can safely skip this row. Only error if coefficient != 0. */
            if (coefficients[i] == 0) {
                continue;
            }
            fprintf(stderr, "[Decrypt] ERROR: Policy requires attr %d but user doesn't have it!\n",
                    policy_attr_idx);
            free(decryption_term_coeff);
            free(recovered);
            return -1;
        }
        
        // Compute ω[ρ(i)]·C[i] as inner product in CRT
    poly temp_sum_crt = (poly)calloc(PARAM_N, sizeof(scalar));
        // DIAGNOSTIC: print first few polynomials of C[i] as seen by decryption
        if (getenv("ARITH_DEBUG")) {
            for (uint32_t _j = 0; _j < 4 && _j < PARAM_M; _j++) {
                poly c_i_j_diag = poly_matrix_element(ct_abe->C[i], 1, _j, 0);
                printf("[DECRYPT DIAG] C_ct i=%u j=%u ptr=%p first4=%u %u %u %u\n",
                       i, _j, (void*)c_i_j_diag, c_i_j_diag[0], c_i_j_diag[1], c_i_j_diag[2], c_i_j_diag[3]);
            }
        }

        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly omega_ij = poly_matrix_element(usk->omega_i[omega_idx], 1, j, 0);
            poly c_i_j = poly_matrix_element(ct_abe->C[i], 1, j, 0);
            
            double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            mul_crt_poly(prod, omega_ij, c_i_j, LOG_R);
            /* Diagnostic: dump reduced CRT components for each inner-product term */
            if (getenv("ARITH_DEBUG")) {
                for (int comp = 0; comp < LOG_R; comp++) {
                    char tag2[80];
                    snprintf(tag2, sizeof(tag2), "DECRYPT_attr_%u_j_%u_comp_%d", policy_attr_idx, j, comp);
                    dump_double_crt_component(prod, LOG_R, comp, tag2);
                }
            }

            poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            reduce_double_crt_poly(prod_reduced, prod, LOG_R);

            // Convert per-term reduced product to COEFF and add to temp_sum_coeff
            coeffs_representation(prod_reduced, LOG_R);
            add_poly(decryption_term_coeff, decryption_term_coeff, prod_reduced, PARAM_N - 1);
            freeze_poly(decryption_term_coeff, PARAM_N - 1);
            
            // Debug: print first coefficients of this product/reduction for first few j
            if (j < 3) {
                printf("[Decrypt DEBUG] attr %u, j=%u: prod_reduced (CRT, first 4) = [%u, %u, %u, %u]\n",
                       policy_attr_idx, j, prod_reduced[0], prod_reduced[1], prod_reduced[2], prod_reduced[3]);
                printf("[Decrypt DEBUG] attr %u, j=%u: temp_sum_crt (CRT, first 4) = [%u, %u, %u, %u]\n",
                       policy_attr_idx, j, temp_sum_crt[0], temp_sum_crt[1], temp_sum_crt[2], temp_sum_crt[3]);
            }
            
            free(prod);
            free(prod_reduced);
        }
        
        /* In the updated path we already converted per-term products to COEFF
         * and added them into decryption_term_coeff, multiplied by 1 as part
         * of the direct accumulation above. If coefficients[i] != 1 we need
         * to scale the contribution we just added. Since we don't track
         * per-attribute temporary storage here, perform a corrective scaling
         * by re-computing temp_sum_crt → COEFF then applying the coefficient
         * and adding (this is only used in the uncommon coefficient != 1
         * case). For the common coeff==1 we can skip extra work. */
        if (coefficients[i] != 1) {
            /* Recompute attribute contribution in CRT then convert to COEFF */
            poly temp_sum_recomputed = (poly)calloc(PARAM_N, sizeof(scalar));
            for (uint32_t j = 0; j < PARAM_M; j++) {
                poly omega_ij = poly_matrix_element(usk->omega_i[omega_idx], 1, j, 0);
                poly c_i_j = poly_matrix_element(ct_abe->C[i], 1, j, 0);
                double_poly prod2 = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
                mul_crt_poly(prod2, omega_ij, c_i_j, LOG_R);
                poly prod_red2 = (poly)calloc(PARAM_N, sizeof(scalar));
                reduce_double_crt_poly(prod_red2, prod2, LOG_R);
                coeffs_representation(prod_red2, LOG_R);
                add_poly(temp_sum_recomputed, temp_sum_recomputed, prod_red2, PARAM_N - 1);
                free(prod2);
                free(prod_red2);
            }
            /* Scale and add */
            for (uint32_t k = 0; k < PARAM_N; k++) {
                uint64_t mul = (uint64_t)coefficients[i];
                if (mul > 0) mul = mul - 1; /* we've already added 1x earlier */
                uint64_t scaled = ((uint64_t)temp_sum_recomputed[k] * mul) % PARAM_Q;
                decryption_term_coeff[k] = (decryption_term_coeff[k] + scaled) % PARAM_Q;
            }
            free(temp_sum_recomputed);
        }
        /* Diagnostic: dump CRT components of temp_sum_crt after coefficient
         * multiplication so we can compare each attribute contribution with
         * the corresponding encryption-side term. */
        if (getenv("ARITH_DEBUG")) {
            for (int comp = 0; comp < LOG_R; comp++) {
                char tagt[96];
                snprintf(tagt, sizeof(tagt), "DECRYPT_temp_sum_crt_attr_%u_comp_%d", policy_attr_idx, comp);
                dump_crt_component(temp_sum_crt, LOG_R, comp, tagt);
            }
        }
        
        // Debug: convert a copy of temp_sum_crt to COEFF for inspection (non-destructive)
        poly temp_sum_coeffs = (poly)calloc(PARAM_N, sizeof(scalar));
        if (temp_sum_coeffs) {
            memcpy(temp_sum_coeffs, temp_sum_crt, PARAM_N * sizeof(scalar));
            coeffs_representation(temp_sum_coeffs, LOG_R);
            printf("[Decrypt DEBUG] attr %u: temp_sum (COEFF, first 4) = [%u, %u, %u, %u]\n",
                   policy_attr_idx, temp_sum_coeffs[0], temp_sum_coeffs[1], temp_sum_coeffs[2], temp_sum_coeffs[3]);
            free(temp_sum_coeffs);
        }

    // temp_sum_crt consumed; we keep aggregated values in decryption_term_coeff
    if (getenv("ARITH_DEBUG")) {
        uint64_t fnv2 = 1469598103934665603ULL;
        for (int _ii = 0; _ii < PARAM_N; _ii++) {
            fnv2 ^= (uint64_t)decryption_term_coeff[_ii];
            fnv2 *= 1099511628211ULL;
        }
        printf("[DECRYPT DIAG] After adding attr %u (policy row %u) decryption_term_coeff ptr=%p hash=0x%016" PRIx64 " first4=[%u,%u,%u,%u]\n",
               policy_attr_idx, i, (void*)decryption_term_coeff, fnv2, decryption_term_coeff[0], decryption_term_coeff[1], decryption_term_coeff[2], decryption_term_coeff[3]);
    }
        free(temp_sum_crt);
    }
    
    printf("[Decrypt]   decryption_term (COEFF accumulator, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
        decryption_term_coeff[0], decryption_term_coeff[1], decryption_term_coeff[2], decryption_term_coeff[3]);

    /* Optional provenance tracing: recompute per-term contributions but only
     * for a small set of coefficient indices so we can observe which prod
     * terms contribute to each coefficient and the running accumulator.
     * Enabled by setting ARITH_PROVENANCE in the environment. This is more
     * expensive but keeps earlier hot path logic unchanged. */
    if (getenv("ARITH_PROVENANCE")) {
        /* default watch indices: 0..7, 16, 31 */
        int watch_idx[] = {0,1,2,3,4,5,6,7,16,31};
        int nwatch = sizeof(watch_idx)/sizeof(watch_idx[0]);
        printf("[DECRYPT PROV] Running provenance tracing for indices:");
        for (int wi = 0; wi < nwatch; wi++) printf(" %d", watch_idx[wi]);
        printf("\n");

        /* accumulators for watched indices */
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

            /* print the watched indices from this prod_reduced and update accum */
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
        /* Step2 replay: iterate policy rows similarly to above; update accum */
        for (uint32_t i = 0; i < n_coeffs && i < ct_abe->policy.matrix_rows; i++) {
            uint32_t policy_attr_idx = ct_abe->policy.rho[i];
            int omega_idx = -1;
            for (uint32_t j = 0; j < usk->attr_set.count; j++) {
                if (usk->attr_set.attrs[j].index == policy_attr_idx) { omega_idx = j; break; }
            }
            if (omega_idx == -1) continue;

            /* temp accumulator for this attribute, but we only care about watched indices */
            long long temp_accum[10];
            for (int a = 0; a < nwatch; a++) temp_accum[a] = 0;

            for (uint32_t j = 0; j < PARAM_M; j++) {
                poly omega_ij = poly_matrix_element(usk->omega_i[omega_idx], 1, j, 0);
                poly c_i_j = poly_matrix_element(ct_abe->C[i], 1, j, 0);
                double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
                mul_crt_poly(prod, omega_ij, c_i_j, LOG_R);
                poly prod_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
                reduce_double_crt_poly(prod_reduced, prod, LOG_R);

                /* update temp_accum for watched indices */
                for (int w = 0; w < nwatch; w++) {
                    int idx = watch_idx[w];
                    temp_accum[w] = (temp_accum[w] + (long long)prod_reduced[idx]) % PARAM_Q;
                }

                free(prod);
                free(prod_reduced);
            }

            /* multiply temp_accum by reconstruction coefficient and add to global accum */
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

    /* decryption_term_coeff now holds the aggregated decryption term in
     * COEFFICIENT domain; we will subtract it directly from ct_key (which
     * is also COEFFICIENT) below. */
    
    // Step 3: Subtract decryption_term from ct_key to recover encode(K_log) + small_error
    printf("\n[Decrypt]   Step 3: Subtracting to extract K_log\n");
    /* Provenance: print pre-subtraction ct_key values for a small set of indices
     * so we can later correlate with post-subtraction and rounding. */
    if (getenv("ARITH_PROVENANCE")) {
        int watch_idx[] = {0,1,2,3,4,5,6,7,16,31};
        int nwatch = sizeof(watch_idx)/sizeof(watch_idx[0]);
        printf("[DECRYPT PROV] Pre-subtraction ct_key values:\n");
        for (int w = 0; w < nwatch; w++) {
            int idx = watch_idx[w];
            printf("  idx=%d ct_key=%u\n", idx, ct_abe->ct_key[idx]);
        }
        /* Compute a compact FNV-1a 64-bit hash of the ct_key vector right
         * before subtraction so we can diff with the early hash printed above
         * and identify when/if the buffer was mutated. */
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
    /* If in minimal provenance mode, print only pointer and compact FNV64 here
     * (pre-subtraction) and avoid the heavy per-index prints. */
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
    
    for (uint32_t i = 0; i < PARAM_N; i++) {
        recovered[i] = (recovered[i] + PARAM_Q - decryption_term_coeff[i]) % PARAM_Q;
    }
    /* Diagnostic: dump the recovered vector after subtraction (this should be
     * approximately encode(K_log) + small error). Compare this with the
     * encryption-side encoded_Klog_coeff_full to localize any mismatch. */
    if (getenv("ARITH_DUMP_FULL")) {
        printf("[DECRYPT DUMP FULL] recovered_after_subtraction_full:\n");
        for (int _i = 0; _i < PARAM_N; _i++) printf(" %u", recovered[_i]);
        printf("\n");
    }
    
    printf("[Decrypt]   After subtraction (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           recovered[0], recovered[1], recovered[2], recovered[3]);
    printf("[Decrypt]   In HEX: [0]=0x%08x, [1]=0x%08x, [2]=0x%08x, [3]=0x%08x\n",
           recovered[0], recovered[1], recovered[2], recovered[3]);
    
    /* Provenance: for watched indices, print the detailed subtraction and
     * centered rounding steps so we can compare with encryption-side encoded
     * K_log coefficients. This prints: ct_key, decryption_term (COEFF),
     * recovered = (ct_key - decryption_term) mod Q, centered value,
     * rounded value, and extracted byte. */
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
    // Extract K_log by rounding to nearest byte value
    // Use centered lift: if recovered[i] > Q/2, treat as negative (recovered[i] - Q)
    printf("[Decrypt]   Extracting K_log using centered modular reduction:\n");
    printf("[Decrypt]   ");
    const uint32_t shift = PARAM_K - 8;  // 30 - 8 = 22 bits
    const uint32_t Q_half = PARAM_Q / 2;
    for (int i = 0; i < 8; i++) {
        // Centered lift: map [0, Q) to [-Q/2, Q/2)
        int64_t centered = (int64_t)recovered[i];
        if (centered > Q_half) {
            centered -= PARAM_Q;
        }
        // Round to nearest: add 2^(shift-1) before right-shifting
        // Handle negative values correctly
        int64_t rounded;
        if (centered >= 0) {
            rounded = (centered + (1LL << (shift - 1))) >> shift;
        } else {
            // For negative: round toward zero after shift
            rounded = -((-centered + (1LL << (shift - 1))) >> shift);
        }
        printf("%02x ", (uint8_t)(rounded & 0xFF));
    }
    printf("\n");
    
    // Extract full K_log using centered modular reduction
    for (uint32_t i = 0; i < AES_KEY_SIZE && i < PARAM_N; i++) {
        // Centered lift
        int64_t centered = (int64_t)recovered[i];
        if (centered > Q_half) {
            centered -= PARAM_Q;
        }
        // Round to nearest
        int64_t rounded;
        if (centered >= 0) {
            rounded = (centered + (1LL << (shift - 1))) >> shift;
        } else {
            rounded = -((-centered + (1LL << (shift - 1))) >> shift);
        }
        key_out[i] = (uint8_t)(rounded & 0xFF);
    }
    
    free(recovered);
    free(decryption_term_coeff);
    
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
