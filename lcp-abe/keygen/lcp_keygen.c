#include "lcp_keygen.h"
#include "../../module_gaussian_lattice/Module_BFRS/sampling.h"
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "../util/lcp_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_OPENMP
#include <omp.h>
#endif

int lcp_keygen(const MasterPublicKey *mpk, const MasterSecretKey *msk,
               const AttributeSet *attr_set, UserSecretKey *usk) {
    
    usk_init(usk, attr_set->count);
    usk->attr_set = *attr_set;
    
    // Parallelize ω_i sampling (independent iterations)
    #ifdef USE_OPENMP
    #pragma omp parallel for
    #endif
    for (uint32_t i = 0; i < attr_set->count; i++) {
        const Attribute *attr = &attr_set->attrs[i];
        
        SampleR_matrix_centered((signed_poly_matrix) usk->omega_i[i], PARAM_M, 1, PARAM_SIGMA);
        
        for (int j = 0; j < PARAM_N * PARAM_M; j++) {
            usk->omega_i[i][j] += PARAM_Q;
        }
        matrix_crt_representation(usk->omega_i[i], PARAM_M, 1, LOG_R);
    }
    
    poly_matrix target = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    poly_matrix sum_term = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    
    // Parallelize B_i^+ · ω_i computation
    #ifdef USE_OPENMP
    #pragma omp parallel
    {
        // Each thread has its own local sum
        poly local_sum = (poly)calloc(PARAM_N, sizeof(scalar));
        if (!local_sum) {
            #pragma omp critical
            {
                fprintf(stderr, "[KeyGen] ERROR: Failed to allocate local_sum\n");
            }
        } else {
            zero_poly(local_sum, PARAM_N - 1);
            
            #pragma omp for
            for (uint32_t i = 0; i < attr_set->count; i++) {
                const Attribute *attr = &attr_set->attrs[i];
                
                if (attr->index >= mpk->n_attributes) {
                    #pragma omp critical
                    {
                        fprintf(stderr, "[KeyGen] ERROR: Invalid attribute index %d (max %d)\n", 
                                attr->index, mpk->n_attributes - 1);
                    }
                    continue;
                }
                
                poly_matrix B_plus_i = &mpk->B_plus[attr->index * PARAM_M * PARAM_N];
                
                poly temp_result = (poly)calloc(PARAM_N, sizeof(scalar));
                if (!temp_result) continue;
                
                double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
                poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
                
                if (!temp_prod || !reduced) {
                    if (temp_prod) free(temp_prod);
                    if (reduced) free(reduced);
                    free(temp_result);
                    continue;
                }
                
                for (uint32_t j = 0; j < PARAM_M; j++) {
                    poly B_ij = &B_plus_i[j * PARAM_N];
                    poly omega_ij = &usk->omega_i[i][j * PARAM_N];
                    
                    memset(temp_prod, 0, 2 * PARAM_N * sizeof(double_scalar));
                    memset(reduced, 0, PARAM_N * sizeof(scalar));
                    
                    mul_crt_poly(temp_prod, B_ij, omega_ij, LOG_R);
                    reduce_double_crt_poly(reduced, temp_prod, LOG_R);
                    add_poly(temp_result, temp_result, reduced, PARAM_N - 1);
                    freeze_poly(temp_result, PARAM_N - 1);  
                }
                
                free(temp_prod);
                free(reduced);
                
                // Accumulate into thread-local sum
                add_poly(local_sum, local_sum, temp_result, PARAM_N - 1);
                freeze_poly(local_sum, PARAM_N - 1);
                free(temp_result);
            }
            
            // Critical section: accumulate thread-local sums into global sum_term
            #pragma omp critical
            {
                poly sum_0 = poly_matrix_element(sum_term, PARAM_D, 0, 0);
                add_poly(sum_0, sum_0, local_sum, PARAM_N - 1);
                freeze_poly(sum_0, PARAM_N - 1);
            }
            
            free(local_sum);
        }
    }
    #else
    // Sequential version (original code)
    for (uint32_t i = 0; i < attr_set->count; i++) {
        const Attribute *attr = &attr_set->attrs[i];
        
        if (attr->index >= mpk->n_attributes) {
            fprintf(stderr, "[KeyGen] ERROR: Invalid attribute index %d (max %d)\n", 
                    attr->index, mpk->n_attributes - 1);
            free(target);
            free(sum_term);
            return -1;
        }
        
        poly_matrix B_plus_i = &mpk->B_plus[attr->index * PARAM_M * PARAM_N];
        
        poly temp_result = (poly)calloc(PARAM_N, sizeof(scalar));
        if (!temp_result) {
            fprintf(stderr, "[KeyGen] ERROR: Failed to allocate temp_result\n");
            free(target);
            free(sum_term);
            return -1;
        }
        
        double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
        poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
        
        if (!temp_prod || !reduced) {
            fprintf(stderr, "[KeyGen] ERROR: Failed to allocate multiplication buffers\n");
            if (temp_prod) free(temp_prod);
            if (reduced) free(reduced);
            free(temp_result);
            free(target);
            free(sum_term);
            return -1;
        }
        
        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly B_ij = &B_plus_i[j * PARAM_N];
            
            poly omega_ij = &usk->omega_i[i][j * PARAM_N];
            
            memset(temp_prod, 0, 2 * PARAM_N * sizeof(double_scalar));
            memset(reduced, 0, PARAM_N * sizeof(scalar));
            
            mul_crt_poly(temp_prod, B_ij, omega_ij, LOG_R);
            reduce_double_crt_poly(reduced, temp_prod, LOG_R);
            add_poly(temp_result, temp_result, reduced, PARAM_N - 1);
            freeze_poly(temp_result, PARAM_N - 1);  
        }
        
        free(temp_prod);
        free(reduced);
        
        poly sum_0 = poly_matrix_element(sum_term, PARAM_D, 0, 0);
        add_poly(sum_0, sum_0, temp_result, PARAM_N - 1);
        freeze_poly(sum_0, PARAM_N - 1);  
        free(temp_result);
    }
    #endif
    
    
    poly target_0 = poly_matrix_element(target, PARAM_D, 0, 0);
    poly sum_0 = poly_matrix_element(sum_term, PARAM_D, 0, 0);
    
    memcpy(target_0, mpk->beta, PARAM_N * sizeof(scalar));
    sub_poly(target_0, target_0, sum_0, PARAM_N - 1);
    freeze_poly(target_0, PARAM_N - 1);

    poly h_inv = (poly)calloc(PARAM_N, sizeof(scalar));
    h_inv[0] = 1;  // Identity
    crt_representation(h_inv, LOG_R);

    if (getenv("ARITH_DEBUG")) {
        for (int comp = 0; comp < LOG_R; comp++) {
            char tagt[80];
            snprintf(tagt, sizeof(tagt), "KEYGEN_target_comp_%d", comp);
            dump_crt_component(target_0, LOG_R, comp, tagt);
        }
    }
    
    fflush(stderr);
    fflush(stdout);
    
    sample_pre_target(usk->omega_A, mpk->A, msk->T, msk->cplx_T, msk->sch_comp, h_inv, target);
    
    fflush(stderr);
    fflush(stdout);
    
    if (getenv("ARITH_DEBUG")) {
        fprintf(stderr, "[KEYGEN PTR] usk->omega_A=%p first8_coeffs:", (void*)usk->omega_A);
        for (int k = 0; k < 8 && k < PARAM_N; ++k) fprintf(stderr, " %u", usk->omega_A[k]);
        fprintf(stderr, "\n"); fflush(stderr);
    }
    
    poly_matrix A_omega_A = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    if (A_omega_A) {
        multiply_by_A(A_omega_A, mpk->A, usk->omega_A);
        poly A_omega_A_0 = poly_matrix_element(A_omega_A, 1, 0, 0);
        
        poly sum_B_omega_0 = (poly)calloc(PARAM_N, sizeof(scalar));
        if (sum_B_omega_0) {
            zero_poly(sum_B_omega_0, PARAM_N - 1);
            
            double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            
            if (temp_prod && reduced) {
                for (uint32_t i = 0; i < attr_set->count; i++) {
                    uint32_t attr_idx = attr_set->attrs[i].index;
                    if (attr_idx >= mpk->n_attributes) continue;
                    
                    poly_matrix B_plus_i = &mpk->B_plus[attr_idx * PARAM_M * PARAM_N];
                    poly temp_result = (poly)calloc(PARAM_N, sizeof(scalar));
                    if (!temp_result) continue;
                    
                    for (uint32_t j = 0; j < PARAM_M; j++) {
                        poly B_ij = &B_plus_i[j * PARAM_N];
                        poly omega_ij = poly_matrix_element(usk->omega_i[i], 1, j, 0);
                        
                        memset(temp_prod, 0, 2 * PARAM_N * sizeof(double_scalar));
                        memset(reduced, 0, PARAM_N * sizeof(scalar));
                        mul_crt_poly(temp_prod, B_ij, omega_ij, LOG_R);
                        reduce_double_crt_poly(reduced, temp_prod, LOG_R);
                        add_poly(temp_result, temp_result, reduced, PARAM_N - 1);
                        freeze_poly(temp_result, PARAM_N - 1);
                    }
                    
                    add_poly(sum_B_omega_0, sum_B_omega_0, temp_result, PARAM_N - 1);
                    freeze_poly(sum_B_omega_0, PARAM_N - 1);
                    free(temp_result);
                }
                
                poly lhs = (poly)calloc(PARAM_N, sizeof(scalar));
                if (lhs) {
                    memcpy(lhs, A_omega_A_0, PARAM_N * sizeof(scalar));
                    add_poly(lhs, lhs, sum_B_omega_0, PARAM_N - 1);
                    freeze_poly(lhs, PARAM_N - 1);
                    
                    poly lhs_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
                    poly beta_coeff = (poly)calloc(PARAM_N, sizeof(scalar));
                    if (lhs_coeff && beta_coeff) {
                        memcpy(lhs_coeff, lhs, PARAM_N * sizeof(scalar));
                        memcpy(beta_coeff, mpk->beta, PARAM_N * sizeof(scalar));
                        coeffs_representation(lhs_coeff, LOG_R);
                        coeffs_representation(beta_coeff, LOG_R);
                        
                        int mismatch_count = 0;
                        for (int k = 0; k < PARAM_N && k < 16; k++) {
                            uint32_t diff = (lhs_coeff[k] > beta_coeff[k]) ? 
                                           (lhs_coeff[k] - beta_coeff[k]) : 
                                           (beta_coeff[k] - lhs_coeff[k]);  
                            if (diff > 1000 && diff < (PARAM_Q - 1000)) {
                                mismatch_count++;
                            }
                        }
                        free(lhs_coeff);
                        free(beta_coeff);
                    }
                    free(lhs);
                }
                
                free(temp_prod);
                free(reduced);
            }
            free(sum_B_omega_0);
        }
        free(A_omega_A);
    }

    if (getenv("ARITH_DEBUG")) {
        poly_matrix y_immediate = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
        if (y_immediate) {
            multiply_by_A(y_immediate, mpk->A, usk->omega_A);
            poly a0i = poly_matrix_element(y_immediate, 1, 0, 0);
            for (int comp = 0; comp < LOG_R; comp++) {
                char tagi[80];
                snprintf(tagi, sizeof(tagi), "KEYGEN_Aomega_immediate_comp_%d", comp);
                dump_crt_component(a0i, LOG_R, comp, tagi);
            }
            free(y_immediate);
        } else {
            fprintf(stderr, "[KEYGEN DIAG] failed to allocate y_immediate\n"); fflush(stderr);
        }
    }

    if (getenv("ARITH_DEBUG")) {
        int dk = PARAM_D * PARAM_K;
        int max_test = dk < 4 ? dk : 4;
        for (int j = 0; j < max_test; ++j) {
            poly_matrix x = (poly_matrix)calloc(dk * PARAM_N, sizeof(scalar));
            if (!x) {
                fprintf(stderr, "[KEYGEN DIAG] failed to alloc x for TI test j=%d\n", j); fflush(stderr); break;
            }

            poly xj = poly_matrix_element(x, dk, 0, j);
            xj[0] = 1;

            matrix_crt_representation(x, dk, 1, LOG_R);

            poly_matrix y_ti = (poly_matrix)calloc(PARAM_M * PARAM_N, sizeof(scalar));
            if (!y_ti) {
                fprintf(stderr, "[KEYGEN DIAG] failed to alloc y_ti for j=%d\n", j); fflush(stderr); free(x); break;
            }

            multiply_by_TI(y_ti, msk->T, x);

            poly_matrix ati = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
            if (!ati) {
                fprintf(stderr, "[KEYGEN DIAG] failed to alloc ati for j=%d\n", j); fflush(stderr); free(x); free(y_ti); break;
            }
            multiply_by_A(ati, mpk->A, y_ti);

            poly ati0 = poly_matrix_element(ati, 1, 0, 0);
            for (int comp = 0; comp < LOG_R; ++comp) {
                char tag[80];
                snprintf(tag, sizeof(tag), "KEYGEN_ATI_col_%d_comp_%d", j, comp);
                dump_crt_component(ati0, LOG_R, comp, tag);
            }

            free(x);
            free(y_ti);
            free(ati);
        }
    }

    
    free(h_inv);
    free(target);
    free(sum_term);

    if (getenv("ARITH_DEBUG")) {
        poly_matrix y = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
        if (y) {
            multiply_by_A(y, mpk->A, usk->omega_A);
            poly a0 = poly_matrix_element(y, 1, 0, 0);
            for (int comp = 0; comp < LOG_R; comp++) {
                char tag[80];
                snprintf(tag, sizeof(tag), "KEYGEN_Aomega_comp_%d", comp);
                dump_crt_component(a0, LOG_R, comp, tag);
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
                snprintf(tagb, sizeof(tagb), "KEYGEN_Bomega_sum_comp_%d", comp);
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
                    snprintf(tagl, sizeof(tagl), "KEYGEN_lhs_AplusB_comp_%d", comp);
                    dump_crt_component(lhs, LOG_R, comp, tagl);
                }

                for (int comp = 0; comp < LOG_R; comp++) {
                    char tagbeta[80];
                    snprintf(tagbeta, sizeof(tagbeta), "KEYGEN_mpk_beta_comp_%d", comp);
                    dump_crt_component(mpk->beta, LOG_R, comp, tagbeta);
                }

                if (getenv("ARITH_DEBUG")) {
                    for (int idx = 0; idx < PARAM_N; ++idx) {
                        if (lhs[idx] != mpk->beta[idx]) {
                            fprintf(stderr, "[KEYGEN ASSERT] trapdoor mismatch at coeff %d: lhs=%u mpk=%u (first mismatch)\n", idx, lhs[idx], mpk->beta[idx]);
                            fflush(stderr);
                            exit(2);
                        }
                    }
                    fprintf(stderr, "[KEYGEN ASSERT] trapdoor identity holds (coeff-wise)\n");
                    fflush(stderr);
                }

                free(lhs);
            }
        }

        if (prod) free(prod);
        if (reduced) free(reduced);
        if (b_sum) free(b_sum);
        if (y) free(y);
    }
    
    return 0;
}

// ============================================================================
// Key Serialization
// ============================================================================

int lcp_save_usk(const UserSecretKey *usk, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    fwrite(&usk->n_components, sizeof(uint32_t), 1, fp);
    fwrite(&usk->attr_set.count, sizeof(uint32_t), 1, fp);
    
    for (uint32_t i = 0; i < usk->attr_set.count; i++) {
        fwrite(&usk->attr_set.attrs[i], sizeof(Attribute), 1, fp);
    }
    
    size_t omega_A_size = PARAM_M * PARAM_N;
    fwrite(usk->omega_A, sizeof(scalar), omega_A_size, fp);
    
    for (uint32_t i = 0; i < usk->n_components; i++) {
        fwrite(usk->omega_i[i], sizeof(scalar), omega_A_size, fp);
    }
    
    fclose(fp);
    return 0;
}

int lcp_load_usk(UserSecretKey *usk, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for reading\n", filename);
        return -1;
    }
    
    uint32_t n_components, attr_count;
    fread(&n_components, sizeof(uint32_t), 1, fp);
    fread(&attr_count, sizeof(uint32_t), 1, fp);
    
    usk_init(usk, n_components);
    usk->attr_set.count = attr_count;
    
    for (uint32_t i = 0; i < attr_count; i++) {
        fread(&usk->attr_set.attrs[i], sizeof(Attribute), 1, fp);
    }
    
    size_t omega_A_size = PARAM_M * PARAM_N;
    fread(usk->omega_A, sizeof(scalar), omega_A_size, fp);
    
    for (uint32_t i = 0; i < n_components; i++) {
        fread(usk->omega_i[i], sizeof(scalar), omega_A_size, fp);
    }
    
    fclose(fp);
    return 0;
}
