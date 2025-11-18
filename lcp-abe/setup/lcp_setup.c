#include "lcp_setup.h"
#include "../../module_gaussian_lattice/Module_BFRS/sampling.h"
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int lcp_setup(uint32_t n_attributes, MasterPublicKey *mpk, MasterSecretKey *msk) {
    static int initialized = 0;
    if (!initialized) {
        init_crt_trees();
        init_cplx_roots_of_unity();
        init_D_lattice_coeffs();
        initialized = 1;
    }
    
    mpk_init(mpk, n_attributes);
    msk_init(msk);
    
    SampleR_matrix_centered((signed_poly_matrix) msk->T, 2 * PARAM_D, PARAM_D * PARAM_K, PARAM_SIGMA);
    
    construct_complex_private_key(msk->cplx_T, msk->sch_comp, msk->T);

    for (int i = 0; i < PARAM_N * 2 * PARAM_D * PARAM_D * PARAM_K; i++) {
        msk->T[i] += PARAM_Q;
    }
    matrix_crt_representation(msk->T, 2 * PARAM_D, PARAM_D * PARAM_K, LOG_R);
    
    scalar *A_hat_coeffs = malloc(PARAM_D * PARAM_D * PARAM_N * sizeof(scalar));
    scalar *AprimeT_coeffs = malloc(PARAM_D * PARAM_D * PARAM_K * PARAM_N * sizeof(scalar));
    poly_matrix A_hat = A_hat_coeffs;
    poly_matrix AprimeT = AprimeT_coeffs;
    
    random_poly(A_hat, PARAM_N * PARAM_D * PARAM_D - 1);
    
    matrix_crt_representation(A_hat, PARAM_D, PARAM_D, LOG_R);
    
    poly_matrix T1 = msk->T;
    poly_matrix T2 = poly_matrix_element(msk->T, PARAM_D * PARAM_K, PARAM_D, 0);
    
    mul_crt_poly_matrix(AprimeT, A_hat, T2, PARAM_D, PARAM_D, PARAM_D * PARAM_K, LOG_R);
    add_to_poly_matrix(AprimeT, T1, PARAM_D, PARAM_D * PARAM_K);
    
    for (int i = 0; i < PARAM_D; i++) {
        poly_matrix A_i0 = poly_matrix_element(mpk->A, PARAM_M - PARAM_D, i, 0);
        poly_matrix A_hat_i = poly_matrix_element(A_hat, PARAM_D, i, 0);
        memcpy(A_i0, A_hat_i, PARAM_D * PARAM_N * sizeof(scalar));
    }
    
    for (int i = 0; i < PARAM_D; i++) {
        poly_matrix A_i1 = poly_matrix_element(mpk->A, PARAM_M - PARAM_D, i, PARAM_D);
        poly_matrix AprimeT_i = poly_matrix_element(AprimeT, PARAM_D * PARAM_K, i, 0);
        for (int j = 0; j < PARAM_D * PARAM_K * PARAM_N; j++) {
            A_i1[j] = 2 * PARAM_Q - AprimeT_i[j];
        }
    }
    
    freeze_poly(mpk->A, PARAM_N * PARAM_D * (PARAM_M - PARAM_D) - 1);
    
    free(A_hat_coeffs);
    free(AprimeT_coeffs);
    
    
    
    random_poly(mpk->beta, PARAM_N - 1);
    
    for (uint32_t i = 0; i < n_attributes; i++) {
        poly_matrix B_plus_i = &mpk->B_plus[i * PARAM_M * PARAM_N];
        random_poly(B_plus_i, PARAM_M * PARAM_N - 1);
        
        poly_matrix B_minus_i = &mpk->B_minus[i * PARAM_M * PARAM_N];
        random_poly(B_minus_i, PARAM_M * PARAM_N - 1);
    }
    
    for (uint32_t i = 0; i < n_attributes; i++) {
        poly_matrix B_plus_i = &mpk->B_plus[i * PARAM_M * PARAM_N];
        poly_matrix B_minus_i = &mpk->B_minus[i * PARAM_M * PARAM_N];
        
        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly B_plus_ij = &B_plus_i[j * PARAM_N];
            poly B_minus_ij = &B_minus_i[j * PARAM_N];
            
            crt_representation(B_plus_ij, LOG_R);
            crt_representation(B_minus_ij, LOG_R);
        }
    }
    
    crt_representation(mpk->beta, LOG_R);
    if (getenv("ARITH_DEBUG")) {
        for (int comp = 0; comp < LOG_R; comp++) {
            char tag[80];
            snprintf(tag, sizeof(tag), "SETUP_mpk_beta_comp_%d", comp);
            dump_crt_component(mpk->beta, LOG_R, comp, tag);
        }
    }
    
    return 0;
}

// ============================================================================
// Key Serialization - MPK with (B+, B-, β) structure
// ============================================================================

int lcp_save_mpk(const MasterPublicKey *mpk, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    fwrite(&mpk->n_attributes, sizeof(uint32_t), 1, fp);
    fwrite(&mpk->k, sizeof(uint32_t), 1, fp);
    fwrite(&mpk->m, sizeof(uint32_t), 1, fp);
    
    size_t a_size = (PARAM_M - PARAM_D) * PARAM_D * PARAM_N;
    fwrite(mpk->A, sizeof(scalar), a_size, fp);
    
    size_t b_size = mpk->n_attributes * PARAM_M * PARAM_N;
    fwrite(mpk->B_plus, sizeof(scalar), b_size, fp);
    
    fwrite(mpk->B_minus, sizeof(scalar), b_size, fp);
    
    fwrite(mpk->beta, sizeof(scalar), PARAM_N, fp);
    
    fclose(fp);
    return 0;
}

int lcp_load_mpk(MasterPublicKey *mpk, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for reading\n", filename);
        return -1;
    }
    
    uint32_t n_attributes, k, m;
    fread(&n_attributes, sizeof(uint32_t), 1, fp);
    fread(&k, sizeof(uint32_t), 1, fp);
    fread(&m, sizeof(uint32_t), 1, fp);
    
    mpk_init(mpk, n_attributes);
    
    size_t a_size = (PARAM_M - PARAM_D) * PARAM_D * PARAM_N;
    fread(mpk->A, sizeof(scalar), a_size, fp);
    
    size_t b_size = n_attributes * PARAM_M * PARAM_N;
    fread(mpk->B_plus, sizeof(scalar), b_size, fp);
    
    fread(mpk->B_minus, sizeof(scalar), b_size, fp);
    
    fread(mpk->beta, sizeof(scalar), PARAM_N, fp);
    
    fclose(fp);
    return 0;
}

// ============================================================================
// MSK Serialization
// ============================================================================

int lcp_save_msk(const MasterSecretKey *msk, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    size_t t_size = 2 * PARAM_D * PARAM_D * PARAM_K * PARAM_N;
    fwrite(msk->T, sizeof(scalar), t_size, fp);
    
    size_t cplx_t_size = 2 * PARAM_D * PARAM_D * PARAM_K * PARAM_N;
    size_t sch_comp_size = PARAM_N * PARAM_D * (2 * PARAM_D + 1);
    fwrite(msk->cplx_T, sizeof(cplx), cplx_t_size, fp);
    fwrite(msk->sch_comp, sizeof(cplx), sch_comp_size, fp);
    
    fclose(fp);
    return 0;
}

int lcp_load_msk(MasterSecretKey *msk, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for reading\n", filename);
        return -1;
    }
    
    msk_init(msk);
    
    size_t t_size = 2 * PARAM_D * PARAM_D * PARAM_K * PARAM_N;
    size_t read_t = fread(msk->T, sizeof(scalar), t_size, fp);
    if (read_t != t_size) {
        fprintf(stderr, "Error: Failed to read T from %s (expected %zu, got %zu)\n", 
                filename, t_size, read_t);
        fclose(fp);
        return -1;
    }
    
    size_t cplx_t_size = 2 * PARAM_D * PARAM_D * PARAM_K * PARAM_N;
    size_t read_cplx_t = fread(msk->cplx_T, sizeof(cplx), cplx_t_size, fp);
    if (read_cplx_t != cplx_t_size) {
        fprintf(stderr, "Error: Failed to read cplx_T from %s (expected %zu, got %zu)\n",
                filename, cplx_t_size, read_cplx_t);
        fclose(fp);
        return -1;
    }
    
    size_t sch_comp_size = PARAM_N * PARAM_D * (2 * PARAM_D + 1);
    size_t read_sch = fread(msk->sch_comp, sizeof(cplx), sch_comp_size, fp);
    if (read_sch != sch_comp_size) {
        fprintf(stderr, "Error: Failed to read sch_comp from %s (expected %zu, got %zu)\n",
                filename, sch_comp_size, read_sch);
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    return 0;
}
