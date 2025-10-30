#include "lcp_setup.h"
#include "../../module_gaussian_lattice/Module_BFRS/sampling.h"
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Phase 1: Setup - Generate Master Keys
// ============================================================================

int lcp_setup(uint32_t n_attributes, MasterPublicKey *mpk, MasterSecretKey *msk) {
    printf("[Setup] Generating LCP-ABE master keys...\n");
    printf("[Setup] Security parameter: %d-bit\n", PARAM_K);
    printf("[Setup] Module dimension: %d\n", PARAM_D);
    printf("[Setup] Polynomial degree: %d\n", PARAM_N);
    printf("[Setup] Modulus q: %d\n", PARAM_Q);
    printf("[Setup] Number of attributes: %d\n", n_attributes);
    
    // Initialize MPK and MSK
    mpk_init(mpk, n_attributes);
    msk_init(msk);
    
    // Step 1: Generate trapdoor for matrix A using Module_BFRS TrapGen
    printf("[Setup] Generating trapdoor matrix A and T_A...\n");
    TrapGen(mpk->A, msk->T);
    
    // Construct complex representation for Gaussian sampling
    printf("[Setup] Computing complex representation of trapdoor...\n");
    construct_complex_private_key(msk->cplx_T, msk->sch_comp, msk->T);
    
    // Step 2: Generate random public vectors u_i for each attribute
    printf("[Setup] Generating attribute public vectors U...\n");
    for (uint32_t i = 0; i < n_attributes; i++) {
        poly_matrix u_i = poly_matrix_element(mpk->U, n_attributes, 0, i);
        
        // Sample random polynomial vector u_i ∈ R_q^d
        for (uint32_t j = 0; j < PARAM_D; j++) {
            poly u_ij = poly_matrix_element(u_i, 1, j, 0);
            random_poly(u_ij, PARAM_N);
        }
    }
    
    printf("[Setup] Master keys generated successfully!\n");
    printf("[Setup] MPK size: A(%dx%d) + U(%dx%d) polynomials\n",
           PARAM_D, PARAM_D, PARAM_D, n_attributes);
    printf("[Setup] MSK size: T(%dx%d) polynomials\n", PARAM_D, PARAM_D);
    
    return 0;
}

// ============================================================================
// Key Serialization
// ============================================================================

int lcp_save_mpk(const MasterPublicKey *mpk, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    // Write header
    fwrite(&mpk->n_attributes, sizeof(uint32_t), 1, fp);
    fwrite(&mpk->matrix_dim, sizeof(uint32_t), 1, fp);
    
    // Write matrix A
    size_t a_size = PARAM_D * PARAM_D * PARAM_N;
    fwrite(mpk->A, sizeof(scalar), a_size, fp);
    
    // Write matrix U
    size_t u_size = PARAM_D * mpk->n_attributes * PARAM_N;
    fwrite(mpk->U, sizeof(scalar), u_size, fp);
    
    fclose(fp);
    printf("[Setup] MPK saved to %s\n", filename);
    return 0;
}

int lcp_load_mpk(MasterPublicKey *mpk, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for reading\n", filename);
        return -1;
    }
    
    // Read header
    uint32_t n_attributes, matrix_dim;
    fread(&n_attributes, sizeof(uint32_t), 1, fp);
    fread(&matrix_dim, sizeof(uint32_t), 1, fp);
    
    // Initialize MPK
    mpk_init(mpk, n_attributes);
    
    // Read matrix A
    size_t a_size = PARAM_D * PARAM_D * PARAM_N;
    fread(mpk->A, sizeof(scalar), a_size, fp);
    
    // Read matrix U
    size_t u_size = PARAM_D * n_attributes * PARAM_N;
    fread(mpk->U, sizeof(scalar), u_size, fp);
    
    fclose(fp);
    printf("[Setup] MPK loaded from %s\n", filename);
    return 0;
}

int lcp_save_msk(const MasterSecretKey *msk, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    // Write trapdoor T
    size_t t_size = PARAM_D * PARAM_D * PARAM_N;
    fwrite(msk->T, sizeof(scalar), t_size, fp);
    
    // Write complex representations
    size_t cplx_size = PARAM_D * PARAM_D * SMALL_DEGREE;
    fwrite(msk->cplx_T, sizeof(cplx), cplx_size, fp);
    fwrite(msk->sch_comp, sizeof(cplx), cplx_size, fp);
    
    fclose(fp);
    printf("[Setup] MSK saved to %s (keep secret!)\n", filename);
    return 0;
}

int lcp_load_msk(MasterSecretKey *msk, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for reading\n", filename);
        return -1;
    }
    
    // Initialize MSK
    msk_init(msk);
    
    // Read trapdoor T
    size_t t_size = PARAM_D * PARAM_D * PARAM_N;
    fread(msk->T, sizeof(scalar), t_size, fp);
    
    // Read complex representations
    size_t cplx_size = PARAM_D * PARAM_D * SMALL_DEGREE;
    fread(msk->cplx_T, sizeof(cplx), cplx_size, fp);
    fread(msk->sch_comp, sizeof(cplx), cplx_size, fp);
    
    fclose(fp);
    printf("[Setup] MSK loaded from %s\n", filename);
    return 0;
}
