#include "lcp_setup.h"
#include "../../module_gaussian_lattice/Module_BFRS/sampling.h"
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Phase 1: Setup - Optimized Module-LWE Based CP-ABE (Algorithm 1)
// ============================================================================
//
// To improve efficiency while maintaining 128-bit post-quantum security,
// the Attribute Authority adopts a Module-LWE based setup rather than
// pure Ring-LWE instantiation. This optimization significantly reduces
// the public key and trapdoor size by using smaller module dimensions
// while preserving the same hardness assumption.
//
// The Attribute Authority executes MTRAPGEN(λ) to generate a random
// module matrix A ∈ R^{k×m}_q with its trapdoor TA. Here k < m denotes
// the module rank (typically k = 4), providing a balanced trade-off
// between key size and sampling efficiency.
//
// A random challenge element β ∈ Rq is selected. For each attribute
// xi ∈ X, public vectors (B+_i, B-_i) ∈ R^{1×m}_q are generated and
// cached for reuse across setup epochs.
//
// Output: MPK = {A, {(B+_i, B-_i)}_{i∈[ℓ]}, β}, MSK = TA
// ============================================================================

int lcp_setup(uint32_t n_attributes, MasterPublicKey *mpk, MasterSecretKey *msk) {
    // Initialize Module_BFRS global structures (must be called before any crypto operations)
    static int initialized = 0;
    if (!initialized) {
        printf("[Setup] Initializing Module-LWE cryptographic primitives...\n");
        init_crt_trees();
        init_cplx_roots_of_unity();
        init_D_lattice_coeffs();
        initialized = 1;
    }

    printf("[Setup] ==========================================\n");
    printf("[Setup] Security parameter λ: %d-bit\n", PARAM_K);
    printf("[Setup] Module rank k: %d\n", PARAM_D);
    printf("[Setup] Module dimension m: %d\n", PARAM_M);
    printf("[Setup] Polynomial degree n: %d\n", PARAM_N);
    printf("[Setup] Modulus q: %d\n", PARAM_Q);
    printf("[Setup] Gaussian parameter σ: %.2f\n", PARAM_SIGMA);
    printf("[Setup] Attribute universe size ℓ: %d\n", n_attributes);
    
    // Initialize MPK and MSK data structures
    mpk_init(mpk, n_attributes);
    msk_init(msk);
    
    // ========================================================================
    // Algorithm 1, Line 1: (A, TA) ← MTRAPGEN(λ, k, m)
    // ========================================================================
    // Execute MTRAPGEN(λ) to generate random module matrix A ∈ R^{k×m}_q
    // with its trapdoor TA. The module rank k < m provides balanced trade-off
    // between key size and sampling efficiency.
    
    // Sample trapdoor T from Gaussian distribution D_{R^{2k,km},σ}
    // This gives us short trapdoor basis in coefficient domain
    SampleR_matrix_centered((signed_poly_matrix) msk->T, 2 * PARAM_D, PARAM_D * PARAM_K, PARAM_SIGMA);
    
    // Construct complex representation and Schur complements for efficient
    // Gaussian sampling. CRITICAL: Must be done BEFORE adding q to preserve
    // small coefficient structure needed for stable covariance computation.
    printf("[Setup]   Computing Schur complements for trapdoor sampling...\n");
    construct_complex_private_key(msk->cplx_T, msk->sch_comp, msk->T);
    
    // Make T coefficients positive by adding q, then convert to CRT domain
    for (int i = 0; i < PARAM_N * 2 * PARAM_D * PARAM_D * PARAM_K; i++) {
        msk->T[i] += PARAM_Q;
    }
    matrix_crt_representation(msk->T, 2 * PARAM_D, PARAM_D * PARAM_K, LOG_R);
    
    // Construct public matrix A = [I_k | A_hat | -A'·T] where A' = A_hat·T2 + T1
    // This yields the k×m module matrix with implicit trapdoor structure
    printf("[Setup]   Constructing public matrix A ∈ R^{k×m}_q...\n");
    scalar *A_hat_coeffs = malloc(PARAM_D * PARAM_D * PARAM_N * sizeof(scalar));
    scalar *AprimeT_coeffs = malloc(PARAM_D * PARAM_D * PARAM_K * PARAM_N * sizeof(scalar));
    poly_matrix A_hat = A_hat_coeffs;
    poly_matrix AprimeT = AprimeT_coeffs;
    
    random_poly(A_hat, PARAM_N * PARAM_D * PARAM_D - 1);
    
    // Decompose T = [T1 | T2] and compute A'·T = A_hat·T2 + T1
    poly_matrix T1 = msk->T;
    poly_matrix T2 = poly_matrix_element(msk->T, PARAM_D * PARAM_K, PARAM_D, 0);
    
    mul_crt_poly_matrix(AprimeT, A_hat, T2, PARAM_D, PARAM_D, PARAM_D * PARAM_K, LOG_R);
    add_to_poly_matrix(AprimeT, T1, PARAM_D, PARAM_D * PARAM_K);
    
    // Assemble A = [I_k | A_hat | -A'·T]
    // Copy A_hat into middle section
    for (int i = 0; i < PARAM_D; i++) {
        poly_matrix A_i0 = poly_matrix_element(mpk->A, PARAM_M - PARAM_D, i, 0);
        poly_matrix A_hat_i = poly_matrix_element(A_hat, PARAM_D, i, 0);
        memcpy(A_i0, A_hat_i, PARAM_D * PARAM_N * sizeof(scalar));
    }
    
    // Copy -A'·T into final section
    for (int i = 0; i < PARAM_D; i++) {
        poly_matrix A_i1 = poly_matrix_element(mpk->A, PARAM_M - PARAM_D, i, PARAM_D);
        poly_matrix AprimeT_i = poly_matrix_element(AprimeT, PARAM_D * PARAM_K, i, 0);
        for (int j = 0; j < PARAM_D * PARAM_K * PARAM_N; j++) {
            A_i1[j] = 2 * PARAM_Q - AprimeT_i[j];
        }
    }
    
    // Reduce A modulo q
    freeze_poly(mpk->A, PARAM_N * PARAM_D * (PARAM_M - PARAM_D) - 1);
    
    free(A_hat_coeffs);
    free(AprimeT_coeffs);
    
    
    
    printf("[Setup]\n");
    printf("[Setup] Algorithm 1, Line 2: β ← Uniform(Rq)\n");
    printf("[Setup] Selecting random challenge element...\n");
    random_poly(mpk->beta, PARAM_N - 1);
    printf("[Setup]   Challenge β generated\n");
    printf("[Setup] Generating %d cacheable attribute sub-matrices...\n", n_attributes);
    
    for (uint32_t i = 0; i < n_attributes; i++) {
        // B+_i: row vector of m polynomials in Rq
        poly_matrix B_plus_i = poly_matrix_element(mpk->B_plus, n_attributes, i, 0);
        random_poly(B_plus_i, PARAM_M * PARAM_N - 1);
        
        // B-_i: row vector of m polynomials in Rq
        poly_matrix B_minus_i = poly_matrix_element(mpk->B_minus, n_attributes, i, 0);
        random_poly(B_minus_i, PARAM_M * PARAM_N - 1);
    }
    
    printf("[Setup]   Generated %d attribute vector pairs (B+_i, B-_i)\n", n_attributes);
    
    // ========================================================================
    // Algorithm 1, Lines 6-7: Output MPK and MSK
    // ========================================================================
    
    printf("[Setup] Master Public Key (MPK):\n");
    printf("[Setup]   - Matrix A: k×m = %d×%d (module matrix)\n", PARAM_D, PARAM_M);
    printf("[Setup]   - Attribute vectors: %d pairs (B+_i, B-_i)\n", n_attributes);
    printf("[Setup]   - Challenge: β ∈ Rq\n");
    printf("[Setup] Master Secret Key (MSK):\n");
    printf("[Setup]   - Trapdoor TA: 2k×km = %d×%d\n", 2*PARAM_D, PARAM_D*PARAM_K);
    printf("[Setup]   - Schur complements for Gaussian sampling\n");
    
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
    
    // Write header: n_attributes, k, m
    fwrite(&mpk->n_attributes, sizeof(uint32_t), 1, fp);
    fwrite(&mpk->k, sizeof(uint32_t), 1, fp);
    fwrite(&mpk->m, sizeof(uint32_t), 1, fp);
    
    // Write matrix A: (m-k) × k × n scalars
    size_t a_size = (PARAM_M - PARAM_D) * PARAM_D * PARAM_N;
    fwrite(mpk->A, sizeof(scalar), a_size, fp);
    
    // Write B_plus: ℓ × m × n scalars
    size_t b_size = mpk->n_attributes * PARAM_M * PARAM_N;
    fwrite(mpk->B_plus, sizeof(scalar), b_size, fp);
    
    // Write B_minus: ℓ × m × n scalars
    fwrite(mpk->B_minus, sizeof(scalar), b_size, fp);
    
    // Write β: n scalars
    fwrite(mpk->beta, sizeof(scalar), PARAM_N, fp);
    
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
    uint32_t n_attributes, k, m;
    fread(&n_attributes, sizeof(uint32_t), 1, fp);
    fread(&k, sizeof(uint32_t), 1, fp);
    fread(&m, sizeof(uint32_t), 1, fp);
    
    // Initialize MPK
    mpk_init(mpk, n_attributes);
    
    // Read matrix A
    size_t a_size = (PARAM_M - PARAM_D) * PARAM_D * PARAM_N;
    fread(mpk->A, sizeof(scalar), a_size, fp);
    
    // Read B_plus
    size_t b_size = n_attributes * PARAM_M * PARAM_N;
    fread(mpk->B_plus, sizeof(scalar), b_size, fp);
    
    // Read B_minus
    fread(mpk->B_minus, sizeof(scalar), b_size, fp);
    
    // Read β
    fread(mpk->beta, sizeof(scalar), PARAM_N, fp);
    
    fclose(fp);
    printf("[Setup] MPK loaded from %s\n", filename);
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
    
    // Write trapdoor T (size: 2*PARAM_D × PARAM_D*PARAM_K × PARAM_N)
    size_t t_size = 2 * PARAM_D * PARAM_D * PARAM_K * PARAM_N;
    fwrite(msk->T, sizeof(scalar), t_size, fp);
    
    // Write complex representations
    size_t cplx_t_size = 2 * PARAM_D * PARAM_D * PARAM_K * PARAM_N;
    size_t sch_comp_size = PARAM_N * PARAM_D * (2 * PARAM_D + 1);
    fwrite(msk->cplx_T, sizeof(cplx), cplx_t_size, fp);
    fwrite(msk->sch_comp, sizeof(cplx), sch_comp_size, fp);
    
    fclose(fp);
    printf("[Setup] MSK saved to %s (keep secret!)\n", filename);
    return 0;
}

int lcp_load_msk(MasterSecretKey *msk, const char *filename) {
    printf("[DEBUG] lcp_load_msk called with filename: %s\n", filename);
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for reading\n", filename);
        return -1;
    }
    printf("[DEBUG] File opened successfully\n");
    
    // Initialize MSK
    msk_init(msk);
    printf("[DEBUG] msk_init completed\n");
    
    // Read trapdoor T (size: 2*PARAM_D × PARAM_D*PARAM_K × PARAM_N)
    size_t t_size = 2 * PARAM_D * PARAM_D * PARAM_K * PARAM_N;
    size_t read_t = fread(msk->T, sizeof(scalar), t_size, fp);
    if (read_t != t_size) {
        fprintf(stderr, "Error: Failed to read T from %s (expected %zu, got %zu)\n", 
                filename, t_size, read_t);
        fclose(fp);
        return -1;
    }
    
    // Read complex representations
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
    printf("[Setup] MSK loaded from %s\n", filename);
    return 0;
}
