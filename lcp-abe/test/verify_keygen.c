#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"

// Test program to verify that A * ω_A ≈ β
// This checks if the keygen formula is correct

int main() {
    printf("\n=== Keygen Verification Test ===\n");
    printf("[Init] Initializing Module_BFRS...\n");
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_crt_trees();
    init_D_lattice_coeffs();
    
    // Load MPK
    MasterPublicKey mpk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0) {
        fprintf(stderr, "Error: Failed to load MPK\n");
        return 1;
    }
    printf("[Load] MPK loaded\n");
    
    // Load user secret key
    UserSecretKey sk;
    if (lcp_load_usk(&sk, "keys/SK_admin_storage.bin") != 0) {
        fprintf(stderr, "Error: Failed to load user secret key\n");
        return 1;
    }
    printf("[Load] SK loaded (attributes: %d)\n", sk.attr_set.count);
    
    // Compute A * ω_A using multiply_by_A (which handles implicit identity)
    printf("\n[Test] Computing A * ω_A...\n");
    printf("[Test] A is %zu scalars (D×(M-D) = %d×%d)\n", 
           (size_t)(PARAM_D * (PARAM_M - PARAM_D) * PARAM_N),
           PARAM_D, PARAM_M - PARAM_D);
    printf("[Test] ω_A is %zu scalars (M×1 = %d×1)\n",
           (size_t)(PARAM_M * PARAM_N), PARAM_M);
    printf("[Test] Result will be %zu scalars (D×1 = %d×1)\n",
           (size_t)(PARAM_D * PARAM_N), PARAM_D);
    
    poly_matrix result = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    
    // ω_A is in CRT domain (from keygen), A is in CRT domain
    printf("[Test] First 4 coeffs of ω_A (CRT): %u %u %u %u\n",
           sk.omega_A[0], sk.omega_A[1], sk.omega_A[2], sk.omega_A[3]);
    printf("[Test] First 4 coeffs of A (CRT): %u %u %u %u\n",
           mpk.A[0], mpk.A[1], mpk.A[2], mpk.A[3]);
    
    multiply_by_A(result, mpk.A, sk.omega_A);
    
    printf("[Test] Result computed (should be ≈ β)\n");
    printf("[Test] First 4 coeffs of result (CRT): %u %u %u %u\n",
           result[0], result[1], result[2], result[3]);
    
    // Compare result with β
    printf("\n[Compare] β vs A*ω_A:\n");
    printf("[Compare] β (first 8 coeffs in CRT):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) {
        printf("%u ", mpk.beta[i]);
    }
    printf("\n");
    
    printf("[Compare] A*ω_A (first 8 coeffs in CRT):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) {
        printf("%u ", result[i]);
    }
    printf("\n");
    
    // Convert both to COEFF domain to see the actual polynomial coefficients
    poly beta_coeff = (poly)malloc(PARAM_N * sizeof(scalar));
    poly result_coeff = (poly)malloc(PARAM_N * sizeof(scalar));
    
    memcpy(beta_coeff, mpk.beta, PARAM_N * sizeof(scalar));
    memcpy(result_coeff, result, PARAM_N * sizeof(scalar));
    
    coeffs_representation(beta_coeff, LOG_R);
    coeffs_representation(result_coeff, LOG_R);
    
    printf("\n[Compare] β (first 8 coeffs in COEFF):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) {
        printf("%u ", beta_coeff[i]);
    }
    printf("\n");
    
    printf("[Compare] A*ω_A (first 8 coeffs in COEFF):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) {
        printf("%u ", result_coeff[i]);
    }
    printf("\n");
    
    // Compute difference (error)
    printf("\n[Error] Difference A*ω_A - β (first 8 coeffs in COEFF):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) {
        int64_t diff = (int64_t)result_coeff[i] - (int64_t)beta_coeff[i];
        if (diff < 0) diff += PARAM_Q;
        if (diff > PARAM_Q/2) diff -= PARAM_Q;  // Center around 0
        printf("%lld ", diff);
    }
    printf("\n");
    
    // Compute max error
    int64_t max_error = 0;
    for (int i = 0; i < PARAM_N; i++) {
        int64_t diff = (int64_t)result_coeff[i] - (int64_t)beta_coeff[i];
        if (diff < 0) diff += PARAM_Q;
        if (diff > PARAM_Q/2) diff -= PARAM_Q;
        if (llabs(diff) > max_error) max_error = llabs(diff);
    }
    
    printf("\n[Result] Max error: %lld\n", max_error);
    printf("[Result] Expected: Small (< 1000 for Gaussian sampling)\n");
    
    if (max_error < 10000) {
        printf("[Result] ✓ PASS - Keygen is correct!\n");
    } else {
        printf("[Result] ✗ FAIL - Keygen has large error!\n");
    }
    
    free(result);
    free(beta_coeff);
    free(result_coeff);
    
    return 0;
}
