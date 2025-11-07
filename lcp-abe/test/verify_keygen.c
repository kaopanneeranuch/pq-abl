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
    printf("\n[Test] Computing A * ω_A + Σ(B[i] * ω[i])...\n");
    printf("[Test] This should equal β (with small Gaussian error)\n");
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
    
    // Step 1: Compute A · ω_A
    multiply_by_A(result, mpk.A, sk.omega_A);
    
    printf("[Test] A*ω_A computed (first 4 coeffs in CRT): %u %u %u %u\n",
           result[0], result[1], result[2], result[3]);
    
    // Step 2: Add Σ(B[i] · ω[i]) for all user attributes
    printf("[Test] Computing Σ(B[i] · ω[i]) for %d user attributes\n", sk.attr_set.count);
    
    for (uint32_t i = 0; i < sk.attr_set.count; i++) {
        uint32_t attr_idx = sk.attr_set.attrs[i].index;
        printf("[Test]   Processing attribute %d/%d (index %d: %s)\n",
               i+1, sk.attr_set.count, attr_idx, sk.attr_set.attrs[i].name);
        
        // Get B_plus[attr_idx] - this is a row of M polynomials
        poly_matrix B_plus_i = &mpk.B_plus[attr_idx * PARAM_M * PARAM_N];
        
        // Compute B[i] · ω[i] as inner product (sum over M polynomials)
        poly temp_result = (poly)calloc(PARAM_N, sizeof(scalar));
        
        for (uint32_t j = 0; j < PARAM_M; j++) {
            poly B_ij = &B_plus_i[j * PARAM_N];
            poly omega_ij = poly_matrix_element(sk.omega_i[i], 1, j, 0);
            
            double_poly prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            mul_crt_poly(prod, B_ij, omega_ij, LOG_R);
            
            poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            reduce_double_crt_poly(reduced, prod, LOG_R);
            
            add_poly(temp_result, temp_result, reduced, PARAM_N - 1);
            freeze_poly(temp_result, PARAM_N - 1);  // CRITICAL: Reduce modulo q after each addition
            
            free(prod);
            free(reduced);
        }
        
        printf("[Test]   B[%d]·ω[%d] (first 4 coeffs in CRT): %u %u %u %u\n",
               attr_idx, i, temp_result[0], temp_result[1], temp_result[2], temp_result[3]);
        
        // Add to result[0] (first component of D-dimensional vector)
        poly result_0 = poly_matrix_element(result, PARAM_D, 0, 0);
        add_poly(result_0, result_0, temp_result, PARAM_N - 1);
        freeze_poly(result_0, PARAM_N - 1);  // CRITICAL: Reduce modulo q after addition
        
        free(temp_result);
    }
    
    printf("[Test] Final result = A*ω_A + Σ(B[i]*ω[i]) (first 4 coeffs in CRT): %u %u %u %u\n",
           result[0], result[1], result[2], result[3]);
    
    // Compare result with β
    printf("\n[Compare] β vs A*ω_A + Σ(B[i]*ω[i]):\n");
    printf("[Compare] β (first 8 coeffs in CRT):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) {
        printf("%u ", mpk.beta[i]);
    }
    printf("\n");
    
    printf("[Compare] A*ω_A + Σ(B[i]*ω[i]) (first 8 coeffs in CRT):\n");
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
    
    // CRITICAL: Reduce modulo q after CRT to COEFF conversion
    freeze_poly(beta_coeff, PARAM_N - 1);
    freeze_poly(result_coeff, PARAM_N - 1);
    
    printf("\n[Compare] β (first 8 coeffs in COEFF):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) {
        printf("%u ", beta_coeff[i]);
    }
    printf("\n");
    
    printf("[Compare] A*ω_A + Σ(B[i]*ω[i]) (first 8 coeffs in COEFF):\n");
    printf("  ");
    for (int i = 0; i < 8; i++) {
        printf("%u ", result_coeff[i]);
    }
    printf("\n");
    
    // Compute difference (error)
    printf("\n[Error] Difference [A*ω_A + Σ(B[i]*ω[i])] - β (first 8 coeffs in COEFF):\n");
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
