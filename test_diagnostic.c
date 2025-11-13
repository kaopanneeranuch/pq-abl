#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/encrypt/lcp_encrypt.h"
#include "lcp-abe/decrypt/lcp_decrypt.h"
#include "lcp-abe/policy/lcp_policy.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"

int main() {
    printf("=== DIAGNOSTIC TEST ===\n\n");
    
    // Setup
    MasterPublicKey mpk;
    MasterSecretKey msk;
    mpk_init(&mpk, 128);
    msk_init(&msk);
    
    if (lcp_setup(128, &mpk, &msk) != 0) {
        fprintf(stderr, "Setup failed\n");
        return 1;
    }
    
    // Create attribute set
    AttributeSet attr_set;
    attr_set.count = 1;
    attr_set.attrs[0].index = 56;
    strcpy(attr_set.attrs[0].name, "user_role:admin");
    
    // Keygen
    UserSecretKey usk;
    if (lcp_keygen(&mpk, &msk, &attr_set, &usk) != 0) {
        fprintf(stderr, "Keygen failed\n");
        return 1;
    }
    
    // Create policy
    AccessPolicy policy;
    policy.attr_count = 1;
    policy.attr_indices[0] = 56;
    policy.threshold = 1;
    policy.is_threshold = 1;
    strcpy(policy.expression, "user_role:admin");
    
    // Build LSSS matrix for policy
    policy.matrix_rows = 1;
    policy.matrix_cols = 1;
    policy.share_matrix = (scalar*)calloc(1, sizeof(scalar));
    policy.rho = (uint32_t*)calloc(1, sizeof(uint32_t));
    if (!policy.share_matrix || !policy.rho) {
        fprintf(stderr, "Policy allocation failed\n");
        return 1;
    }
    policy.share_matrix[0] = 1;  // Coefficient 1
    policy.rho[0] = 56;  // Attribute index
    
    // Encrypt
    ABECiphertext ct_abe_template;
    poly_matrix s_shared = NULL;
    
    if (lcp_abe_encrypt_batch_init(&policy, &mpk, &ct_abe_template, &s_shared) != 0) {
        fprintf(stderr, "Encrypt init failed\n");
        return 1;
    }
    
    uint8_t k_log[32];
    for (int i = 0; i < 32; i++) k_log[i] = 0xA5 + i;
    
    ABECiphertext ct_abe;
    if (lcp_abe_encrypt_batch_key(k_log, s_shared, &mpk, &ct_abe_template, &ct_abe) != 0) {
        fprintf(stderr, "Encrypt key failed\n");
        return 1;
    }
    
    // Compute β·s[0] for comparison
    poly s_0 = poly_matrix_element(s_shared, 1, 0, 0);
    double_poly beta_s0_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
    poly beta_s0_reduced = (poly)calloc(PARAM_N, sizeof(scalar));
    mul_crt_poly(beta_s0_prod, mpk.beta, s_0, LOG_R);
    reduce_double_crt_poly(beta_s0_reduced, beta_s0_prod, LOG_R);
    coeffs_representation(beta_s0_reduced, LOG_R);
    
    printf("\n=== KEY DIAGNOSTICS ===\n");
    printf("ENCRYPT: β·s[0] (COEFF, first 4): [0]=%u, [1]=%u, [2]=%u, [3]=%u\n",
           beta_s0_reduced[0], beta_s0_reduced[1], beta_s0_reduced[2], beta_s0_reduced[3]);
    
    // Decrypt
    uint8_t recovered_key[32];
    if (lcp_abe_decrypt(&ct_abe, &usk, &mpk, recovered_key) != 0) {
        fprintf(stderr, "Decrypt failed\n");
        return 1;
    }
    
    printf("\n=== COMPARISON ===\n");
    printf("Original K_log (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02x ", k_log[i]);
    printf("\n");
    
    printf("Recovered K_log (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02x ", recovered_key[i]);
    printf("\n");
    
    int match = memcmp(k_log, recovered_key, 32) == 0;
    printf("Match: %s\n", match ? "YES" : "NO");
    
    free(beta_s0_prod);
    free(beta_s0_reduced);
    free(s_shared);
    
    return match ? 0 : 1;
}

