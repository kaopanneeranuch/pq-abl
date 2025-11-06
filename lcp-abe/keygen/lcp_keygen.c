#include "lcp_keygen.h"
#include "../../module_gaussian_lattice/Module_BFRS/sampling.h"
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "../util/lcp_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Phase 2: Key Generation - Generate User Secret Keys for Attributes
// ============================================================================

// Hash attribute name to polynomial using SHA3-256
// NOTE: For compatibility with Module_BFRS construct_A_m, we only generate
// SMALL_DEGREE = PARAM_N/PARAM_R coefficients (the polynomial is "small degree")
void hash_attribute_to_poly(const char *attr_name, poly output) {
    uint8_t hash[SHA3_DIGEST_SIZE];
    sha3_256((const uint8_t *)attr_name, strlen(attr_name), hash);
    
    // Zero out the entire polynomial first
    memset(output, 0, PARAM_N * sizeof(scalar));
    
    // Convert hash to polynomial coefficients (only SMALL_DEGREE coefficients)
    uint32_t small_deg = PARAM_N / PARAM_R;  // SMALL_DEGREE
    for (uint32_t i = 0; i < small_deg && i * 4 < SHA3_DIGEST_SIZE; i++) {
        // Take 4 bytes to form a coefficient (mod q)
        uint32_t coeff = 0;
        for (int j = 0; j < 4 && i * 4 + j < SHA3_DIGEST_SIZE; j++) {
            coeff |= ((uint32_t)hash[i * 4 + j]) << (j * 8);
        }
        output[i] = coeff % PARAM_Q;
    }
    
    // Ensure polynomial is non-zero (add 1 to constant term if needed)
    if (output[0] == 0) {
        output[0] = 1;
    }
}

int lcp_keygen(const MasterPublicKey *mpk, const MasterSecretKey *msk,
               const AttributeSet *attr_set, UserSecretKey *usk) {
    printf("[KeyGen] Generating user secret key for %d attributes...\n", attr_set->count);
    
    // CP-ABE Key Generation Algorithm (Lattice-Based):
    // For each attribute i in the user's attribute set S:
    //   1. Compute f_i = H(attr_i) ∈ R_q (hash attribute to polynomial)
    //   2. Get u_i from MPK (public vector for attribute i)
    //   3. Compute target = u_i + f_i·e_1, where e_1 = [1,0,...,0]^T
    //   4. Use trapdoor T_A to sample sk_i from D_{Λ_q^⊥(A), σ} s.t. A·sk_i = target
    // The user can decrypt if their attributes satisfy the access policy.
    
    // Initialize user secret key
    usk_init(usk, attr_set->count);
    usk->attr_set = *attr_set;
    
    // Allocate temporary storage
    poly f_i = (poly)calloc(PARAM_N, sizeof(scalar));
    poly_matrix target = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    
    // For each attribute in the set
    for (uint32_t idx = 0; idx < attr_set->count; idx++) {
        const Attribute *attr = &attr_set->attrs[idx];
        printf("[KeyGen]   Processing attribute %d/%d: %s\n",
               idx + 1, attr_set->count, attr->name);
        
        printf("[KeyGen]     Step 1: Hashing attribute to polynomial...\n");
        // Step 1: Hash attribute to polynomial f_i = H(attr_i)
        hash_attribute_to_poly(attr->name, f_i);
        
        printf("[KeyGen]     Step 2: Getting u_i from MPK as target...\n");
        // Step 2: Verify attribute index is valid
        if (attr->index >= mpk->n_attributes) {
            fprintf(stderr, "Error: Attribute index %d out of range\n", attr->index);
            free(f_i);
            free(target);
            return -1;
        }
        
        // Copy u_i from MPK to use as target
        memcpy(target, poly_matrix_element(mpk->U, mpk->n_attributes, 0, attr->index),
               PARAM_D * PARAM_N * sizeof(scalar));
        
        printf("[KeyGen]     Step 3: Target is u_i (attribute public vector from MPK)\n");
        
        printf("[KeyGen]     Step 4: Sampling preimage using trapdoor (this may take a few seconds)...\n");
        // Step 4: Use Gaussian sampling to compute sk_i such that A_i · sk_i = target
        // where A_i = A + f_i * g^T (augmented matrix for attribute i)
        
        printf("[KeyGen]       DEBUG: Allocating f_i_inv...\n");
        // Compute f_i's inverse and put it in CRT domain (required by sample_pre_target)
        poly f_i_inv = (poly)calloc(PARAM_N, sizeof(scalar));
        
        printf("[KeyGen]       DEBUG: Computing inverse of f_i...\n");
        printf("[KeyGen]       DEBUG: f_i[0]=%u, f_i[1]=%u, f_i[31]=%u\n", 
               f_i[0], f_i[1], f_i[31]);
        
        // Invert f_i modulo x^PARAM_N + 1 (even though f_i is small degree)
        // This matches the IBE Extract implementation
        invert_poly(f_i_inv, f_i, PARAM_N, 1);
        
        printf("[KeyGen]       DEBUG: f_i_inv[0]=%u, f_i_inv[1]=%u, f_i_inv[31]=%u\n", 
               f_i_inv[0], f_i_inv[1], f_i_inv[31]);
        
        // Check if inversion succeeded (f_i_inv should not be all zeros)
        int is_zero = 1;
        for (uint32_t k = 0; k < PARAM_N; k++) {
            if (f_i_inv[k] != 0) {
                is_zero = 0;
                break;
            }
        }
        if (is_zero) {
            fprintf(stderr, "[KeyGen] ERROR: f_i inversion failed - result is zero!\n");
            free(f_i_inv);
            free(f_i);
            free(target);
            free(u_i);
            return -1;
        }
        
        printf("[KeyGen]       DEBUG: Converting f_i_inv to CRT domain...\n");
        printf("[KeyGen]       DEBUG: Calling crt_representation with LOG_R=%d\n", LOG_R);
        fflush(stdout);  // Force output before potential crash
        crt_representation(f_i_inv, LOG_R);
        printf("[KeyGen]       DEBUG: CRT conversion complete!\n");
        
        printf("[KeyGen]       DEBUG: Constructing augmented matrix A_i...\n");
        // Construct augmented matrix A_i = A + f_i * g^T
        // This modifies mpk->A temporarily to include attribute-specific component
        construct_A_m(mpk->A, f_i);
        
        // NOTE: target should stay in coefficient domain based on IBE implementation
        // The u parameter in sample_pre_target is used in coefficient-domain arithmetic
        
        printf("[KeyGen]       DEBUG: Calling sample_pre_target...\n");
        printf("[KeyGen]       DEBUG: This may take 10-30 seconds for Gaussian sampling...\n");
        fflush(stdout);
        
        // Sample preimage: find sk_i such that A_i · sk_i = target
        sample_pre_target(usk->sk_components[idx], mpk->A, msk->T,
                         msk->cplx_T, msk->sch_comp, f_i_inv, target);
        
        printf("[KeyGen]       DEBUG: sample_pre_target returned successfully!\n");
        
        printf("[KeyGen]       DEBUG: Restoring matrix A...\n");
        // Restore A to original state by removing f_i * g^T
        deconstruct_A_m(mpk->A, f_i);
        
        printf("[KeyGen]     Attribute %d complete!\n", idx + 1);
        free(f_i_inv);
    }
    
    free(f_i);
    free(target);
    
    printf("[KeyGen] User secret key generated successfully!\n");
    printf("[KeyGen] SK size: %d attribute components, each %d polynomials\n",
           attr_set->count, PARAM_D);
    
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
    
    // Write header
    fwrite(&usk->n_components, sizeof(uint32_t), 1, fp);
    fwrite(&usk->attr_set.count, sizeof(uint32_t), 1, fp);
    
    // Write attribute set
    for (uint32_t i = 0; i < usk->attr_set.count; i++) {
        fwrite(&usk->attr_set.attrs[i], sizeof(Attribute), 1, fp);
    }
    
    // Write secret key components (each is PARAM_M x PARAM_N)
    size_t sk_component_size = PARAM_M * PARAM_N;
    for (uint32_t i = 0; i < usk->n_components; i++) {
        fwrite(usk->sk_components[i], sizeof(scalar), sk_component_size, fp);
    }
    
    fclose(fp);
    printf("[KeyGen] User secret key saved to %s\n", filename);
    return 0;
}

int lcp_load_usk(UserSecretKey *usk, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s for reading\n", filename);
        return -1;
    }
    
    // Read header
    uint32_t n_components, attr_count;
    fread(&n_components, sizeof(uint32_t), 1, fp);
    fread(&attr_count, sizeof(uint32_t), 1, fp);
    
    // Initialize USK
    usk_init(usk, n_components);
    usk->attr_set.count = attr_count;
    
    // Read attribute set
    for (uint32_t i = 0; i < attr_count; i++) {
        fread(&usk->attr_set.attrs[i], sizeof(Attribute), 1, fp);
    }
    
    // Read secret key components (each is PARAM_M x PARAM_N)
    size_t sk_component_size = PARAM_M * PARAM_N;
    for (uint32_t i = 0; i < n_components; i++) {
        fread(usk->sk_components[i], sizeof(scalar), sk_component_size, fp);
    }
    
    fclose(fp);
    printf("[KeyGen] User secret key loaded from %s\n", filename);
    return 0;
}
