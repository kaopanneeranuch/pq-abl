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
void hash_attribute_to_poly(const char *attr_name, poly output) {
    uint8_t hash[SHA3_DIGEST_SIZE];
    sha3_256((const uint8_t *)attr_name, strlen(attr_name), hash);
    
    // Convert hash to polynomial coefficients
    for (uint32_t i = 0; i < PARAM_N && i * 4 < SHA3_DIGEST_SIZE; i++) {
        // Take 4 bytes to form a coefficient (mod q)
        uint32_t coeff = 0;
        for (int j = 0; j < 4 && i * 4 + j < SHA3_DIGEST_SIZE; j++) {
            coeff |= ((uint32_t)hash[i * 4 + j]) << (j * 8);
        }
        output[i] = coeff % PARAM_Q;
    }
    
    // Fill remaining coefficients with pattern from hash
    for (uint32_t i = SHA3_DIGEST_SIZE / 4; i < PARAM_N; i++) {
        output[i] = hash[i % SHA3_DIGEST_SIZE] % PARAM_Q;
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
    poly_matrix u_i = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    
    // For each attribute in the set
    for (uint32_t idx = 0; idx < attr_set->count; idx++) {
        const Attribute *attr = &attr_set->attrs[idx];
        printf("[KeyGen]   Processing attribute %d/%d: %s\n",
               idx + 1, attr_set->count, attr->name);
        
        printf("[KeyGen]     Step 1: Hashing attribute to polynomial...\n");
        // Step 1: Hash attribute to polynomial f_i = H(attr_i)
        hash_attribute_to_poly(attr->name, f_i);
        
        printf("[KeyGen]     Step 2: Getting u_i from MPK...\n");
        // Step 2: Get u_i from MPK (attribute's public vector)
        if (attr->index >= mpk->n_attributes) {
            fprintf(stderr, "Error: Attribute index %d out of range\n", attr->index);
            free(f_i);
            free(target);
            free(u_i);
            return -1;
        }
        
        // Copy u_i from MPK
        memcpy(u_i, poly_matrix_element(mpk->U, mpk->n_attributes, 0, attr->index),
               PARAM_D * PARAM_N * sizeof(scalar));
        
        printf("[KeyGen]     Step 3: Computing target vector...\n");
        // Step 3: Compute target = u_i + f_i * e_1, where e_1 = [1, 0, ..., 0]^T
        // This is the standard construction for lattice-based ABE:
        // target[0] = u_i[0] + f_i (coefficient-wise polynomial addition)
        // target[j] = u_i[j] for j > 0 (unchanged)
        for (uint32_t j = 0; j < PARAM_D; j++) {
            poly target_j = poly_matrix_element(target, 1, j, 0);
            poly u_i_j = poly_matrix_element(u_i, 1, j, 0);
            
            if (j == 0) {
                // First component: add f_i coefficient-wise
                // target[0] = u_i[0] + f_i in R_q
                for (uint32_t k = 0; k < PARAM_N; k++) {
                    target_j[k] = (u_i_j[k] + f_i[k]) % PARAM_Q;
                }
            } else {
                // Other components: copy as-is
                memcpy(target_j, u_i_j, PARAM_N * sizeof(scalar));
            }
        }
        
        printf("[KeyGen]     Step 4: Sampling preimage using trapdoor (this may take a few seconds)...\n");
        // Step 4: Use Gaussian sampling to compute sk_i such that A · sk_i = target
        // This uses the trapdoor T_A and sample_pre_target function
        poly h_inv = (poly)calloc(PARAM_N, sizeof(scalar));
        h_inv[0] = 1; // Identity polynomial in coefficient domain
        
        // Convert h_inv to CRT domain (required by sample_pre_target)
        crt_representation(h_inv, LOG_R);
        
        sample_pre_target(usk->sk_components[idx], mpk->A, msk->T,
                         msk->cplx_T, msk->sch_comp, h_inv, target);
        
        printf("[KeyGen]     Attribute %d complete!\n", idx + 1);
        free(h_inv);
    }
    
    free(f_i);
    free(target);
    free(u_i);
    
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
    
    // Write secret key components
    size_t sk_component_size = PARAM_D * PARAM_N;
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
    
    // Read secret key components
    size_t sk_component_size = PARAM_D * PARAM_N;
    for (uint32_t i = 0; i < n_components; i++) {
        fread(usk->sk_components[i], sizeof(scalar), sk_component_size, fp);
    }
    
    fclose(fp);
    printf("[KeyGen] User secret key loaded from %s\n", filename);
    return 0;
}
