#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../common/lcp_params.h"
#include "../common/lcp_types.h"

// View a CT_obj binary file in human-readable format
int view_ctobj(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    printf("\n=== CT_obj File: %s ===\n\n", filename);
    
    // Read metadata
    LogMetadata meta;
    if (fread(&meta, sizeof(LogMetadata), 1, fp) != 1) {
        fprintf(stderr, "Error reading metadata\n");
        fclose(fp);
        return -1;
    }
    
    printf("--- Metadata ---\n");
    printf("Timestamp: %s\n", meta.timestamp);
    printf("User ID: %s\n", meta.user_id);
    printf("User Role: %s\n", meta.user_role);
    printf("Team: %s\n", meta.team);
    printf("Action Type: %s\n", meta.action_type);
    printf("Resource ID: %s\n", meta.resource_id);
    printf("Resource Type: %s\n", meta.resource_type);
    printf("Service Name: %s\n", meta.service_name);
    printf("Region: %s\n", meta.region);
    printf("\n");
    
    // Read CT_sym
    printf("--- CT_sym (AES-GCM Symmetric Ciphertext) ---\n");
    uint32_t ct_len;
    if (fread(&ct_len, sizeof(uint32_t), 1, fp) != 1) {
        fprintf(stderr, "Error reading ct_len\n");
        fclose(fp);
        return -1;
    }
    printf("Ciphertext length: %u bytes\n", ct_len);
    
    unsigned char *ciphertext = malloc(ct_len);
    unsigned char nonce[AES_NONCE_SIZE];
    unsigned char tag[AES_TAG_SIZE];
    
    fread(ciphertext, ct_len, 1, fp);
    fread(nonce, AES_NONCE_SIZE, 1, fp);
    fread(tag, AES_TAG_SIZE, 1, fp);
    
    printf("Ciphertext (first 64 bytes): ");
    for (uint32_t i = 0; i < (ct_len < 64 ? ct_len : 64); i++) {
        printf("%02x", ciphertext[i]);
    }
    if (ct_len > 64) printf("...");
    printf("\n");
    
    printf("Nonce: ");
    for (int i = 0; i < AES_NONCE_SIZE; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\n");
    
    printf("Tag: ");
    for (int i = 0; i < AES_TAG_SIZE; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n\n");
    
    free(ciphertext);
    
    // Read CT_ABE
    printf("--- CT_ABE (LCP-ABE Ciphertext) ---\n");
    
    char policy[MAX_POLICY_SIZE];
    uint32_t n_components;
    
    fread(policy, MAX_POLICY_SIZE, 1, fp);
    fread(&n_components, sizeof(uint32_t), 1, fp);
    
    printf("Policy: %s\n", policy);
    printf("Number of components: %u\n", n_components);
    
    // Read C0
    size_t c0_size = PARAM_M * PARAM_N;
    scalar *C0 = malloc(sizeof(scalar) * c0_size);
    fread(C0, sizeof(scalar), c0_size, fp);
    
    printf("\nC0 (matrix %d x %d in CRT domain):\n", PARAM_M, PARAM_N);
    printf("  First element: %u\n", C0[0]);
    printf("  Last element: %u\n", C0[c0_size - 1]);
    printf("  Sample values: [%u, %u, %u, %u, ...]\n", 
           C0[0], C0[1], C0[2], C0[3]);
    
    // Read C[i] components
    printf("\nC[i] components (%u total):\n", n_components);
    for (uint32_t i = 0; i < n_components; i++) {
        scalar *Ci = malloc(sizeof(scalar) * c0_size);
        fread(Ci, sizeof(scalar), c0_size, fp);
        
        printf("  C[%u]: First=%u, Last=%u\n", 
               i, Ci[0], Ci[c0_size - 1]);
        free(Ci);
    }
    
    // Read ct_key
    scalar *ct_key = malloc(sizeof(scalar) * PARAM_N);
    fread(ct_key, sizeof(scalar), PARAM_N, fp);
    
    printf("\nct_key (encapsulated K_log, length %d):\n", PARAM_N);
    printf("  First 4 elements: [%u, %u, %u, %u]\n",
           ct_key[0], ct_key[1], ct_key[2], ct_key[3]);
    printf("  Last 4 elements: [%u, %u, %u, %u]\n",
           ct_key[PARAM_N-4], ct_key[PARAM_N-3], 
           ct_key[PARAM_N-2], ct_key[PARAM_N-1]);
    
    free(ct_key);
    free(C0);
    
    // Read rho (attribute mapping)
    uint32_t matrix_rows;
    fread(&matrix_rows, sizeof(uint32_t), 1, fp);
    
    if (matrix_rows > 0) {
        uint32_t *rho = malloc(sizeof(uint32_t) * matrix_rows);
        fread(rho, sizeof(uint32_t), matrix_rows, fp);
        
        printf("\nAttribute mapping (rho, %u rows):\n", matrix_rows);
        printf("  rho = [");
        for (uint32_t i = 0; i < matrix_rows && i < 20; i++) {
            printf("%u", rho[i]);
            if (i < matrix_rows - 1) printf(", ");
        }
        if (matrix_rows > 20) printf(", ...");
        printf("]\n");
        
        free(rho);
    } else {
        printf("\nNo attribute mapping (rho is empty)\n");
    }
    
    fclose(fp);
    
    printf("\n=== End of CT_obj ===\n\n");
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <ctobj_file.bin> [<ctobj_file2.bin> ...]\n", argv[0]);
        printf("\n");
        printf("View CT_obj binary files in human-readable format.\n");
        printf("\n");
        printf("Examples:\n");
        printf("  %s encrypted/ctobj_epoch1_log1.bin\n", argv[0]);
        printf("  %s encrypted/ctobj_*.bin\n", argv[0]);
        return 1;
    }
    
    // Process each file specified
    for (int i = 1; i < argc; i++) {
        if (view_ctobj(argv[i]) != 0) {
            fprintf(stderr, "Failed to view %s\n", argv[i]);
        }
    }
    
    return 0;
}
