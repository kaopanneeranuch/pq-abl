#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <dirent.h>
#include <string.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/decrypt/lcp_decrypt.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"
#ifdef _WIN32
#include <direct.h>
#endif

int main(int argc, char *argv[]) {
    // Initialize Module_BFRS components (required for polynomial operations)
    printf("\n=== LCP-ABE Batch Decryption Test ===\n");
    printf("[Init] Initializing Module_BFRS...\n");
    init_crt_trees();
    init_cplx_roots_of_unity();
    /* init_D_lattice_coeffs() removed/absent in Module_BFRS - skip it */
    
    // Load MPK and user secret key
    printf("[Init] Loading keys...\n");
    MasterPublicKey mpk;
    UserSecretKey sk;
    
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0) {
        fprintf(stderr, "Error: Failed to load MPK\n");
        return 1;
    }
    printf("[Init] Loaded MPK\n");
    
    if (lcp_load_usk(&sk, "keys/SK_admin_storage.bin") != 0) {
        fprintf(stderr, "Error: Failed to load user secret key\n");
        return 1;
    }
    printf("[Init] Loaded SK (attributes: %d)\n", sk.attr_set.count);
    
    // Create output directory (cross-platform)
#ifdef _WIN32
    _mkdir("out/decrypted");
#else
    mkdir("out/decrypted", 0755);
#endif
    
    char *ctobj_files[1000];
    uint32_t n_files = 0;
    
    // Check if specific file argument provided
    if (argc > 1) {
        // Single file mode
        printf("\n[Mode] Single file decryption: %s\n", argv[1]);
        ctobj_files[0] = argv[1];
        n_files = 1;
    } else {
        // Batch mode - find all CT_obj files in encrypted directory
        printf("\n[Scan] Scanning for CT_obj files...\n");
        DIR *dir = opendir("out/encrypted");
        if (!dir) {
            fprintf(stderr, "Error: Cannot open out/encrypted/ directory\n");
            return 1;
        }
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            // Look for ctobj_*.bin files (not hash files)
            if (strstr(entry->d_name, "ctobj_") && 
                strstr(entry->d_name, ".bin") && 
                !strstr(entry->d_name, "hash")) {
                
                char *filepath = (char*)malloc(512);
                snprintf(filepath, 512, "out/encrypted/%s", entry->d_name);
                ctobj_files[n_files++] = filepath;
                
                if (n_files >= 1000) break;
            }
        }
        closedir(dir);
        
        if (n_files == 0) {
            fprintf(stderr, "Error: No CT_obj files found in out/encrypted/\n");
            fprintf(stderr, "Hint: Run test_encrypt first to generate encrypted files\n");
            return 1;
        }
        
        printf("[Scan] Found %d CT_obj files\n", n_files);
    }
    
    // Perform batch decryption with policy reuse optimization
    printf("\n[Decrypt] Starting batch decryption...\n");
    decrypt_ctobj_batch((const char**)ctobj_files, n_files, &sk, &mpk, "out/decrypted");
    
    // Cleanup (only free if we allocated in batch mode)
    if (argc <= 1) {
        for (uint32_t i = 0; i < n_files; i++) {
            free(ctobj_files[i]);
        }
    }
        
    return 0;
}