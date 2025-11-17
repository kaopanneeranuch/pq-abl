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
#include "module_gaussian_lattice/Module_BFRS/sampling.h"
#ifdef _WIN32
#include <direct.h>
#endif

int main(int argc, char *argv[]) {
    // Initialize Module_BFRS components (required for polynomial operations)
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();  // REQUIRED: Initialize l_coeffs, d_coeffs, h_coeffs for sampling
    
    // Parse command-line arguments
    // Usage: test_decrypt [CT_obj_file] [SK_file]
    //   - No args: decrypt all files in out/encrypted/ with default SK
    //   - 1 arg: CT_obj file path (uses default SK)
    //   - 2 args: CT_obj file path, SK file path
    const char *sk_file = "keys/SK_admin_storage_team.bin";  // Default
    const char *ctobj_file = NULL;
    
    if (argc > 1) {
        // First argument is CT_obj file
        ctobj_file = argv[1];
    }
    if (argc > 2) {
        // Second argument is SK file
        sk_file = argv[2];
    }
    
    if (argc > 3) {
        fprintf(stderr, "Usage: %s [CT_obj_file] [SK_file]\n", argv[0]);
        fprintf(stderr, "  - No args: decrypt all files with default SK (keys/SK_admin_storage.bin)\n");
        fprintf(stderr, "  - 1 arg (CT_obj_file): decrypt specific file with default SK\n");
        fprintf(stderr, "  - 2 args (CT_obj_file SK_file): decrypt specific file with specified SK\n");
        fprintf(stderr, "\nExample: %s out/encrypted/ctobj_xxx.bin keys/SK_admin_storage.bin\n", argv[0]);
        return 1;
    }
    
    // Load MPK and user secret key
    MasterPublicKey mpk;
    UserSecretKey sk;
    
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0) {
        fprintf(stderr, "Error: Failed to load MPK\n");
        return 1;
    }
    
    if (lcp_load_usk(&sk, sk_file) != 0) {
        fprintf(stderr, "Error: Failed to load user secret key from %s\n", sk_file);
        fprintf(stderr, "Hint: Make sure the SK file exists and was generated with test_keygen\n");
        return 1;
    }
    
    // Create output directory (cross-platform)
#ifdef _WIN32
    _mkdir("out/decrypted");
#else
    mkdir("out/decrypted", 0755);
#endif
    
    char *ctobj_files[1000];
    uint32_t n_files = 0;
    
    // Check if specific file argument provided
    if (ctobj_file != NULL) {
        // Single file mode
        ctobj_files[0] = (char*)ctobj_file;
        n_files = 1;
    } else {
        // Batch mode - find all CT_obj files in encrypted directory
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
    }
    
    // Perform batch decryption with policy reuse optimization
    decrypt_ctobj_batch((const char**)ctobj_files, n_files, &sk, &mpk, "out/decrypted");
    
    // Cleanup (only free if we allocated in batch mode)
    if (ctobj_file == NULL && argc <= 1) {
        for (uint32_t i = 0; i < n_files; i++) {
            free(ctobj_files[i]);
        }
    }
    
    // Free SK resources
    usk_free(&sk);
    mpk_free(&mpk);
        
    return 0;
}