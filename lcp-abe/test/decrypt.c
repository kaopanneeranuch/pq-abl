#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/decrypt/lcp_decrypt.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"

int main(void) {
    // Initialize Module_BFRS components (required for polynomial operations)
    printf("[Decrypt Test] Initializing Module_BFRS...\n");
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();
    
    MasterPublicKey mpk;
    UserSecretKey sk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0 ||
        lcp_load_usk(&sk, "keys/SK_admin_storage.bin") != 0) {
        fprintf(stderr,"Failed to load keys\n"); return 1;
    }
    mkdir("out/decrypted",0755);
    
    // Find first available batch file
    DIR *dir = opendir("out/encrypted");
    if (!dir) {
        fprintf(stderr, "Error: Cannot open out/encrypted/ directory\n");
        return 1;
    }
    
    char ctfile[256] = {0};
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, "batch_epoch") && strstr(entry->d_name, ".bin") && 
            !strstr(entry->d_name, "hashes")) {
            snprintf(ctfile, sizeof(ctfile), "out/encrypted/%s", entry->d_name);
            break;
        }
    }
    closedir(dir);
    
    if (ctfile[0] == '\0') {
        fprintf(stderr, "Error: No batch files found in out/encrypted/\n");
        return 1;
    }
    
    printf("[Decrypt Test] Testing decryption on: %s\n", ctfile);
    if (load_and_decrypt_batch(ctfile, &sk, &mpk) != 0) {
        fprintf(stderr,"Decrypt failed\n"); return 1;
    }
    printf("Decryption done. See out/decrypted/\n");
    return 0;
}