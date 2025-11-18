#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#ifdef _WIN32
#include <direct.h>
#endif
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/encrypt/lcp_encrypt.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "module_gaussian_lattice/Module_BFRS/sampling.h"

int main(void) {
    // Initialize Module_BFRS components (required for polynomial operations)
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();  // REQUIRED: Initialize l_coeffs, d_coeffs, h_coeffs for sampling
    
    MasterPublicKey mpk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0) {
        fprintf(stderr,"Failed to load MPK\n"); return 1;
    }
    /* Create output directories in a cross-platform way */
#ifdef _WIN32
    _mkdir("out");
    _mkdir("out/encrypted");
#else
    mkdir("out",0755);
    mkdir("out/encrypted",0755);
#endif

    /* Parse logs */
    JsonLogArray logs;
    if (json_parse_log_file("logs/log.json", &logs) != 0) {
        fprintf(stderr, "Failed to parse logs/log.json\n"); return 1;
    }

    /* Build AND policy: user_role:admin AND team:storage-team */
    AccessPolicy policies[1];
    
    policy_init(&policies[0]);
    policy_parse("user_role:admin AND team:storage-team", &policies[0]);
    if (lsss_policy_to_matrix(&policies[0]) != 0) {
        fprintf(stderr, "[Test] ERROR: Failed to build LSSS matrix for policy\n");
        return 1;
    }

    Microbatch *batches = NULL;
    uint32_t n_batches = 0;
    if (process_logs_microbatch(&logs, policies, 1, &mpk, &batches, &n_batches) != 0) {
        fprintf(stderr, "Encrypt pipeline failed\n"); 
        policy_free(&policies[0]);
        json_free_log_array(&logs); 
        return 1;
    }

    for (uint32_t i = 0; i < n_batches; i++) {
        if (batches[i].logs == NULL) {
            fprintf(stderr, "[Test] ERROR: Batch %d has NULL logs pointer!\n", i);
            continue;
        }
        
        if (save_encrypted_batch(&batches[i], "out/encrypted") != 0) {
            fprintf(stderr, "[Test] Failed to save batch %d\n", i);
        }
    }

    policy_free(&policies[0]);
    json_free_log_array(&logs);
    mpk_free(&mpk);
    
    return 0;
}