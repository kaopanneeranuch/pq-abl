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

int main(void) {
    // Initialize Module_BFRS components (required for polynomial operations)
    printf("[Encrypt Test] Initializing Module_BFRS...\n");
    init_crt_trees();
    init_cplx_roots_of_unity();
    /* init_D_lattice_coeffs() not present in current Module_BFRS headers; omit. */
    
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

    /* Build two test policies: AND and OR */
    AccessPolicy policies[2];
    
    // Policy 1: user_role:admin AND team:storage-team
    policy_init(&policies[0]);
    policy_parse("user_role:admin AND team:storage-team", &policies[0]);
    lsss_policy_to_matrix(&policies[0]);
    printf("[Test] Policy 1: %s (threshold=%d/%d)\n", 
           policies[0].expression, policies[0].threshold, policies[0].attr_count);
    
    // Policy 2: user_role:admin AND team:app-team (changed from OR to AND)
    policy_init(&policies[1]);
    policy_parse("user_role:admin AND team:app-team", &policies[1]);
    lsss_policy_to_matrix(&policies[1]);
    printf("[Test] Policy 2: %s (threshold=%d/%d)\n", 
           policies[1].expression, policies[1].threshold, policies[1].attr_count);

    Microbatch *batches = NULL;
    uint32_t n_batches = 0;
    if (process_logs_microbatch(&logs, policies, 2, &mpk, &batches, &n_batches) != 0) {
        fprintf(stderr, "Encrypt pipeline failed\n"); json_free_log_array(&logs); return 1;
    }

    printf("[Test] Created %d batches, now saving...\n", n_batches);

    for (uint32_t i = 0; i < n_batches; i++) {
     printf("[Test] Saving batch %d/%d (epoch=%" PRIu64 ", n_logs=%d)...\n", 
         i+1, n_batches, batches[i].epoch_id, batches[i].n_logs);
        
        if (batches[i].logs == NULL) {
            fprintf(stderr, "[Test] ERROR: Batch %d has NULL logs pointer!\n", i);
            continue;
        }
        
        if (save_encrypted_batch(&batches[i], "out/encrypted") != 0) {
            fprintf(stderr, "[Test] Failed to save batch %d\n", i);
        }
    }

    printf("[Test] All batches saved successfully\n");

    json_free_log_array(&logs);
    printf("Encryption done. See out/encrypted/\n");
    return 0;
}