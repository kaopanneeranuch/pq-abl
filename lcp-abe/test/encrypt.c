#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/encrypt/lcp_encrypt.h"

int main(void) {
    MasterPublicKey mpk;
    if (!lcp_load_mpk(&mpk, "keys/MPK.bin")) {
        fprintf(stderr,"Failed to load MPK\n"); return 1;
    }
    mkdir("out",0755);
    mkdir("out/encrypted",0755);

    /* Parse logs */
    JsonLogArray logs;
    if (json_parse_log_file("logs/log.json", &logs) != 0) {
        fprintf(stderr, "Failed to parse logs/log.json\n"); return 1;
    }

    /* Build a simple policy array (example: user_role:admin) */
    AccessPolicy policy;
    policy_init(&policy);
    policy_parse("user_role:admin", &policy);
    lsss_policy_to_matrix(&policy);

    Microbatch *batches = NULL;
    uint32_t n_batches = 0;
    if (process_logs_microbatch(&logs, &policy, 1, &mpk, &batches, &n_batches) != 0) {
        fprintf(stderr, "Encrypt pipeline failed\n"); json_free_log_array(&logs); return 1;
    }

    for (uint32_t i = 0; i < n_batches; i++) {
        save_encrypted_batch(&batches[i], "out/encrypted");
    }

    json_free_log_array(&logs);
    printf("Encryption done. See out/encrypted/\n");
    return 0;
}