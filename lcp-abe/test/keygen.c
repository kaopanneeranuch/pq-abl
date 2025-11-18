#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/policy/lcp_policy.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "module_gaussian_lattice/Module_BFRS/sampling.h"

int main(void) {
    // Initialize Module_BFRS components (required for CRT operations)
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();  // REQUIRED: Initialize l_coeffs, d_coeffs, h_coeffs for sampling
    
    MasterPublicKey mpk;
    MasterSecretKey msk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0 ||
        lcp_load_msk(&msk, "keys/MSK.bin") != 0) {
        fprintf(stderr,"Failed to load MPK/MSK\n"); return 1;
    }

    // Generate all possible SK combinations from gen_log.py
    // ROLES = ["devops", "admin", "analyst", "auditor", "user"]
    // TEAMS = ["infra-team", "storage-team", "app-team", "sec-team"]
    typedef struct {
        const char *filename;
        const char *attr_names[2];
        size_t attr_count;
    } KeygenRequest;

    const KeygenRequest requests[] = {
        // devops + all teams
        { "keys/SK_devops_infra_team.bin", { "user_role:devops", "team:infra-team" }, 2 },
        { "keys/SK_devops_storage_team.bin", { "user_role:devops", "team:storage-team" }, 2 },
        { "keys/SK_devops_app_team.bin", { "user_role:devops", "team:app-team" }, 2 },
        { "keys/SK_devops_sec_team.bin", { "user_role:devops", "team:sec-team" }, 2 },
        // admin + all teams
        { "keys/SK_admin_infra_team.bin", { "user_role:admin", "team:infra-team" }, 2 },
        { "keys/SK_admin_storage_team.bin", { "user_role:admin", "team:storage-team" }, 2 },
        { "keys/SK_admin_app_team.bin", { "user_role:admin", "team:app-team" }, 2 },
        { "keys/SK_admin_sec_team.bin", { "user_role:admin", "team:sec-team" }, 2 },
        // analyst + all teams
        { "keys/SK_analyst_infra_team.bin", { "user_role:analyst", "team:infra-team" }, 2 },
        { "keys/SK_analyst_storage_team.bin", { "user_role:analyst", "team:storage-team" }, 2 },
        { "keys/SK_analyst_app_team.bin", { "user_role:analyst", "team:app-team" }, 2 },
        { "keys/SK_analyst_sec_team.bin", { "user_role:analyst", "team:sec-team" }, 2 },
        // auditor + all teams
        { "keys/SK_auditor_infra_team.bin", { "user_role:auditor", "team:infra-team" }, 2 },
        { "keys/SK_auditor_storage_team.bin", { "user_role:auditor", "team:storage-team" }, 2 },
        { "keys/SK_auditor_app_team.bin", { "user_role:auditor", "team:app-team" }, 2 },
        { "keys/SK_auditor_sec_team.bin", { "user_role:auditor", "team:sec-team" }, 2 },
        // user + all teams
        { "keys/SK_user_infra_team.bin", { "user_role:user", "team:infra-team" }, 2 },
        { "keys/SK_user_storage_team.bin", { "user_role:user", "team:storage-team" }, 2 },
        { "keys/SK_user_app_team.bin", { "user_role:user", "team:app-team" }, 2 },
        { "keys/SK_user_sec_team.bin", { "user_role:user", "team:sec-team" }, 2 }
    };

    uint32_t success_count = 0;
    uint32_t total_requests = sizeof(requests) / sizeof(requests[0]);
    
    for (size_t r = 0; r < total_requests; r++) {
        const KeygenRequest *req = &requests[r];
        
        AttributeSet attrs;
        attribute_set_init(&attrs);

        for (size_t i = 0; i < req->attr_count; i++) {
            const char *name = req->attr_names[i];
            if (!name) {
                continue;
            }

            Attribute attr;
            uint32_t index = attr_name_to_index(name);
            attribute_init(&attr, name, index);
            attribute_set_add(&attrs, &attr);
        }

        UserSecretKey sk;
        usk_init(&sk, (uint32_t)attrs.count);

        if (lcp_keygen(&mpk, &msk, &attrs, &sk) != 0) {
            fprintf(stderr, "KeyGen failed for %s\n", req->filename);
            usk_free(&sk);
            continue;
        }

        if (lcp_save_usk(&sk, req->filename) != 0) {
            fprintf(stderr, "Failed to write %s\n", req->filename);
            usk_free(&sk);
            continue;
        }

        usk_free(&sk);
        success_count++;
    }
    
    // Note: Skipping mpk_free/msk_free to avoid crash on exit
    // The OS will clean up memory when the process exits
    
    if (success_count == 0) {
        fprintf(stderr, "Failed to generate any SKs\n");
        return 1;
    }
    
    return 0;
}