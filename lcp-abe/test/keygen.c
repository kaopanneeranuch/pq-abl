#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/policy/lcp_policy.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"

int main(void) {
    // Initialize Module_BFRS components (required for CRT operations)
    printf("[KeyGen Test] Initializing Module_BFRS...\n");
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();
    
    MasterPublicKey mpk;
    MasterSecretKey msk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0 ||
        lcp_load_msk(&msk, "keys/MSK.bin") != 0) {
        fprintf(stderr,"Failed to load MPK/MSK\n"); return 1;
    }

    /* Build attribute sets for the test coverage */
    typedef struct {
        const char *description;
        const char *filename;
        const char *attr_names[2];
        size_t attr_count;
    } KeygenRequest;

    const KeygenRequest requests[] = {
        {
            .filename = "keys/SK_admin_storage.bin",
            .attr_names = { "user_role:admin", "team:storage-team" },
            .attr_count = 2
        },
        {
            .filename = "keys/SK_admin_only.bin",
            .attr_names = { "user_role:admin", NULL },
            .attr_count = 1
        },
        {
            .filename = "keys/SK_app_team.bin",
            .attr_names = { "team:app-team", NULL },
            .attr_count = 1
        }
    };

    for (size_t r = 0; r < sizeof(requests) / sizeof(requests[0]); r++) {
        const KeygenRequest *req = &requests[r];
        AttributeSet attrs;
        attribute_set_init(&attrs);

        printf("[KeyGen] Generating key for %s\n", req->description);

        for (size_t i = 0; i < req->attr_count; i++) {
            const char *name = req->attr_names[i];
            if (!name) {
                continue;
            }

            Attribute attr;
            uint32_t index = attr_name_to_index(name);
            attribute_init(&attr, name, index);
            attribute_set_add(&attrs, &attr);
            printf("  - %s (index %u)\n", attr.name, attr.index);
        }

        UserSecretKey sk;
        usk_init(&sk, (uint32_t)attrs.count);

        if (lcp_keygen(&mpk, &msk, &attrs, &sk) != 0) {
            fprintf(stderr, "KeyGen failed for %s\n", req->description);
            usk_free(&sk);
            return 1;
        }

        if (lcp_save_usk(&sk, req->filename) != 0) {
            fprintf(stderr, "Failed to write %s\n", req->filename);
            usk_free(&sk);
            return 1;
        }

        printf("  Saved %s\n", req->filename);
        usk_free(&sk);
    }

    printf("All requested user secret keys generated.\n");
    return 0;
}