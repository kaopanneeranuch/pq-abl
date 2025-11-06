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

    /* Build attribute set */
    AttributeSet attrs;
    attribute_set_init(&attrs);
    
    // Use the same hash function as policy parsing to compute indices
    // This ensures attribute indices match between encryption and decryption
    Attribute a1;
    Attribute a2;
    
    // Hash "user_role:admin" to get consistent index
    attribute_init(&a1, "user_role:admin", attr_name_to_index("user_role:admin"));
    // Hash "team:storage-team" to get consistent index  
    attribute_init(&a2, "team:storage-team", attr_name_to_index("team:storage-team"));
    
    attribute_set_add(&attrs, &a1);
    attribute_set_add(&attrs, &a2);
    
    printf("[KeyGen] User attributes:\n");
    printf("  - %s (index %u)\n", a1.name, a1.index);
    printf("  - %s (index %u)\n", a2.name, a2.index);

    UserSecretKey sk;
    usk_init(&sk, 2);
    if (lcp_keygen(&mpk, &msk, &attrs, &sk) != 0) { // lcp_keygen returns 0 on success
        fprintf(stderr,"KeyGen failed\n"); return 1;
    }
    lcp_save_usk(&sk, "keys/SK_admin_storage.bin");
    printf("Wrote keys/SK_admin_storage.bin\n");
    return 0;
}