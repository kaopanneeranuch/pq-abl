#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"

int main(void) {
    MasterPublicKey mpk;
    MasterSecretKey msk;
    if (!lcp_load_mpk(&mpk, "keys/MPK.bin") ||
        !lcp_load_msk(&msk, "keys/MSK.bin")) {
        fprintf(stderr,"Failed to load MPK/MSK\n"); return 1;
    }

    /* Build attribute set */
    AttributeSet attrs;
    attribute_set_init(&attrs);
    Attribute a1; attribute_init(&a1, "user_role:admin", 0);
    Attribute a2; attribute_init(&a2, "team:storage-team", 1);
    attribute_set_add(&attrs, &a1);
    attribute_set_add(&attrs, &a2);

    UserSecretKey sk;
    usk_init(&sk, 2);
    if (lcp_keygen(&mpk, &msk, &attrs, &sk) != 0) { // lcp_keygen returns 0 on success
        fprintf(stderr,"KeyGen failed\n"); return 1;
    }
    lcp_save_usk(&sk, "keys/SK_admin_storage.bin");
    printf("Wrote keys/SK_admin_storage.bin\n");
    return 0;
}