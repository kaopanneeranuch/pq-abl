#include <stdio.h>
#include <stdlib.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/keygen/lcp_keygen.h"

int main(void) {
    MasterPublicKey mpk;
    MasterSecretKey msk;
    if (!lcp_types_load_mpk("keys/MPK.bin",&mpk) ||
        !lcp_types_load_msk("keys/MSK.bin",&msk)) {
        fprintf(stderr,"Failed to load MPK/MSK\n"); return 1;
    }
    AttributeSet attrs = attribute_set_new();
    attribute_set_add(&attrs,"user_role","admin");
    attribute_set_add(&attrs,"team","storage-team");

    UserSecretKey sk;
    if (!lcp_keygen(&mpk,&msk,&attrs,&sk)) {
        fprintf(stderr,"KeyGen failed\n"); return 1;
    }
    lcp_types_save_sk("keys/SK_admin_storage.bin",&sk);
    printf("Wrote keys/SK_admin_storage.bin\n");
    return 0;
}