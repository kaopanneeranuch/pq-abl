#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/decrypt/lcp_decrypt.h"

int main(void) {
    MasterPublicKey mpk;
    UserSecretKey sk;
    if (!lcp_types_load_mpk("keys/MPK.bin",&mpk) ||
        !lcp_types_load_sk("keys/SK_admin_storage.bin",&sk)) {
        fprintf(stderr,"Failed to load keys\n"); return 1;
    }
    mkdir("out/decrypted",0755);
    // choose one encrypted file produced earlier:
    const char *ctfile = "out/encrypted/epoch_0_policy_admin_storage.json";
    if (!lcp_decrypt_file(&mpk,&sk,ctfile,"out/decrypted")) {
        fprintf(stderr,"Decrypt failed\n"); return 1;
    }
    printf("Decryption done. See out/decrypted/\n");
    return 0;
}