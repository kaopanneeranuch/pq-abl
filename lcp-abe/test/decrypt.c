#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/decrypt/lcp_decrypt.h"

int main(void) {
    MasterPublicKey mpk;
    UserSecretKey sk;
    if (!lcp_load_mpk(&mpk, "keys/MPK.bin") ||
        !lcp_load_usk(&sk, "keys/SK_admin_storage.bin")) {
        fprintf(stderr,"Failed to load keys\n"); return 1;
    }
    mkdir("out/decrypted",0755);
    // choose one encrypted file produced earlier:
    const char *ctfile = "out/encrypted/batch_epoch0_policy1.bin";
    if (load_and_decrypt_batch(ctfile, &sk, &mpk) != 0) {
        fprintf(stderr,"Decrypt failed\n"); return 1;
    }
    printf("Decryption done. See out/decrypted/\n");
    return 0;
}