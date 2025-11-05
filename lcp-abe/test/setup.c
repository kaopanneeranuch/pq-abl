#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/common/lcp_types.h"

int main(void) {
    MasterPublicKey mpk;
    MasterSecretKey msk;
    if (!lcp_setup(128, &mpk, &msk)) { // adjust param if your API differs
        fprintf(stderr,"Setup failed\n");
        return 1;
    }
    mkdir("keys",0755);
    /* save functions take (const obj*, filename) */
    lcp_save_mpk(&mpk, "keys/MPK.bin");
    lcp_save_msk(&msk, "keys/MSK.bin");
    printf("Wrote keys/MPK.bin and keys/MSK.bin\n");
    return 0;
}