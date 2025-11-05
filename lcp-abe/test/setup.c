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
    lcp_types_save_mpk("keys/MPK.bin",&mpk);
    lcp_types_save_msk("keys/MSK.bin",&msk);
    printf("Wrote keys/MPK.bin and keys/MSK.bin\n");
    return 0;
}