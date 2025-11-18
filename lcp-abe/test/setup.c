#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#endif
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/common/lcp_types.h"

int main(void) {
    MasterPublicKey mpk;
    MasterSecretKey msk;
    if (lcp_setup(128, &mpk, &msk) != 0) { // lcp_setup returns 0 on success
        fprintf(stderr,"Setup failed\n");
        return 1;
    }
    /* Create keys directory (cross-platform) */
#ifdef _WIN32
    _mkdir("keys");
#else
    mkdir("keys",0755);
#endif
    /* save functions take (const obj*, filename) */
    lcp_save_mpk(&mpk, "keys/MPK.bin");
    lcp_save_msk(&msk, "keys/MSK.bin");
    printf("Setup successful. Keys saved to: keys/\n");
    return 0;
}