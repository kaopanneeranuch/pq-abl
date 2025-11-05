#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/encrypt/lcp_encrypt.h"

int main(void) {
    MasterPublicKey mpk;
    if (!lcp_types_load_mpk("keys/MPK.bin",&mpk)) {
        fprintf(stderr,"Failed to load MPK\n"); return 1;
    }
    mkdir("out",0755);
    mkdir("out/encrypted",0755);
    // epoch duration in seconds (60)
    if (!lcp_encrypt_file(&mpk,"logs/log.json","out/encrypted",60)) {
        fprintf(stderr,"Encrypt failed\n"); return 1;
    }
    printf("Encryption done. See out/encrypted/\n");
    return 0;
}