#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/decrypt/lcp_decrypt.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"

int main(void) {
    // Initialize Module_BFRS components (required for polynomial operations)
    printf("[Decrypt Test] Initializing Module_BFRS...\n");
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();
    
    MasterPublicKey mpk;
    UserSecretKey sk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0 ||
        lcp_load_usk(&sk, "keys/SK_admin_storage.bin") != 0) {
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