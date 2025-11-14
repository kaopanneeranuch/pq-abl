// Small in-memory round-trip test for LCP-ABE key encapsulation
// Uses existing APIs: setup, keygen, batch init/key, decrypt to verify K_log round-trip

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "../setup/lcp_setup.h"
#include "../keygen/lcp_keygen.h"
#include "../encrypt/lcp_encrypt.h"
#include "../decrypt/lcp_decrypt.h"
#include "../policy/lcp_policy.h"

int main(void) {
    MasterPublicKey mpk;
    MasterSecretKey msk;
    AttributeSet attrs;
    UserSecretKey usk;
    AccessPolicy policy;
    ABECiphertext ct_template, ct_log;
    poly_matrix s_shared = NULL;
    uint8_t k_log[AES_KEY_SIZE];
    uint8_t k_out[AES_KEY_SIZE];

    printf("[RT] Starting in-memory round-trip test\n");

    // Setup with small attribute universe consistent with test_all
    if (lcp_setup(128, &mpk, &msk) != 0) {
        fprintf(stderr, "[RT] setup failed\n");
        return 1;
    }

    // Prepare an attribute set with two attributes as in test_all
    attribute_set_init(&attrs);
    Attribute a1, a2;
    attribute_init(&a1, "user_role:admin", 56);
    attribute_init(&a2, "team:storage-team", 47);
    attribute_set_add(&attrs, &a1);
    attribute_set_add(&attrs, &a2);

    // Keygen
    usk_init(&usk, attrs.count);
    usk.attr_set = attrs;
    if (lcp_keygen(&mpk, &msk, &attrs, &usk) != 0) {
        fprintf(stderr, "[RT] keygen failed\n");
        return 2;
    }

    // Prepare AND policy that requires BOTH user attributes (matches all user attributes)
    // This ensures trapdoor relationship holds: KeyGen uses all attributes, Decrypt uses all policy attributes
    policy_init(&policy);
    strncpy(policy.expression, "user_role:admin AND team:storage-team", MAX_POLICY_SIZE-1);
    policy.attr_count = 2;
    policy.attr_indices[0] = 56;  // user_role:admin
    policy.attr_indices[1] = 47;  // team:storage-team
    
    // Build LSSS matrix for AND policy (requires both attributes)
    if (lsss_policy_to_matrix(&policy) != 0) {
        fprintf(stderr, "[RT] Failed to build LSSS matrix for policy\n");
        return 3;
    }

    // Batch init (shared s and C0/C[i])
    if (lcp_abe_encrypt_batch_init(&policy, &mpk, &ct_template, &s_shared) != 0) {
        fprintf(stderr, "[RT] batch_init failed\n");
        return 3;
    }

    // Determine number of in-process iterations to run (to avoid repeated
    // process startup cost). Controlled by RT_ITERS env var; default 10.
    int iters = 10;
    const char *iters_env = getenv("RT_ITERS");
    if (iters_env) {
        int v = atoi(iters_env);
        if (v > 0) iters = v;
    }
    printf("[RT] Running %d in-process roundtrip iterations\n", iters);

    // Use a deterministic K_log for reproducibility across iterations
    for (int i = 0; i < AES_KEY_SIZE; i++) k_log[i] = (uint8_t)(0xA5 + i);

    for (int iter = 0; iter < iters; iter++) {
        printf("[RT] Iteration %d/%d\n", iter + 1, iters);
        // Encrypt into ct_log (fresh per-iteration)
        if (lcp_abe_encrypt_batch_key(k_log, s_shared, &mpk, &ct_template, &ct_log) != 0) {
            fprintf(stderr, "[RT] batch_key failed on iter %d\n", iter);
            return 4;
        }

        // Now decrypt the produced ct_log using user key usk
        if (lcp_abe_decrypt(&ct_log, &usk, &mpk, k_out) != 0) {
            fprintf(stderr, "[RT] decrypt failed on iter %d\n", iter);
            abe_ct_free(&ct_log);
            return 5;
        }

        // Compare
        if (memcmp(k_log, k_out, AES_KEY_SIZE) == 0) {
            printf("[RT] Iter %d SUCCESS\n", iter);
        } else {
            printf("[RT] Iter %d FAILURE: K_log mismatch\n", iter);
            printf("[RT] original: ");
            for (int ii = 0; ii < AES_KEY_SIZE; ii++) printf("%02x", k_log[ii]);
            printf("\n[RT] recovered: ");
            for (int ii = 0; ii < AES_KEY_SIZE; ii++) printf("%02x", k_out[ii]);
            printf("\n");
            abe_ct_free(&ct_log);
            return 6;
        }

        abe_ct_free(&ct_log);
    }

    printf("[RT] Cleaning up\n");
    abe_ct_free(&ct_template);
    abe_ct_free(&ct_log);
    usk_free(&usk);
    mpk_free(&mpk);
    msk_free(&msk);
    policy_free(&policy);
    free(s_shared);

    return 0;
}
