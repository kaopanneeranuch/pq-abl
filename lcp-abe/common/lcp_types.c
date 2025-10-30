#include "lcp_types.h"
#include <string.h>
#include <stdlib.h>

// ============================================================================
// Attribute Functions
// ============================================================================

void attribute_init(Attribute *attr, const char *name, uint32_t index) {
    strncpy(attr->name, name, ATTRIBUTE_NAME_LEN - 1);
    attr->name[ATTRIBUTE_NAME_LEN - 1] = '\0';
    attr->index = index;
}

void attribute_set_init(AttributeSet *set) {
    set->count = 0;
    memset(set->attrs, 0, sizeof(set->attrs));
}

void attribute_set_add(AttributeSet *set, const Attribute *attr) {
    if (set->count < MAX_ATTRIBUTES) {
        set->attrs[set->count++] = *attr;
    }
}

bool attribute_set_contains(const AttributeSet *set, const char *name) {
    for (uint32_t i = 0; i < set->count; i++) {
        if (strcmp(set->attrs[i].name, name) == 0) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Policy Functions
// ============================================================================

void policy_init(AccessPolicy *policy) {
    memset(policy->expression, 0, MAX_POLICY_SIZE);
    memset(policy->attr_indices, 0, sizeof(policy->attr_indices));
    policy->attr_count = 0;
    policy->share_matrix = NULL;
    policy->rho = NULL;
    policy->matrix_rows = 0;
    policy->matrix_cols = 0;
}

void policy_free(AccessPolicy *policy) {
    if (policy->share_matrix) {
        free(policy->share_matrix);
        policy->share_matrix = NULL;
    }
    if (policy->rho) {
        free(policy->rho);
        policy->rho = NULL;
    }
}

// ============================================================================
// Master Public Key Functions
// ============================================================================

void mpk_init(MasterPublicKey *mpk, uint32_t n_attributes) {
    mpk->n_attributes = n_attributes;
    mpk->matrix_dim = PARAM_D;
    
    // Allocate matrices
    mpk->A = (poly_matrix)calloc(PARAM_D * PARAM_D * PARAM_N, sizeof(scalar));
    mpk->U = (poly_matrix)calloc(PARAM_D * n_attributes * PARAM_N, sizeof(scalar));
}

void mpk_free(MasterPublicKey *mpk) {
    if (mpk->A) {
        free(mpk->A);
        mpk->A = NULL;
    }
    if (mpk->U) {
        free(mpk->U);
        mpk->U = NULL;
    }
}

// ============================================================================
// Master Secret Key Functions
// ============================================================================

void msk_init(MasterSecretKey *msk) {
    // Allocate trapdoor matrix T
    msk->T = (poly_matrix)calloc(PARAM_D * PARAM_D * PARAM_N, sizeof(scalar));
    
    // Allocate complex representations for Gaussian sampling
    msk->cplx_T = (cplx_poly_matrix)calloc(PARAM_D * PARAM_D * SMALL_DEGREE, sizeof(cplx));
    msk->sch_comp = (cplx_poly_matrix)calloc(PARAM_D * PARAM_D * SMALL_DEGREE, sizeof(cplx));
}

void msk_free(MasterSecretKey *msk) {
    if (msk->T) {
        free(msk->T);
        msk->T = NULL;
    }
    if (msk->cplx_T) {
        free(msk->cplx_T);
        msk->cplx_T = NULL;
    }
    if (msk->sch_comp) {
        free(msk->sch_comp);
        msk->sch_comp = NULL;
    }
}

// ============================================================================
// User Secret Key Functions
// ============================================================================

void usk_init(UserSecretKey *usk, uint32_t n_components) {
    attribute_set_init(&usk->attr_set);
    usk->n_components = n_components;
    usk->sk_components = (poly_matrix*)calloc(n_components, sizeof(poly_matrix));
    
    for (uint32_t i = 0; i < n_components; i++) {
        usk->sk_components[i] = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
    }
}

void usk_free(UserSecretKey *usk) {
    if (usk->sk_components) {
        for (uint32_t i = 0; i < usk->n_components; i++) {
            if (usk->sk_components[i]) {
                free(usk->sk_components[i]);
            }
        }
        free(usk->sk_components);
        usk->sk_components = NULL;
    }
}

// ============================================================================
// ABE Ciphertext Functions
// ============================================================================

void abe_ct_init(ABECiphertext *ct) {
    policy_init(&ct->policy);
    ct->C0 = NULL;
    ct->C = NULL;
    ct->ct_key = NULL;
    ct->n_components = 0;
}

void abe_ct_free(ABECiphertext *ct) {
    policy_free(&ct->policy);
    
    if (ct->C0) {
        free(ct->C0);
        ct->C0 = NULL;
    }
    
    if (ct->C) {
        for (uint32_t i = 0; i < ct->n_components; i++) {
            if (ct->C[i]) {
                free(ct->C[i]);
            }
        }
        free(ct->C);
        ct->C = NULL;
    }
    
    if (ct->ct_key) {
        free(ct->ct_key);
        ct->ct_key = NULL;
    }
}

// ============================================================================
// Symmetric Ciphertext Functions
// ============================================================================

void sym_ct_init(SymmetricCiphertext *ct) {
    ct->ciphertext = NULL;
    ct->ct_len = 0;
    memset(ct->nonce, 0, AES_NONCE_SIZE);
    memset(ct->tag, 0, AES_TAG_SIZE);
}

void sym_ct_free(SymmetricCiphertext *ct) {
    if (ct->ciphertext) {
        free(ct->ciphertext);
        ct->ciphertext = NULL;
    }
    ct->ct_len = 0;
}

// ============================================================================
// Encrypted Log Object Functions
// ============================================================================

void encrypted_log_init(EncryptedLogObject *obj) {
    sym_ct_init(&obj->ct_sym);
    abe_ct_init(&obj->ct_abe);
    memset(&obj->metadata, 0, sizeof(LogMetadata));
    memset(obj->hash, 0, SHA3_DIGEST_SIZE);
}

void encrypted_log_free(EncryptedLogObject *obj) {
    sym_ct_free(&obj->ct_sym);
    abe_ct_free(&obj->ct_abe);
}

// ============================================================================
// Microbatch Functions
// ============================================================================

void microbatch_init(Microbatch *batch, uint32_t n_logs) {
    policy_init(&batch->policy);
    abe_ct_init(&batch->shared_ct_abe);
    
    batch->n_logs = n_logs;
    batch->logs = (EncryptedLogObject*)calloc(n_logs, sizeof(EncryptedLogObject));
    
    for (uint32_t i = 0; i < n_logs; i++) {
        encrypted_log_init(&batch->logs[i]);
    }
    
    batch->epoch_id = 0;
    memset(batch->epoch_start, 0, 32);
    memset(batch->epoch_end, 0, 32);
}

void microbatch_free(Microbatch *batch) {
    policy_free(&batch->policy);
    abe_ct_free(&batch->shared_ct_abe);
    
    if (batch->logs) {
        for (uint32_t i = 0; i < batch->n_logs; i++) {
            encrypted_log_free(&batch->logs[i]);
        }
        free(batch->logs);
        batch->logs = NULL;
    }
}
