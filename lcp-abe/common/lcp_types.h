#ifndef LCP_TYPES_H
#define LCP_TYPES_H

#include "lcp_params.h"
#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// LCP-ABE Core Types
// ============================================================================

// Attribute structure
typedef struct {
    char name[ATTRIBUTE_NAME_LEN];   // e.g., "role:admin"
    uint32_t index;                   // Index in the attribute universe
} Attribute;

// Attribute set (for user secret keys)
typedef struct {
    Attribute attrs[MAX_ATTRIBUTES];
    uint32_t count;
} AttributeSet;

// Access policy structure (for encryption)
typedef struct {
    char expression[MAX_POLICY_SIZE];  // e.g., "(role:admin AND team:storage-team)"
    uint32_t attr_indices[MAX_ATTRIBUTES];
    uint32_t attr_count;
    
    // LSSS matrix representation
    scalar *share_matrix;              // Share-generating matrix M (rows × cols)
    uint32_t *rho;                     // Row labeling function ρ: row -> attribute index
    uint32_t matrix_rows;
    uint32_t matrix_cols;
    
    // Policy type metadata
    uint32_t threshold;                // For threshold policies (k-out-of-n)
    uint32_t is_threshold;             // Flag: 1 if threshold policy, 0 otherwise
} AccessPolicy;

typedef struct {
    poly_matrix A;                     // Public random matrix A ∈ R_q^(k×m) where k=PARAM_D, m=PARAM_M
    poly_matrix B_plus;                // B+_i vectors: n_attributes × m matrix (stored as rows)
    poly_matrix B_minus;               // B-_i vectors: n_attributes × m matrix (stored as rows)
    poly beta;                         // Challenge element β ∈ Rq
    uint32_t n_attributes;             // Total number of attributes in universe ℓ
    uint32_t k;                        // Module rank k (= PARAM_D)
    uint32_t m;                        // Module dimension m (= PARAM_M)
} MasterPublicKey;

typedef struct {
    poly_matrix T;                     // Trapdoor TA for matrix A (2k × m in Module_BFRS)
    cplx_poly_matrix cplx_T;          // Complex representation of T (for Gaussian sampling)
    cplx_poly_matrix sch_comp;        // Schur complement (for Gaussian sampling)
} MasterSecretKey;

typedef struct {
    AttributeSet attr_set;             // Set of attributes Y
    poly_matrix omega_A;               // ωA ∈ R^m (m-dimensional vector)
    poly_matrix *omega_i;              // {ωi}_{xi∈Y}: one m-dimensional vector per attribute
    uint32_t n_components;             // Number of attributes in Y
} UserSecretKey;

typedef struct {
    AccessPolicy policy;               // Access policy W
    poly_matrix C0;                    // C0 = A^T · s + e_0
    poly_matrix *C;                    // C_i components for each row of LSSS matrix
    poly ct_key;                       // Encrypted key component
    uint32_t n_components;
} ABECiphertext;

// ============================================================================
// Logging and Encryption Types
// ============================================================================

typedef struct {
    char timestamp[32];
    char user_id[64];
    char user_role[32];
    char team[32];
    char action_type[32];
    char resource_id[64];
    char resource_type[32];
    char resource_owner[64];
    char service_name[32];
    char region[32];
    char instance_id[64];
    char ip_address[32];
    char application[64];
    char event_description[256];
} LogMetadata;

typedef struct {
    uint8_t *ciphertext;               // AES-GCM ciphertext
    uint32_t ct_len;
    uint8_t nonce[AES_NONCE_SIZE];
    uint8_t tag[AES_TAG_SIZE];
} SymmetricCiphertext;

typedef struct {
    SymmetricCiphertext ct_sym;        // AES-GCM encrypted log data
    ABECiphertext ct_abe;              // LCP-ABE encrypted K_log
    LogMetadata metadata;
    uint8_t hash[SHA3_DIGEST_SIZE];    // SHA3-256(CT_obj)
} EncryptedLogObject;

typedef struct {
    AccessPolicy policy;               // Shared access policy W
    ABECiphertext shared_ct_abe;       // Shared ABE ciphertext structure
    EncryptedLogObject *logs;          // Array of encrypted logs
    uint32_t n_logs;
    uint64_t epoch_id;
    char epoch_start[32];
    char epoch_end[32];
} Microbatch;

// ============================================================================
// Helper Functions
// ============================================================================

void attribute_init(Attribute *attr, const char *name, uint32_t index);
void attribute_set_init(AttributeSet *set);
void attribute_set_add(AttributeSet *set, const Attribute *attr);
bool attribute_set_contains(const AttributeSet *set, const char *name);

void policy_init(AccessPolicy *policy);
void policy_free(AccessPolicy *policy);

void mpk_init(MasterPublicKey *mpk, uint32_t n_attributes);
void mpk_free(MasterPublicKey *mpk);
void msk_init(MasterSecretKey *msk);
void msk_free(MasterSecretKey *msk);
void usk_init(UserSecretKey *usk, uint32_t n_components);
void usk_free(UserSecretKey *usk);

void abe_ct_init(ABECiphertext *ct);
void abe_ct_free(ABECiphertext *ct);
void sym_ct_init(SymmetricCiphertext *ct);
void sym_ct_free(SymmetricCiphertext *ct);
void encrypted_log_init(EncryptedLogObject *obj);
void encrypted_log_free(EncryptedLogObject *obj);

void microbatch_init(Microbatch *batch, uint32_t n_logs);
void microbatch_free(Microbatch *batch);

#endif // LCP_TYPES_H
