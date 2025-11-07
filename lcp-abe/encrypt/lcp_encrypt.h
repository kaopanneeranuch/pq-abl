#ifndef LCP_ENCRYPT_H
#define LCP_ENCRYPT_H

#include "../common/lcp_types.h"
#include "../policy/lcp_policy.h"
#include "../util/lcp_util.h"

// ============================================================================
// Phase 3: Encryption
// ============================================================================

// LCP-ABE Encrypt a symmetric key under access policy
// Input: K_log (256-bit key), policy W, MPK
// Output: ABE ciphertext CT_ABE
//
// Encrypt(K_log, W, MPK) → CT_ABE:
//   1. Convert policy W to LSSS matrix (M, ρ)
//   2. Choose random s ∈ R_q
//   3. Generate shares: λ = M · [s, r_1, ..., r_n]^T
//   4. For each row i: compute C_i = s^T · A + e_i + λ_i · G
//   5. Encrypt key: ct_key = s^T · u + e + encode(K_log)
//   Return CT_ABE = (W, C_0, {C_i}, ct_key)
//
int lcp_abe_encrypt(const uint8_t key[AES_KEY_SIZE],
                    const AccessPolicy *policy,
                    const MasterPublicKey *mpk,
                    ABECiphertext *ct_abe);

// Batch-optimized ABE encryption: Shared components
// Computes C0 and C[i] once per batch (reusable across all logs with same policy)
// Returns secret s for use in per-log ct_key encryption
int lcp_abe_encrypt_batch_init(const AccessPolicy *policy,
                               const MasterPublicKey *mpk,
                               ABECiphertext *ct_abe_template,
                               poly_matrix *s_out);

// Batch-optimized ABE encryption: Per-log component
// Encrypts K_log using pre-computed s and shared C0/C[i]
// Only computes ct_key = β·s + e_key + encode(K_log)
int lcp_abe_encrypt_batch_key(const uint8_t key[AES_KEY_SIZE],
                              const poly_matrix s,
                              const MasterPublicKey *mpk,
                              const ABECiphertext *ct_abe_template,
                              ABECiphertext *ct_abe);

// Encrypt log data with AES-GCM
// Input: log data, K_log, nonce, AAD (metadata)
// Output: symmetric ciphertext CT_sym
int encrypt_log_symmetric(const uint8_t *log_data, size_t log_len,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t nonce[AES_NONCE_SIZE],
                         const LogMetadata *metadata,
                         SymmetricCiphertext *ct_sym);

// Encrypt single log entry (combines ABE + AES-GCM)
int encrypt_log_entry(const JsonLogEntry *log_entry,
                     const AccessPolicy *policy,
                     const MasterPublicKey *mpk,
                     EncryptedLogObject *encrypted_log);

// ============================================================================
// Microbatch Processing
// ============================================================================

// Process logs in microbatches (group by epoch and policy)
// Input: array of log entries, MPK
// Output: array of microbatches
int process_logs_microbatch(const JsonLogArray *logs,
                            const AccessPolicy *policies,
                            uint32_t n_policies,
                            const MasterPublicKey *mpk,
                            Microbatch **batches,
                            uint32_t *n_batches);

// Encrypt logs within an epoch for a specific policy (microbatch)
int encrypt_microbatch(const JsonLogEntry *logs,
                      uint32_t n_logs,
                      const AccessPolicy *policy,
                      const MasterPublicKey *mpk,
                      uint64_t epoch_id,
                      Microbatch *batch);

// Save encrypted batch to file
int save_encrypted_batch(const Microbatch *batch, const char *output_dir);

#endif // LCP_ENCRYPT_H
