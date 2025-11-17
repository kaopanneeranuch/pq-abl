#ifndef LCP_REVOCATION_H
#define LCP_REVOCATION_H

#include "../common/lcp_types.h"
#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Revocation Types
// ============================================================================

// Revocation notice structure (for blockchain broadcast)
typedef struct {
    char revoked_uid[64];              // Revoked user pseudonym uid*
    uint32_t *revoked_attr_indices;     // Array of revoked attribute indices
    uint32_t n_revoked_attrs;           // Number of revoked attributes
    uint32_t ver_id;                    // Policy version identifier
    uint64_t timestamp;                 // Revocation timestamp
} RevocationNotice;

// Revocation context (tracks current state)
typedef struct {
    uint32_t current_ver_id;            // Current policy version
    uint32_t *revoked_attr_indices;     // Cumulative list of revoked attributes
    uint32_t n_revoked_attrs;          // Total number of revoked attributes
    bool trapdoor_rotated;              // Flag indicating if trapdoor was rotated
} RevocationContext;

// ============================================================================
// Phase 1: Revocation Trigger and Policy Update
// ============================================================================

// Create revocation notice for a user or attributes
// Input: revoked_uid (can be NULL for attribute-only revocation),
//        revoked_attr_names (array of attribute names to revoke),
//        n_attrs (number of attributes)
// Output: revocation notice structure
int lcp_create_revocation_notice(const char *revoked_uid,
                                 const char **revoked_attr_names,
                                 uint32_t n_attrs,
                                 uint32_t ver_id,
                                 RevocationNotice *notice);

// Update access policy by excluding revoked attributes
// W(t+1) = W(t) \ { xr | xr revoked }
// Input: original policy, revoked attribute indices
// Output: updated policy (new version)
int lcp_update_policy_exclude_attrs(const AccessPolicy *policy_old,
                                    const uint32_t *revoked_attr_indices,
                                    uint32_t n_revoked,
                                    AccessPolicy *policy_new);

// ============================================================================
// Phase 2: Lattice-Based Trapdoor Re-Keying
// ============================================================================

// Rotate trapdoor by adding perturbation: T(t+1) = T(t) + ΔT
// where ΔT ← D_m^σs (discrete Gaussian distribution)
// Input: current trapdoor T(t), output: new trapdoor T(t+1)
// Note: This preserves R-LWE hardness while invalidating prior keys
int lcp_rotate_trapdoor(const MasterSecretKey *msk_old,
                       MasterSecretKey *msk_new);

// Regenerate A matrix from new trapdoor T
// CRITICAL: After rotating T, we must regenerate A to maintain trapdoor relationship
// A is constructed as [A_hat | 2Q - AprimeT] where AprimeT = A_hat·T2 + T1
// This matches the setup procedure to ensure consistency
int lcp_regenerate_A_from_trapdoor(const MasterSecretKey *msk_new,
                                   MasterPublicKey *mpk_new);

// Update master public key if needed after trapdoor rotation
// (In this scheme, MPK may remain the same, but we update version)
int lcp_update_mpk_version(MasterPublicKey *mpk, uint32_t ver_id);

// ============================================================================
// Phase 3: Selective Key Regeneration for Valid Users
// ============================================================================

// Regenerate user secret key under new trapdoor T(t+1)
// Only called for non-revoked users
// Input: new MSK, MPK, user's attribute set (must not contain revoked attrs)
// Output: new user secret key SK(t+1)
int lcp_regenerate_user_key(const MasterPublicKey *mpk,
                            const MasterSecretKey *msk_new,
                            const AttributeSet *attr_set,
                            UserSecretKey *usk_new);

// Check if user's attributes are revoked
// Returns 1 if user has revoked attributes, 0 otherwise
int lcp_check_user_revoked(const AttributeSet *attr_set,
                           const uint32_t *revoked_attr_indices,
                           uint32_t n_revoked);

// ============================================================================
// Phase 4: Selective Re-Encryption of Encrypted Logs
// ============================================================================

// Re-encapsulate symmetric key K_log for affected ciphertexts
// Only re-encrypts the ABE component (CT_ABE), not the symmetric payload
// Input: original encrypted log, new policy, new MPK
// Output: re-encrypted log object (structure initialized, but K_log must be provided separately)
int lcp_reencrypt_log_abe(const EncryptedLogObject *log_old,
                         const AccessPolicy *policy_new,
                         const MasterPublicKey *mpk_new,
                         EncryptedLogObject *log_new);

// Re-encrypt log with known K_log (for when AA has stored K_log separately)
// This performs the actual re-encryption of the ABE component
int lcp_reencrypt_log_abe_with_key(const EncryptedLogObject *log_old,
                                   const uint8_t k_log[AES_KEY_SIZE],
                                   const AccessPolicy *policy_new,
                                   const MasterPublicKey *mpk_new,
                                   EncryptedLogObject *log_new);

// Batch re-encryption for multiple log objects
// Input: array of encrypted logs, new policy, new MPK
// Output: array of re-encrypted logs
int lcp_reencrypt_logs_batch(const EncryptedLogObject *logs_old,
                            uint32_t n_logs,
                            const AccessPolicy *policy_new,
                            const MasterPublicKey *mpk_new,
                            EncryptedLogObject *logs_new);

// ============================================================================
// Complete Revocation Workflow
// ============================================================================

// Execute complete revocation workflow:
// 1. Update policy
// 2. Rotate trapdoor
// 3. Regenerate keys for valid users
// 4. Re-encrypt affected ciphertexts
int lcp_execute_revocation(const char **revoked_attr_names,
                          uint32_t n_revoked_attrs,
                          const AccessPolicy *policy_old,
                          const MasterPublicKey *mpk_old,
                          const MasterSecretKey *msk_old,
                          AccessPolicy *policy_new,
                          MasterPublicKey *mpk_new,
                          MasterSecretKey *msk_new,
                          RevocationContext *ctx);

// ============================================================================
// Helper Functions
// ============================================================================

// Initialize revocation context
void revocation_context_init(RevocationContext *ctx);

// Free revocation context
void revocation_context_free(RevocationContext *ctx);

// Initialize revocation notice
void revocation_notice_init(RevocationNotice *notice);

// Free revocation notice
void revocation_notice_free(RevocationNotice *notice);

#endif // LCP_REVOCATION_H

