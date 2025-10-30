#ifndef LCP_POLICY_H
#define LCP_POLICY_H

#include "../common/lcp_types.h"

// ============================================================================
// Policy Parsing
// ============================================================================

// Parse policy expression into AccessPolicy structure
// Example: "(user_role:admin AND team:storage-team)"
int policy_parse(const char *expression, AccessPolicy *policy);

// Match log entry to policy (determine which policy applies)
int policy_match_log(const JsonLogEntry *log, const AccessPolicy *policy);

// ============================================================================
// Linear Secret Sharing Scheme (LSSS)
// ============================================================================

// Convert access policy to LSSS representation (share-generating matrix M and labeling ρ)
// For CP-ABE: converts policy tree/expression into matrix form
int lsss_policy_to_matrix(AccessPolicy *policy);

// Generate shares for a secret using LSSS matrix
// s ∈ Z_q is the secret, shares are computed as v = M · [s, r1, r2, ..., rn]^T
int lsss_generate_shares(const AccessPolicy *policy, scalar secret, scalar *shares);

// Reconstruct secret from shares given attribute set
// Returns 1 if successful, 0 if attributes don't satisfy policy
int lsss_reconstruct_secret(const AccessPolicy *policy, const scalar *shares,
                            const AttributeSet *attr_set, scalar *secret);

// Check if attribute set satisfies policy
int lsss_check_satisfaction(const AccessPolicy *policy, const AttributeSet *attr_set);

// Compute reconstruction coefficients for satisfied policy
// omega_i for each row i such that ρ(i) ∈ S
int lsss_compute_coefficients(const AccessPolicy *policy, const AttributeSet *attr_set,
                              scalar *coefficients, uint32_t *n_coeffs);

#endif // LCP_POLICY_H
