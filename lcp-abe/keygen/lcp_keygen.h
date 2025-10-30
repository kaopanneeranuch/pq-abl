#ifndef LCP_KEYGEN_H
#define LCP_KEYGEN_H

#include "../common/lcp_types.h"

// ============================================================================
// Phase 2: Key Generation
// ============================================================================

// LCP-ABE KeyGen algorithm
// Input: MSK, MPK, attribute set S
// Output: User Secret Key SK_S
//
// KeyGen(MSK, S) → SK_S:
//   For each attribute i ∈ S:
//     1. Compute f_i = hash(attr_i) (map attribute to polynomial)
//     2. Compute target vector: v_i = A^{-1}(u_i - f_i)
//     3. Use Gaussian sampling with trapdoor T_A to sample sk_i
//        such that A · sk_i = u_i - f_i (mod q)
//   Return SK_S = {sk_i}_{i ∈ S}
//
int lcp_keygen(const MasterPublicKey *mpk, const MasterSecretKey *msk,
               const AttributeSet *attr_set, UserSecretKey *usk);

// Helper: Hash attribute name to polynomial (random oracle)
void hash_attribute_to_poly(const char *attr_name, poly output);

// Save/load user secret key
int lcp_save_usk(const UserSecretKey *usk, const char *filename);
int lcp_load_usk(UserSecretKey *usk, const char *filename);

#endif // LCP_KEYGEN_H
