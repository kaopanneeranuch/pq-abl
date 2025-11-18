#ifndef LCP_KEYGEN_H
#define LCP_KEYGEN_H

#include "../common/lcp_types.h"

// ============================================================================
// Phase 2: Key Generation
// ============================================================================

int lcp_keygen(const MasterPublicKey *mpk, const MasterSecretKey *msk,
               const AttributeSet *attr_set, UserSecretKey *usk);

// Helper: Hash attribute name to polynomial (random oracle)
void hash_attribute_to_poly(const char *attr_name, poly output);

// Save/load user secret key
int lcp_save_usk(const UserSecretKey *usk, const char *filename);
int lcp_load_usk(UserSecretKey *usk, const char *filename);

#endif // LCP_KEYGEN_H
