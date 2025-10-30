#ifndef LCP_SETUP_H
#define LCP_SETUP_H

#include "../common/lcp_types.h"

// ============================================================================
// Phase 1: Setup
// ============================================================================

// LCP-ABE Setup algorithm
// Input: Security parameter λ (implicit), number of attributes n
// Output: Master Public Key (MPK), Master Secret Key (MSK)
//
// Setup(1^λ, n) → (MPK, MSK):
//   1. Sample random matrix A ∈ R_q^(d×d) using TrapGen → (A, T_A)
//   2. For each attribute i ∈ [n]: sample random u_i ∈ R_q^d
//   3. Construct U = [u_1 | u_2 | ... | u_n]
//   4. MPK = (A, U), MSK = T_A
//
int lcp_setup(uint32_t n_attributes, MasterPublicKey *mpk, MasterSecretKey *msk);

// Save keys to files
int lcp_save_mpk(const MasterPublicKey *mpk, const char *filename);
int lcp_load_mpk(MasterPublicKey *mpk, const char *filename);

int lcp_save_msk(const MasterSecretKey *msk, const char *filename);
int lcp_load_msk(MasterSecretKey *msk, const char *filename);

#endif // LCP_SETUP_H
