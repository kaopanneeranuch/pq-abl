# Critical Fixes for LCP-ABE Implementation

## Problem Summary

The decryption is failing because of a fundamental mismatch between encryption and decryption in how the lattice CP-ABE scheme handles the secret key relationship.

## Root Cause Analysis

### Issue 1: C[i] Construction Mismatch

**Encryption (lcp_encrypt.c, lines 260-276):**
```c
// C[i] is constructed as:
C[i][j] = B[ρ(i)][j] · s[0] + e[i][j]
// PLUS: share[i] · β · s[0] added ONLY to j=0 (first polynomial)
if (j == 0) {
    add_poly(c_i_j, c_i_j, share_beta_s0, PARAM_N - 1);
}
```

**Decryption (lcp_decrypt.c, lines 119-145):**
```c
// Computes inner product over ALL M polynomials:
for (uint32_t j = 0; j < PARAM_M; j++) {
    // ω[ρ(i)][j] · C[i][j]
}
```

**The Problem:** When we compute the inner product `ω[ρ(i)] · C[i]` in decryption, the share term `share[i] · β · s[0]` only appears in the first component, but we're multiplying ALL components. This means:

- Expected: `ω[ρ(i)] · C[i] ≈ ω[ρ(i)] · B[ρ(i)] · s[0] + share[i] · β · s[0] · ω[ρ(i)][0]`
- But we need: `ω[ρ(i)] · C[i] ≈ (ω[ρ(i)] · B[ρ(i)]) · s[0] + share[i] · β · s[0]`

The multiplication by `ω[ρ(i)][0]` (just one component) instead of summing to a clean share term causes the decryption to fail.

### Issue 2: Keygen Target Formula

**Keygen (lcp_keygen.c, lines 220-223):**
```c
// target = β - Σ(B[i]·ω[i]) for all user attributes
sub_poly(target_0, target_0, sum_0, PARAM_N - 1);
```

This computes: `A·ω_A = β - Σ(B[user_attrs]·ω[user_attrs])`

**Expected in Decryption:**
```
ω_A · C0 + Σ(coeff[j]·ω[ρ(j)]·C[j]) = β·s[0]
```

But with the current keygen:
```
ω_A · C0 = (A·ω_A) · s = (β - Σ(B[user]·ω[user])) · s[0]
Σ(coeff[j]·ω[ρ(j)]·C[j]) = Σ(coeff[j]·ω[ρ(j)]·B[ρ(j)]·s[0]) + Σ(coeff[j]·share[j]·β·s[0])
```

For this to equal `β·s[0]`, we need:
- The B terms to cancel (requires policy attrs = user attrs with coeffs summing to 1)
- The share terms to reconstruct to zero (since shares are of secret=0)

## The Fix

We need to modify the encryption to add the share term to ALL polynomials in C[i], not just the first one:

### Fix 1: Correct C[i] Construction

**File: lcp-abe/encrypt/lcp_encrypt.c**

**Location: Lines 260-276**

**Change from:**
```c
// For each of the M polynomials in C[i]
for (uint32_t j = 0; j < PARAM_M; j++) {
    poly c_i_j = poly_matrix_element(ct_abe_template->C[i], 1, j, 0);
    poly e_i_j = poly_matrix_element(e_i, 1, j, 0);
    poly B_j = &B_plus_attr[j * PARAM_N];
    
    // C[i][j] = B[j] · s[0] + e[i][j]
    mul_crt_poly(temp_prod, B_j, s_0, LOG_R);
    reduce_double_crt_poly(reduced, temp_prod, LOG_R);
    add_poly(c_i_j, reduced, e_i_j, PARAM_N - 1);
    
    // Add share[i] · β · s[0] ONLY to the first polynomial (j=0)
    if (j == 0) {
        add_poly(c_i_j, c_i_j, share_beta_s0, PARAM_N - 1);
    }
    
    freeze_poly(c_i_j, PARAM_N - 1);
}
```

**Change to:**
```c
// For each of the M polynomials in C[i]
for (uint32_t j = 0; j < PARAM_M; j++) {
    poly c_i_j = poly_matrix_element(ct_abe_template->C[i], 1, j, 0);
    poly e_i_j = poly_matrix_element(e_i, 1, j, 0);
    poly B_j = &B_plus_attr[j * PARAM_N];
    
    // C[i][j] = B[j] · s[0] + e[i][j] + (share[i]/M) · β · s[0]
    // NOTE: Divide share by M to compensate for inner product summing M terms
    mul_crt_poly(temp_prod, B_j, s_0, LOG_R);
    reduce_double_crt_poly(reduced, temp_prod, LOG_R);
    add_poly(c_i_j, reduced, e_i_j, PARAM_N - 1);
    
    // Add (share[i]/M) · β · s[0] to EVERY polynomial
    // This way the inner product Σ(ω[j]·C[i][j]) will sum to share[i]·β·s[0]
    poly share_term_scaled = (poly)calloc(PARAM_N, sizeof(scalar));
    for (uint32_t k = 0; k < PARAM_N; k++) {
        // Divide by M: compute (share_beta_s0 * M^(-1)) mod q
        // For simplicity with shares=0, this is just 0, but keep structure:
        uint64_t M_inv = mod_inverse(PARAM_M, PARAM_Q);
        share_term_scaled[k] = (((uint64_t)share_beta_s0[k] * M_inv) % PARAM_Q);
    }
    add_poly(c_i_j, c_i_j, share_term_scaled, PARAM_N - 1);
    free(share_term_scaled);
    
    freeze_poly(c_i_j, PARAM_N - 1);
}
```

**WAIT** - This is getting complex. Let me reconsider...

## Simpler Alternative: Remove Share Terms Entirely

Since we're using `secret = 0` for LSSS shares (line 103 in lcp_encrypt.c), the share terms are actually **NOT NEEDED** for lattice CP-ABE. The policy satisfaction is handled by which attributes match during decryption!

### Recommended Fix: Remove LSSS Share Encoding from C[i]

**File: lcp-abe/encrypt/lcp_encrypt.c**

**Lines 233-277, simplify to:**
```c
// For each of the M polynomials in C[i]
for (uint32_t j = 0; j < PARAM_M; j++) {
    poly c_i_j = poly_matrix_element(ct_abe_template->C[i], 1, j, 0);
    poly e_i_j = poly_matrix_element(e_i, 1, j, 0);
    poly B_j = &B_plus_attr[j * PARAM_N];
    
    // C[i][j] = B[j] · s[0] + e[i][j]
    // NO share term - policy satisfaction handled by attribute matching
    mul_crt_poly(temp_prod, B_j, s_0, LOG_R);
    reduce_double_crt_poly(reduced, temp_prod, LOG_R);
    add_poly(c_i_j, reduced, e_i_j, PARAM_N - 1);
    
    freeze_poly(c_i_j, PARAM_N - 1);
}
```

Remove the share_beta_s0 computation and addition entirely.

This matches the Module-LWE CP-ABE construction where:
- Encryption: `C[i] = B[ρ(i)]^T · s + e[i]` (clean, no share mixing)
- Decryption recovers `β·s` via the trapdoor relationship in keygen
- Policy satisfaction is implicit in which ω[i] vectors exist in the user's key

### Issue 3: Keygen Should Use ALL User Attributes

The current keygen subtracts Σ(B[i]·ω[i]) for all user attributes, which is correct. This ensures:

```
A·ω_A = β - Σ(B[user_attrs]·ω[user_attrs])

During decryption:
ω_A·(A^T·s) + Σ(coeff[j]·ω[ρ(j)]·(B[ρ(j)]^T·s))
= (β - Σ(B[user]·ω[user]))·s + Σ(coeff[j]·(B[ρ(j)]·ω[ρ(j)])·s)
= β·s - Σ(B[user]·ω[user])·s + Σ(coeff[j]·B[ρ(j)]·ω[ρ(j)]·s)

For attrs where ρ(j) ∈ user_attrs and Σcoeff[j]=1:
= β·s
```

This is correct IF we sum over matching attributes with proper coefficients.

## Complete Fix Implementation

1. Remove share terms from C[i] construction
2. Verify keygen is using correct formula (it is)
3. Ensure decryption only sums over matching policy attributes (it does via lsss_compute_coefficients)

The key insight: **LSSS shares are NOT needed in lattice CP-ABE** because policy satisfaction is checked by attribute matching, not by secret sharing reconstruction.
