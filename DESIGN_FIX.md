# LCP-ABE Correctness Fix: GPSW-Style Module-LWE CP-ABE

## Problem Analysis

Current implementation has architectural inconsistency:
- Uses LSSS shares of random scalar (disconnected from lattice secret)
- Embeds shares incorrectly (scalar addition doesn't work with polynomial multiplication)
- Keygen/encryption/decryption formulas don't align properly

## Correct GPSW-Style Lattice CP-ABE for Module-LWE

### Mathematical Structure

**Setup:**
- Public: A (D×M matrix), B[0..127] (one M×1 matrix per attribute), β (1 polynomial)
- Master secret: Trapdoor T_A for A

**Encryption (for policy with L rows):**
1. Sample secret vector s = (s[0], s[1], ..., s[D-1]) in R_q^D
2. Generate LSSS shares of **s[0][0]** (first coefficient of first polynomial):
   - shares[i] = LSSS(s[0][0], policy_matrix, row i)
3. Compute:
   - C0 = A^T · s + e0 (M×1 matrix of polynomials)
   - For each policy row i:
     - C[i] = B[ρ(i)]^T · s + shares[i]·g + e[i]
     - where g is embedding vector (e.g., [1, 0, 0, ...] for constant term embedding)

**Key Generation (for user with attributes):**
1. Compute target = β - Σ(B[j] · u_j) for user's attributes j
   - where u_j are random short vectors
2. Sample ω_A such that A · ω_A = target (using trapdoor T_A)
3. User key: {ω_A, {ω[j] = u_j for each user attribute j}}

**Decryption:**
1. Check policy satisfaction, get LSSS reconstruction coefficients
2. Compute:
   ```
   decryption_term = ω_A^T · C0 + Σ(coeff[i] · ω[ρ(i)]^T · C[i])
   
   = ω_A^T · (A^T·s + e0) + Σ(coeff[i] · ω[ρ(i)]^T · (B[ρ(i)]^T·s + shares[i]·g + e[i]))
   
   = (A·ω_A)^T · s + Σ(coeff[i] · (B[ρ(i)]·ω[ρ(i)])^T · s) + Σ(coeff[i]·shares[i])·g^T·ω[ρ(i)] + noise
   
   = β^T·s - Σ(B[j]·u_j)^T·s + Σ(coeff[i]·B[ρ(i)]·ω[ρ(i)])^T·s + s[0][0]·g^T·ω[ρ(i)] + noise
   ```

For matching attributes, B[ρ(i)]·ω[ρ(i)] = B[j]·u_j, so those terms cancel!

If g = [1, 0, ...] (constant term), then g^T·ω[ρ(i)] ≈ ω[ρ(i)][0] (first coefficient)

**Key Issue**: We need ω[j] to have controlled first coefficient to make extraction work!

## Simplified Solution for OR Policies

Since your policies are mostly OR (threshold-1), here's a **much simpler approach**:

### Encryption:
```
C0 = A^T · s + e0
C[i] = B[ρ(i)]^T · s + e[i]  (NO share embedding in C[i]!)

ct_key = e_key + β^T · s
ct_key[0] += s[0][0] * (Q/256)  (embed LSSS secret in first coefficient)
Then add K_log encoding: ct_key[i] += K_log[i] * (Q/256)
```

### Key Generation:
```
target = β - Σ(B[j] · ω[j])
A · ω_A = target

For each user attribute j:
  ω[j] is sampled such that B[j] · ω[j] contributes to target
  AND ω[j][0] = 1 (first coefficient = 1 for extraction)
```

### Decryption:
```
decryption_term = ω_A^T · C0 + Σ(coeff[i] · ω[ρ(i)]^T · C[i])
                = β^T · s + noise

recovered = ct_key - decryption_term[0]  (extract first coefficient)
          = e_key[0] + s[0][0] * (Q/256) + K_log[i] * (Q/256) - (β^T·s)[0] + noise

Wait, this still doesn't work cleanly...
```

## Recommended Approach: Use Standard IBE-to-ABE Transform

Actually, the **cleanest solution** is to follow the standard approach:

1. **DON'T try to be too clever with LSSS embedding**
2. **Use the secret vector s directly, no LSSS shares needed!**
3. **For OR policies**: Just use ONE attribute match, forget LSSS reconstruction

### Simplified OR Policy Encryption:

```c
// Sample s (D polynomials)
// For policy "A OR B OR C":
// - C0 = A^T · s + e0
// - C[A] = B[A]^T · s + e[A]  // one per policy attribute
// - C[B] = B[B]^T · s + e[B]
// - C[C] = B[C]^T · s + e[C]
// - ct_key = e_key + β^T · s + K_log * (Q/256)
```

### Decryption (user has attribute A):
```c
// Use ω_A and ω[A] from user key
// decryption_term = ω_A^T · C0 + ω[A]^T · C[A]
//                 ≈ β^T · s  (with noise)
// recovered = ct_key - decryption_term
//           = e_key + K_log * (Q/256) + noise
// Extract K_log by rounding
```

**This is much simpler and doesn't need LSSS at all for OR policies!**

## Proposed Implementation Fix

I recommend **removing LSSS from OR policies entirely** and using the simple direct approach above. For AND/threshold policies, we can add LSSS later once the basic structure works.

Shall I implement this simplified version?
