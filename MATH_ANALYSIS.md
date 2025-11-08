# Mathematical Analysis of LCP-ABE Decryption Failure

## Dimension Analysis

### Setup Parameters
- `PARAM_D = 4` (module rank k)
- `PARAM_M = 128` (module dimension m)  
- `PARAM_N = 256` (polynomial degree n)
- `A`: D × (M-D) matrix (stored), represents [I_D | Ā]
- Full A is actually D × M when considering implicit identity: A = [I_D | mpk->A]

### Keygen
```
target = D-dimensional vector with:
  target[0] = β - Σ(B[i]·ω[i])  (for i ∈ user_attrs)
  target[1..D-1] = 0

sample_pre_target(ω_A, A, ..., target) solves:
  A · ω_A ≈ target

Since A is D×M and ω_A is M×1, result is D×1:
  A · ω_A = [
    (A·ω_A)[0],  // ≈ β - Σ(B[user]·ω[user])
    (A·ω_A)[1],  // ≈ 0
    ...
    (A·ω_A)[D-1] // ≈ 0
  ]
```

### Encryption
```
s: D-dimensional secret vector (D×1)

C0 = A^T · s + e0
where:
  A^T is M×D (transpose of D×M)
  s is D×1
  Result C0 is M×1

Specifically (from lcp_encrypt.c lines 158-190):
  C0[0..D-1] = s[0..D-1] + e0[0..D-1]  (from identity part of A)
  C0[D..M-1] = Ā^T · s + e0[D..M-1]    (from stored part)
```

### Decryption - Step 1
```
Compute: ω_A · C0

ω_A is M×1 (as a column), so ω_A^T is 1×M
C0 is M×1

ω_A^T · C0 = Σ(i=0 to M-1) ω_A[i] · C0[i]
           = ω_A^T · (A^T · s + e0)
           = ω_A^T · A^T · s + ω_A^T · e0
           = (A · ω_A)^T · s + small_noise

Since A·ω_A is D-dimensional:
  (A·ω_A)^T · s = Σ(j=0 to D-1) (A·ω_A)[j] · s[j]
                ≈ (β - Σ(B[user]·ω[user])) · s[0] + 0·s[1] + ... + 0·s[D-1]
                ≈ (β - Σ(B[user]·ω[user])) · s[0]
```

### Encryption - C[i]
```
For each policy row i:
  attr_idx = ρ(i)
  B_plus_attr = mpk->B_plus[attr_idx]  (M-dimensional vector)
  
  C[i] = B_plus_attr · s[0] + e[i]

This is computing:
  C[i] = [
    B_plus[0] · s[0] + e[i][0],
    B_plus[1] · s[0] + e[i][1],
    ...
    B_plus[M-1] · s[0] + e[i][M-1]
  ]
```

### Decryption - Step 2
```
For matching policy row i (with ρ(i) ∈ user_attrs):
  
  ω[ρ(i)]^T · C[i] = Σ(j=0 to M-1) ω[ρ(i)][j] · C[i][j]
                    = Σ(j=0 to M-1) ω[ρ(i)][j] · (B_plus[ρ(i)][j] · s[0] + e[i][j])
                    = s[0] · Σ(j=0 to M-1) (ω[ρ(i)][j] · B_plus[ρ(i)][j]) + noise
                    = s[0] · (B[ρ(i)]·ω[ρ(i)]) + noise

Sum over all matching rows with reconstruction coefficients:
  Σ(i∈matching) coeff[i] · (ω[ρ(i)]^T · C[i])
    = Σ(i∈matching) coeff[i] · s[0] · (B[ρ(i)]·ω[ρ(i)])
    = s[0] · Σ(i∈matching) coeff[i] · (B[ρ(i)]·ω[ρ(i)])
```

### Combined Decryption Term
```
ω_A^T · C0 + Σ(i∈matching) coeff[i] · (ω[ρ(i)]^T · C[i])
  ≈ (β - Σ(j∈user) B[j]·ω[j]) · s[0] + s[0] · Σ(i∈matching) coeff[i] · B[ρ(i)]·ω[ρ(i)]
  = s[0] · (β - Σ(j∈user) B[j]·ω[j] + Σ(i∈matching) coeff[i] · B[ρ(i)]·ω[ρ(i)])

For this to equal β·s[0], we need:
  -Σ(j∈user) B[j]·ω[j] + Σ(i∈matching) coeff[i] · B[ρ(i)]·ω[ρ(i)] = 0

This holds IF:
  1. All policy attributes match user attributes (ρ(i) ∈ user_attrs for all i)
  2. The coefficients sum to 1: Σ coeff[i] = 1
  3. Each policy attribute appears exactly once

BUT: The user might have MORE attributes than the policy requires!
```

## THE BUG

The keygen subtracts **ALL user attributes**:
```c
target[0] = β - Σ(j∈ALL_USER_ATTRS) B[j]·ω[j]
```

But decryption only adds back the **MATCHING policy attributes**:
```c
+ Σ(i∈POLICY_ATTRS) coeff[i] · B[ρ(i)]·ω[ρ(i)]
```

If the user has attributes NOT in the policy, those B[j]·ω[j] terms are subtracted in keygen but NEVER added back in decryption!

## THE FIX

**Keygen should only subtract B[i]·ω[i] for attributes that could appear in ANY policy!**

But we don't know future policies during keygen. The solution:

### Option 1: Don't subtract B terms at all
```c
target[0] = β  (NO subtraction)
A·ω_A = β
```

Then in decryption, ensure the B terms sum to zero by proper policy construction.

### Option 2: Use IBE-style construction
Each attribute gets its own "identity-like" handling where:
```c
// For attribute with index attr_idx:
A_attr = [A | B_plus[attr_idx]]  // Augmented matrix
// Sample ω such that A_attr · ω ≈ β
```

But this requires separate keys per attribute, not compatible with CP-ABE.

### Option 3: **CORRECT APPROACH - Match Paper Design**

The paper's CP-ABE uses:
- **Keygen:** Sample ω_A such that `A·ω_A = β` (NO B term subtraction!)
- **Keygen:** Sample each ω_i such that `B[i]·ω_i ≈ 0` (using a trapdoor for B[i])
- **Result:** Clean decryption without term cancellation issues

But we don't have trapdoors for B matrices. So we can't make B[i]·ω[i] ≈ 0.

### Option 4: **WORKING SOLUTION - Policy-Specific Keys**

What if we only subtract B terms for attributes **actually in the current policy**?

NO - this requires knowing the policy during keygen, defeating CP-ABE's purpose.

### Option 5: **SIMPLEST FIX - Just use β**

```c
// In keygen:
target[0] = β  // Don't subtract anything

// In decryption:
// We get: β·s[0] - Σ(user)B[j]·ω[j]·s[0] + Σ(policy)coeff[i]·B[ρ(i)]·ω[ρ(i)]·s[0]

// This equals β·s[0] IF:
//   Σ(user)B[j]·ω[j] = Σ(policy)coeff[i]·B[ρ(i)]·ω[ρ(i)]
```

This won't work either because the left side has all user attrs, right side only policy attrs.

## CORRECT SOLUTION

After studying the Module-LWE CP-ABE paper more carefully:

The keygen target should be computed **per-policy**, not globally! But that breaks CP-ABE.

Actually, looking at real lattice CP-ABE schemes (like Boyen 2013, Boneh et al.), they:
1. Use **dual Regev encryption** where ct = (c_0, c_1) with c_1 containing the message
2. The B matrices have trapdoors or are constructed specially
3. OR they use a different algebraic structure

Our current approach is mixing IBE-style (A·ω = target) with CP-ABE (multiple attributes).

## THE REAL FIX

Looking at the encryption code again - **C[i] uses only s[0]**, not the full s vector!

So the scheme should be:
- s is D-dimensional, but only s[0] matters for the secret
- C[i] = B[ρ(i)] · s[0] + e[i]  ✓ (current)
- ct_key = β · s[0] + e + encode(K)  ✓ (current)

For decryption to recover β·s[0]:
```
ω_A · C0 + Σcoeff[i]·ω[ρ(i)]·C[i]
= (A·ω_A)·s + Σcoeff[i]·(B[ρ(i)]·ω[ρ(i)])·s[0]
= (A·ω_A)[0]·s[0] + 0 + Σcoeff[i]·(B[ρ(i)]·ω[ρ(i)])·s[0]
= s[0]·((A·ω_A)[0] + Σcoeff[i]·B[ρ(i)]·ω[ρ(i)])

This equals β·s[0] IF:
  (A·ω_A)[0] = β - Σcoeff[i]·B[ρ(i)]·ω[ρ(i)]
```

But (A·ω_A)[0] is fixed at keygen time! We can't adjust it per-policy!

**CONCLUSION:** The current design is fundamentally broken because:
1. Keygen sets A·ω_A based on user's attributes
2. Decryption needs it based on policy's attributes
3. These don't match when user has extra attributes

**THE ONLY FIX:** Keygen must NOT subtract B terms:
```c
A · ω_A = β  (no B term subtraction)
```

And accept that B[i]·ω[i] will be small noise (not zero), increasing the error budget.
