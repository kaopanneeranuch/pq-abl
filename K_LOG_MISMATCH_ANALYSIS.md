# K_log Mismatch Problem Analysis

## Core Issue

**Problem**: `k_log` recovered during decryption does not match the original `k_log` used during encryption, causing AES-GCM authentication to fail.

## Root Cause

The fundamental issue is:
- **Encryption computes**: `ct_key = β·s[0] + e_key + encode(K_log)`
- **Decryption computes**: `decryption_term = β·C0[0] = β·s[0] + β·e0[0]`
- **After subtraction**: `recovered = ct_key - decryption_term = e_key + encode(K_log) - β·e0[0]`

The **noise term `-β·e0[0]`** is corrupting `k_log` extraction.

## Why This Happens

1. **We cannot access `s[0]` directly during decryption**
   - We only have `C0[0] = s[0] + e0[0]` (noisy version)
   - `e0[0]` is Gaussian noise sampled during encryption

2. **The trapdoor relationship**
   - `(A·ω_A)[0] + Σ(B+_i · ω_i)[0] ≈ β`
   - This gives us `β`, but when we multiply by `C0[0]`, we get `β·C0[0] = β·s[0] + β·e0[0]`

3. **The standard CP-ABE formula should work**
   - `ω_A·C0 + Σ(coeff[j]·ω[ρ(j)]·C[j]) ≈ β·s[0]` (approximately, within noise)
   - But we need to verify this is correctly implemented

## What We've Tried

### Attempt 1: `(A·ω_A)[0]·C0[0]` for Step 1
- **Result**: `decryption_term = β·C0[0] = β·s[0] + β·e0[0]`
- **Problem**: Includes exact noise term `β·e0[0]`

### Attempt 2: `ω_A·C0` (full inner product) for Step 1
- **Result**: `decryption_term = (A·ω_A)·s + ω_A·e0`
- **Theory**: Should approximate `β·s[0]` better because `ω_A·e0` is small Gaussian noise
- **Status**: Still mismatch (may need verification)

### Attempt 3: Step 2 variations
- Tried `(B+_attr · ω_attr)[0]·C0[0]` → same noise issue
- Reverted to `ω[ρ(j)]·C[j]` (original formula)

## Possible Root Causes (Narrowed Down)

### 1. **Noise Magnitude Issue** ⚠️ MOST LIKELY
   - The noise `β·e0[0]` might be too large
   - `k_log` is encoded in high 22 bits (shifted by `PARAM_K - 8 = 22`)
   - If `β·e0[0]` affects these high bits, `k_log` will be corrupted
   - **Check**: What is the magnitude of `β·e0[0]`? Is it small enough?

### 2. **Incorrect Decryption Formula** ⚠️ LIKELY
   - The formula `ω_A·C0 + Σ(coeff[j]·ω[ρ(j)]·C[j])` should recover `β·s[0]`
   - But `(A·ω_A)·s` includes contributions from all D components of `s`, not just `s[0]`
   - **Question**: Does `(A·ω_A)·s` equal `β·s[0]` or `β·s` (vector)?
   - **Check**: Verify the mathematical relationship

### 3. **Domain Conversion Issues** ⚠️ POSSIBLE
   - Encryption: accumulates in CRT, converts to COEFF once
   - Decryption: accumulates in CRT, converts to COEFF once
   - **Check**: Are the conversions identical? Any rounding differences?

### 4. **Trapdoor Relationship Not Exact** ⚠️ POSSIBLE
   - `(A·ω_A)[0] + Σ(B+_i · ω_i)[0] ≈ β` (approximate, not exact)
   - The approximation error might accumulate
   - **Check**: How close is the trapdoor relationship? What's the error?

### 5. **Polynomial Arithmetic Errors** ⚠️ LESS LIKELY
   - `multiply_by_A`, `mul_crt_poly`, `reduce_double_crt_poly` might have bugs
   - **Check**: Verified trapdoor relationship holds, so arithmetic seems correct

## Diagnostic Evidence

From terminal output:
- `ct_key before K_log encoding` = `β·s[0] + e_key` = `[0]=440554503`
- `decryption_term` = `β·C0[0]` = `[0]=140619863`
- **Difference**: `299934640` (very large!)
- This suggests `β·e0[0]` is significant

## Next Steps to Narrow Down

1. **Measure noise magnitude**: Compute `β·e0[0]` directly and check if it's small enough
2. **Verify decryption formula**: Check if `ω_A·C0 + Σ(...)` actually equals `β·s[0]`
3. **Compare with encryption**: Print `β·s[0]` from encryption and compare with `decryption_term`
4. **Check noise parameters**: Verify `PARAM_SIGMA` is appropriate for the encoding scheme

## Key Questions

1. **Q**: Should `decryption_term` equal `β·s[0]` exactly or approximately?
   - **A**: Approximately (within noise tolerance)

2. **Q**: What is the noise tolerance for `k_log` extraction?
   - **A**: `k_log` is in high 22 bits, so noise must be < 2^22

3. **Q**: Does `ω_A·C0` compute `β·s[0]` or `β·s`?
   - **A**: Need to verify mathematically - `(A·ω_A)·s` is inner product over D components

4. **Q**: Can we eliminate `β·e0[0]` somehow?
   - **A**: Not directly, but the standard formula should minimize its impact

