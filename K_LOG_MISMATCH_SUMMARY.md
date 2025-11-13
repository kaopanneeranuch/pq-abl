# K_log Mismatch Problem - Comprehensive Summary

## Problem Statement
`k_log` recovered during decryption does not match the original `k_log` used during encryption, causing AES-GCM authentication to fail.

## Current Status
- **Trapdoor relationship**: ✅ VERIFIED (holds during keygen)
- **Decryption formula**: Multiple attempts, still mismatch
- **Arithmetic consistency**: ✅ FIXED (`multiply_by_A` now uses `add_poly`)
- **Sampling adjustment**: ✅ FIXED (unconditional `A * p == u` adjustment)

---

## What We've Found

### 1. **Encryption Side** ✅
- **Formula**: `ct_key = β·s[0] + e_key + encode(K_log)`
- **Encoding**: `encode(K_log) = K_log << 22` (shift by PARAM_K - 8 = 22 bits)
- **Redundancy**: 3× encoding with spacing=16 (recently added)
- **Noise reduction**: `e0[0]` sampled with 0.5× sigma (recently added)
- **Domain**: Computes `β·s[0]` in CRT, converts to COEFF for encoding

### 2. **Decryption Side** ⚠️
- **Current formula**: 
  - Step 1: `(A·ω_A)[0]·C0[0]` where `C0[0] = s[0] + e0[0]`
  - Step 2: `Σ(coeff[j]·(B+_attr · ω[ρ(j)])·C0[0])`
  - Combined: `Step 1 + Step 2 ≈ β·C0[0] ≈ β·s[0] + β·e0[0]`
- **Extraction**: Averaging across 3 redundant positions
- **Issue**: Decryption recovers `β·C0[0] = β·s[0] + β·e0[0]`, but encryption uses `β·s[0]`
- **Noise term**: `β·e0[0]` is corrupting `k_log` extraction

### 3. **Trapdoor Relationship** ✅
- **Formula**: `(A·ω_A)[0] + Σ(B+_i · ω_i) ≈ β`
- **Status**: VERIFIED during keygen (first 16 coeffs match within noise)
- **Implication**: The relationship holds, so the issue is in how it's used during decryption

### 4. **Matrix Structure** ✅
- **A structure**: `A = [I_d | Ā]` (identity in first D columns)
- **C0 structure**: `C0 = A^T · s + e0`
  - First D components: `C0[0..D-1] = s[0..D-1] + e0[0..D-1]`
  - Last (M-D) components: `C0[D..M-1] = Ā^T · s + e0[D..M-1]`
- **C[i] structure**: `C[i] = B+_attr · s[0] + e_i` (uses only `s[0]`)

### 5. **Arithmetic Fixes Applied** ✅
- **`multiply_by_A`**: Changed from direct addition to `add_poly` for consistent reduction
- **`sample_pre_target`**: Adjustment `A * p == u` is now unconditional (was wrapped in ARITH_DEBUG)
- **Domain conversions**: All operations accumulate in CRT, convert to COEFF once at end

---

## Possible Root Causes (Narrowed Down)

### 🔴 **HIGH PROBABILITY**

#### 1. **Noise Magnitude Issue** (MOST LIKELY)
- **Problem**: `β·e0[0]` noise term is too large for `k_log` extraction
- **Evidence**: 
  - `k_log` is encoded in upper 22 bits (shift = 22)
  - Noise must be < 2^22 ≈ 4,194,304 to not corrupt high bits
  - `β` is a random polynomial, so `β·e0[0]` can have large coefficients
- **Diagnostic**: Check maximum coefficient magnitude of `β·e0[0]`
- **Possible solutions**:
  - Further reduce `e0[0]` noise (already at 0.5× sigma)
  - Increase encoding shift (reduce from 22 to smaller value)
  - Use error correction codes instead of simple redundancy

#### 2. **Decryption Formula Mismatch**
- **Problem**: Decryption computes `β·C0[0]` but encryption uses `β·s[0]`
- **Evidence**: 
  - `C0[0] = s[0] + e0[0]`, so `β·C0[0] = β·s[0] + β·e0[0]`
  - The `β·e0[0]` term is the mismatch
- **Possible solutions**:
  - Find a way to extract `s[0]` from `C0[0]` (impossible without trapdoor)
  - Use a different decryption formula that cancels `e0[0]` noise
  - Accept approximate recovery and use better error correction

#### 3. **Domain Conversion Rounding Errors**
- **Problem**: Multiple CRT ↔ COEFF conversions may accumulate rounding errors
- **Evidence**: 
  - Encryption: CRT → COEFF once
  - Decryption: Multiple conversions in Step 1 and Step 2
- **Status**: Already optimized to accumulate in CRT, convert once
- **Possible solutions**:
  - Verify all conversions use same rounding mode
  - Check if `coeffs_representation` and `crt_representation` are exact inverses

### 🟡 **MEDIUM PROBABILITY**

#### 4. **Coefficient Reconstruction Issues**
- **Problem**: LSSS coefficients might not be computed correctly
- **Evidence**: Step 2 uses `coeff[j]` from `lsss_compute_coefficients`
- **Check**: Verify coefficients sum to 1 and satisfy LSSS reconstruction

#### 5. **Polynomial Reduction Inconsistencies**
- **Problem**: Different reduction paths might yield different results
- **Evidence**: 
  - `add_poly` reduces mod Q immediately
  - `freeze_poly` uses `reduce_naive` (x % Q)
  - Direct addition might wrap around
- **Status**: Fixed `multiply_by_A` to use `add_poly`
- **Check**: Verify all polynomial operations use consistent reduction

#### 6. **Trapdoor Relationship Only Holds for [0] Component**
- **Problem**: `(A·ω_A)[0] + Σ(B+_i · ω_i) ≈ β` only applies to first component
- **Evidence**: 
  - `(A·ω_A)[i] ≠ 0` for `i > 0` (confirmed in diagnostics)
  - This means `(A·ω_A)·s` includes contributions from `s[1..D-1]`
- **Status**: Already using `(A·ω_A)[0]·C0[0]` to extract only [0] component
- **Check**: Verify that Step 2 also uses only [0] component correctly

### 🟢 **LOW PROBABILITY**

#### 7. **Sampling Errors**
- **Problem**: Gaussian sampling might introduce errors
- **Evidence**: Trapdoor relationship verified, so sampling is correct
- **Status**: Adjustment `A * p == u` is unconditional

#### 8. **Parameter Selection**
- **Problem**: `PARAM_SIGMA`, `PARAM_Q`, `PARAM_K` might be incompatible
- **Check**: Verify parameters are appropriate for Module-LWE security and noise tolerance

---

## What We've Tried

### ✅ **Attempts That Didn't Work**
1. **Full inner product `ω_A·C0`**: Includes all D components, not just `s[0]`
2. **`(A·ω_A)[0]·C0[0]`**: Correct formula but noise `β·e0[0]` still corrupts
3. **Reduced `e0[0]` noise (0.5× sigma)**: Still mismatch
4. **Redundant encoding (3×)**: Still mismatch
5. **Step 2 using `C[i]` vs `C0[0]`**: Both tried, still mismatch

### ✅ **Fixes Applied**
1. **Arithmetic consistency**: `multiply_by_A` now uses `add_poly`
2. **Sampling adjustment**: Unconditional `A * p == u`
3. **Domain optimization**: Accumulate in CRT, convert once

---

## Next Steps to Narrow Down

### 1. **Measure Noise Magnitude** 🔍
```c
// In decryption, after computing decryption_term:
// Measure |β·e0[0]| = |decryption_term - β·s[0]|
// Check if max coefficient > 2^22
```

### 2. **Compare Encryption vs Decryption** 🔍
- Print `β·s[0]` from encryption side
- Print `decryption_term` from decryption side
- Compute difference and analyze magnitude

### 3. **Verify Encoding/Decoding** 🔍
- Check if encoding shift (22 bits) is appropriate
- Verify extraction rounding is correct
- Test with known `k_log` values

### 4. **Check Parameter Compatibility** 🔍
- Verify `PARAM_SIGMA` is appropriate for `PARAM_Q`
- Check if noise tolerance matches encoding scheme
- Consider increasing `PARAM_K` to allow larger shift

### 5. **Alternative Decryption Formula** 🔍
- Try: `ω_A·C0 + Σ(coeff[j]·ω[ρ(j)]·C[j])` (standard CP-ABE)
- Verify if this gives better noise cancellation

---

## Key Questions to Answer

1. **Q**: What is the maximum coefficient magnitude of `β·e0[0]`?
   - **A**: Need to measure during decryption

2. **Q**: Is the noise `β·e0[0]` larger than 2^22?
   - **A**: If yes, it will corrupt the high bits where `k_log` is encoded

3. **Q**: Can we eliminate or reduce `β·e0[0]`?
   - **A**: Not directly, but we can:
     - Reduce `e0[0]` further (already at 0.5×)
     - Use better error correction
     - Increase encoding shift (if parameters allow)

4. **Q**: Is the decryption formula fundamentally correct?
   - **A**: Mathematically yes, but noise makes it approximate
     - `β·C0[0] = β·s[0] + β·e0[0]` is correct
     - The issue is that `β·e0[0]` is too large

5. **Q**: Should we use a different encoding scheme?
   - **A**: Possibly - consider:
     - Error correction codes (Reed-Solomon, etc.)
     - Larger shift (if parameters allow)
     - Multiple independent encodings with voting

---

## Recommended Diagnostic Steps

1. **Add noise measurement** in decryption:
   ```c
   // After computing decryption_term
   // Estimate β·e0[0] magnitude
   // Print max coefficient and compare with 2^22
   ```

2. **Compare encryption β·s[0] with decryption_term**:
   ```c
   // In encryption: print β·s[0] (first 4 coeffs)
   // In decryption: print decryption_term (first 4 coeffs)
   // Compute difference
   ```

3. **Test with zero noise**:
   ```c
   // Temporarily set e0[0] = 0 in encryption
   // See if k_log recovers correctly
   // This confirms noise is the issue
   ```

4. **Check encoding extraction**:
   ```c
   // Print recovered values before rounding
   // Verify rounding is correct
   // Check if averaging across redundant positions helps
   ```

---

## Conclusion

The **most likely root cause** is that **`β·e0[0]` noise is too large** for the current encoding scheme (22-bit shift). Even with reduced `e0[0]` noise (0.5× sigma) and redundant encoding, the noise magnitude might still exceed the tolerance.

**Next actions**:
1. Measure actual noise magnitude `|β·e0[0]|`
2. Compare with encoding tolerance (2^22)
3. If noise is too large, consider:
   - Further noise reduction
   - Better error correction
   - Parameter adjustment
   - Alternative encoding scheme

