# Memory Corruption Fix - KeyGen Phase

## Problem
Segmentation fault in `test_keygen` with error:
```
free(): invalid next size (normal)
Aborted (core dumped)
```

## Root Cause
**Incorrect matrix indexing** when accessing B_plus attribute vectors.

### Matrix Storage Layout
B_plus is allocated as a **flat 1D array**:
```c
// In mpk_init():
mpk->B_plus = calloc(n_attributes * PARAM_M * PARAM_N, sizeof(scalar));
```

**Layout**: `[attr0_poly0...attr0_polyM, attr1_poly0...attr1_polyM, ...]`
- Total size: `n_attributes × PARAM_M × PARAM_N` scalars
- Each attribute row: `PARAM_M × PARAM_N` scalars (128 polynomials of 256 coefficients)

### The Bug
Files were using **WRONG** macro parameter:

❌ **WRONG**:
```c
poly_matrix_element(mpk->B_plus, n_attributes, attr_idx, 0)
// Expands to: &B_plus[PARAM_N * (attr_idx * n_attributes + 0)]
// With n_attributes=128: &B_plus[attr_idx * 128 * 256]
// This is WRONG! Each row is 128*256, not just 128!
```

The macro `poly_matrix_element(M, nb_col, i, j)` means:
- `M` = base pointer
- `nb_col` = number of COLUMNS in the matrix
- `i` = row index
- `j` = column index
- Formula: `&M[PARAM_N * (i * nb_col + j)]`

For B_plus:
- Each row (attribute) has `PARAM_M` columns (polynomials)
- So `nb_col` should be `PARAM_M`, NOT `n_attributes`!

✅ **CORRECT**:
```c
poly_matrix B_plus_i = &mpk->B_plus[attr_idx * PARAM_M * PARAM_N];
// Direct offset calculation
// With PARAM_M=128, PARAM_N=256: attr_idx * 32768 scalars per attribute
```

## Files Fixed

### 1. `lcp-abe/setup/lcp_setup.c`
**Before**:
```c
poly_matrix B_plus_i = poly_matrix_element(mpk->B_plus, n_attributes, i, 0);
```

**After**:
```c
poly_matrix B_plus_i = &mpk->B_plus[i * PARAM_M * PARAM_N];
```

### 2. `lcp-abe/keygen/lcp_keygen.c`
**Before**:
```c
poly_matrix B_plus_i = poly_matrix_element(mpk->B_plus, PARAM_M, attr->index, 0);
```

**After**:
```c
poly_matrix B_plus_i = &mpk->B_plus[attr->index * PARAM_M * PARAM_N];
```

### 3. `lcp-abe/encrypt/lcp_encrypt.c`
**Before**:
```c
poly_matrix B_plus_attr = poly_matrix_element(mpk->B_plus, PARAM_M, attr_idx, 0);
```

**After**:
```c
poly_matrix B_plus_attr = &mpk->B_plus[attr_idx * PARAM_M * PARAM_N];
```

## Added Debugging

### Setup Phase
```c
printf("[Setup]   B_plus layout: %d attributes × %d polynomials = %d total polys\n",
       n_attributes, PARAM_M, n_attributes * PARAM_M);
printf("[Setup]     Attribute %d: B_plus offset=%lu, B_minus offset=%lu\n", ...);
```

### KeyGen Phase
```c
printf("[KeyGen]   Memory allocated: target=%p, sum_term=%p\n", ...);
printf("[KeyGen]   MPK has %d attributes, PARAM_M=%d, PARAM_N=%d\n", ...);
printf("[KeyGen]       Accessing B_plus[%d] = offset %d scalars\n", ...);
printf("[KeyGen]       B_plus_i address: %p\n", ...);
printf("[KeyGen]       Computing dot product over %d polynomials\n", PARAM_M);
```

### Encrypt Phase
```c
printf("[Encrypt]     B_plus_attr offset: %lu scalars\n", ...);
```

## Expected Output After Fix

```
[KeyGen]   Computing Σ(B+_i · ωi)...
[KeyGen]   MPK has 128 attributes, PARAM_M=128, PARAM_N=256
[KeyGen]     Processing attribute 1/2 (index 0): user_role:admin
[KeyGen]       Accessing B_plus[0] = offset 0 scalars
[KeyGen]       B_plus_i address: 0x...
[KeyGen]       Computing dot product over 128 polynomials
[KeyGen]     Attribute 1 processed successfully
[KeyGen]     Processing attribute 2/2 (index 1): team:storage-team
[KeyGen]       Accessing B_plus[1] = offset 32768 scalars
[KeyGen]       Computing dot product over 128 polynomials
[KeyGen]     Attribute 2 processed successfully
```

## Memory Safety Checks Added

1. **Attribute index validation**: Check `attr->index < mpk->n_attributes`
2. **NULL pointer checks**: Verify memory allocations succeed
3. **Detailed logging**: Track memory addresses and offsets
4. **Error cleanup**: Proper free() on error paths

## Rebuild and Test

```bash
cd ~/pq-abl
rm -rf build
mkdir build && cd build
cmake -DUSE_OPENSSL=ON ..
make -j$(nproc)
cd ..
./test_all.sh
```

Should now complete KeyGen without segfault!
