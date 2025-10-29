#ifndef PQ_ABL_RNG_H
#define PQ_ABL_RNG_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pq_abl::util {

// Simple CSPRNG abstraction. Implement with a real CSPRNG (getrandom/OpenSSL/etc.)

// Fill 'out' with 'len' random bytes. Returns 0 on success.
int csprng_random(uint8_t *out, size_t len);

// Deterministic seed expansion for KATs/tests. Expand seed into len bytes.
int csprng_expand_from_seed(const uint8_t *seed, size_t seed_len, uint8_t *out, size_t len);

} // namespace pq_abl::util

#endif // PQ_ABL_RNG_H