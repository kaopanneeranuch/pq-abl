#ifndef PQ_ABL_SHA3_H
#define PQ_ABL_SHA3_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pq_abl::crypto {

// Compute SHA3-256 digest of input buffer
std::vector<uint8_t> sha3_256(const uint8_t *in, size_t in_len);

} // namespace pq_abl::crypto

#endif // PQ_ABL_SHA3_H
