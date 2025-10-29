#ifndef MICROBATCH_H
#define MICROBATCH_H

#include <vector>
#include <string>
#include <cstdint>

namespace pq_abl::batch {

// Simple in-memory micro-batch controller (stub). Collects CTObj serialized blobs
// and exposes a flush interface for committing a batch.

struct BatchEntry {
    std::vector<uint8_t> ct_obj; // serialized CT_obj bytes
    std::vector<uint8_t> digest; // SHA3-256 digest placeholder
    std::string policy_id;
};

class MicroBatch {
public:
    MicroBatch();
    ~MicroBatch();

    // Add a CT object to the current micro-batch
    void add(const std::vector<uint8_t> &ct_obj, const std::string &policy_id);

    // Flush the current batch: compute digests, return vector of digests
    std::vector<std::vector<uint8_t>> flush();

    // Current size of batch
    size_t size() const;

private:
    std::vector<BatchEntry> entries;
};

} // namespace pq_abl::batch

#endif // MICROBATCH_H
