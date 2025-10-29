#include "../../include/batch/microbatch.h"
#include <iostream>
#include "../../include/crypto/sha3.h"

namespace pq_abl::batch {

MicroBatch::MicroBatch() {}
MicroBatch::~MicroBatch() {}

void MicroBatch::add(const std::vector<uint8_t> &ct_obj, const std::string &policy_id) {
    BatchEntry e;
    e.ct_obj = ct_obj;
    e.policy_id = policy_id;
    // digest will be computed on flush
    entries.push_back(std::move(e));
}

std::vector<std::vector<uint8_t>> MicroBatch::flush() {
    std::vector<std::vector<uint8_t>> digests;
    for (auto &e : entries) {
        // compute SHA3-256 digest of the serialized CT object
        if (e.ct_obj.empty()) {
            e.digest.clear();
        } else {
            e.digest = pq_abl::crypto::sha3_256(e.ct_obj.data(), e.ct_obj.size());
        }
        digests.push_back(e.digest);
    }
    entries.clear();
    std::cout << "MicroBatch: flushed " << digests.size() << " entries\n";
    return digests;
}

size_t MicroBatch::size() const { return entries.size(); }

} // namespace pq_abl::batch
