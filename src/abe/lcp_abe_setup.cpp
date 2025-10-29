#include "../../include/abe/lcp_abe.h"
#include "../../include/util/rng.h"
#include "../../include/crypto/sha3.h"
#include <openssl/rand.h>
#include <iostream>

static std::vector<uint8_t> derive_attribute_component(const std::vector<uint8_t> &A_buf, const std::string &attr, const std::string &tag, size_t out_len) {
    // Deterministically derive out_len bytes from A||attr||tag using repeated SHA3-256
    std::vector<uint8_t> out;
    auto state = pq_abl::crypto::sha3_256(A_buf.data(), A_buf.size());
    size_t pos = 0;
    while (out.size() < out_len) {
        // mix attr and tag
        std::string s;
        s.reserve(state.size() + attr.size() + tag.size() + 16);
        s.append((const char*)state.data(), state.size());
        s += attr;
        s += tag;
        s += std::to_string(pos);
        auto h = pq_abl::crypto::sha3_256((const uint8_t*)s.data(), s.size());
        out.insert(out.end(), h.begin(), h.end());
        pos++;
        state = h;
    }
    out.resize(out_len);
    return out;
}

// Phase 1: Setup - call into Module_BFRS trapdoor generation via glue.

namespace pq_abl {

// forward-declare glue function (implemented in src/glue)
namespace glue { 
    int mtrapgen_wrap(const uint8_t *seed, size_t seed_len, std::vector<uint8_t> &A_out, std::vector<uint8_t> &T_out,
                      std::vector<uint8_t> &cplx_T_out, std::vector<uint8_t> &sch_comp_out, std::vector<uint8_t> &u_out);
}

int lcp_abe_setup(const std::vector<std::string>& attributes, const std::vector<uint8_t>& seed, MPK &mpk, MSK &msk) {
    (void)seed;
    std::cout << "lcp_abe_setup: calling Module_BFRS Setup, seed len=" << seed.size() << "\n";

    std::vector<uint8_t> A_buf, T_buf, cplx_T_buf, sch_comp_buf, u_buf;
    int rc = pq_abl::glue::mtrapgen_wrap(seed.empty() ? nullptr : seed.data(), seed.size(), A_buf, T_buf, cplx_T_buf, sch_comp_buf, u_buf);
    if (rc != 0) {
        std::cerr << "mtrapgen_wrap failed: " << rc << "\n";
        return rc;
    }

    mpk.A = std::move(A_buf);
    // beta not produced by Module_BFRS Setup; leave empty or compute separately later
    mpk.beta.clear();

    msk.T_A = std::move(T_buf);
    msk.cplx_T = std::move(cplx_T_buf);
    msk.sch_comp = std::move(sch_comp_buf);
    msk.u = std::move(u_buf);

    // derive per-attribute public components B_i^+ and B_i^- as random matrices (scalars) of length PARAM_N
    // and derive a random beta vector (target) of length PARAM_N. These are stored as serialized scalar arrays
    // (little-endian uint32 per scalar). This is a practical representation compatible with the sampler's h_inv size.
    size_t scalar_bytes = sizeof(scalar);
    size_t b_size = (size_t) PARAM_N * scalar_bytes;

    mpk.beta.resize(b_size);
    if (RAND_bytes(mpk.beta.data(), (int)mpk.beta.size()) != 1) {
        std::cerr << "lcp_abe_setup: RAND_bytes failed for beta\n";
        return -4;
    }

    for (const auto &attr : attributes) {
        mpk.B_pos[attr].resize(b_size);
        mpk.B_neg[attr].resize(b_size);
        if (RAND_bytes(mpk.B_pos[attr].data(), (int)mpk.B_pos[attr].size()) != 1) {
            std::cerr << "lcp_abe_setup: RAND_bytes failed for B_pos\n";
            return -5;
        }
        if (RAND_bytes(mpk.B_neg[attr].data(), (int)mpk.B_neg[attr].size()) != 1) {
            std::cerr << "lcp_abe_setup: RAND_bytes failed for B_neg\n";
            return -6;
        }
    }

    std::cout << "lcp_abe_setup: Setup complete, A size=" << mpk.A.size() << ", T size=" << msk.T_A.size() << ", attributes=" << attributes.size() << "\n";
    return 0;
}

} // namespace pq_abl
