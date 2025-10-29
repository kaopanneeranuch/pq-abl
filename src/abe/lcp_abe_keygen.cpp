#include "../../include/abe/lcp_abe.h"
#include <iostream>
#include <openssl/rand.h>

// include Module_BFRS params to determine buffer sizes
#include "../../module_gaussian_lattice/Module_BFRS/common.h"

// forward-declare glue function
namespace pq_abl { namespace glue {
    int sample_pre_wrap(const std::vector<uint8_t> &A_buf, const std::vector<uint8_t> &T_buf,
                        const std::vector<uint8_t> &cplx_T_buf, const std::vector<uint8_t> &sch_comp_buf,
                        const std::vector<uint8_t> &h_inv_buf, const std::vector<uint8_t> &u_buf,
                        std::vector<uint8_t> &x_out);
    int multiply_matrix_vector_wrap(const std::vector<uint8_t> &B_buf, const std::vector<uint8_t> &x_buf, std::vector<uint8_t> &y_out);
} }

// Phase 2: Key generation stub. Samples per-attribute omegas and computes omega_A via trapdoor sampler.

namespace pq_abl {

int lcp_abe_keygen(const MSK &msk, const MPK &mpk, const std::vector<std::string>& user_attrs, SK &sk) {
    std::cout << "lcp_abe_keygen: starting, attrs=" << user_attrs.size() << "\n";

    // Basic checks
    if (msk.T_A.empty() || mpk.A.empty() || msk.u.empty()) {
        std::cerr << "lcp_abe_keygen: missing MSK/MPK components\n";
        return -1;
    }

    // size for h_inv is PARAM_N * sizeof(scalar)
    size_t h_inv_bytes = (size_t) PARAM_N * sizeof(scalar);

    for (const auto &attr : user_attrs) {
        // generate random target h_inv for this attribute
        std::vector<uint8_t> h_inv(h_inv_bytes);
        if (RAND_bytes(h_inv.data(), (int)h_inv.size()) != 1) {
            std::cerr << "lcp_abe_keygen: RAND_bytes failed\n";
            return -2;
        }

        std::vector<uint8_t> omega_i;
        int rc = pq_abl::glue::sample_pre_wrap(mpk.A, msk.T_A, msk.cplx_T, msk.sch_comp, h_inv, msk.u, omega_i);
        if (rc != 0) {
            std::cerr << "lcp_abe_keygen: sample_pre_wrap failed for attr=" << attr << " rc=" << rc << "\n";
            return rc;
        }

        // store omega_i in SK map
        sk.omegas[attr] = std::move(omega_i);
    }

    // Compute the true target h_inv = beta - sum_{i in attrs} B_pos[attr] .* omega_i  (element-wise mod q)
    // Note: We use an element-wise product and reduction as a practical/matching-size target.
    if (mpk.beta.size() != h_inv_bytes) {
        std::cerr << "lcp_abe_keygen: mpk.beta has unexpected size\n";
        return -7;
    }

    // initialize h_inv to beta
    std::vector<uint8_t> h_inv_beta = mpk.beta;

    // helper to interpret bytes as scalars (little-endian uint32)
    auto to_scalar = [](const uint8_t *b) -> uint32_t {
        uint32_t v; memcpy(&v, b, sizeof(uint32_t)); return v;
    };
    auto from_scalar = [](uint32_t v, uint8_t *out) {
        memcpy(out, &v, sizeof(uint32_t));
    };

    // subtract contributions of each attribute using full matrix-vector multiplication:
    // y = B_pos[attr] * omega_i  (y is PARAM_D polynomials -> serialized size PARAM_N * PARAM_D)
    // fold y into a single polynomial by summing the d component polynomials elementwise, then subtract from beta
    for (const auto &attr : user_attrs) {
        auto it = sk.omegas.find(attr);
        if (it == sk.omegas.end()) continue; // should not happen
        const std::vector<uint8_t> &omega_blob = it->second;
        const std::vector<uint8_t> &B = mpk.B_pos.at(attr);

        // compute y = B * omega_blob using glue helper
        std::vector<uint8_t> y_buf;
        int mrc = pq_abl::glue::multiply_matrix_vector_wrap(B, omega_blob, y_buf);
        if (mrc != 0) {
            std::cerr << "lcp_abe_keygen: multiply_matrix_vector_wrap failed for attr=" << attr << " rc=" << mrc << "\n";
            return mrc;
        }

        // y_buf should be PARAM_N * PARAM_D scalars; fold into single polynomial by summing component polynomials
        if (y_buf.size() != h_inv_bytes * (size_t) PARAM_D) {
            std::cerr << "lcp_abe_keygen: unexpected y_buf size for attr=" << attr << "\n";
            return -10;
        }

        for (size_t off = 0; off < h_inv_bytes; off += sizeof(scalar)) {
            uint64_t acc = 0;
            for (int j = 0; j < PARAM_D; ++j) {
                size_t idx = off + (size_t) j * h_inv_bytes;
                uint32_t wj; memcpy(&wj, y_buf.data() + idx, sizeof(uint32_t));
                acc += (uint64_t) (wj % PARAM_Q);
            }
            uint32_t acc_red = (uint32_t)(acc % (uint64_t) PARAM_Q);
            uint32_t cur; memcpy(&cur, h_inv_beta.data() + off, sizeof(uint32_t));
            uint32_t next = (cur + PARAM_Q - acc_red) % PARAM_Q;
            memcpy(h_inv_beta.data() + off, &next, sizeof(uint32_t));
        }
    }

    // call sample_pre_wrap with computed h_inv_beta to obtain omega_A
    std::vector<uint8_t> omega_A;
    int rc2 = pq_abl::glue::sample_pre_wrap(mpk.A, msk.T_A, msk.cplx_T, msk.sch_comp, h_inv_beta, msk.u, omega_A);
    if (rc2 != 0) {
        std::cerr << "lcp_abe_keygen: sample_pre_wrap failed for omega_A rc=" << rc2 << "\n";
        return rc2;
    }
    sk.omega_A = std::move(omega_A);

    std::cout << "lcp_abe_keygen: key generation complete, produced omega_A size=" << sk.omega_A.size() << " bytes\n";
    return 0;
}

} // namespace pq_abl
