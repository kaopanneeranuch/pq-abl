// Glue wrappers to call Module_BFRS functions: Setup and sample_pre_target

#include <vector>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <cstring>

extern "C" {
    // Module_BFRS public functions (declared in ibe.h / sampling.h)
    void Setup(scalar *A, scalar *T, cplx *cplx_T, cplx *sch_comp, scalar *u);
    void sample_pre_target(scalar *x, scalar *A_m, scalar *T, cplx *cplx_T, cplx *sch_comp, scalar *h_inv, scalar *u);
}

// Include common.h types
#include "../../module_gaussian_lattice/Module_BFRS/common.h"
// include arithmetic header to access multiply_by_A signature
#include "../../module_gaussian_lattice/Module_BFRS/arithmetic.h"

namespace pq_abl::glue {

// Serialize a buffer of scalars (uint32_t) into bytes (little-endian)
static void serialize_scalars_to_bytes(const scalar *in, size_t count, std::vector<uint8_t> &out) {
    out.resize(count * sizeof(scalar));
    for (size_t i = 0; i < count; ++i) {
        uint32_t v = (uint32_t) in[i];
        std::memcpy(out.data() + i * sizeof(uint32_t), &v, sizeof(uint32_t));
    }
}

// Serialize complex double (cplx) array into bytes (real+imag doubles)
static void serialize_cplx_to_bytes(const cplx *in, size_t count, std::vector<uint8_t> &out) {
    out.resize(count * sizeof(cplx));
    std::memcpy(out.data(), in, count * sizeof(cplx));
}

// mtrapgen_wrap: calls Setup and returns serialized A, T, cplx_T, sch_comp and u
int mtrapgen_wrap(const uint8_t * /*seed*/, size_t /*seed_len*/, std::vector<uint8_t> &A_out, std::vector<uint8_t> &T_out,
                   std::vector<uint8_t> &cplx_T_out, std::vector<uint8_t> &sch_comp_out, std::vector<uint8_t> &u_out) {

    // allocate buffers using sizes from common.h (same as timing.c)
    size_t A_coeffs_count = (size_t) PARAM_N * PARAM_D * (PARAM_M - PARAM_D);
    size_t T_coeffs_count = (size_t) PARAM_N * 2 * PARAM_D * PARAM_D * PARAM_K;
    size_t sch_comp_count = (size_t) PARAM_N * PARAM_D * (2 * PARAM_D + 1);
    size_t cplx_T_count = (size_t) PARAM_N * 2 * PARAM_D * PARAM_D * PARAM_K;
    size_t u_count = (size_t) PARAM_D * PARAM_N;

    scalar *A_coeffs = (scalar*) malloc(A_coeffs_count * sizeof(scalar));
    scalar *T_coeffs = (scalar*) malloc(T_coeffs_count * sizeof(scalar));
    cplx  *sch_comp_coeffs = (cplx*) malloc(sch_comp_count * sizeof(cplx));
    cplx  *cplx_T_coeffs = (cplx*) malloc(cplx_T_count * sizeof(cplx));
    scalar *u_coeffs = (scalar*) malloc(u_count * sizeof(scalar));

    if (!A_coeffs || !T_coeffs || !sch_comp_coeffs || !cplx_T_coeffs || !u_coeffs) {
        free(A_coeffs); free(T_coeffs); free(sch_comp_coeffs); free(cplx_T_coeffs); free(u_coeffs);
        return -1;
    }

    // Call the Module_BFRS Setup to fill these buffers
    Setup(A_coeffs, T_coeffs, cplx_T_coeffs, sch_comp_coeffs, u_coeffs);

    // Serialize outputs into byte vectors
    serialize_scalars_to_bytes(A_coeffs, A_coeffs_count, A_out);
    serialize_scalars_to_bytes(T_coeffs, T_coeffs_count, T_out);
    serialize_cplx_to_bytes(cplx_T_coeffs, cplx_T_count, cplx_T_out);
    serialize_cplx_to_bytes(sch_comp_coeffs, sch_comp_count, sch_comp_out);
    serialize_scalars_to_bytes(u_coeffs, u_count, u_out);

    free(A_coeffs); free(T_coeffs); free(sch_comp_coeffs); free(cplx_T_coeffs); free(u_coeffs);
    return 0;
}

// sample_pre_wrap: deserialize inputs, call sample_pre_target and serialize output x
int sample_pre_wrap(const std::vector<uint8_t> &A_buf, const std::vector<uint8_t> &T_buf,
                    const std::vector<uint8_t> &cplx_T_buf, const std::vector<uint8_t> &sch_comp_buf,
                    const std::vector<uint8_t> &h_inv_buf, const std::vector<uint8_t> &u_buf,
                    std::vector<uint8_t> &x_out) {

    // compute counts (must match serialization done above)
    size_t A_coeffs_count = (size_t) PARAM_N * PARAM_D * (PARAM_M - PARAM_D);
    size_t T_coeffs_count = (size_t) PARAM_N * 2 * PARAM_D * PARAM_D * PARAM_K;
    size_t sch_comp_count = (size_t) PARAM_N * PARAM_D * (2 * PARAM_D + 1);
    size_t cplx_T_count = (size_t) PARAM_N * 2 * PARAM_D * PARAM_D * PARAM_K;
    size_t u_count = (size_t) PARAM_D * PARAM_N;

    if (A_buf.size() != A_coeffs_count * sizeof(scalar) || T_buf.size() != T_coeffs_count * sizeof(scalar) ||
        cplx_T_buf.size() != cplx_T_count * sizeof(cplx) || sch_comp_buf.size() != sch_comp_count * sizeof(cplx) ||
        u_buf.size() != u_count * sizeof(scalar) || h_inv_buf.size() != (size_t) PARAM_N * sizeof(scalar)) {
        std::cerr << "sample_pre_wrap: input buffer sizes do not match expected sizes\n";
        return -2;
    }

    scalar *A_coeffs = (scalar*) malloc(A_coeffs_count * sizeof(scalar));
    scalar *T_coeffs = (scalar*) malloc(T_coeffs_count * sizeof(scalar));
    cplx  *cplx_T_coeffs = (cplx*) malloc(cplx_T_count * sizeof(cplx));
    cplx  *sch_comp_coeffs = (cplx*) malloc(sch_comp_count * sizeof(cplx));
    scalar *u_coeffs = (scalar*) malloc(u_count * sizeof(scalar));
    scalar *h_inv_coeffs = (scalar*) malloc(PARAM_N * sizeof(scalar));
    scalar *x_coeffs = (scalar*) malloc((size_t) PARAM_N * PARAM_D * sizeof(scalar)); // x size used by Extract/TrapGen samples

    if (!A_coeffs || !T_coeffs || !cplx_T_coeffs || !sch_comp_coeffs || !u_coeffs || !h_inv_coeffs || !x_coeffs) {
        free(A_coeffs); free(T_coeffs); free(cplx_T_coeffs); free(sch_comp_coeffs); free(u_coeffs); free(h_inv_coeffs); free(x_coeffs);
        return -3;
    }

    // copy bytes into arrays (assume little-endian uint32_t for scalars)
    memcpy(A_coeffs, A_buf.data(), A_buf.size());
    memcpy(T_coeffs, T_buf.data(), T_buf.size());
    memcpy(cplx_T_coeffs, cplx_T_buf.data(), cplx_T_buf.size());
    memcpy(sch_comp_coeffs, sch_comp_buf.data(), sch_comp_buf.size());
    memcpy(u_coeffs, u_buf.data(), u_buf.size());
    memcpy(h_inv_coeffs, h_inv_buf.data(), h_inv_buf.size());

    // Call sample_pre_target to compute x
    sample_pre_target(x_coeffs, A_coeffs, T_coeffs, cplx_T_coeffs, sch_comp_coeffs, h_inv_coeffs, u_coeffs);

    // Serialize x (x_coeffs length depends on usage; here we pick PARAM_N * PARAM_D)
    serialize_scalars_to_bytes(x_coeffs, (size_t) PARAM_N * PARAM_D, x_out);

    free(A_coeffs); free(T_coeffs); free(cplx_T_coeffs); free(sch_comp_coeffs); free(u_coeffs); free(h_inv_coeffs); free(x_coeffs);
    return 0;
}

// multiply_matrix_vector_wrap: y = B * x
// B_buf: serialized scalars with count PARAM_N * PARAM_D * (PARAM_M - PARAM_D)
// x_buf: serialized scalars with count PARAM_N * PARAM_M
// y_out: serialized scalars with count PARAM_N * PARAM_D
int multiply_matrix_vector_wrap(const std::vector<uint8_t> &B_buf, const std::vector<uint8_t> &x_buf, std::vector<uint8_t> &y_out) {
    size_t A_coeffs_count = (size_t) PARAM_N * PARAM_D * (PARAM_M - PARAM_D);
    size_t x_coeffs_count = (size_t) PARAM_N * PARAM_M;
    size_t y_coeffs_count = (size_t) PARAM_N * PARAM_D;

    if (B_buf.size() != A_coeffs_count * sizeof(scalar) || x_buf.size() != x_coeffs_count * sizeof(scalar)) {
        std::cerr << "multiply_matrix_vector_wrap: input buffer sizes do not match expected sizes\n";
        return -2;
    }

    scalar *B_coeffs = (scalar*) malloc(A_coeffs_count * sizeof(scalar));
    scalar *x_coeffs = (scalar*) malloc(x_coeffs_count * sizeof(scalar));
    scalar *y_coeffs = (scalar*) malloc(y_coeffs_count * sizeof(scalar));
    if (!B_coeffs || !x_coeffs || !y_coeffs) {
        free(B_coeffs); free(x_coeffs); free(y_coeffs);
        return -3;
    }

    memcpy(B_coeffs, B_buf.data(), B_buf.size());
    memcpy(x_coeffs, x_buf.data(), x_buf.size());

    // Call multiply_by_A to compute y <- B * x (uses Module_BFRS arithmetic)
    // multiply_by_A expects poly_matrix types; here we pass raw pointers which map to the same layout
    multiply_by_A((poly_matrix) y_coeffs, (poly_matrix) B_coeffs, (poly_matrix) x_coeffs);

    // serialize y into bytes
    y_out.resize(y_coeffs_count * sizeof(scalar));
    memcpy(y_out.data(), y_coeffs, y_coeffs_count * sizeof(scalar));

    free(B_coeffs); free(x_coeffs); free(y_coeffs);
    return 0;
}

} // namespace pq_abl::glue
