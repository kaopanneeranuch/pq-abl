#ifndef ABE_PARAMS_H
#define ABE_PARAMS_H

// Single source of truth for LWE/Module-LWE parameters used by the ABE layers.
// Update these to match Module_BFRS/common.h values.

#ifdef __cplusplus
extern "C" {
#endif

// Field / LWE parameters
#define ABE_PARAM_N 256
#define ABE_PARAM_K 4
#define ABE_PARAM_Q 12289
#define ABE_PARAM_B 8
#define ABE_PARAM_SIGMA 4.2

// Other derived constants and notes can be added here. Ensure these match
// `module_gaussian_lattice/Module_BFRS/common.h` to avoid mismatches.

#ifdef __cplusplus
}
#endif

#endif // ABE_PARAMS_H
