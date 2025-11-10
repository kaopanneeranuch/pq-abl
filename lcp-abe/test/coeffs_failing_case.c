/* Harness to reproduce conversion-order mismatch using extracted failing CRT terms */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "failing_terms.h"

int main()
{
    init_crt_trees();
    init_cplx_roots_of_unity();

    printf("=== coeffs failing case harness ===\n");
    poly sum_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    poly sum_back_crt = (poly)calloc(PARAM_N, sizeof(scalar));

    for (int j = 0; j < FAIL_TERMS_M; ++j) {
        /* terms are stored in CRT layout already */
        poly term = (poly)calloc(PARAM_N, sizeof(scalar));
        for (int i = 0; i < PARAM_N; ++i) term[i] = (scalar)failing_terms[j][i];

        add_poly(sum_crt, sum_crt, term, PARAM_N - 1);
        freeze_poly(sum_crt, PARAM_N - 1);

        /* convert term -> COEFF -> back to CRT and add */
        poly tmp = (poly)calloc(PARAM_N, sizeof(scalar));
        memcpy(tmp, term, PARAM_N * sizeof(scalar));
        coeffs_representation(tmp, LOG_R);
        crt_representation(tmp, LOG_R);
        add_poly(sum_back_crt, sum_back_crt, tmp, PARAM_N - 1);
        freeze_poly(sum_back_crt, PARAM_N - 1);

        free(tmp);
        free(term);
    }

    /* Convert aggregated CRT sums to COEFF */
    poly sum_crt_copy = (poly)calloc(PARAM_N, sizeof(scalar));
    memcpy(sum_crt_copy, sum_crt, PARAM_N * sizeof(scalar));
    freeze_poly(sum_crt_copy, PARAM_N - 1);
    coeffs_representation(sum_crt_copy, LOG_R);

    poly sum_back_copy = (poly)calloc(PARAM_N, sizeof(scalar));
    memcpy(sum_back_copy, sum_back_crt, PARAM_N * sizeof(scalar));
    freeze_poly(sum_back_copy, PARAM_N - 1);
    coeffs_representation(sum_back_copy, LOG_R);

    /* Print comparison */
    int mismatch = 0;
    printf("Comparing first 32 coeffs:\n");
    for (int i = 0; i < 32; ++i) {
        printf("%2d: %10u  %10u\n", i, sum_crt_copy[i], sum_back_copy[i]);
        if (sum_crt_copy[i] != sum_back_copy[i]) mismatch = 1;
    }
    if (mismatch) printf("RESULT: MISMATCH (first 32 differ)\n"); else printf("RESULT: OK\n");

    free(sum_crt);
    free(sum_back_crt);
    free(sum_crt_copy);
    free(sum_back_copy);
    return mismatch;
}
