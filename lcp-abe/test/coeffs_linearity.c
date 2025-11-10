/*
 * Simple harness to test linearity of coeffs_representation vs CRT addition.
 *
 * Create a set of random polynomials in CRT domain, sum them in CRT and
 * convert the sum to COEFF. Then convert each term to COEFF, convert back
 * to CRT and sum those, convert that sum to COEFF and compare the two
 * COEFF arrays. If they differ, it reproduces the non-linearity observed
 * in the larger ABE flow.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"

int main()
{
    printf("\n=== coeffs_representation linearity test ===\n");
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();

    const int TERMS = 64; /* number of terms to sum (try 64 or 128) */

    /* Allocate arrays */
    poly *terms = (poly*)calloc(TERMS, sizeof(poly));
    for (int t = 0; t < TERMS; t++) {
        terms[t] = (poly)calloc(PARAM_N, sizeof(scalar));
        random_poly(terms[t], PARAM_N - 1);
        /* Ensure values are reduced to [0,q) */
        freeze_poly(terms[t], PARAM_N - 1);
    }

    /* Sum in CRT domain */
    poly sum_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    for (int t = 0; t < TERMS; t++) {
        add_poly(sum_crt, sum_crt, terms[t], PARAM_N - 1);
        freeze_poly(sum_crt, PARAM_N - 1);
    }

    /* Convert the CRT sum to COEFF */
    poly sum_crt_copy = (poly)calloc(PARAM_N, sizeof(scalar));
    memcpy(sum_crt_copy, sum_crt, PARAM_N * sizeof(scalar));
    coeffs_representation(sum_crt_copy, LOG_R);

    /* For each term: convert to COEFF then back to CRT and sum those CRTs */
    poly sum_back_crt = (poly)calloc(PARAM_N, sizeof(scalar));
    for (int t = 0; t < TERMS; t++) {
        poly tmp = (poly)calloc(PARAM_N, sizeof(scalar));
        memcpy(tmp, terms[t], PARAM_N * sizeof(scalar));
        coeffs_representation(tmp, LOG_R);
        crt_representation(tmp, LOG_R);
        add_poly(sum_back_crt, sum_back_crt, tmp, PARAM_N - 1);
        freeze_poly(sum_back_crt, PARAM_N - 1);
        free(tmp);
    }

    /* Convert accumulated back-sum to COEFF */
    poly sum_back_copy = (poly)calloc(PARAM_N, sizeof(scalar));
    memcpy(sum_back_copy, sum_back_crt, PARAM_N * sizeof(scalar));
    coeffs_representation(sum_back_copy, LOG_R);

    /* Compare first 32 coefficients */
    int mismatch = 0;
    printf("Comparing first 32 coeffs of coeff(sum_crt) vs sum(coeff(term)->CRT->coeff)\n");
    printf("Index: sum_crt_copy  sum_back_copy\n");
    for (int i = 0; i < 32; i++) {
        printf("%2d: %10u  %10u\n", i, sum_crt_copy[i], sum_back_copy[i]);
        if (sum_crt_copy[i] != sum_back_copy[i]) mismatch = 1;
    }

    if (mismatch) {
        printf("RESULT: MISMATCH detected\n");
    } else {
        printf("RESULT: OK (first 32 equal)\n");
    }

    /* Cleanup */
    for (int t = 0; t < TERMS; t++) free(terms[t]);
    free(terms);
    free(sum_crt);
    free(sum_crt_copy);
    free(sum_back_crt);
    free(sum_back_copy);

    return mismatch;
}
