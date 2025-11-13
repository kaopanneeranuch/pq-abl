#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include <assert.h>
#include <string.h>

#include "common.h"
#include "random.h"
#include "sampling.h"
#include "arithmetic.h"

/* Debug storage for expected v (A·omega_A) used only with ARITH_DEBUG.
 * Stored in CRT representation as PARAM_D * PARAM_N scalars. */
static scalar *sampler_debug_expected_v = NULL;
static int sampler_debug_expected_v_set = 0;

void sampler_debug_set_expected_v(poly expected_v)
{
	if (!getenv("ARITH_DEBUG")) return;
	if (!sampler_debug_expected_v) {
		sampler_debug_expected_v = malloc(sizeof(scalar) * PARAM_D * PARAM_N);
		if (!sampler_debug_expected_v) {
			fprintf(stderr, "[SAMPLER DEBUG] malloc failed\n"); fflush(stderr);
			return;
		}
	}
	/* expected_v points to a sequence of PARAM_D polynomials of length PARAM_N */
	memcpy(sampler_debug_expected_v, expected_v, sizeof(scalar) * PARAM_D * PARAM_N);
	sampler_debug_expected_v_set = 1;
}

void sampler_debug_clear_expected_v(void)
{
	if (sampler_debug_expected_v) {
		free(sampler_debug_expected_v);
		sampler_debug_expected_v = NULL;
	}
	sampler_debug_expected_v_set = 0;
}

/*
	Generates a matrix A in R_q^{d,m} along with its trapdoor T in R^{2d,dk}
		A's first d columns are implicit, since they are the identity I_d
		A and T are both returned in the CRT domain
*/
void TrapGen(poly_matrix A, poly_matrix T)
	{
	scalar A_hat_coeffs[PARAM_D * PARAM_D * PARAM_N], AprimeT_coeffs[PARAM_D * PARAM_D * PARAM_K * PARAM_N];
	poly_matrix A_hat = A_hat_coeffs, AprimeT = AprimeT_coeffs;
	
	// A_hat <- U(R_q^{d,d}) is considered to be in the CRT domain
	random_poly(A_hat, PARAM_N * PARAM_D * PARAM_D);

		
	// T <- D_{R^{2d,dk},sigma}
	SampleR_matrix_centered((signed_poly_matrix) T, 2*PARAM_D, PARAM_D * PARAM_K, PARAM_SIGMA);
	
	matrix_crt_representation(T, 2*PARAM_D, PARAM_D * PARAM_K, LOG_R);
	
	// AprimeT = A_hat * T2 + T1, where T1 and T2 are the upper and lower half of T
	poly_matrix T1 = T, T2 = poly_matrix_element(T, PARAM_D * PARAM_K, PARAM_D, 0);
	mul_crt_poly_matrix(AprimeT, A_hat, T2, PARAM_D, PARAM_D, PARAM_D * PARAM_K, LOG_R);
	add_to_poly_matrix(AprimeT, T1, PARAM_D, PARAM_D * PARAM_K);

	
	// A = (A_hat | -A'T) ( = (I | A_hat | -A'T) implicitly)
	for(int i = 0 ; i < PARAM_D ; ++i)
		{
		poly_matrix A_i0 = poly_matrix_element(A, PARAM_M - PARAM_D, i, 0);
		poly_matrix A_hat_i = poly_matrix_element(A_hat, PARAM_D, i, 0);
		memcpy(A_i0, A_hat_i, PARAM_D * PARAM_N * sizeof(scalar));

		}
	for(int i = 0 ; i < PARAM_D ; ++i)
		{
		poly_matrix A_i1 = poly_matrix_element(A, PARAM_M - PARAM_D, i, PARAM_D);
		poly_matrix AprimeT_i = poly_matrix_element(AprimeT, PARAM_D * PARAM_K, i, 0);
		for(int j = 0 ; j < PARAM_D * PARAM_K * PARAM_N ; ++j)
			{
			A_i1[j] = 2*PARAM_Q - AprimeT_i[j];
			}
		}
	}


//==============================================================================
// Samples from distribution D_{c,sigma}, ie                                              
// Samples an element in Z with probability proportionnal to e^{-(c-x)^2/2*(sigma^2)}    
//==============================================================================
signed int SampleZ(RR_t c, RR_t sigma)
	{
	
	return algorithmF(c, sigma);
	}

/*
	Samples from D_{R,sigma} where R = Z[X] / <X^n+1> is isomorphic to Z^n
*/
void SampleR_centered(signed_poly f, RR_t sigma)
	{
	for(int i=0 ; i < PARAM_N ; ++i)
		{
		f[i] = SampleZ(0, sigma);
		}
	}

/*
	Samples from D_{R^{l1,l2},sigma}
		coefficients are centered on 0
*/
void SampleR_matrix_centered(signed_poly_matrix A, int l1, int l2, RR_t sigma)
	{
	for(int i = 0 ; i < l1 * l2 * PARAM_N ; ++i)
		{
		A[i] = SampleZ(0, sigma);
		}
	}

real d_coeffs[PARAM_K];
real l_coeffs[PARAM_K];
real h_coeffs[PARAM_K];

/*
	Compute coefficients used in D-sampling and G-perturbation-sampling :
		- d_coeffs : the coefficients of D's last column
		- l_coeffs and h_coeffs : the coefficients defining L
*/
void init_D_lattice_coeffs(void)
	{
	// d_i = (d_{i-1} + q_i) / 2, with d_{-1} = 0
	d_coeffs[0] = Q_BIT(0) / PARAM_B;  // we have d_0 = q_0/b
	for(int i = 1 ; i < PARAM_K ; ++i)
		{
		d_coeffs[i] = (d_coeffs[i-1] + Q_BIT(i)) / PARAM_B;
		}
	
	// l_0^2 = b(1 + 1/k) + 1, and l_i^2 = b(1 + 1/(k-i))
	l_coeffs[0] = sqrt(PARAM_B*(1 + 1.0 / PARAM_K) + 1);
	for(int i = 0 ; i < PARAM_K ; ++i)
		{
		l_coeffs[i] = sqrt(PARAM_B*(1 + 1.0 / (PARAM_K - i)));
		}
	
	// h_{i+1}^2 = b(1 - 1/(k-i)), there is no h_0 so we set it to zero
	h_coeffs[0] = 0;
	for(int i = 0 ; i < PARAM_K - 1 ; ++i)
		{
		h_coeffs[i+1] = sqrt(PARAM_B*(1 - 1.0 / (PARAM_K - i)));
		}
	}

/*
	Sample z from the D-lattice (included in Z^k) with center c and parameter sigma
*/
void sample_D(signed_scalar *z, real *c, real sigma)
	{
	real c_d = - c[PARAM_K - 1] / d_coeffs[PARAM_K - 1];
	real c_d_floor = floor(c_d);
	real c_d_frac = c_d - c_d_floor;
	
	z[PARAM_K - 1] = c_d_floor + SampleZ(c_d_frac, sigma / d_coeffs[PARAM_K - 1]);
	
	for(int i = 0 ; i < PARAM_K - 1 ; ++i)
		{
		real c_i = z[PARAM_K - 1] * d_coeffs[i] - c[i];
		real c_i_floor = floor(c_i);
		real c_i_frac = c_i - c_i_floor;
		z[i] = c_i_floor + SampleZ(c_i_frac, sigma);
		}
	}

/*
	Samples the perturbation vector p so that the distribution of Sample_G is spherical
*/
void sample_G_perturb(real *p, real sigma)
	{
	real beta = 0, z[PARAM_K+1];
	z[PARAM_K] = 0;
	
	for(int i = 0 ; i < PARAM_K ; ++i)
		{
		real c_i = beta / l_coeffs[i], c_i_floor = floor(c_i), c_i_frac = c_i - c_i_floor;
		real sigma_i = sigma / l_coeffs[i];
		z[i] = c_i_floor + SampleZ(c_i_frac, sigma_i);
		beta = -z[i] * h_coeffs[i];
		}
	
	p[0] = (2*PARAM_B+1)*z[0] + PARAM_B*z[1];
	for(int i = 1 ; i < PARAM_K ; ++i)
		{
		p[i] = PARAM_B * (z[i-1] + 2*z[i] + z[i+1]);
		}
	}

/*
	Sample t from the scalar G-lattice (included in Z^k) with parameter alpha, such that <g,t> = u mod q
*/
void scalar_sample_G(signed_scalar *t, scalar u)
	{
	real sigma = PARAM_ALPHA / (PARAM_B + 1), c[PARAM_K], p[PARAM_K];
	signed_scalar z[PARAM_K];
	sample_G_perturb(p, sigma);
	
	c[0] = ((real) get_bit_b(u,0) - p[0]) / PARAM_B;
	for(int i = 1 ; i < PARAM_K ; ++i)
		{
		c[i] = (c[i-1] + get_bit_b(u,i) - p[i]) / PARAM_B;
		}
	
	sample_D(z, c, sigma);
	
	t[0] = PARAM_B*z[0] + Q_BIT(0)*z[PARAM_K - 1] + get_bit_b(u,0);
	for(int i = 1 ; i < PARAM_K - 1 ; ++i)
		{
		t[i] = PARAM_B*z[i] - z[i-1] + Q_BIT(i)*z[PARAM_K - 1] + get_bit_b(u,i);
		}
	t[PARAM_K - 1] = Q_BIT(PARAM_K - 1)*z[PARAM_K - 1] - z[PARAM_K - 2] + get_bit_b(u,PARAM_K-1);
	}

/*
	Sample t form the ring G-lattice (included in R^k) with parameter alpha, such that <g,t> = u mod q
*/
void ring_sample_G(signed_poly_matrix t, poly u)
	{
	signed_scalar t_T[PARAM_N * PARAM_K];
	
	// sample n times from the scalar G-lattice
	for(int i = 0 ; i < PARAM_N ; ++i)
		{
		signed_poly t_i = &t_T[i*PARAM_K];
		scalar_sample_G(t_i, u[i]);
		}
	
	
	// permute the coefficients of t
	// as if t was a (n, k) matrix of scalars and we transposed it
	transpose_scalar_matrix((scalar *) t, (scalar *) t_T, PARAM_N, PARAM_K);
	}

/*
	Transpose A of size (l0, l1) into A_T of size (l1, l0)
*/
void transpose_scalar_matrix(scalar *A_T, scalar *A, int l0, int l1)
	{
	#define mat_A(i,j) A[i*l1 + j]
	#define mat_A_T(i,j) A_T[i*l0 + j]
	for(int i = 0 ; i < l0 ; ++i)
		{
		for(int j = 0 ; j < l1 ; ++j)
			{
			mat_A_T(j,i) = mat_A(i,j);
			}
		}
	#undef mat_A
	#undef mat_A_T
	}

void transpose_signed_scalar_matrix(signed_scalar *A_T, signed_scalar *A, int l0, int l1)
	{
	#define mat_A(i,j) A[i*l1 + j]
	#define mat_A_T(i,j) A_T[i*l0 + j]
	for(int i = 0 ; i < l0 ; ++i)
		{
		for(int j = 0 ; j < l1 ; ++j)
			{
			mat_A_T(j,i) = mat_A(i,j);
			}
		}
	#undef mat_A
	#undef mat_A_T
	}

void transpose_signed_scalar_matrix2(signed_scalar *A_T, scalar *A, int l0, int l1)
	{
	#define mat_A(i,j) A[i*l1 + j]
	#define mat_A_T(i,j) A_T[i*l0 + j]
	for(int i = 0 ; i < l0 ; ++i)
		{
		for(int j = 0 ; j < l1 ; ++j)
			{
			mat_A_T(j,i) = mat_A(i,j);
			}
		}
	#undef mat_A
	#undef mat_A_T
	}


void module_sample_G(signed_poly_matrix t, poly_matrix u)
	{
	// sample d times from the ring G-lattice
	for(int i = 0 ; i < PARAM_D ; ++i)
		{
		signed_poly_matrix t_i = poly_matrix_element(t, PARAM_D, 0, i*PARAM_K);
		poly u_i = poly_matrix_element(u, 1, i, 0);
		
		ring_sample_G(t_i, u_i);
		}
	}

/*
	Samples q in Z^(2*deg) with center c and a covariance defined by a, b, d (each of degree < deg)
*/
void sample_2z(signed_scalar *q, cplx_poly cplx_q, cplx_poly a, cplx_poly b, cplx_poly d, cplx *c, int depth)
	{
	int deg = PARAM_N >> depth;

	
	// Split q = (q0, q1) and c = (c0, c1) in half, and copy c1
	signed_scalar *q0 = q, *q1 = &q[deg];
	cplx *c0 = c, *c1 = &c[deg], *cplx_q0 = cplx_q, *cplx_q1 = &cplx_q[deg];
	
	// Copy c1 since it will be modified by sample_fz and we need it afterwards
	cplx c1_bis[deg];
	
	memcpy(c1_bis, c1, deg * sizeof(cplx));

	
	// b_times_d_inv <- b * d^(-1)
	cplx b_times_d_inv_coeffs[deg];
	cplx_poly b_times_d_inv = b_times_d_inv_coeffs;
	
	div_cplx_poly(b_times_d_inv, b, d, deg-1);
	
	// Sample q1 with covariance d and center c1
	sample_fz(q1, cplx_q1, d, c1_bis, depth);
	

	// Compute the new covariance
	// a <- a - b^T * d^(-1) * b
	fmsub_transpose_cplx_poly(a, b_times_d_inv, b, deg-1);
	
	// Compute the new center
	// c0 <- c0 + b * d^(-1) * (q1 - c1)
	
	sub_cplx_poly(c1, cplx_q1, c1, deg - 1); // we don't need c1 anymore so we can overwrite it with (q1 - c1)

	fma_cplx_poly(c0, b_times_d_inv, c1, deg - 1);
	
	
	
	// Sample q0 with the new covariance and the new center
	sample_fz(q0, cplx_q0, a, c0, depth);
	
	// Update cplx_q by merging q0 and q1 the FFT way
	// Defensive: avoid calling with negative depth (UB when depth == 0)
	if (depth > 0) {
		inverse_stride(cplx_q, depth - 1);
	} else {
		inverse_stride(cplx_q, 0);
	}
	}

/*
	Samples p in Z^deg with center c and covariance f, where f is of degree < deg
*/
void sample_fz(signed_scalar *p, cplx_poly cplx_p, cplx_poly f, cplx *c, int depth)
	{
	int deg = PARAM_N >> depth;
	
	if(deg == 1)
		{
		// f is a real polynomial of degree 0, so Re(f[0]) = f[0] = f(-1) = f
		#ifdef TESTING_ZETA
		p[0] = (creal(f[0]) <= 0);
		#else
		p[0] = SampleZ(*c, sqrt(creal(f[0])));
		#endif
		cplx_p[0] = p[0];
		
		return;
		}
	
	stride(f, depth);
	stride(c, depth);
	cplx_poly f0 = f, f1 = &f[deg/2];

	// copy f0 before calling sample_2z
	cplx f0_bis_coeffs[deg/2];
	cplx_poly f0_bis = f0_bis_coeffs;
	
	memcpy(f0_bis, f0, deg/2 * sizeof(cplx));


	
	sample_2z(p, cplx_p, f0, f1, f0_bis, c, depth + 1);
	scalar_stride(p, deg);
	}

/*
	Sample a perturbation p in R^m with the complementary covariance \Sigma_p defined by T and represented by sch_comp
		p is returned in the normal domain
		T is given in the complex CRT domain
		sch_comp is given in the complex CRT domain
*/
void sample_perturb(signed_poly_matrix p, cplx_poly_matrix T, cplx_poly_matrix sch_comp)
	{
	printf("[DEBUG] sample_perturb: START\n"); fflush(stdout);
	
	// Validate sch_comp contains reasonable values
	printf("[DEBUG] sample_perturb: Validating sch_comp...\n"); fflush(stdout);
	int bad_count = 0;
	for(int i = 0; i < PARAM_N * PARAM_D * (2 * PARAM_D + 1); ++i) {
		if (isnan(creal(sch_comp[i])) || isnan(cimag(sch_comp[i])) || 
		    isinf(creal(sch_comp[i])) || isinf(cimag(sch_comp[i]))) {
			bad_count++;
			if (bad_count < 5) {
				printf("[ERROR] sch_comp[%d] = %f + %fi (NaN or Inf!)\n", i, creal(sch_comp[i]), cimag(sch_comp[i]));
			}
		}
	}
	if (bad_count > 0) {
		printf("[ERROR] Found %d invalid values in sch_comp! This will cause infinite loops.\n", bad_count);
	} else {
		printf("[DEBUG] sch_comp validation passed (first few values: [0]=%f+%fi, [1]=%f+%fi)\n", 
		       creal(sch_comp[0]), cimag(sch_comp[0]), creal(sch_comp[1]), cimag(sch_comp[1]));
	}
	
	//cplx T_coeffs[PARAM_N * 2 * PARAM_D * PARAM_D * PARAM_K], sch_comp_coeffs[PARAM_N * PARAM_D * (2 * PARAM_D + 1)], c_coeffs[PARAM_N * 2 * PARAM_D], cplx_p_coeffs[PARAM_N * PARAM_D * PARAM_K];
	//cplx *T_coeffs = malloc(PARAM_N * 2 * PARAM_D * PARAM_D * PARAM_K * sizeof(cplx)), sch_comp_coeffs[PARAM_N * PARAM_D * (2 * PARAM_D + 1)], c_coeffs[PARAM_N * 2 * PARAM_D], cplx_p_coeffs[PARAM_N * PARAM_D * PARAM_K];
	//cplx_poly_matrix T = T_coeffs, sch_comp = sch_comp_coeffs, c = c_coeffs, cplx_p = cplx_p_coeffs;
	cplx c_coeffs[PARAM_N * 2 * PARAM_D], cplx_p_coeffs[PARAM_N * PARAM_D * PARAM_K];
	cplx_poly_matrix c = c_coeffs, cplx_p = cplx_p_coeffs;
	
	// First sample dk independant centred polynomials with covariance (zeta^2 - alpha^2)
	signed_poly_matrix p_2d = poly_matrix_element(p, 1, 2 * PARAM_D, 0);
	
	printf("[DEBUG] sample_perturb: Sampling %d coefficients with param=%f\n", PARAM_N * PARAM_D * PARAM_K, sqrt((PARAM_ZETA * PARAM_ZETA) - (PARAM_ALPHA * PARAM_ALPHA))); fflush(stdout);
	real param = sqrt((PARAM_ZETA * PARAM_ZETA) - (PARAM_ALPHA * PARAM_ALPHA));
	for(int i = 0 ; i < PARAM_N * PARAM_D * PARAM_K ; ++i)
		{
		p_2d[i] = SampleZ(0, param); // add q so that the coefficients are positive
		}
	printf("[DEBUG] sample_perturb: Initial sampling done\n"); fflush(stdout);

	

	
	// Compute the complex CRT transform of the sampled polynomials
	for(int i = 0 ; i < PARAM_N * PARAM_D * PARAM_K ; ++i)
		{
		cplx_p[i] = p_2d[i];
		}
	

	
	matrix_cplx_crt_representation(cplx_p, PARAM_D * PARAM_K, 1);

	printf("[DEBUG] sample_perturb: CRT transform done, constructing first center\n"); fflush(stdout);
	
	
	// Construct the new center (depends on the dk polynomials sampled before)
	construct_first_center(c, T, cplx_p);

	printf("[DEBUG] sample_perturb: First center constructed, starting iterative sampling for %d polynomials\n", 2 * PARAM_D - 2); fflush(stdout);

	
	// Sample 2d - 2 polynomials iteratively
	for(int i = 2 * PARAM_D - 1 ; i > 1 ; --i)
		{
		printf("[DEBUG] sample_perturb: Iteration i=%d, calling sample_fz\n", i); fflush(stdout);
		
		// Sample p[i] with covariance sch_comp[i,i] and center c[i]
		// (copying sch_comp[i,i] and c[i] since they're going to be modified)
		signed_scalar *p_i = poly_matrix_element(p, 1, i, 0);
		cplx_poly sch_comp_ii = triangular_poly_matrix_element(sch_comp, i, i);
		cplx_poly c_i = poly_matrix_element(c, 1, i, 0);
		
		cplx covariance_coeffs[PARAM_N], center_coeffs[PARAM_N];
		cplx_poly covariance = covariance_coeffs, center = center_coeffs;
		memcpy(covariance, sch_comp_ii, PARAM_N * sizeof(cplx));
		memcpy(center, c_i, PARAM_N * sizeof(cplx));
		sample_fz(p_i, cplx_p, covariance, center, 0);
		
		printf("[DEBUG] sample_perturb: Iteration i=%d, sample_fz done\n", i); fflush(stdout);
		
		// Update the center
		construct_new_center(c, sch_comp, cplx_p, i);
		}
	
	printf("[DEBUG] sample_perturb: Iterative sampling done, calling sample_2z for last 2 polynomials\n"); fflush(stdout);
	// Sample the last 2 polynomials with the specialized sample_2z algorithm (do not forget to copy the covariance first)
	cplx sch_comp_copy_coeffs[PARAM_N * 3];
	cplx_poly_matrix sch_comp_copy = sch_comp_copy_coeffs;
	
	memcpy(sch_comp_copy, sch_comp, PARAM_N * 3 * sizeof(cplx));
	
	cplx_poly sch_comp_00 = triangular_poly_matrix_element(sch_comp_copy, 0, 0);
	cplx_poly sch_comp_01 = triangular_poly_matrix_element(sch_comp_copy, 1, 0);
	transpose_cplx_poly(sch_comp_01, PARAM_N - 1); // transpose it since sch_comp[0, 1] = sch_comp[1, 0]^T
	cplx_poly sch_comp_11 = triangular_poly_matrix_element(sch_comp_copy, 1, 1);
	
	sample_2z((signed_scalar *) p, cplx_p, sch_comp_00, sch_comp_01, sch_comp_11, c, 0);
	printf("[DEBUG] sample_perturb: DONE!\n"); fflush(stdout);
	}

/*
	Sample x in R^m with parameter zeta such that A_m * x = 0 mod q (using the trapdoor T and h_inv the inverse of the tag for A_m)
		x is in the CRT domain
		A is in the CRT domain
		T is in the CRT domain
		cplx_T is in the complex CRT domain
		sch_comp is in the complex CRT domain
		h_inv is in the CRT domain
*/
void sample_pre(poly_matrix x, poly_matrix A_m, poly_matrix T, cplx_poly_matrix cplx_T, cplx_poly_matrix sch_comp, poly h_inv)
	{

	// Sample a perturbation p in R^m
	signed_scalar p_coeffs[PARAM_N * PARAM_M];
	signed_poly_matrix p = p_coeffs;
	

	sample_perturb(p, cplx_T, sch_comp);	
	
	// Add q to p's coeffs so that they are positive, and put p in the CRT domain
	for(int i = 0 ; i < PARAM_N * PARAM_M ; ++i)
		{
		p[i] += PARAM_Q;
		}
	
	matrix_crt_representation((poly_matrix) p, PARAM_M, 1, LOG_R);
	
	// v <- - h_inv * A_m * p (in the CRT domain)
	double_scalar prod_coeffs[2*PARAM_N];
	poly_matrix v = x; // store v at the beginning of x
	double_poly prod = prod_coeffs;
	
	multiply_by_A(v, A_m, (poly_matrix) p);
	
	
	for(int i = 0 ; i < PARAM_D ; ++i)
		{
		poly v_i = poly_matrix_element(v, 1, i, 0);
		
		mul_crt_poly(prod, h_inv, v_i, LOG_R);
		reduce_double_crt_poly(v_i, prod, LOG_R);
		for(int j = 0 ; j < PARAM_N ; ++j)
			{
			v_i[j] = PARAM_Q - v_i[j];
			}
		}

	
	// Put v back into the normal domain
	matrix_coeffs_representation(v, PARAM_D, 1, LOG_R);
	
	
	// Sample z from the G-lattice with target v
	signed_poly_matrix z = (signed_poly_matrix) poly_matrix_element(x, 1, 2 * PARAM_D, 0); // store z at the end of x to get TI * z for cheaper
	
	module_sample_G(z, v);

	
	// Make sure z has positive coefficients and put it in the CRT domain
	for(int i = 0 ; i < PARAM_N * PARAM_D * PARAM_K ; ++i)
		{
		z[i] += PARAM_Q;
		}
	
	matrix_crt_representation((poly_matrix) z, PARAM_D * PARAM_K, 1, LOG_R);

	
	// Put T in the CRT domain
	//matrix_crt_representation(T, 2 * PARAM_D, PARAM_D * PARAM_K, LOG_R);
	
	// x <- p + TI * z (in the CRT domain)
	multiply_by_T(x, T, (poly_matrix) z); // only need to multiply by T since z is already at the end of x
	
	
	add_poly(x, x, (poly) p, PARAM_N * PARAM_M - 1);
	// Reduce x mod q one final time but keep it in the CRT domain
	freeze_poly(x, PARAM_N * PARAM_M - 1);

	/* Debug: print pointer and first few coefficients of x (which should be the
	 * caller's omega_A buffer). This helps detect aliasing/copy issues. */
	if (getenv("ARITH_DEBUG")) {
		poly x0 = poly_matrix_element(x, 1, 0, 0);
		fprintf(stderr, "[SAMPLER PTR] x=%p first8_coeffs:", (void*)x);
		for (int k = 0; k < 8 && k < PARAM_N; ++k) fprintf(stderr, " %u", x0[k]);
		fprintf(stderr, "\n"); fflush(stderr);
	}

	/* Debug: print pointer and first few coefficients of x (which should be the
	 * caller's omega_A buffer). This helps detect aliasing/copy issues. */
	if (getenv("ARITH_DEBUG")) {
		poly x0 = poly_matrix_element(x, 1, 0, 0);
		fprintf(stderr, "[SAMPLER PTR] x=%p first8_coeffs:", (void*)x);
		for (int k = 0; k < 8 && k < PARAM_N; ++k) fprintf(stderr, " %u", x0[k]);
		fprintf(stderr, "\n"); fflush(stderr);
	}

	/* Debug: print pointer and first few coefficients of x (which should be the
	 * caller's omega_A buffer). This helps detect aliasing/copy issues. */
	if (getenv("ARITH_DEBUG")) {
		poly x0 = poly_matrix_element(x, 1, 0, 0);
		fprintf(stderr, "[SAMPLER PTR] x=%p first8_coeffs:", (void*)x);
		for (int k = 0; k < 8 && k < PARAM_N; ++k) fprintf(stderr, " %u", x0[k]);
		fprintf(stderr, "\n"); fflush(stderr);
	}
	}


	




// sample_pre with a target u


void sample_pre_target(poly_matrix x, poly_matrix A_m, poly_matrix T, cplx_poly_matrix cplx_T, cplx_poly_matrix sch_comp, poly h_inv, poly_matrix u)
	{
	printf("[DEBUG] sample_pre_target: START\n"); fflush(stdout);
	
	// Sample a perturbation p in R^m
	signed_scalar p_coeffs[PARAM_N * PARAM_M];
	signed_poly_matrix p = p_coeffs;
	
	printf("[DEBUG] sample_pre_target: Calling sample_perturb...\n"); fflush(stdout);
	sample_perturb(p, cplx_T, sch_comp);
	printf("[DEBUG] sample_pre_target: sample_perturb done\n"); fflush(stdout);
	
	
	// Add q to p's coeffs so that they are positive, and put p in the CRT domain
	printf("[DEBUG] sample_pre_target: Adding q to p coeffs...\n"); fflush(stdout);
	for(int i = 0 ; i < PARAM_N * PARAM_M ; ++i)
		{
		p[i] += PARAM_Q;
		}
	
	printf("[DEBUG] sample_pre_target: Converting p to CRT...\n"); fflush(stdout);
	matrix_crt_representation((poly_matrix) p, PARAM_M, 1, LOG_R);
	printf("[DEBUG] sample_pre_target: p in CRT domain\n"); fflush(stdout);

	/* Adjust p's first d polynomials so that A * p == u (make p a particular solution)
	 * This is necessary because TI spans the kernel of A: adding TI*z will not
	 * change A*p, so p must already satisfy the target u.
	 * 
	 * CRITICAL FIX: This adjustment MUST run unconditionally, not just in ARITH_DEBUG mode!
	 * Without this, A * x = A * p ≠ u, breaking the trapdoor relationship.
	 */
	// compute tmp = A * p
	printf("[DEBUG] sample_pre_target: Computing A * p (this may take a while)...\n"); fflush(stdout);
	poly_matrix tmp = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
	if (tmp) {
		printf("[DEBUG] sample_pre_target: Calling multiply_by_A (D=%d, M=%d, N=%d)...\n", PARAM_D, PARAM_M, PARAM_N); fflush(stdout);
		multiply_by_A(tmp, A_m, (poly_matrix) p);
		printf("[DEBUG] sample_pre_target: multiply_by_A completed\n"); fflush(stdout);
		// delta = u - tmp (for all D components)
		printf("[DEBUG] sample_pre_target: Adjusting p components (D=%d)...\n", PARAM_D); fflush(stdout);
		for (int comp = 0; comp < PARAM_D; comp++) {
			printf("[DEBUG] sample_pre_target: Adjusting component %d/%d...\n", comp+1, PARAM_D); fflush(stdout);
			poly tmp_comp = poly_matrix_element(tmp, 1, comp, 0);
			poly u_comp = poly_matrix_element(u, PARAM_D, comp, 0);
			poly delta = (poly)calloc(PARAM_N, sizeof(scalar));
			if (delta) {
				// delta = u_comp - tmp_comp
				memcpy(delta, u_comp, PARAM_N * sizeof(scalar));
				sub_poly(delta, delta, tmp_comp, PARAM_N - 1);
				freeze_poly(delta, PARAM_N - 1);
				
				// Since A = [I_d | Ā], we can adjust p[comp] directly to fix the first D components
				// For component comp, p[comp] contributes directly to A*p[comp] via the identity part
				poly_matrix p_as_poly = (poly_matrix) p;
				poly p_comp = poly_matrix_element(p_as_poly, 1, comp, 0);
				add_poly(p_comp, p_comp, delta, PARAM_N - 1);
				freeze_poly(p_comp, PARAM_N - 1);
				
				free(delta);
			}
		}
		printf("[DEBUG] sample_pre_target: p adjustment completed\n"); fflush(stdout);
		free(tmp);
	} else {
		fprintf(stderr, "[DEBUG] sample_pre_target: ERROR: Failed to allocate tmp\n"); fflush(stderr);
	}

	/* Diagnostic: compute A * p (CRT) to see whether p already maps to the
	 * desired target before the sampler attempts to adjust via TI·z. This
	 * will help determine whether the issue is in p construction or in TI. */
	if (getenv("ARITH_DEBUG")) {
		poly_matrix ap = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
		if (ap) {
			multiply_by_A(ap, A_m, (poly_matrix) p);
			poly ap0 = poly_matrix_element(ap, 1, 0, 0);
			for (int comp = 0; comp < LOG_R; ++comp) {
				char tag[80];
				snprintf(tag, sizeof(tag), "SAMPLE_Ap_comp_%d", comp);
				dump_crt_component(ap0, LOG_R, comp, tag);
			}
			free(ap);
		} else {
			fprintf(stderr, "[SAMPLER DIAG] failed to alloc ap\n"); fflush(stderr);
		}
	}
	
	// v <- - h_inv * A_m * p (in the CRT domain)
	double_scalar prod_coeffs[2*PARAM_N];
	poly_matrix v = x; // store v at the beginning of x
	double_poly prod = prod_coeffs;

	/* Debug expected v pointer (set via sampler_debug_set_expected_v) */
	static scalar *debug_expected_v = NULL;
	static int debug_expected_v_set = 0;


	scalar *zero_coeffs = malloc(PARAM_N * PARAM_D * sizeof(scalar));
	poly_matrix zero = zero_coeffs;
	zero_poly(zero, PARAM_N * PARAM_D - 1);

	

	multiply_by_A(v, A_m, (poly_matrix) p);

	if (getenv("ARITH_DEBUG")) {
		/* Dump v (first poly) and target u (first poly) in CRT for comparison */
	poly v0 = poly_matrix_element(v, 1, 0, 0);
	poly u0 = poly_matrix_element(u, PARAM_D, 0, 0);
		for (int comp = 0; comp < LOG_R; ++comp) {
			char tagv[80]; char tagu[80];
			snprintf(tagv, sizeof(tagv), "SAMPLE_v_after_A_comp_%d", comp);
			snprintf(tagu, sizeof(tagu), "SAMPLE_u_comp_%d", comp);
			dump_crt_component(v0, LOG_R, comp, tagv);
			dump_crt_component(u0, LOG_R, comp, tagu);
		}
	}

	/* Compute v <- v - u directly in-place (both are in CRT domain). */
	sub_poly(v, v, u, PARAM_N * PARAM_D - 1);

	/* If KeyGen provided an expected A·omega_A, compare it to our v (CRT)
	 * before any h_inv / canonicalization. This will fail-fast with a
	 * focused dump to help pinpoint representation / ordering / aliasing bugs.
	 */
	if (getenv("ARITH_DEBUG") && sampler_debug_expected_v_set) {
		for (int comp = 0; comp < PARAM_D; ++comp) {
			poly v_i = poly_matrix_element(v, 1, comp, 0);
			scalar *expect = &sampler_debug_expected_v[comp * PARAM_N];
			for (int j = 0; j < PARAM_N; ++j) {
				if (v_i[j] != expect[j]) {
					/* Print focused mismatch and exit */
					int idx = j;
					uint32_t actual = v_i[idx];
					uint32_t expv = expect[idx];
					int32_t s_actual = (actual >= (1u<<31)) ? (int32_t)(actual - (1u<<32)) : (int32_t)actual;
					int32_t s_exp = (expv >= (1u<<31)) ? (int32_t)(expv - (1u<<32)) : (int32_t)expv;
					long long raw = (long long)actual - (long long)expv;
					long long modq = (raw % PARAM_Q + PARAM_Q) % PARAM_Q;
					fprintf(stderr, "[SAMPLER ASSERT] mismatch comp=%d coeff=%d: v(actual)=%u (s=%d) expected=%u (s=%d) raw_diff=%lld modQ=%lld\n",
							comp, idx, actual, s_actual, expv, s_exp, raw, modq);
					fflush(stderr);

					/* Print first few coeffs for both arrays to help debugging */
					int show = 8;
					fprintf(stderr, "[SAMPLER ASSERT] actual v (comp %d) first %d: ", comp, show);
					for (int k = 0; k < show && k < PARAM_N; ++k) {
						uint32_t vkk = v_i[k];
						int32_t sv = (vkk >= (1u<<31)) ? (int32_t)(vkk - (1u<<32)) : (int32_t)vkk;
						fprintf(stderr, "%u(s=%d) ", vkk, sv);
					}
					fprintf(stderr, "\n");
					fprintf(stderr, "[SAMPLER ASSERT] expected (comp %d) first %d: ", comp, show);
					for (int k = 0; k < show && k < PARAM_N; ++k) {
						uint32_t vkk = expect[k];
						int32_t sv = (vkk >= (1u<<31)) ? (int32_t)(vkk - (1u<<32)) : (int32_t)vkk;
						fprintf(stderr, "%u(s=%d) ", vkk, sv);
					}
					fprintf(stderr, "\n");
					fflush(stderr);
					exit(2);
				}
			}
		}
	}
    
	for(int i = 0 ; i < PARAM_D ; ++i)
		{
		poly v_i = poly_matrix_element(v, 1, i, 0);

		if (getenv("ARITH_DEBUG")) {
			char tagb[80];
			snprintf(tagb, sizeof(tagb), "SAMPLE_v_before_hinv_comp_%d", i);
			for (int comp = 0; comp < LOG_R; ++comp) {
				dump_crt_component(v_i, LOG_R, comp, tagb);
			}
		}
        
		mul_crt_poly(prod, h_inv, v_i, LOG_R);
		reduce_double_crt_poly(v_i, prod, LOG_R);
		for (int j = 0; j < PARAM_N; ++j) {
			/* Keep the same canonicalization as the non-target path:
			 * reduce_double_crt_poly produced values in [0,q-1], so subtract
			 * from q to get the correct representative. */
			v_i[j] = PARAM_Q - v_i[j];
		}

		if (getenv("ARITH_DEBUG")) {
			char taga[80];
			snprintf(taga, sizeof(taga), "SAMPLE_v_after_hinv_comp_%d", i);
			for (int comp = 0; comp < LOG_R; ++comp) {
				dump_crt_component(v_i, LOG_R, comp, taga);
			}
		}
		}

	
	// Put v back into the normal domain
	matrix_coeffs_representation(v, PARAM_D, 1, LOG_R);
	
	
	// Sample z from the G-lattice with target v
	signed_poly_matrix z = (signed_poly_matrix) poly_matrix_element(x, 1, 2 * PARAM_D, 0); // store z at the end of x to get TI * z for cheaper
	
	module_sample_G(z, v);

	
	// Make sure z has positive coefficients and put it in the CRT domain
	for(int i = 0 ; i < PARAM_N * PARAM_D * PARAM_K ; ++i)
		{
		z[i] += PARAM_Q;
		}
	
	matrix_crt_representation((poly_matrix) z, PARAM_D * PARAM_K, 1, LOG_R);

	
	// Put T in the CRT domain
	//matrix_crt_representation(T, 2 * PARAM_D, PARAM_D * PARAM_K, LOG_R);
	
	// x <- p + TI * z (in the CRT domain)
	multiply_by_T(x, T, (poly_matrix) z); // only need to multiply by T since z is already at the end of x
	
	
	add_poly(x, x, (poly) p, PARAM_N * PARAM_M - 1);
	// Reduce x mod q one final time but keep it in the CRT domain
	freeze_poly(x, PARAM_N * PARAM_M - 1);

	/* Debug: print pointer and first few coefficients of x (which should be the
	 * caller's omega_A buffer). This helps detect aliasing/copy issues. */
	if (getenv("ARITH_DEBUG")) {
		poly x0 = poly_matrix_element(x, 1, 0, 0);
		fprintf(stderr, "[SAMPLER PTR] x=%p first8_coeffs:", (void*)x);
		for (int k = 0; k < 8 && k < PARAM_N; ++k) fprintf(stderr, " %u", x0[k]);
		fprintf(stderr, "\n"); fflush(stderr);
	}
	}
