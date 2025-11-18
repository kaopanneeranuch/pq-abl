#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/keygen/lcp_keygen.h"
#include "lcp-abe/policy/lcp_policy.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "module_gaussian_lattice/Module_BFRS/sampling.h"

#ifdef USE_OPENMP
#include <omp.h>
#endif

// Measure ONLY the parallelizable parts: ω_i sampling + B_i^+ · ω_i computation
// This excludes fixed costs like sample_pre_target()
double benchmark_parallelizable_parts(MasterPublicKey *mpk, MasterSecretKey *msk,
                                      int num_attrs, int num_threads, int iterations) {
    #ifdef USE_OPENMP
    omp_set_num_threads(num_threads);
    #endif
    
    const char *attribute_names[] = {
        "admin", "storage-team", "devops", "analyst", "auditor",
        "infra-team", "app-team", "sec-team", "user", "manager",
        "developer", "tester", "designer", "architect", "lead",
        "senior", "junior", "intern", "contractor", "consultant",
        "director", "vp", "ceo", "cto", "cfo",
        "hr", "finance", "legal", "marketing", "sales",
        "support", "operations"
    };
    
    double total_time = 0.0;
    int success_count = 0;
    
    for (int iter = 0; iter < iterations; iter++) {
        // Create attribute set
        AttributeSet attrs;
        attribute_set_init(&attrs);
        
        for (int i = 0; i < num_attrs; i++) {
            const char *attr_name = attribute_names[i % 32];
            Attribute attr;
            uint32_t index = attr_name_to_index(attr_name);
            attribute_init(&attr, attr_name, index);
            attribute_set_add(&attrs, &attr);
        }
        
        UserSecretKey sk;
        usk_init(&sk, (uint32_t)attrs.count);
        sk.attr_set = attrs;
        
        clock_t start = clock();
        
        // ============================================================
        // PARALLELIZABLE PART 1: Sample ω_i vectors (Algorithm lines 2-7)
        // ============================================================
        #ifdef USE_OPENMP
        #pragma omp parallel for
        #endif
        for (uint32_t i = 0; i < attrs.count; i++) {
            SampleR_matrix_centered((signed_poly_matrix) sk.omega_i[i], PARAM_M, 1, PARAM_SIGMA);
            
            for (int j = 0; j < PARAM_N * PARAM_M; j++) {
                sk.omega_i[i][j] += PARAM_Q;
            }
            matrix_crt_representation(sk.omega_i[i], PARAM_M, 1, LOG_R);
        }
        
        // ============================================================
        // PARALLELIZABLE PART 2: Compute B_i^+ · ω_i (Algorithm lines 9-15)
        // ============================================================
        poly_matrix sum_term = (poly_matrix)calloc(PARAM_D * PARAM_N, sizeof(scalar));
        
        #ifdef USE_OPENMP
        #pragma omp parallel
        {
            poly local_sum = (poly)calloc(PARAM_N, sizeof(scalar));
            if (local_sum) {
                zero_poly(local_sum, PARAM_N - 1);
                
                #pragma omp for
                for (uint32_t i = 0; i < attrs.count; i++) {
                    const Attribute *attr = &attrs.attrs[i];
                    
                    if (attr->index >= mpk->n_attributes) continue;
                    
                    poly_matrix B_plus_i = &mpk->B_plus[attr->index * PARAM_M * PARAM_N];
                    poly temp_result = (poly)calloc(PARAM_N, sizeof(scalar));
                    if (!temp_result) continue;
                    
                    double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
                    poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
                    
                    if (!temp_prod || !reduced) {
                        if (temp_prod) free(temp_prod);
                        if (reduced) free(reduced);
                        free(temp_result);
                        continue;
                    }
                    
                    // Compute B_i^+ · ω_i = sum over j of (B_i^+[j] · ω_i[j])
                    for (uint32_t j = 0; j < PARAM_M; j++) {
                        poly B_ij = &B_plus_i[j * PARAM_N];
                        poly omega_ij = &sk.omega_i[i][j * PARAM_N];
                        
                        memset(temp_prod, 0, 2 * PARAM_N * sizeof(double_scalar));
                        memset(reduced, 0, PARAM_N * sizeof(scalar));
                        
                        mul_crt_poly(temp_prod, B_ij, omega_ij, LOG_R);
                        reduce_double_crt_poly(reduced, temp_prod, LOG_R);
                        add_poly(temp_result, temp_result, reduced, PARAM_N - 1);
                        freeze_poly(temp_result, PARAM_N - 1);
                    }
                    
                    free(temp_prod);
                    free(reduced);
                    
                    // Accumulate into thread-local sum
                    add_poly(local_sum, local_sum, temp_result, PARAM_N - 1);
                    freeze_poly(local_sum, PARAM_N - 1);
                    free(temp_result);
                }
                
                // Critical section: accumulate thread-local sums
                #pragma omp critical
                {
                    poly sum_0 = poly_matrix_element(sum_term, PARAM_D, 0, 0);
                    add_poly(sum_0, sum_0, local_sum, PARAM_N - 1);
                    freeze_poly(sum_0, PARAM_N - 1);
                }
                
                free(local_sum);
            }
        }
        #else
        // Sequential version
        for (uint32_t i = 0; i < attrs.count; i++) {
            const Attribute *attr = &attrs.attrs[i];
            
            if (attr->index >= mpk->n_attributes) continue;
            
            poly_matrix B_plus_i = &mpk->B_plus[attr->index * PARAM_M * PARAM_N];
            poly temp_result = (poly)calloc(PARAM_N, sizeof(scalar));
            if (!temp_result) continue;
            
            double_poly temp_prod = (double_poly)calloc(2 * PARAM_N, sizeof(double_scalar));
            poly reduced = (poly)calloc(PARAM_N, sizeof(scalar));
            
            if (!temp_prod || !reduced) {
                if (temp_prod) free(temp_prod);
                if (reduced) free(reduced);
                free(temp_result);
                continue;
            }
            
            for (uint32_t j = 0; j < PARAM_M; j++) {
                poly B_ij = &B_plus_i[j * PARAM_N];
                poly omega_ij = &sk.omega_i[i][j * PARAM_N];
                
                memset(temp_prod, 0, 2 * PARAM_N * sizeof(double_scalar));
                memset(reduced, 0, PARAM_N * sizeof(scalar));
                
                mul_crt_poly(temp_prod, B_ij, omega_ij, LOG_R);
                reduce_double_crt_poly(reduced, temp_prod, LOG_R);
                add_poly(temp_result, temp_result, reduced, PARAM_N - 1);
                freeze_poly(temp_result, PARAM_N - 1);
            }
            
            free(temp_prod);
            free(reduced);
            
            poly sum_0 = poly_matrix_element(sum_term, PARAM_D, 0, 0);
            add_poly(sum_0, sum_0, temp_result, PARAM_N - 1);
            freeze_poly(sum_0, PARAM_N - 1);
            free(temp_result);
        }
        #endif
        
        clock_t end = clock();
        
        free(sum_term);
        usk_free(&sk);
        
        double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
        total_time += elapsed;
        success_count++;
    }
    
    return (success_count > 0) ? (total_time / success_count) : 0.0;
}

int main(void) {
    // Initialize Module_BFRS components
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();
    
    MasterPublicKey mpk;
    MasterSecretKey msk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0 ||
        lcp_load_msk(&msk, "keys/MSK.bin") != 0) {
        fprintf(stderr, "Failed to load MPK/MSK\n");
        return 1;
    }
    
    #ifdef USE_OPENMP
    int max_threads = omp_get_max_threads();
    printf("OpenMP: ENABLED\n");
    printf("Max available threads: %d\n\n", max_threads);
    #else
    int max_threads = 1;
    printf("OpenMP: DISABLED\n");
    printf("Only sequential (1 thread) will be tested\n\n");
    #endif
    
    const int NUM_ITERATIONS = 10;
    const int MAX_ATTR_COUNT = 32;  // Test up to system limit
    
    // Test attribute counts in increments (to show scaling better)
    // Test: 1, 2, 3, 4, 5, 10, 15, 20, 25, 30, 32
    int attr_counts[] = {1, 2, 3, 4, 5, 10, 15, 20, 25, 30, 32};
    const int NUM_ATTR_TESTS = sizeof(attr_counts) / sizeof(attr_counts[0]);
    
    // Test with different thread counts
    int thread_counts[] = {1, 2, 4, 8};
    int num_thread_configs = 4;
    
    #ifndef USE_OPENMP
    num_thread_configs = 1;
    #endif
    
    // Store results: [thread_config][attr_test_index]
    double results[4][NUM_ATTR_TESTS];
    double time_per_attr[4][NUM_ATTR_TESTS];
    
    // Benchmark for each thread configuration
    for (int t = 0; t < num_thread_configs; t++) {
        int threads = thread_counts[t];
        printf("========================================\n");
        printf("Testing with %d thread(s) %s\n", threads, 
               (threads == 1) ? "(SEQUENTIAL)" : "(PARALLEL)");
        printf("========================================\n\n");
        
        for (int test_idx = 0; test_idx < NUM_ATTR_TESTS; test_idx++) {
            int num_attrs = attr_counts[test_idx];
            double avg_time = benchmark_parallelizable_parts(&mpk, &msk, num_attrs, threads, NUM_ITERATIONS);
            double tpa = avg_time / num_attrs;
            
            results[t][test_idx] = avg_time;
            time_per_attr[t][test_idx] = tpa;
            
            printf("  %d attributes: %.3f ms (%.3f ms/attr)\n", num_attrs, avg_time, tpa);
        }
        printf("\n");
    }
    
    // Comparison table
    printf("========================================\n");
    printf("COMPARISON: Sequential vs Parallel\n");
    printf("(Only parallelizable attribute work)\n");
    printf("========================================\n\n");
    
    printf("%-12s | %8s | %8s | %8s | %8s | %10s\n", 
           "Attributes", "1 Thread", "2 Threads", "4 Threads", "8 Threads", "Speedup");
    printf("------------|----------|----------|----------|----------|------------\n");
    
    for (int test_idx = 0; test_idx < NUM_ATTR_TESTS; test_idx++) {
        int num_attrs = attr_counts[test_idx];
        double seq_time = results[0][test_idx];
        printf("%-12d | %8.2f", num_attrs, seq_time);
        
        #ifdef USE_OPENMP
        for (int t = 1; t < num_thread_configs; t++) {
            double par_time = results[t][test_idx];
            double speedup = seq_time / par_time;
            printf(" | %8.2f", par_time);
            if (t == num_thread_configs - 1) {
                printf(" | %9.2fx", speedup);
            }
        }
        #else
        printf(" |    N/A   |    N/A   |    N/A   |    N/A");
        #endif
        printf("\n");
    }
    
    printf("\n");
    printf("========================================\n");
    printf("Time Per Attribute (Should be CONSTANT if parallelization works)\n");
    printf("========================================\n\n");
    
    printf("%-12s | %12s | %12s | %12s | %12s | %10s\n", 
           "Attributes", "1 Thread", "2 Threads", "4 Threads", "8 Threads", "Improvement");
    printf("------------|--------------|--------------|--------------|--------------|------------\n");
    
    for (int test_idx = 0; test_idx < NUM_ATTR_TESTS; test_idx++) {
        int num_attrs = attr_counts[test_idx];
        double seq_tpa = time_per_attr[0][test_idx];
        printf("%-12d | %12.3f", num_attrs, seq_tpa);
        
        #ifdef USE_OPENMP
        for (int t = 1; t < num_thread_configs; t++) {
            double par_tpa = time_per_attr[t][test_idx];
            double improvement = seq_tpa / par_tpa;
            printf(" | %12.3f", par_tpa);
            if (t == num_thread_configs - 1) {
                printf(" | %9.2fx", improvement);
            }
        }
        #else
        printf(" |         N/A |         N/A |         N/A |        N/A");
        #endif
        printf("\n");
    }
    
    // Summary statistics
    printf("\n========================================\n");
    printf("Summary: Parallelization Efficiency\n");
    printf("========================================\n\n");
    
    #ifdef USE_OPENMP
    if (num_thread_configs > 1) {
        // Find indices for 10 and 32 attributes
        int idx_10 = -1, idx_32 = -1;
        for (int i = 0; i < NUM_ATTR_TESTS; i++) {
            if (attr_counts[i] == 10) idx_10 = i;
            if (attr_counts[i] == 32) idx_32 = i;
        }
        
        // Calculate speedup for 10 and 32 attributes
        if (idx_10 >= 0) {
            double seq_10 = results[0][idx_10];
            double par2_10 = results[1][idx_10];
            double par4_10 = (num_thread_configs > 2) ? results[2][idx_10] : 0;
            double par8_10 = (num_thread_configs > 3) ? results[3][idx_10] : 0;
            
            printf("10 Attributes (parallelizable work only):\n");
            printf("  Sequential (1 thread):  %.2f ms\n", seq_10);
            printf("  Parallel (2 threads):   %.2f ms (%.2fx speedup)\n", 
                   par2_10, seq_10 / par2_10);
            if (par4_10 > 0) {
                printf("  Parallel (4 threads):   %.2f ms (%.2fx speedup)\n", 
                       par4_10, seq_10 / par4_10);
            }
            if (par8_10 > 0) {
                printf("  Parallel (8 threads):   %.2f ms (%.2fx speedup)\n", 
                       par8_10, seq_10 / par8_10);
            }
        }
        
        if (idx_32 >= 0) {
            double seq_32 = results[0][idx_32];
            double par2_32 = results[1][idx_32];
            double par4_32 = (num_thread_configs > 2) ? results[2][idx_32] : 0;
            double par8_32 = (num_thread_configs > 3) ? results[3][idx_32] : 0;
            
            printf("\n32 Attributes (maximum, parallelizable work only):\n");
            printf("  Sequential (1 thread):  %.2f ms\n", seq_32);
            printf("  Parallel (2 threads):   %.2f ms (%.2fx speedup)\n", 
                   par2_32, seq_32 / par2_32);
            if (par4_32 > 0) {
                printf("  Parallel (4 threads):   %.2f ms (%.2fx speedup)\n", 
                       par4_32, seq_32 / par4_32);
            }
            if (par8_32 > 0) {
                printf("  Parallel (8 threads):   %.2f ms (%.2fx speedup)\n", 
                       par8_32, seq_32 / par8_32);
            }
        }
        
        // Check if time per attribute is constant (good parallelization)
        double seq_tpa_1 = time_per_attr[0][0];
        double seq_tpa_10 = (idx_10 >= 0) ? time_per_attr[0][idx_10] : 0;
        double seq_tpa_32 = (idx_32 >= 0) ? time_per_attr[0][idx_32] : 0;
        double par4_tpa_1 = (num_thread_configs > 2) ? time_per_attr[2][0] : 0;
        double par4_tpa_10 = (num_thread_configs > 2 && idx_10 >= 0) ? time_per_attr[2][idx_10] : 0;
        double par4_tpa_32 = (num_thread_configs > 2 && idx_32 >= 0) ? time_per_attr[2][idx_32] : 0;
        
        printf("\nTime per Attribute Consistency:\n");
        printf("  Sequential: 1 attr = %.2f ms/attr", seq_tpa_1);
        if (seq_tpa_10 > 0) printf(", 10 attrs = %.2f ms/attr", seq_tpa_10);
        if (seq_tpa_32 > 0) printf(", 32 attrs = %.2f ms/attr", seq_tpa_32);
        printf("\n");
        
        if (par4_tpa_1 > 0) {
            printf("  Parallel (4): 1 attr = %.2f ms/attr", par4_tpa_1);
            if (par4_tpa_10 > 0) printf(", 10 attrs = %.2f ms/attr", par4_tpa_10);
            if (par4_tpa_32 > 0) printf(", 32 attrs = %.2f ms/attr", par4_tpa_32);
            printf("\n");
            
            if (seq_tpa_1 > 0 && seq_tpa_32 > 0) {
                double seq_variance = (seq_tpa_1 - seq_tpa_32) / seq_tpa_1 * 100.0;
                double par4_variance = (par4_tpa_1 - par4_tpa_32) / par4_tpa_1 * 100.0;
                
                printf("\n  Sequential variance (1->32): %.1f%%\n", seq_variance);
                printf("  Parallel variance (1->32): %.1f%% (should be lower if parallelization works)\n", par4_variance);
            }
        }
        
        // Ideal speedup check for 32 attributes (best case) - compare 4 and 8 threads
        if (idx_32 >= 0 && num_thread_configs > 2) {
            double seq_32 = results[0][idx_32];
            double par4_32 = results[2][idx_32];
            double par8_32 = (num_thread_configs > 3) ? results[3][idx_32] : 0;
            
            printf("\nParallelization Efficiency (32 attributes):\n");
            
            // 4 threads
            double ideal_speedup_4 = 4.0;
            double actual_speedup_4 = seq_32 / par4_32;
            double efficiency_4 = (actual_speedup_4 / ideal_speedup_4) * 100.0;
            
            printf("  4 Threads:\n");
            printf("    Ideal speedup: 4.00x\n");
            printf("    Actual speedup: %.2fx\n", actual_speedup_4);
            printf("    Efficiency: %.1f%%\n", efficiency_4);
            
            if (par8_32 > 0) {
                double ideal_speedup_8 = 8.0;
                double actual_speedup_8 = seq_32 / par8_32;
                double efficiency_8 = (actual_speedup_8 / ideal_speedup_8) * 100.0;
                
                printf("  8 Threads:\n");
                printf("    Ideal speedup: 8.00x\n");
                printf("    Actual speedup: %.2fx\n", actual_speedup_8);
                printf("    Efficiency: %.1f%%\n", efficiency_8);
                
                // Compare 4 vs 8 threads
                double speedup_4_to_8 = par4_32 / par8_32;
                printf("\n  Scaling from 4 to 8 threads: %.2fx (ideal: 2.00x)\n", speedup_4_to_8);
                
                if (efficiency_8 > 70.0) {
                    printf("  EXCELLENT: Near-linear speedup with 8 threads!\n");
                } else if (efficiency_8 > 50.0) {
                    printf("  GOOD: Significant parallelization benefit with 8 threads\n");
                } else {
                    printf("  MODERATE: Some benefit with 8 threads, but limited by overhead\n");
                }
            } else {
                if (efficiency_4 > 70.0) {
                    printf("  EXCELLENT: Near-linear speedup achieved!\n");
                } else if (efficiency_4 > 50.0) {
                    printf("  GOOD: Significant parallelization benefit\n");
                } else {
                    printf("  MODERATE: Some benefit, but limited by overhead\n");
                }
            }
        }
    }
    #else
    printf("OpenMP not enabled - cannot show parallelization benefits.\n");
    #endif
    
    return 0;
}