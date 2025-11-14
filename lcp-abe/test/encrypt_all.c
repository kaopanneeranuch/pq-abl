#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <inttypes.h>
#ifdef _WIN32
#include <direct.h>
#endif
#include "lcp-abe/common/lcp_types.h"
#include "lcp-abe/setup/lcp_setup.h"
#include "lcp-abe/encrypt/lcp_encrypt.h"
#include "lcp-abe/policy/lcp_policy.h"
#include "module_gaussian_lattice/Module_BFRS/arithmetic.h"
#include "module_gaussian_lattice/Module_BFRS/sampling.h"

// Helper: Create policy from log entry (user_role AND team)
static int build_policy_from_log(const JsonLogEntry *log, AccessPolicy *policy) {
    char policy_expr[MAX_POLICY_SIZE];
    snprintf(policy_expr, sizeof(policy_expr), "user_role:%s AND team:%s", 
             log->user_role, log->team);
    
    policy_init(policy);
    if (policy_parse(policy_expr, policy) != 0) {
        return -1;
    }
    if (lsss_policy_to_matrix(policy) != 0) {
        return -1;
    }
    return 0;
}

int main(void) {
    // Initialize Module_BFRS components (required for polynomial operations)
    init_crt_trees();
    init_cplx_roots_of_unity();
    init_D_lattice_coeffs();  // REQUIRED: Initialize l_coeffs, d_coeffs, h_coeffs for sampling
    
    MasterPublicKey mpk;
    if (lcp_load_mpk(&mpk, "keys/MPK.bin") != 0) {
        fprintf(stderr,"Failed to load MPK\n"); return 1;
    }
    /* Create output directories in a cross-platform way */
#ifdef _WIN32
    _mkdir("out");
    _mkdir("out/encrypted");
#else
    mkdir("out",0755);
    mkdir("out/encrypted",0755);
#endif

    /* Parse logs */
    JsonLogArray logs;
    if (json_parse_log_file("logs/log.json", &logs) != 0) {
        fprintf(stderr, "Failed to parse logs/log.json\n"); return 1;
    }

    // Create policy for each unique (user_role, team) combination
    // Collect unique policies (allocate on heap to avoid stack overflow)
    AccessPolicy *temp_policies = (AccessPolicy*)calloc(1000, sizeof(AccessPolicy));
    if (!temp_policies) {
        fprintf(stderr, "Failed to allocate temp_policies array\n");
        json_free_log_array(&logs);
        return 1;
    }
    // Initialize all policies
    for (uint32_t i = 0; i < 1000; i++) {
        policy_init(&temp_policies[i]);
    }
    uint32_t temp_count = 0;

    for (uint32_t i = 0; i < logs.count && temp_count < 1000; i++) {
        // Build policy for this log
        AccessPolicy log_policy;
        if (build_policy_from_log(&logs.entries[i], &log_policy) != 0) {
            continue; // Skip if policy creation fails
        }

        // Check if we already have this policy
        int found = 0;
        for (uint32_t j = 0; j < temp_count; j++) {
            if (strcmp(temp_policies[j].expression, log_policy.expression) == 0) {
                found = 1;
                policy_free(&log_policy);
                break;
            }
        }

        if (!found) {
            // Deep copy log_policy to temp_policies
            temp_policies[temp_count].attr_count = log_policy.attr_count;
            temp_policies[temp_count].threshold = log_policy.threshold;
            temp_policies[temp_count].is_threshold = log_policy.is_threshold;
            temp_policies[temp_count].matrix_rows = log_policy.matrix_rows;
            temp_policies[temp_count].matrix_cols = log_policy.matrix_cols;
            strncpy(temp_policies[temp_count].expression, log_policy.expression, MAX_POLICY_SIZE - 1);
            temp_policies[temp_count].expression[MAX_POLICY_SIZE - 1] = '\0';
            
            // Copy attribute indices
            for (uint32_t k = 0; k < log_policy.attr_count && k < MAX_ATTRIBUTES; k++) {
                temp_policies[temp_count].attr_indices[k] = log_policy.attr_indices[k];
            }
            
            // Deep copy share_matrix
            if (log_policy.share_matrix && log_policy.matrix_rows > 0 && log_policy.matrix_cols > 0) {
                size_t matrix_size = log_policy.matrix_rows * log_policy.matrix_cols * sizeof(scalar);
                temp_policies[temp_count].share_matrix = (scalar*)malloc(matrix_size);
                if (!temp_policies[temp_count].share_matrix) {
                    policy_free(&log_policy);
                    continue;
                }
                memcpy(temp_policies[temp_count].share_matrix, log_policy.share_matrix, matrix_size);
            } else {
                temp_policies[temp_count].share_matrix = NULL;
            }
            
            // Deep copy rho
            if (log_policy.rho && log_policy.matrix_rows > 0) {
                temp_policies[temp_count].rho = (uint32_t*)malloc(log_policy.matrix_rows * sizeof(uint32_t));
                if (!temp_policies[temp_count].rho) {
                    if (temp_policies[temp_count].share_matrix) {
                        free(temp_policies[temp_count].share_matrix);
                    }
                    policy_free(&log_policy);
                    continue;
                }
                memcpy(temp_policies[temp_count].rho, log_policy.rho, log_policy.matrix_rows * sizeof(uint32_t));
            } else {
                temp_policies[temp_count].rho = NULL;
            }
            
            // Now we can free log_policy since we've deep copied everything
            policy_free(&log_policy);
            temp_count++;
        } else {
            policy_free(&log_policy);
        }
    }

    if (temp_count == 0) {
        fprintf(stderr, "No valid policies created from logs\n");
        for (uint32_t i = 0; i < 1000; i++) {
            policy_free(&temp_policies[i]);
        }
        free(temp_policies);
        json_free_log_array(&logs);
        return 1;
    }

    // Allocate final policies array and deep copy each policy
    AccessPolicy *policies = (AccessPolicy*)malloc(temp_count * sizeof(AccessPolicy));
    if (!policies) {
        fprintf(stderr, "Failed to allocate policies array\n");
        for (uint32_t i = 0; i < 1000; i++) {
            policy_free(&temp_policies[i]);
        }
        free(temp_policies);
        json_free_log_array(&logs);
        return 1;
    }

    // Deep copy each policy (including share_matrix and rho)
    for (uint32_t i = 0; i < temp_count; i++) {
        policy_init(&policies[i]);
        strncpy(policies[i].expression, temp_policies[i].expression, MAX_POLICY_SIZE - 1);
        policies[i].expression[MAX_POLICY_SIZE - 1] = '\0';
        policies[i].attr_count = temp_policies[i].attr_count;
        policies[i].threshold = temp_policies[i].threshold;
        policies[i].is_threshold = temp_policies[i].is_threshold;
        policies[i].matrix_rows = temp_policies[i].matrix_rows;
        policies[i].matrix_cols = temp_policies[i].matrix_cols;
        
        // Copy attribute indices
        for (uint32_t j = 0; j < temp_policies[i].attr_count && j < MAX_ATTRIBUTES; j++) {
            policies[i].attr_indices[j] = temp_policies[i].attr_indices[j];
        }
        
        // Deep copy share_matrix
        if (temp_policies[i].share_matrix && temp_policies[i].matrix_rows > 0 && temp_policies[i].matrix_cols > 0) {
            size_t matrix_size = temp_policies[i].matrix_rows * temp_policies[i].matrix_cols * sizeof(scalar);
            policies[i].share_matrix = (scalar*)malloc(matrix_size);
            if (!policies[i].share_matrix) {
                fprintf(stderr, "Failed to allocate share_matrix for policy %u\n", i);
                // Free already allocated policies
                for (uint32_t k = 0; k < i; k++) {
                    policy_free(&policies[k]);
                }
                free(policies);
                for (uint32_t k = 0; k < temp_count; k++) {
                    policy_free(&temp_policies[k]);
                }
                json_free_log_array(&logs);
                return 1;
            }
            memcpy(policies[i].share_matrix, temp_policies[i].share_matrix, matrix_size);
        }
        
        // Deep copy rho
        if (temp_policies[i].rho && temp_policies[i].matrix_rows > 0) {
            policies[i].rho = (uint32_t*)malloc(temp_policies[i].matrix_rows * sizeof(uint32_t));
            if (!policies[i].rho) {
                fprintf(stderr, "Failed to allocate rho for policy %u\n", i);
                // Free already allocated policies
                if (policies[i].share_matrix) {
                    free(policies[i].share_matrix);
                }
                for (uint32_t k = 0; k < i; k++) {
                    policy_free(&policies[k]);
                }
                free(policies);
                for (uint32_t k = 0; k < temp_count; k++) {
                    policy_free(&temp_policies[k]);
                }
                json_free_log_array(&logs);
                return 1;
            }
            memcpy(policies[i].rho, temp_policies[i].rho, temp_policies[i].matrix_rows * sizeof(uint32_t));
        }
    }
    
    // Now we can free temp_policies
    for (uint32_t i = 0; i < 1000; i++) {
        policy_free(&temp_policies[i]);
    }
    free(temp_policies);

    Microbatch *batches = NULL;
    uint32_t n_batches = 0;
    if (process_logs_microbatch(&logs, policies, temp_count, &mpk, &batches, &n_batches) != 0) {
        fprintf(stderr, "Encrypt pipeline failed\n");
        for (uint32_t i = 0; i < temp_count; i++) {
            policy_free(&policies[i]);
        }
        free(policies);
        json_free_log_array(&logs);
        return 1;
    }

    for (uint32_t i = 0; i < n_batches; i++) {
        if (batches[i].logs == NULL) {
            fprintf(stderr, "[Test] ERROR: Batch %d has NULL logs pointer!\n", i);
            continue;
        }
        
        if (save_encrypted_batch(&batches[i], "out/encrypted") != 0) {
            fprintf(stderr, "[Test] Failed to save batch %d\n", i);
        }
    }

    // Cleanup
    for (uint32_t i = 0; i < temp_count; i++) {
        policy_free(&policies[i]);
    }
    free(policies);
    json_free_log_array(&logs);
    mpk_free(&mpk);
    
    return 0;
}

