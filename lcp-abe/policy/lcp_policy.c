#include "lcp_policy.h"
#include "../util/lcp_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// ============================================================================
// Policy Parsing
// ============================================================================

// Simple hash function to map attribute name to index [0, 127]
uint32_t attr_name_to_index(const char *attr_name) {
    uint32_t hash = 5381;
    int c;
    while ((c = *attr_name++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % 128; // Map to [0, 127] for our 128-attribute universe
}

// Simple policy parser for AND/OR/THRESHOLD policies
// Supported formats:
//   - "(attr1 AND attr2)" - Need all attributes
//   - "(attr1 OR attr2)" - Need any one attribute
//   - "THRESHOLD(2, attr1, attr2, attr3)" - Need k=2 out of 3 attributes
//   - Future: Complex monotone formulas via MSP
// Example: "(user_role:admin AND team:storage-team)"
int policy_parse(const char *expression, AccessPolicy *policy) {
    strncpy(policy->expression, expression, MAX_POLICY_SIZE - 1);
    policy->expression[MAX_POLICY_SIZE - 1] = '\0';
    
    policy->attr_count = 0;
    
    // Simple parser: extract attributes between colons
    // Example: "(user_role:admin AND team:storage-team)"
    // Extracts: "user_role:admin", "team:storage-team"
    
    const char *ptr = expression;
    char attr_buffer[ATTRIBUTE_NAME_LEN];
    int in_attr = 0;
    int attr_start = 0;
    
    for (int i = 0; expression[i] != '\0' && policy->attr_count < MAX_ATTRIBUTES; i++) {
        char c = expression[i];
        
        // Start of attribute (letter after space or opening paren)
        if (isalpha(c) && !in_attr) {
            in_attr = 1;
            attr_start = i;
        }
        
        // End of attribute (space, closing paren, or operator)
        if (in_attr && (c == ' ' || c == ')' || c == '\0')) {
            int attr_len = i - attr_start;
            if (attr_len > 0 && attr_len < ATTRIBUTE_NAME_LEN) {
                strncpy(attr_buffer, &expression[attr_start], attr_len);
                attr_buffer[attr_len] = '\0';
                
                // Check if it's not an operator keyword
                if (strcmp(attr_buffer, "AND") != 0 && strcmp(attr_buffer, "OR") != 0) {
                    // Map attribute name to universe index using hash
                    uint32_t attr_index = attr_name_to_index(attr_buffer);
                    policy->attr_indices[policy->attr_count] = attr_index;
                    printf("[Policy] Parsed attribute '%s' → index %u\n", attr_buffer, attr_index);
                    policy->attr_count++;
                }
            }
            in_attr = 0;
        }
    }
    
    return 0;
}

// Match log entry attributes to policy
int policy_match_log(const JsonLogEntry *log, const AccessPolicy *policy) {
    // Simple matching: check if policy expression contains log's role and/or team
    char role_attr[128];
    char team_attr[128];
    
    snprintf(role_attr, sizeof(role_attr), "user_role:%s", log->user_role);
    snprintf(team_attr, sizeof(team_attr), "team:%s", log->team);
    
    int has_role = (strstr(policy->expression, role_attr) != NULL);
    int has_team = (strstr(policy->expression, team_attr) != NULL);
    
    // Check if policy contains role or team prefix
    int policy_has_role = (strstr(policy->expression, "user_role:") != NULL);
    int policy_has_team = (strstr(policy->expression, "team:") != NULL);
    
    // Check if AND or OR
    int is_and = (strstr(policy->expression, "AND") != NULL);
    int is_or = (strstr(policy->expression, "OR") != NULL);
    
    if (is_and) {
        return has_role && has_team;
    } else if (is_or) {
        return has_role || has_team;
    } else {
        // Single attribute policy: match if any required attribute matches
        if (policy_has_role && !policy_has_team) {
            return has_role;
        } else if (policy_has_team && !policy_has_role) {
            return has_team;
        } else {
            // Both attributes in policy but no explicit AND/OR, default to AND
            return has_role && has_team;
        }
    }
}

// ============================================================================
// Linear Secret Sharing Scheme (LSSS) for Lattice-Based CP-ABE
// ============================================================================

static int lsss_threshold_matrix(AccessPolicy *policy) {
    uint32_t k = policy->threshold;
    uint32_t n = policy->attr_count;
    
    if (k > n || k == 0) {
        fprintf(stderr, "Error: Invalid threshold %u for %u attributes\n", k, n);
        return -1;
    }
    
    policy->matrix_rows = n;
    policy->matrix_cols = k;
    policy->share_matrix = (scalar *)calloc(n * k, sizeof(scalar));
    policy->rho = (uint32_t *)calloc(n, sizeof(uint32_t));
    
    for (uint32_t i = 0; i < n; i++) {
        policy->rho[i] = i; 
        
        uint64_t x = i + 1; 
        uint64_t power = 1; 
        
        for (uint32_t j = 0; j < k; j++) {
            policy->share_matrix[i * k + j] = (scalar)(power % PARAM_Q);
            power = (power * x) % PARAM_Q;
        }
    }
    
    return 0;
}

int lsss_policy_to_matrix(AccessPolicy *policy) {
    if (policy->attr_count == 0) {
        return -1;
    }
    
    policy->is_threshold = 0;
    policy->threshold = policy->attr_count; 
    
    int is_and = (strstr(policy->expression, "AND") != NULL);
    int is_or = (strstr(policy->expression, "OR") != NULL);
    
    const char *thresh_ptr = strstr(policy->expression, "THRESHOLD(");
    if (thresh_ptr) {
        policy->is_threshold = 1;
        sscanf(thresh_ptr, "THRESHOLD(%u", &policy->threshold);
        
        return lsss_threshold_matrix(policy);
    }
    
    if (is_and) {
        policy->threshold = policy->attr_count;
        policy->matrix_rows = policy->attr_count;
        policy->matrix_cols = policy->attr_count;
        
        policy->share_matrix = (scalar *)calloc(
            policy->matrix_rows * policy->matrix_cols, sizeof(scalar)
        );
        policy->rho = (uint32_t *)calloc(policy->matrix_rows, sizeof(uint32_t));
        
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            policy->rho[i] = policy->attr_indices[i]; 
            
            for (uint32_t j = 0; j < policy->matrix_cols; j++) {
                if (i == 0 && j == 0) {
                    policy->share_matrix[i * policy->matrix_cols + j] = 1;
                } else if (j == i) {
                    policy->share_matrix[i * policy->matrix_cols + j] = 1;
                } else {
                    policy->share_matrix[i * policy->matrix_cols + j] = 0;
                }
            }
        }
        
    } else if (is_or) {
        policy->threshold = 1;
        policy->matrix_rows = policy->attr_count;
        policy->matrix_cols = 1;
        
        policy->share_matrix = (scalar *)calloc(
            policy->matrix_rows * policy->matrix_cols, sizeof(scalar)
        );
        policy->rho = (uint32_t *)calloc(policy->matrix_rows, sizeof(uint32_t));
        
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            policy->rho[i] = policy->attr_indices[i]; 
            policy->share_matrix[i] = 1; 
        }
        
    } else {
        return lsss_policy_to_matrix(policy);
    }
    
    return 0;
}

int lsss_generate_shares(const AccessPolicy *policy, scalar secret, scalar *shares) {
    if (!policy->share_matrix || !shares) {
        return -1;
    }
    
    scalar *vector = (scalar *)calloc(policy->matrix_cols, sizeof(scalar));
    vector[0] = secret;
    
    for (uint32_t i = 1; i < policy->matrix_cols; i++) {
        vector[i] = rand() % PARAM_Q;
    }
    
    for (uint32_t i = 0; i < policy->matrix_rows; i++) {
        uint64_t sum = 0;
        for (uint32_t j = 0; j < policy->matrix_cols; j++) {
            uint64_t prod = (uint64_t)policy->share_matrix[i * policy->matrix_cols + j] * vector[j];
            sum = (sum + prod) % PARAM_Q;
        }
        shares[i] = (scalar)sum;
    }
    
    free(vector);
    return 0;
}

int lsss_check_satisfaction(const AccessPolicy *policy, const AttributeSet *attr_set) {
    printf("[Policy Check] Policy: %s\n", policy->expression);
    printf("[Policy Check] Policy requires %d attributes:\n", policy->attr_count);
    for (uint32_t i = 0; i < policy->attr_count; i++) {
        printf("[Policy Check]   - Index %u\n", policy->attr_indices[i]);
    }
    
    printf("[Policy Check] User has %d attributes:\n", attr_set->count);
    for (uint32_t i = 0; i < attr_set->count; i++) {
        printf("[Policy Check]   - %s (index %u)\n", 
               attr_set->attrs[i].name, attr_set->attrs[i].index);
    }
    
    uint32_t match_count = 0;
    
    printf("[Policy Check] Checking attribute matches:\n");
    for (uint32_t i = 0; i < policy->attr_count; i++) {
        uint32_t policy_attr_index = policy->attr_indices[i];
        printf("[Policy Check]   Policy attr %d: index=%u\n", i, policy_attr_index);
        
        int matched = 0;
        for (uint32_t j = 0; j < attr_set->count; j++) {
            printf("[Policy Check]     Comparing with user attr %d: '%s' (index=%u)\n",
                   j, attr_set->attrs[j].name, attr_set->attrs[j].index);
            
            if (attr_set->attrs[j].index == policy_attr_index) {
                match_count++;
                matched = 1;
                printf("[Policy Check]     MATCH! Policy index %u == User attr '%s' (index %u)\n",
                       policy_attr_index, attr_set->attrs[j].name, attr_set->attrs[j].index);
                break;
            }
        }
        
        if (!matched) {
            printf("[Policy Check]     No match for policy index %u\n", policy_attr_index);
        }
    }
    
    printf("[Policy Check] Matched %d/%d policy attributes\n", match_count, policy->attr_count);
    
    if (policy->is_threshold) {
        int satisfied = (match_count >= policy->threshold);
        printf("[Policy Check] Threshold policy: need %d, have %d → %s\n",
               policy->threshold, match_count, satisfied ? "SATISFIED" : "NOT SATISFIED");
        return satisfied;
    }
    
    int is_and = (strstr(policy->expression, "AND") != NULL);
    int is_or = (strstr(policy->expression, "OR") != NULL);
    
    if (is_and) {
        int satisfied = (match_count == policy->attr_count);
        printf("[Policy Check] AND policy: need all %d, have %d → %s\n",
               policy->attr_count, match_count, satisfied ? "SATISFIED" : "NOT SATISFIED");
        return satisfied;
    } else if (is_or) {
        int satisfied = (match_count > 0);
        printf("[Policy Check] OR policy: need ≥1, have %d → %s\n",
               match_count, satisfied ? "SATISFIED" : "NOT SATISFIED");
        return satisfied;
    } else {
        int satisfied = (match_count == policy->attr_count);
        printf("[Policy Check] Default (AND) policy: need all %d, have %d → %s\n",
               policy->attr_count, match_count, satisfied ? "SATISFIED" : "NOT SATISFIED");
        return satisfied;
    }
}

int lsss_compute_coefficients(const AccessPolicy *policy, const AttributeSet *attr_set,
                              scalar *coefficients, uint32_t *n_coeffs) {
    if (!lsss_check_satisfaction(policy, attr_set)) {
        return -1; 
    }
    
    int is_or = (strstr(policy->expression, "OR") != NULL);
    
    if (is_or) {
        memset(coefficients, 0, policy->matrix_rows * sizeof(scalar));
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            uint32_t policy_attr_idx = policy->rho[i];
            for (uint32_t j = 0; j < attr_set->count; j++) {
                if (attr_set->attrs[j].index == policy_attr_idx) {
                    coefficients[i] = 1;
                    printf("[LSSS] OR policy: Using policy row %d (attr idx %d) with coeff=1\n",
                           i, policy_attr_idx);
                    break;
                }
            }
        }
        *n_coeffs = policy->matrix_rows;
        return 0;
    } else {
        // For AND policy: Must use ALL policy attributes
        memset(coefficients, 0, policy->matrix_rows * sizeof(scalar));
        *n_coeffs = 0;
        
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            uint32_t policy_attr_idx = policy->rho[i];
            
            int has_attr = 0;
            for (uint32_t j = 0; j < attr_set->count; j++) {
                if (attr_set->attrs[j].index == policy_attr_idx) {
                    has_attr = 1;
                    (*n_coeffs)++;
                    break;
                }
            }
            
            if (!has_attr) {
                return -1;
            }
        }
        
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            coefficients[i] = 1; 
            printf("[LSSS] AND policy: Using policy row %d (attr idx %d) with coeff=1\n",
                   i, policy->rho[i]);
        }
    }
    
    return 0;
}

int lsss_reconstruct_secret(const AccessPolicy *policy, const scalar *shares,
                            const AttributeSet *attr_set, scalar *secret) {
    if (!lsss_check_satisfaction(policy, attr_set)) {
        return 0; // Cannot reconstruct
    }
    
    scalar coefficients[MAX_ATTRIBUTES];
    uint32_t n_coeffs = 0;
    
    if (lsss_compute_coefficients(policy, attr_set, coefficients, &n_coeffs) != 0) {
        return 0;
    }
    
    uint64_t sum = 0;
    for (uint32_t i = 0; i < n_coeffs; i++) {
        uint64_t prod = (uint64_t)coefficients[i] * shares[i];
        sum = (sum + prod) % PARAM_Q;
    }
    
    *secret = (scalar)sum;
    return 1;
}
