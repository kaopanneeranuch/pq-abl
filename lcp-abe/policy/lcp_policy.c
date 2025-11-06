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
static uint32_t attr_name_to_index(const char *attr_name) {
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

// Helper: Build (k, n) threshold LSSS matrix using Shamir secret sharing
// Matrix has n rows (one per attribute) and k columns
// Row i corresponds to attribute i with evaluation point x_i = i+1
static int lsss_threshold_matrix(AccessPolicy *policy) {
    uint32_t k = policy->threshold;
    uint32_t n = policy->attr_count;
    
    if (k > n || k == 0) {
        fprintf(stderr, "Error: Invalid threshold %u for %u attributes\n", k, n);
        return -1;
    }
    
    // Allocate LSSS matrix (n × k)
    policy->matrix_rows = n;
    policy->matrix_cols = k;
    policy->share_matrix = (scalar *)calloc(n * k, sizeof(scalar));
    policy->rho = (uint32_t *)calloc(n, sizeof(uint32_t));
    
    // Build Vandermonde-like matrix for Shamir secret sharing
    // M[i][j] = (i+1)^j mod q, where i is attribute index, j is power
    for (uint32_t i = 0; i < n; i++) {
        policy->rho[i] = i; // Row i → attribute i
        
        uint64_t x = i + 1; // Evaluation point x_i = i+1
        uint64_t power = 1; // x^j
        
        for (uint32_t j = 0; j < k; j++) {
            policy->share_matrix[i * k + j] = (scalar)(power % PARAM_Q);
            power = (power * x) % PARAM_Q;
        }
    }
    
    return 0;
}

// Convert policy to LSSS matrix representation
// Supports:
// - AND policy: (n, n) threshold - need all attributes
// - OR policy: (1, n) threshold - need any one attribute  
// - THRESHOLD policy: (k, n) threshold - need k out of n attributes
// - Complex policies via LSSS matrix (future work: monotone span programs)
int lsss_policy_to_matrix(AccessPolicy *policy) {
    if (policy->attr_count == 0) {
        return -1;
    }
    
    // Initialize policy metadata
    policy->is_threshold = 0;
    policy->threshold = policy->attr_count; // Default: AND (need all)
    
    // Check if policy is AND, OR, or THRESHOLD
    int is_and = (strstr(policy->expression, "AND") != NULL);
    int is_or = (strstr(policy->expression, "OR") != NULL);
    
    // Check for threshold format: "THRESHOLD(k, attr1, attr2, ...)"
    const char *thresh_ptr = strstr(policy->expression, "THRESHOLD(");
    if (thresh_ptr) {
        policy->is_threshold = 1;
        // Parse threshold value k
        sscanf(thresh_ptr, "THRESHOLD(%u", &policy->threshold);
        
        // Build (k, n) threshold LSSS matrix using Shamir secret sharing
        return lsss_threshold_matrix(policy);
    }
    
    if (is_and) {
        // AND policy: (n, n) threshold scheme - need ALL attributes
        policy->threshold = policy->attr_count;
        // Matrix M is n×n identity-like matrix
        policy->matrix_rows = policy->attr_count;
        policy->matrix_cols = policy->attr_count;
        
        policy->share_matrix = (scalar *)calloc(
            policy->matrix_rows * policy->matrix_cols, sizeof(scalar)
        );
        policy->rho = (uint32_t *)calloc(policy->matrix_rows, sizeof(uint32_t));
        
        // Create identity-based sharing matrix
        // Row i corresponds to attribute policy->attr_indices[i]
        // M[i][0] = 1, M[i][j] = random for j > 0
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            policy->rho[i] = policy->attr_indices[i]; // Row i → actual attribute index in universe
            
            for (uint32_t j = 0; j < policy->matrix_cols; j++) {
                if (i == 0 && j == 0) {
                    // First element is 1 (secret in first position)
                    policy->share_matrix[i * policy->matrix_cols + j] = 1;
                } else if (j == i) {
                    // Diagonal elements for additive sharing
                    policy->share_matrix[i * policy->matrix_cols + j] = 1;
                } else {
                    policy->share_matrix[i * policy->matrix_cols + j] = 0;
                }
            }
        }
        
    } else if (is_or) {
        // OR policy: (1, n) threshold scheme - need ANY ONE attribute
        policy->threshold = 1;
        // Matrix M has n rows, 1 column, all entries are 1
        policy->matrix_rows = policy->attr_count;
        policy->matrix_cols = 1;
        
        policy->share_matrix = (scalar *)calloc(
            policy->matrix_rows * policy->matrix_cols, sizeof(scalar)
        );
        policy->rho = (uint32_t *)calloc(policy->matrix_rows, sizeof(uint32_t));
        
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            policy->rho[i] = policy->attr_indices[i]; // Row i → actual attribute index in universe
            policy->share_matrix[i] = 1; // Each row gets the secret
        }
        
    } else {
        // Default: treat as AND
        return lsss_policy_to_matrix(policy);
    }
    
    return 0;
}

// Generate shares from secret using LSSS matrix
// v = M · [s, r_1, r_2, ..., r_{n-1}]^T where s is secret, r_i are random
int lsss_generate_shares(const AccessPolicy *policy, scalar secret, scalar *shares) {
    if (!policy->share_matrix || !shares) {
        return -1;
    }
    
    // Create vector [s, r_1, ..., r_{n-1}]
    scalar *vector = (scalar *)calloc(policy->matrix_cols, sizeof(scalar));
    vector[0] = secret;
    
    // Fill with random values (mod q)
    for (uint32_t i = 1; i < policy->matrix_cols; i++) {
        vector[i] = rand() % PARAM_Q;
    }
    
    // Compute shares: shares = M · vector (mod q)
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

// Check if attribute set satisfies policy
int lsss_check_satisfaction(const AccessPolicy *policy, const AttributeSet *attr_set) {
    // Count how many policy attributes are in the attribute set
    uint32_t match_count = 0;
    for (uint32_t i = 0; i < policy->attr_count; i++) {
        // Check if attribute i is in attr_set
        // (simplified: check by index for now)
        if (i < attr_set->count) {
            match_count++;
        }
    }
    
    // Check satisfaction based on policy type
    if (policy->is_threshold) {
        // Threshold policy: need at least k matching attributes
        return match_count >= policy->threshold;
    }
    
    // Check if policy is AND or OR
    int is_and = (strstr(policy->expression, "AND") != NULL);
    int is_or = (strstr(policy->expression, "OR") != NULL);
    
    if (is_and) {
        // Need ALL attributes
        return (match_count == policy->attr_count);
    } else if (is_or) {
        // Need at least ONE attribute
        return (match_count > 0);
    } else {
        // Default: AND
        return (match_count == policy->attr_count);
    }
}

// Compute reconstruction coefficients (ω_i) for satisfied attributes
// For AND: ω_i such that Σ ω_i · λ_i = s where λ_i are shares
// For OR: ω_i = 1 for any satisfied attribute
int lsss_compute_coefficients(const AccessPolicy *policy, const AttributeSet *attr_set,
                              scalar *coefficients, uint32_t *n_coeffs) {
    if (!lsss_check_satisfaction(policy, attr_set)) {
        return -1; // Policy not satisfied
    }
    
    // Check if policy is AND or OR
    int is_or = (strstr(policy->expression, "OR") != NULL);
    
    if (is_or) {
        // For OR policy: use first matching attribute with coefficient 1
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            if (i < attr_set->count) {
                coefficients[0] = 1;
                *n_coeffs = 1;
                return 0;
            }
        }
    } else {
        // For AND policy: coefficients to reconstruct from all shares
        // Simplified: use equal weights (1/n for each)
        *n_coeffs = policy->matrix_rows;
        for (uint32_t i = 0; i < policy->matrix_rows; i++) {
            coefficients[i] = 1; // Simplified: equal contribution
        }
    }
    
    return 0;
}

// Reconstruct secret from shares (if policy is satisfied)
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
    
    // Reconstruct: s = Σ ω_i · λ_i (mod q)
    uint64_t sum = 0;
    for (uint32_t i = 0; i < n_coeffs; i++) {
        uint64_t prod = (uint64_t)coefficients[i] * shares[i];
        sum = (sum + prod) % PARAM_Q;
    }
    
    *secret = (scalar)sum;
    return 1;
}
