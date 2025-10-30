#ifndef LCP_UTIL_H
#define LCP_UTIL_H

#include "../common/lcp_params.h"
#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Random Number Generation (RNG)
// ============================================================================

// Initialize RNG with seed
void rng_init(void);
void rng_seed(uint64_t seed);

// Generate random bytes
void rng_bytes(uint8_t *output, size_t len);

// Generate random 256-bit key
void rng_key(uint8_t key[AES_KEY_SIZE]);

// Generate random 96-bit nonce
void rng_nonce(uint8_t nonce[AES_NONCE_SIZE]);

// ============================================================================
// SHA3-256 Hash Function
// ============================================================================

// Compute SHA3-256 hash
void sha3_256(const uint8_t *input, size_t input_len, uint8_t output[SHA3_DIGEST_SIZE]);

// Compute SHA3-256 hash of encrypted log object
void sha3_256_log_object(const void *ct_obj, uint8_t output[SHA3_DIGEST_SIZE]);

// ============================================================================
// JSON Parsing (Simple Parser for Log Files)
// ============================================================================

typedef struct {
    char timestamp[32];
    char user_id[64];
    char user_role[32];
    char team[32];
    char action_type[32];
    char resource_id[64];
    char resource_type[32];
    char resource_owner[64];
    char service_name[32];
    char region[32];
    char instance_id[64];
    char ip_address[32];
    char application[64];
    char event_description[256];
    char log_data[1024];
} JsonLogEntry;

typedef struct {
    JsonLogEntry *entries;
    uint32_t count;
    uint32_t capacity;
} JsonLogArray;

// Parse JSON log file
int json_parse_log_file(const char *filename, JsonLogArray *logs);

// Free log array
void json_free_log_array(JsonLogArray *logs);

// Get field value from JSON string
int json_get_string_field(const char *json, const char *field_name, char *output, size_t max_len);

// ============================================================================
// Time/Epoch Utilities
// ============================================================================

// Parse ISO 8601 timestamp to epoch time (seconds)
uint64_t parse_timestamp(const char *timestamp);

// Get epoch ID from timestamp (30-minute windows)
uint64_t get_epoch_id(uint64_t timestamp_seconds);

// Check if two timestamps are in the same epoch
int in_same_epoch(const char *ts1, const char *ts2);

#endif // LCP_UTIL_H
