#include "lcp_util.h"
#include "../../module_gaussian_lattice/Module_BFRS/random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================================================
// Random Number Generation
// ============================================================================

static int rng_initialized = 0;

void rng_init(void) {
    if (!rng_initialized) {
        // Use Module_BFRS random initialization if available
        srand(time(NULL));
        rng_initialized = 1;
    }
}

void rng_seed(uint64_t seed) {
    srand((unsigned int)seed);
    rng_initialized = 1;
}

void rng_bytes(uint8_t *output, size_t len) {
    if (!rng_initialized) {
        rng_init();
    }
    
    for (size_t i = 0; i < len; i++) {
        output[i] = (uint8_t)(rand() & 0xFF);
    }
}

void rng_key(uint8_t key[AES_KEY_SIZE]) {
    rng_bytes(key, AES_KEY_SIZE);
}

void rng_nonce(uint8_t nonce[AES_NONCE_SIZE]) {
    rng_bytes(nonce, AES_NONCE_SIZE);
}

// ============================================================================
// SHA3-256 Implementation (Keccak)
// ============================================================================

// SHA3-256 constants
#define SHA3_256_RATE 136  // 1088 bits = 136 bytes
#define SHA3_STATE_SIZE 200  // 1600 bits = 200 bytes

// Keccak round constants
static const uint64_t keccak_round_constants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets
static const int keccak_rotation_offsets[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

// Pi lane mapping
static const int keccak_pi_lane[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

// Helper: Rotate left
static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak-f[1600] permutation
static void keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < 24; round++) {
        // Theta
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[x + 5 * y] ^= D[x];
            }
        }
        
        // Rho and Pi
        uint64_t temp = state[1];
        for (int i = 0; i < 24; i++) {
            int j = keccak_pi_lane[i];
            uint64_t temp2 = state[j];
            state[j] = rotl64(temp, keccak_rotation_offsets[i]);
            temp = temp2;
        }
        
        // Chi
        for (int y = 0; y < 5; y++) {
            uint64_t temp_row[5];
            for (int x = 0; x < 5; x++) {
                temp_row[x] = state[x + 5 * y];
            }
            for (int x = 0; x < 5; x++) {
                state[x + 5 * y] = temp_row[x] ^ ((~temp_row[(x + 1) % 5]) & temp_row[(x + 2) % 5]);
            }
        }
        
        // Iota
        state[0] ^= keccak_round_constants[round];
    }
}

// SHA3-256 hash function
void sha3_256(const uint8_t *input, size_t input_len, uint8_t output[SHA3_DIGEST_SIZE]) {
    uint64_t state[25] = {0};
    uint8_t *state_bytes = (uint8_t *)state;
    
    // Absorbing phase
    size_t block_size = SHA3_256_RATE;
    for (size_t i = 0; i < input_len; i += block_size) {
        size_t chunk_size = (input_len - i < block_size) ? (input_len - i) : block_size;
        
        for (size_t j = 0; j < chunk_size; j++) {
            state_bytes[j] ^= input[i + j];
        }
        
        if (chunk_size == block_size) {
            keccak_f1600(state);
        }
    }
    
    // Padding (SHA3 uses 0x06 suffix)
    size_t offset = input_len % block_size;
    state_bytes[offset] ^= 0x06;
    state_bytes[block_size - 1] ^= 0x80;
    
    keccak_f1600(state);
    
    // Squeezing phase
    memcpy(output, state_bytes, SHA3_DIGEST_SIZE);
}

void sha3_256_log_object(const void *ct_obj, uint8_t output[SHA3_DIGEST_SIZE]) {
    // Simple implementation: hash the memory block
    // In production, you'd serialize fields properly
    sha3_256((const uint8_t *)ct_obj, sizeof(void*), output);
}

// ============================================================================
// JSON Parsing
// ============================================================================

// Simple JSON string field extractor
int json_get_string_field(const char *json, const char *field_name, char *output, size_t max_len) {
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":", field_name);
    
    const char *field_start = strstr(json, search_pattern);
    if (!field_start) {
        return -1;
    }
    
    // Skip to value
    field_start += strlen(search_pattern);
    while (*field_start == ' ' || *field_start == '\t') field_start++;
    
    // Check if it's a string value (starts with ")
    if (*field_start != '"') {
        return -1;
    }
    field_start++; // Skip opening quote
    
    // Find closing quote
    const char *field_end = strchr(field_start, '"');
    if (!field_end) {
        return -1;
    }
    
    size_t len = field_end - field_start;
    if (len >= max_len) {
        len = max_len - 1;
    }
    
    strncpy(output, field_start, len);
    output[len] = '\0';
    
    return 0;
}

// Parse JSON log file (simple implementation)
int json_parse_log_file(const char *filename, JsonLogArray *logs) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    // Read entire file
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *json_content = (char *)malloc(file_size + 1);
    if (!json_content) {
        fclose(fp);
        return -1;
    }
    
    fread(json_content, 1, file_size, fp);
    json_content[file_size] = '\0';
    fclose(fp);
    
    // Initialize log array
    logs->capacity = 1000;
    logs->count = 0;
    logs->entries = (JsonLogEntry *)calloc(logs->capacity, sizeof(JsonLogEntry));
    
    // Simple parser: find each object between { }
    const char *ptr = json_content;
    while ((ptr = strchr(ptr, '{')) != NULL) {
        const char *obj_end = strchr(ptr, '}');
        if (!obj_end) break;
        
        size_t obj_len = obj_end - ptr + 1;
        char *obj_str = (char *)malloc(obj_len + 1);
        strncpy(obj_str, ptr, obj_len);
        obj_str[obj_len] = '\0';
        
        // Parse fields
        JsonLogEntry *entry = &logs->entries[logs->count];
        json_get_string_field(obj_str, "timestamp", entry->timestamp, sizeof(entry->timestamp));
        json_get_string_field(obj_str, "user_id", entry->user_id, sizeof(entry->user_id));
        json_get_string_field(obj_str, "user_role", entry->user_role, sizeof(entry->user_role));
        json_get_string_field(obj_str, "team", entry->team, sizeof(entry->team));
        json_get_string_field(obj_str, "action_type", entry->action_type, sizeof(entry->action_type));
        json_get_string_field(obj_str, "resource_id", entry->resource_id, sizeof(entry->resource_id));
        json_get_string_field(obj_str, "resource_type", entry->resource_type, sizeof(entry->resource_type));
        json_get_string_field(obj_str, "resource_owner", entry->resource_owner, sizeof(entry->resource_owner));
        json_get_string_field(obj_str, "service_name", entry->service_name, sizeof(entry->service_name));
        json_get_string_field(obj_str, "region", entry->region, sizeof(entry->region));
        json_get_string_field(obj_str, "instance_id", entry->instance_id, sizeof(entry->instance_id));
        json_get_string_field(obj_str, "ip_address", entry->ip_address, sizeof(entry->ip_address));
        json_get_string_field(obj_str, "application", entry->application, sizeof(entry->application));
        json_get_string_field(obj_str, "event_description", entry->event_description, sizeof(entry->event_description));
        json_get_string_field(obj_str, "log_data", entry->log_data, sizeof(entry->log_data));
        
        free(obj_str);
        logs->count++;
        
        if (logs->count >= logs->capacity) {
            break;
        }
        
        ptr = obj_end + 1;
    }
    
    free(json_content);
    return 0;
}

void json_free_log_array(JsonLogArray *logs) {
    if (logs->entries) {
        free(logs->entries);
        logs->entries = NULL;
    }
    logs->count = 0;
    logs->capacity = 0;
}

// ============================================================================
// Time/Epoch Utilities
// ============================================================================

// Simple ISO 8601 timestamp parser (YYYY-MM-DDTHH:MM:SS.ssssssZ)
uint64_t parse_timestamp(const char *timestamp) {
    struct tm tm_time = {0};
    int year, month, day, hour, minute, second;
    
    if (sscanf(timestamp, "%d-%d-%dT%d:%d:%d", 
               &year, &month, &day, &hour, &minute, &second) == 6) {
        tm_time.tm_year = year - 1900;
        tm_time.tm_mon = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min = minute;
        tm_time.tm_sec = second;
        tm_time.tm_isdst = 0;
        
        return (uint64_t)mktime(&tm_time);
    }
    
    return 0;
}

uint64_t get_epoch_id(uint64_t timestamp_seconds) {
    // 30-minute epochs = 1800 seconds
    return timestamp_seconds / (EPOCH_DURATION_MINUTES * 60);
}

int in_same_epoch(const char *ts1, const char *ts2) {
    uint64_t t1 = parse_timestamp(ts1);
    uint64_t t2 = parse_timestamp(ts2);
    
    return get_epoch_id(t1) == get_epoch_id(t2);
}
