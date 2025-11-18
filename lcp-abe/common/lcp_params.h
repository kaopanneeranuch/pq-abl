#ifndef LCP_PARAMS_H
#define LCP_PARAMS_H

// Link to Module_BFRS parameters
#include "../../module_gaussian_lattice/Module_BFRS/common.h"

// LCP-ABE specific parameters
#define MAX_ATTRIBUTES 32        // Maximum number of attributes per policy
#define MAX_POLICY_SIZE 256      // Maximum policy string length
#define ATTRIBUTE_NAME_LEN 64    // Maximum attribute name length

// AES-GCM parameters
#define AES_KEY_SIZE 32          // 256 bits
#define AES_NONCE_SIZE 12        // 96 bits
#define AES_TAG_SIZE 16          // 128 bits

// SHA3 parameters
#define SHA3_DIGEST_SIZE 32      // 256 bits

// Epoch parameters
#define EPOCH_DURATION_SECONDS 60

#endif // LCP_PARAMS_H
