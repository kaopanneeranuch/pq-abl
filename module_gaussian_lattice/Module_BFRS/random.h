#include <inttypes.h>

// Platform-specific intrinsic headers
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    // x86/x86_64 platforms
    #if defined(__GNUC__) || defined(__clang__)
        // GCC/Clang on x86_64: use specific headers for better macOS compatibility
        #if defined(__APPLE__)
            #include <emmintrin.h>  // SSE2
            #include <wmmintrin.h>  // AES-NI intrinsics
        #else
            #include <x86intrin.h>  // All x86 intrinsics (Linux/Windows)
        #endif
    #elif defined(_MSC_VER)
        #include <intrin.h>
        #include <wmmintrin.h>
    #endif
#elif defined(__aarch64__) || defined(_M_ARM64)
    // ARM64: AES intrinsics are not available, will need fallback
    // Define dummy types for compatibility
    typedef struct { uint64_t v[2]; } __m128i;
#endif

#include "common.h"

uint32_t uniform_int_distribution(uint32_t n);

scalar uniform_mod_q(void);

/*
	Code from random_aesni.c
*/

//public API
void random_bytes_init(void);

void random_bytes(uint8_t * restrict data);

/*
	Code from exp_aes.cpp
*/

double algorithm_EA(uint64_t * n);

/*
	Code from algoF_aes.cpp
*/

int algorithmF(double mu, double sigma);
