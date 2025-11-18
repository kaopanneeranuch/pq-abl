cmake_minimum_required(VERSION 3.10)
project(pq_abl C)

set(CMAKE_C_STANDARD 11)

# Platform-specific compiler flags
if(MSVC)
    # MSVC compiler flags
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /O2 /W3")
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    # GCC/Clang compiler flags
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -Wextra")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter -Wno-unused-variable")
endif()

# Option to use OpenSSL for AES-GCM
option(USE_OPENSSL "Use OpenSSL for AES-GCM" ON)
if(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    add_definitions(-DUSE_OPENSSL)
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/lcp-abe/common
    ${CMAKE_SOURCE_DIR}/lcp-abe/util
    ${CMAKE_SOURCE_DIR}/lcp-abe/policy
    ${CMAKE_SOURCE_DIR}/lcp-abe/setup
    ${CMAKE_SOURCE_DIR}/lcp-abe/keygen
    ${CMAKE_SOURCE_DIR}/lcp-abe/encrypt
    ${CMAKE_SOURCE_DIR}/lcp-abe/decrypt
    ${CMAKE_SOURCE_DIR}/lcp-abe/revocation
    ${CMAKE_SOURCE_DIR}/module_gaussian_lattice/Module_BFRS
)

# Module_BFRS source files
set(MODULE_BFRS_SOURCES
    module_gaussian_lattice/Module_BFRS/arithmetic.c
    module_gaussian_lattice/Module_BFRS/sampling.c
    module_gaussian_lattice/Module_BFRS/random.c
    module_gaussian_lattice/Module_BFRS/cpucycles.c
    module_gaussian_lattice/Module_BFRS/crt_trees.c
    module_gaussian_lattice/Module_BFRS/signature.c
    module_gaussian_lattice/Module_BFRS/ibe.c
    module_gaussian_lattice/Module_BFRS/timing.c
)

# LCP-ABE source files
set(LCP_ABE_SOURCES
    lcp-abe/common/lcp_types.c
    lcp-abe/util/lcp_util.c
    lcp-abe/policy/lcp_policy.c
    lcp-abe/setup/lcp_setup.c
    lcp-abe/keygen/lcp_keygen.c
    lcp-abe/encrypt/lcp_encrypt.c
    lcp-abe/encrypt/aes_gcm.c
    lcp-abe/decrypt/lcp_decrypt.c
    lcp-abe/revocation/lcp_revocation.c
)

# Build Module_BFRS library
add_library(module_bfrs STATIC ${MODULE_BFRS_SOURCES})

# Link math library (needed for GCC/Clang, but not MSVC)
# MSVC includes math functions automatically, but GCC/Clang (including MinGW) need -lm
if(NOT MSVC)
    target_link_libraries(module_bfrs m)
endif()

# Link Windows cryptography library for CryptGenRandom on Windows
if(WIN32)
    target_link_libraries(module_bfrs advapi32)
endif()

## Enable AES intrinsics when using GCC/Clang on x86_64 so <wmmintrin.h> inlines work
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    # Only enable -maes on x86_64 architectures (not on ARM)
    # Check if we're on x86_64 architecture (exclude ARM64/aarch64)
    set(IS_X86_64 FALSE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64|i[3-6]86)")
        if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "(aarch64|arm64|ARM64)")
            set(IS_X86_64 TRUE)
        endif()
    endif()
    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64)")
            set(IS_X86_64 TRUE)
        endif()
    endif()
    
    if(IS_X86_64)
        # -maes enables AES-NI intrinsics; add privately to this target
        target_compile_options(module_bfrs PRIVATE -maes)
    endif()
endif()

# Build LCP-ABE library
add_library(lcp_abe STATIC ${LCP_ABE_SOURCES})
target_link_libraries(lcp_abe module_bfrs)

# Link math library (needed for GCC/Clang, but not MSVC)
if(NOT MSVC)
    target_link_libraries(lcp_abe m)
endif()

if(USE_OPENSSL)
    target_link_libraries(lcp_abe OpenSSL::SSL OpenSSL::Crypto)
endif()

# Test executables (built from lcp-abe/test)
add_executable(test_setup lcp-abe/test/setup.c)
target_link_libraries(test_setup lcp_abe)

add_executable(test_keygen lcp-abe/test/keygen.c)
target_link_libraries(test_keygen lcp_abe)

add_executable(test_encrypt lcp-abe/test/encrypt.c)
target_link_libraries(test_encrypt lcp_abe)

add_executable(test_encrypt_all lcp-abe/test/encrypt_all.c)
target_link_libraries(test_encrypt_all lcp_abe)

# In-memory round-trip test
add_executable(test_roundtrip lcp-abe/test/test_roundtrip.c)
target_include_directories(test_roundtrip PRIVATE ${CMAKE_SOURCE_DIR}/lcp-abe)
target_link_libraries(test_roundtrip PRIVATE lcp_abe module_bfrs)

# Link math library (needed for GCC/Clang, but not MSVC)
if(NOT MSVC)
    target_link_libraries(test_roundtrip PRIVATE m)
endif()

add_executable(test_decrypt lcp-abe/test/decrypt.c)
target_link_libraries(test_decrypt lcp_abe)

add_executable(test_decrypt_all lcp-abe/test/decrypt_all.c)
target_link_libraries(test_decrypt_all lcp_abe)

# Revocation test
add_executable(test_revocation lcp-abe/test/revocation.c)
target_include_directories(test_revocation PRIVATE ${CMAKE_SOURCE_DIR}/lcp-abe)
target_link_libraries(test_revocation PRIVATE lcp_abe module_bfrs)

# Link math library (needed for GCC/Clang, but not MSVC)
if(NOT MSVC)
    target_link_libraries(test_revocation PRIVATE m)
endif()

# Utility to view CT_obj files
add_executable(view_ctobj lcp-abe/util/view_ctobj.c)
target_link_libraries(view_ctobj lcp_abe)

# Installation
install(TARGETS lcp_abe module_bfrs
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(DIRECTORY lcp-abe/
        DESTINATION include/lcp-abe
        FILES_MATCHING PATTERN "*.h")