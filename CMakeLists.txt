cmake_minimum_required(VERSION 3.10)
project(pq_abl C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -Wextra -march=native")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter -Wno-unused-variable")

# Add math library
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lm")

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
)

# Build Module_BFRS library
add_library(module_bfrs STATIC ${MODULE_BFRS_SOURCES})
target_link_libraries(module_bfrs m)

# Build LCP-ABE library
add_library(lcp_abe STATIC ${LCP_ABE_SOURCES})
target_link_libraries(lcp_abe module_bfrs m)
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

add_executable(test_decrypt lcp-abe/test/decrypt.c)
target_link_libraries(test_decrypt lcp_abe)

# Installation
install(TARGETS lcp_abe module_bfrs
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(DIRECTORY lcp-abe/
        DESTINATION include/lcp-abe
        FILES_MATCHING PATTERN "*.h")

# Print configuration
message(STATUS "========================================")
message(STATUS "PQ-ABL Configuration")
message(STATUS "========================================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C Flags: ${CMAKE_C_FLAGS}")
message(STATUS "Use OpenSSL: ${USE_OPENSSL}")
message(STATUS "========================================")
