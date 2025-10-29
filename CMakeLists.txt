cmake_minimum_required(VERSION 3.10)
project(pq_abl_stubs LANGUAGES CXX C)

# Simple CMake to build stub library for development
add_library(pq_abl_stubs
    src/abe/lcp_abe_setup.cpp
    src/abe/lcp_abe_keygen.cpp
    src/abe/lcp_abe_enc.cpp
    src/crypto/aes_gcm.cpp
    src/batch/microbatch.cpp
    src/glue/mtrapdoor_wrap.cpp
)

target_include_directories(pq_abl_stubs PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Build as position independent for linking into other projects
set_target_properties(pq_abl_stubs PROPERTIES POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)
if (OpenSSL_FOUND)
    target_link_libraries(pq_abl_stubs PRIVATE OpenSSL::Crypto)
endif()
add_executable(encrypt_logs_cli apps/encrypt_logs_cli/main.cpp)
target_link_libraries(encrypt_logs_cli PRIVATE pq_abl_stubs OpenSSL::Crypto)
target_include_directories(encrypt_logs_cli PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_executable(keygen_smoke apps/keygen_smoke/main.cpp)
target_link_libraries(keygen_smoke PRIVATE pq_abl_stubs OpenSSL::Crypto)
target_include_directories(keygen_smoke PRIVATE ${CMAKE_SOURCE_DIR}/include)
