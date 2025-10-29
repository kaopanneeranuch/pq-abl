#ifndef LCP_ABE_H
#define LCP_ABE_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>

// High-level LCP-ABE public API for Phase 1/2/3

namespace pq_abl {

struct MPK {
    std::vector<uint8_t> A; // serialized matrix A
    // serialized B_pos and B_neg map could be added later
    std::vector<uint8_t> beta;
    std::unordered_map<std::string, std::vector<uint8_t>> B_pos; // per-attribute public components
    std::unordered_map<std::string, std::vector<uint8_t>> B_neg;
};

struct MSK {
    std::vector<uint8_t> T_A; // trapdoor (serialized scalar array)
    std::vector<uint8_t> cplx_T; // complex CRT representation (serialized)
    std::vector<uint8_t> sch_comp; // Schur complement (serialized)
    std::vector<uint8_t> u; // auxiliary public vector u
};

struct SK {
    std::vector<uint8_t> omega_A;
    // per-attribute omegas (serialized vectors) for attributes in user's key
    std::unordered_map<std::string, std::vector<uint8_t>> omegas;
    // per-attribute omegas serialized
};

struct CTObj {
    std::vector<uint8_t> ct_sym; // AES-GCM ciphertext
    std::vector<uint8_t> ct_abe; // ABE encapsulation blob
    std::string meta_json;       // JSON meta for easy testing
};

// Phase 1: Setup
int lcp_abe_setup(const std::vector<std::string>& attributes, const std::vector<uint8_t>& seed, MPK &mpk, MSK &msk);

// Phase 2: User key generation
int lcp_abe_keygen(const MSK &msk, const MPK &mpk, const std::vector<std::string>& user_attrs, SK &sk);

// Phase 3: Encryption (per-log: produce CTObj)
int lcp_abe_encrypt_log(const MPK &mpk, const std::string &policy_id, const uint8_t *payload, size_t payload_len, CTObj &out);

// Phase 3: Decryption (decapsulation + AES-GCM decrypt will be added later)
int lcp_abe_decrypt_log(const SK &sk, const MPK &mpk, const CTObj &ct, std::vector<uint8_t> &out_plaintext);

} // namespace pq_abl

#endif // LCP_ABE_H
