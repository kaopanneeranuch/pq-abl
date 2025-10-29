#include "../../include/abe/lcp_abe.h"
#include "../../include/crypto/aes_gcm.h"
#include "../../include/batch/microbatch.h"
#include <iostream>
#include "../../include/crypto/sha3.h"
#include <openssl/rand.h>
#include <unordered_map>

// This file implements a batched placeholder for LCP-ABE encapsulation.
// It demonstrates per-policy heavy precomputation caching and cheap per-log finalization.

struct PolicyPrecomp {
    std::vector<uint8_t> heavy; // heavy precomputed bytes (e.g., derived from MPK and policy)
};

static std::unordered_map<std::string, PolicyPrecomp> policy_cache;

// Encapsulate K_log under policy_id using MPK. This is a placeholder that:
// - on cache miss, computes heavy = SHA3( policy_id || concat(B_pos matching tokens) )
// - per-log, derives a symmetric key from heavy||nonce and AES-GCM-encrypts K_log to produce CT_ABE
static int enc_lcp_abe_placeholder(const MPK &mpk, const std::string &policy_id, const std::vector<uint8_t> &K_log, std::vector<uint8_t> &ct_abe) {
    // find or create precomp
    auto it = policy_cache.find(policy_id);
    if (it == policy_cache.end()) {
        // heavy = sha3(policy_id || concat of B_pos for attributes whose name appears in policy_id)
        std::vector<uint8_t> mix;
        mix.insert(mix.end(), policy_id.begin(), policy_id.end());
        for (const auto &kv : mpk.B_pos) {
            if (policy_id.find(kv.first) != std::string::npos) {
                mix.insert(mix.end(), kv.second.begin(), kv.second.end());
            }
        }
        auto heavy = pq_abl::crypto::sha3_256(mix.data(), mix.size());
        PolicyPrecomp pc{heavy};
        policy_cache.emplace(policy_id, std::move(pc));
        it = policy_cache.find(policy_id);
    }

    const auto &heavy = it->second.heavy;
    // derive per-log key using SHA3(heavy || random nonce)
    uint8_t nonce_local[12];
    if (RAND_bytes(nonce_local, sizeof(nonce_local)) != 1) return -1;
    std::vector<uint8_t> dk_input = heavy;
    dk_input.insert(dk_input.end(), nonce_local, nonce_local + sizeof(nonce_local));
    auto dk = pq_abl::crypto::sha3_256(dk_input.data(), dk_input.size());

    // Use first 32 bytes of dk as key to encrypt K_log via AES-GCM
    std::vector<uint8_t> ct; std::vector<uint8_t> out_nonce;
    int rc = pq_abl::crypto::aes_gcm_encrypt(dk.data(), dk.size(), nonce_local, sizeof(nonce_local), nullptr, 0, K_log.data(), K_log.size(), ct, out_nonce);
    if (rc != 0) return rc;

    // Serialize ct_abe as: nonce || ciphertext (both binary)
    ct_abe.clear();
    ct_abe.insert(ct_abe.end(), nonce_local, nonce_local + sizeof(nonce_local));
    ct_abe.insert(ct_abe.end(), ct.begin(), ct.end());
    return 0;
}

namespace pq_abl {

int lcp_abe_encrypt_log(const MPK &mpk, const std::string &policy_id, const uint8_t *payload, size_t payload_len, CTObj &out) {
    (void)payload_len;
    // 1) generate fresh per-log symmetric key K_log
    std::vector<uint8_t> K_log(32);
    if (RAND_bytes(K_log.data(), (int)K_log.size()) != 1) return -1;

    // 2) AES-GCM encrypt the payload with K_log
    std::vector<uint8_t> ct_sym; std::vector<uint8_t> sym_nonce;
    int rc = pq_abl::crypto::aes_gcm_encrypt(K_log.data(), K_log.size(), nullptr, 0, nullptr, 0, payload, payload_len, ct_sym, sym_nonce);
    if (rc != 0) return rc;

    // 3) Encapsulate K_log under policy via batched LCP-ABE placeholder
    std::vector<uint8_t> ct_abe;
    rc = enc_lcp_abe_placeholder(mpk, policy_id, K_log, ct_abe);
    if (rc != 0) return rc;

    // 4) produce meta JSON (minimal)
    out.ct_sym = std::move(ct_sym);
    out.ct_abe = std::move(ct_abe);
    out.meta_json = "{\"policy_id\":\"" + policy_id + "\"}";
    return 0;
}

int lcp_abe_decrypt_log(const SK &sk, const MPK &mpk, const CTObj &ct, std::vector<uint8_t> &out_plaintext) {
    (void)sk; (void)mpk; (void)ct;
    // TODO: call ABE decapsulation then AES-GCM decrypt
    std::cout << "lcp_abe_decrypt_log: stub called\n";
    out_plaintext = std::vector<uint8_t>{};
    return -1; // not implemented
}

} // namespace pq_abl
