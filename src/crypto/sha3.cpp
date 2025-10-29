#include "../../include/crypto/sha3.h"
#include <openssl/evp.h>

namespace pq_abl::crypto {

std::vector<uint8_t> sha3_256(const uint8_t *in, size_t in_len) {
    std::vector<uint8_t> out(32);
    unsigned int out_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return {};
    if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1) { EVP_MD_CTX_free(mdctx); return {}; }
    if (EVP_DigestUpdate(mdctx, in, in_len) != 1) { EVP_MD_CTX_free(mdctx); return {}; }
    if (EVP_DigestFinal_ex(mdctx, out.data(), &out_len) != 1) { EVP_MD_CTX_free(mdctx); return {}; }
    EVP_MD_CTX_free(mdctx);
    out.resize(out_len);
    return out;
}

} // namespace pq_abl::crypto
