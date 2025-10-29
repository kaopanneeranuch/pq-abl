// Simple smoke test: run lcp_abe_setup -> lcp_abe_keygen and print sizes
#include <iostream>
#include <vector>
#include <string>
#include <openssl/rand.h>
#include <abe/lcp_abe.h>

int main() {
    std::cout << "KeyGen smoke test: starting\n";
    std::vector<std::string> attributes = {"role:admin", "dept:finance"};
    std::vector<uint8_t> seed(32);
    if (RAND_bytes(seed.data(), (int)seed.size()) != 1) {
        std::cerr << "RAND_bytes failed for seed\n";
        // continue with empty seed
        seed.clear();
    }

    pq_abl::MPK mpk;
    pq_abl::MSK msk;
    int rc = pq_abl::lcp_abe_setup(attributes, seed, mpk, msk);
    if (rc != 0) {
        std::cerr << "lcp_abe_setup failed rc=" << rc << "\n";
        return rc;
    }

    std::cout << "Setup produced A size=" << mpk.A.size() << " beta size=" << mpk.beta.size() << "\n";

    // choose a subset for the user
    std::vector<std::string> user_attrs = {"role:admin"};
    pq_abl::SK sk;
    int krc = pq_abl::lcp_abe_keygen(msk, mpk, user_attrs, sk);
    if (krc != 0) {
        std::cerr << "lcp_abe_keygen failed rc=" << krc << "\n";
        return krc;
    }

    std::cout << "KeyGen complete: omega_A size=" << sk.omega_A.size() << " bytes\n";
    for (auto &a : user_attrs) {
        auto it = sk.omegas.find(a);
        if (it != sk.omegas.end()) std::cout << " omega[" << a << "] size=" << it->second.size() << " bytes\n";
        else std::cout << " omega[" << a << "] missing\n";
    }

    // print B_pos sizes
    for (auto &a : attributes) {
        auto it = mpk.B_pos.find(a);
        if (it != mpk.B_pos.end()) std::cout << "mpk.B_pos[" << a << "] size=" << it->second.size() << "\n";
    }

    std::cout << "Smoke test finished\n";
    return 0;
}
