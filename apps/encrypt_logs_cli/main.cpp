#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <optional>
#include <sstream>

#include "../..//include/crypto/aes_gcm.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace fs = std::filesystem;
using namespace pq_abl::crypto;

static std::optional<std::string> extract_json_field(const std::string &s, const std::string &field) {
    // naive extraction: find "field" then ':' then optional whitespace then either "value" or number
    std::string key = "\"" + field + "\"";
    auto pos = s.find(key);
    if (pos == std::string::npos) return std::nullopt;
    pos = s.find(':', pos + key.size());
    if (pos == std::string::npos) return std::nullopt;
    pos++;
    while (pos < s.size() && isspace((unsigned char)s[pos])) pos++;
    if (pos >= s.size()) return std::nullopt;
    if (s[pos] == '"') {
        pos++;
        std::ostringstream out;
        while (pos < s.size()) {
            char c = s[pos++];
            if (c == '\\') {
                if (pos < s.size()) { out << s[pos++]; }
            } else if (c == '"') break;
            else out << c;
        }
        return out.str();
    } else {
        // number or token until , or }
        size_t start = pos;
        while (pos < s.size() && s[pos] != ',' && s[pos] != '}' && s[pos] != '\n') pos++;
        std::string tok = s.substr(start, pos - start);
        // trim
        size_t a = tok.find_first_not_of(" \t\r\n");
        size_t b = tok.find_last_not_of(" \t\r\n");
        if (a == std::string::npos) return std::nullopt;
        return tok.substr(a, b - a + 1);
    }
}

static std::string base64_encode(const std::vector<uint8_t> &in) {
    // use OpenSSL EVP_EncodeBlock (requires output buffer size ((len+2)/3*4)+1)
    int in_len = (int)in.size();
    int out_len = 4 * ((in_len + 2) / 3);
    std::vector<unsigned char> out(out_len + 1);
    int rc = EVP_EncodeBlock(out.data(), in.data(), in_len);
    if (rc < 0) return std::string();
    return std::string((char*)out.data(), (size_t)rc);
}

int main(int argc, char **argv) {
    std::string in_dir = "logs";
    std::string out_dir = "logs_enc";
    std::string key_file = "aes_key.bin";

    if (argc > 1) in_dir = argv[1];
    if (argc > 2) out_dir = argv[2];
    if (argc > 3) key_file = argv[3];

    fs::create_directories(out_dir);

    // load or generate key
    std::vector<uint8_t> key(32);
    std::ifstream kf(key_file, std::ios::binary);
    if (kf.good()) {
        kf.read((char*)key.data(), key.size());
        if (kf.gcount() != (std::streamsize)key.size()) {
            std::cerr << "Key file too short or read error" << std::endl;
            return 2;
        }
    } else {
        if (RAND_bytes(key.data(), (int)key.size()) != 1) {
            std::cerr << "RAND_bytes failed" << std::endl;
            return 3;
        }
        std::ofstream ko(key_file, std::ios::binary);
        ko.write((char*)key.data(), key.size());
    }

    for (auto &p : fs::directory_iterator(in_dir)) {
        if (!p.is_regular_file()) continue;
        if (p.path().extension() != ".json") continue;
        std::string content;
        {
            std::ifstream f(p.path());
            std::ostringstream ss;
            ss << f.rdbuf();
            content = ss.str();
        }
        std::optional<std::string> ts = extract_json_field(content, "timestamp");
        std::optional<std::string> uid = extract_json_field(content, "user_id");
        std::optional<std::string> policy = extract_json_field(content, "abe_policy");

        std::vector<uint8_t> ct, nonce;
        int rc = aes_gcm_encrypt(key.data(), key.size(), nullptr, 0,
                                 (const uint8_t*)(ts ? ts->data() : std::string().data()), ts ? ts->size() : 0,
                                 (const uint8_t*)content.data(), content.size(), ct, nonce);
        if (rc != 0) {
            std::cerr << "Encryption failed for " << p.path() << " rc=" << rc << std::endl;
            continue;
        }

        std::string ct_b64 = base64_encode(ct);
        std::string nonce_b64 = base64_encode(nonce);

        // build CT_obj JSON
        std::ostringstream outj;
        outj << "{\n";
        outj << "  \"ct_sym_b64\": \"" << ct_b64 << "\"," << "\n";
        outj << "  \"ct_abe\": { \"scheme\": \"LCP-ABE-placeholder\" },\n";
        outj << "  \"meta\": {\n";
        outj << "    \"policy\": \"" << (policy ? *policy : "") << "\"," << "\n";
        outj << "    \"timestamp\": \"" << (ts ? *ts : "") << "\"," << "\n";
        outj << "    \"source_file\": \"" << p.path().filename().string() << "\"," << "\n";
        outj << "    \"nonce_b64\": \"" << nonce_b64 << "\"\n";
        outj << "  }\n";
        outj << "}\n";

        fs::path outpath = fs::path(out_dir) / p.path().filename();
        std::ofstream of(outpath);
        of << outj.str();
        std::cout << "Encrypted " << p.path().filename().string() << " -> " << outpath.string() << std::endl;
    }

    return 0;
}
