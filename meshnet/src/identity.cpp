/*
 * identity.cpp
 *
 * Implementation of Identity class for Ed25519 keypair management.
 */

#include "identity.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <sys/stat.h>
#include <cstdlib>

namespace gossip {

namespace {

/*
 * Converts a hex string to bytes.
 * Returns false if the string is invalid.
 */
bool hex_to_bytes(const std::string& hex, uint8_t* out, size_t out_len) {
    if (hex.length() != out_len * 2) {
        return false;
    }
    
    for (size_t i = 0; i < out_len; ++i) {
        char high = hex[i * 2];
        char low = hex[i * 2 + 1];
        
        int h, l;
        if (high >= '0' && high <= '9') h = high - '0';
        else if (high >= 'a' && high <= 'f') h = 10 + (high - 'a');
        else if (high >= 'A' && high <= 'F') h = 10 + (high - 'A');
        else return false;
        
        if (low >= '0' && low <= '9') l = low - '0';
        else if (low >= 'a' && low <= 'f') l = 10 + (low - 'a');
        else if (low >= 'A' && low <= 'F') l = 10 + (low - 'A');
        else return false;
        
        out[i] = static_cast<uint8_t>((h << 4) | l);
    }
    return true;
}

/*
 * Converts bytes to a hex string.
 */
std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

/*
 * Creates directory and parents if they don't exist.
 */
bool ensure_directory(const std::string& path) {
    size_t pos = 0;
    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        std::string dir = path.substr(0, pos);
        if (!dir.empty()) {
            mkdir(dir.c_str(), 0700);
        }
    }
    return true;
}

}  /* anonymous namespace */

Identity::Identity() : valid_(false) {
    std::memset(public_key_, 0, sizeof(public_key_));
    std::memset(secret_key_, 0, sizeof(secret_key_));
}

Identity::~Identity() {
    crypto::secure_zero(secret_key_, sizeof(secret_key_));
}

void Identity::generate() {
    crypto::ed25519_generate_keypair(public_key_, secret_key_);
    valid_ = true;
}

bool Identity::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    std::string hex_key;
    std::getline(file, hex_key);
    file.close();
    
    /*
     * Trim whitespace
     */
    while (!hex_key.empty() && (hex_key.back() == '\n' || hex_key.back() == '\r' || hex_key.back() == ' ')) {
        hex_key.pop_back();
    }
    
    /*
     * Ed25519 secret key is 64 bytes = 128 hex characters
     */
    if (!hex_to_bytes(hex_key, secret_key_, crypto::ED25519_SECRET_KEY_SIZE)) {
        return false;
    }
    
    /*
     * The public key is embedded in the last 32 bytes of the Ed25519 secret key.
     * This is a libsodium convention: secret_key = seed (32) || public_key (32)
     */
    std::memcpy(public_key_, secret_key_ + 32, crypto::ED25519_PUBLIC_KEY_SIZE);
    valid_ = true;
    
    return true;
}

bool Identity::save(const std::string& path) const {
    if (!valid_) {
        return false;
    }
    
    ensure_directory(path);
    
    std::ofstream file(path, std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    
    file << bytes_to_hex(secret_key_, crypto::ED25519_SECRET_KEY_SIZE) << std::endl;
    file.close();
    
    /*
     * Set restrictive permissions (owner only)
     */
    chmod(path.c_str(), 0600);
    
    return true;
}

void Identity::set_from_keys(const uint8_t* public_key, const uint8_t* secret_key) {
    if (public_key && secret_key) {
        std::memcpy(public_key_, public_key, crypto::ED25519_PUBLIC_KEY_SIZE);
        std::memcpy(secret_key_, secret_key, crypto::ED25519_SECRET_KEY_SIZE);
        valid_ = true;
    }
}

bool Identity::set_from_seed(const uint8_t* seed) {
    if (!seed) {
        return false;
    }
    
    /*
     * Derive Ed25519 keypair from 32-byte seed.
     * Uses crypto_sign_seed_keypair internally via crypto module.
     * The seed must be kept secret as it can regenerate the full keypair.
     */
    crypto::ed25519_keypair_from_seed(public_key_, secret_key_, seed);
    valid_ = true;
    return true;
}

std::string Identity::public_key_hex() const {
    return bytes_to_hex(public_key_, crypto::ED25519_PUBLIC_KEY_SIZE);
}

bool Identity::sign(const uint8_t* data, size_t len, uint8_t* signature) const {
    if (!valid_) {
        return false;
    }
    return crypto::ed25519_sign(secret_key_, data, len, signature);
}

bool Identity::verify(
    const uint8_t* public_key,
    const uint8_t* data,
    size_t len,
    const uint8_t* signature
) {
    return crypto::ed25519_verify(public_key, data, len, signature);
}

std::string Identity::default_path() {
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home) + "/.gossip/identity.key";
    }
    return ".gossip/identity.key";
}

}  /* namespace gossip */
