/*
 * identity.cpp
 *
 * Implementation of Identity class for keypair management.
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
    std::memset(private_key_, 0, sizeof(private_key_));
}

Identity::~Identity() {
    crypto::secure_zero(private_key_, sizeof(private_key_));
}

void Identity::generate() {
    crypto::generate_keypair(public_key_, private_key_);
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
    
    if (!hex_to_bytes(hex_key, private_key_, crypto::PRIVATE_KEY_SIZE)) {
        return false;
    }
    
    /*
     * Derive public key from private key
     */
    crypto::derive_public_key(public_key_, private_key_);
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
    
    file << bytes_to_hex(private_key_, crypto::PRIVATE_KEY_SIZE) << std::endl;
    file.close();
    
    /*
     * Set restrictive permissions (owner only)
     */
    chmod(path.c_str(), 0600);
    
    return true;
}

std::string Identity::public_key_hex() const {
    return bytes_to_hex(public_key_, crypto::PUBLIC_KEY_SIZE);
}

std::string Identity::default_path() {
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home) + "/.gossip/identity.key";
    }
    return ".gossip/identity.key";
}

}  /* namespace gossip */
