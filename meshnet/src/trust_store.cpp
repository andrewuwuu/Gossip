#include "trust_store.h"
#include <cstring>
#include <ctime>

namespace gossip {

bool TrustStore::pin(const uint8_t* node_id, const uint8_t* public_key) {
    if (!node_id || !public_key) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = node_id_to_key(node_id);
    auto it = pinned_.find(key);
    
    int64_t now = std::time(nullptr);
    
    /* TOFU: First time seeing this NodeID */
    if (it == pinned_.end()) {
        PinnedIdentity id;
        std::memcpy(id.node_id, node_id, crypto::ED25519_PUBLIC_KEY_SIZE);
        std::memcpy(id.public_key, public_key, crypto::ED25519_PUBLIC_KEY_SIZE);
        id.first_seen_timestamp = now;
        id.last_seen_timestamp = now;
        pinned_[key] = id;
        return true;
    }
    
    /* Identity exists: Verify Key matches Pin */
    if (std::memcmp(it->second.public_key, public_key, crypto::ED25519_PUBLIC_KEY_SIZE) != 0) {
        /* TOFU Violation! */
        return false;
    }
    
    /* Valid: Update timestamp */
    it->second.last_seen_timestamp = now;
    return true;
}

bool TrustStore::verify(const uint8_t* node_id, const uint8_t* public_key) const {
    if (!node_id || !public_key) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = node_id_to_key(node_id);
    auto it = pinned_.find(key);
    
    /* Unknown identity is considered valid for TOFU (will be pinned later) */
    if (it == pinned_.end()) {
        return true;
    }
    
    /* Verify pinned key matches */
    return std::memcmp(it->second.public_key, public_key, crypto::ED25519_PUBLIC_KEY_SIZE) == 0;
}

bool TrustStore::should_reject(const uint8_t* node_id, const uint8_t* public_key) const {
    /* Reject if verify returns false (mismatch) */
    /* Note: verify returns true if unknown (TOFU allowed) */
    return !verify(node_id, public_key);
}

bool TrustStore::is_known(const uint8_t* node_id) const {
    if (!node_id) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    return pinned_.count(node_id_to_key(node_id)) > 0;
}

size_t TrustStore::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pinned_.size();
}

bool TrustStore::unpin(const uint8_t* node_id) {
    if (!node_id) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    return pinned_.erase(node_id_to_key(node_id)) > 0;
}

void TrustStore::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    pinned_.clear();
}

std::string TrustStore::node_id_to_key(const uint8_t* node_id) {
    /* Use hex string of NodeID as map key */
    static const char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (size_t i = 0; i < crypto::ED25519_PUBLIC_KEY_SIZE; ++i) {
        s += hex[(node_id[i] >> 4) & 0xF];
        s += hex[node_id[i] & 0xF];
    }
    return s;
}

}  /* namespace gossip */
