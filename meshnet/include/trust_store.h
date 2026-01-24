/*
 * trust_store.h
 *
 * TOFU (Trust On First Use) Identity Pinning for Gossip Protocol v1.0.
 * 
 * Per specification Section 1.3:
 * - UDP discovery is never trusted
 * - TCP sessions establish trust via authenticated handshake
 * - A peer identity is pinned as: PinnedIdentity := (NodeID, IK_pub)
 * - Pinning occurs only after successful handshake completion
 * - If a pinned NodeID is observed with different IK_pub, connection MUST be rejected
 */

#ifndef GOSSIP_TRUST_STORE_H
#define GOSSIP_TRUST_STORE_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <mutex>
#include <unordered_map>
#include "crypto.h"

namespace gossip {

/*
 * PinnedIdentity
 * 
 * Represents a trusted peer identity that was established via
 * successful handshake.
 */
struct PinnedIdentity {
    uint8_t node_id[crypto::ED25519_PUBLIC_KEY_SIZE];      /* NodeID = IK_pub */
    uint8_t public_key[crypto::ED25519_PUBLIC_KEY_SIZE];   /* Pinned IK_pub (equals node_id) */
    int64_t first_seen_timestamp;                          /* Unix timestamp of first trust */
    int64_t last_seen_timestamp;                           /* Unix timestamp of last connection */
};

/*
 * TrustStore
 *
 * Manages TOFU pinning of peer identities.
 * Thread-safe for concurrent access.
 * 
 * Note: Since NodeID := IK_pub in the specification, the node_id and
 * public_key fields are always identical. We store both for clarity.
 */
class TrustStore {
public:
    TrustStore() = default;
    ~TrustStore() = default;
    
    TrustStore(const TrustStore&) = delete;
    TrustStore& operator=(const TrustStore&) = delete;
    
    /*
     * Pins a peer identity after successful handshake.
     * If already pinned with the same key, updates last_seen_timestamp.
     * If already pinned with a different key, returns false (TOFU violation).
     *
     * @param node_id     32-byte NodeID (= IK_pub)
     * @param public_key  32-byte public key (should equal node_id per spec)
     * @return true if pinned successfully, false if TOFU violation
     */
    bool pin(const uint8_t* node_id, const uint8_t* public_key);
    
    /*
     * Checks if the identity should be rejected based on pinning.
     * Wrapper strictly for rejection logic (inverse of verify/TOFU acceptance).
     *
     * @param node_id     32-byte NodeID
     * @param public_key  32-byte public key to verify
     * @return true if connection should be rejected (pin mismatch)
     */
    bool should_reject(const uint8_t* node_id, const uint8_t* public_key) const;
    
    /*
     * Verifies that a peer's claimed identity matches pinned identity.
     * Returns true if:
     * - NodeID is not known (not yet pinned), OR
     * - NodeID is known and public_key matches
     * 
     * Returns false if:
     * - NodeID is known but public_key differs (TOFU violation)
     *
     * @param node_id     32-byte NodeID
     * @param public_key  32-byte public key to verify
     * @return true if identity is valid, false if TOFU violation
     */
    bool verify(const uint8_t* node_id, const uint8_t* public_key) const;
    
    /*
     * Checks if we have a pinned identity for this NodeID.
     *
     * @param node_id  32-byte NodeID
     * @return true if NodeID is in the trust store
     */
    bool is_known(const uint8_t* node_id) const;
    
    /*
     * Returns the number of pinned identities.
     */
    size_t count() const;
    
    /*
     * Removes a pinned identity.
     * Use with caution - bypasses TOFU protection.
     *
     * @param node_id  32-byte NodeID to unpin
     * @return true if removed, false if not found
     */
    bool unpin(const uint8_t* node_id);
    
    /*
     * Clears all pinned identities.
     * Use with extreme caution - completely resets trust.
     */
    void clear();

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, PinnedIdentity> pinned_;
    
    /* Convert NodeID to hex string for map key */
    static std::string node_id_to_key(const uint8_t* node_id);
};

}  /* namespace gossip */

#endif  /* GOSSIP_TRUST_STORE_H */
