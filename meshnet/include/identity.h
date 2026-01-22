/*
 * identity.h
 *
 * Identity management for the Gossip Protocol.
 * Handles X25519 keypair generation, storage, and loading.
 */

#ifndef GOSSIP_IDENTITY_H
#define GOSSIP_IDENTITY_H

#include <cstdint>
#include <string>
#include "crypto.h"

namespace gossip {

/*
 * Identity
 *
 * Represents a node's cryptographic identity (X25519 keypair).
 * Provides methods for persistence to disk.
 */
class Identity {
public:
    /*
     * Creates an empty identity (no keys loaded).
     */
    Identity();
    
    ~Identity();
    
    Identity(const Identity&) = delete;
    Identity& operator=(const Identity&) = delete;
    
    /*
     * Generates a new random keypair.
     */
    void generate();
    
    /*
     * Loads private key from file.
     * Public key is derived automatically.
     *
     * @param path  Path to key file (hex-encoded private key)
     * @return true on success, false if file not found or invalid
     */
    bool load(const std::string& path);
    
    /*
     * Saves private key to file.
     * Creates parent directories if needed.
     *
     * @param path  Path to save key file
     * @return true on success, false on I/O error
     */
    bool save(const std::string& path) const;
    
    /*
     * Checks if this identity has a valid keypair.
     */
    bool valid() const { return valid_; }
    
    /*
     * Returns the 32-byte public key.
     */
    const uint8_t* public_key() const { return public_key_; }
    
    /*
     * Returns the 32-byte private key.
     */
    const uint8_t* private_key() const { return private_key_; }
    
    /*
     * Returns the public key as a hex string.
     */
    std::string public_key_hex() const;
    
    /*
     * Default path for identity file.
     */
    static std::string default_path();

private:
    uint8_t public_key_[crypto::PUBLIC_KEY_SIZE];
    uint8_t private_key_[crypto::PRIVATE_KEY_SIZE];
    bool valid_;
};

}  /* namespace gossip */

#endif  /* GOSSIP_IDENTITY_H */
