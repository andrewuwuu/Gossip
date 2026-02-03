/*
 * identity.h
 *
 * Identity management for the Gossip Protocol v1.0.
 * Each node has a static Ed25519 keypair (IK_pub, IK_priv).
 * The NodeID is defined as the 32-byte public key (NodeID := IK_pub).
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
 * Represents a node's cryptographic identity (Ed25519 keypair).
 * The public key serves as the NodeID per the Gossip Protocol v1.0 spec.
 * Provides methods for signing, verification, and persistence to disk.
 */
class Identity {
public:
    /*
     * Creates an empty identity (no keys loaded).
     */
    Identity();
    
    /*
     * Destructor securely wipes the secret key.
     */
    ~Identity();
    
    Identity(const Identity&) = delete;
    Identity& operator=(const Identity&) = delete;
    
    /*
     * Generates a new random Ed25519 keypair.
     */
    void generate();
    
    /*
     * Loads identity from file.
     * File format: hex-encoded secret key (128 characters = 64 bytes).
     *
     * @param path  Path to key file
     * @return true on success, false if file not found or invalid
     */
    bool load(const std::string& path);
    
    /*
     * Saves identity to file (secret key only, hex-encoded).
     * Creates parent directories if needed.
     * Sets restrictive file permissions (0600).
     *
     * @param path  Path to save key file
     * @return true on success, false on I/O error
     */
    bool save(const std::string& path) const;
    
    /*
     * Sets the keys directly from memory.
     * Useful for integration when keys are managed externally.
     *
     * @param public_key 32-byte Ed25519 public key
     * @param secret_key 64-byte Ed25519 secret key
     */
    void set_from_keys(const uint8_t* public_key, const uint8_t* secret_key);
    
    /*
     * Sets identity from a 32-byte seed (derives Ed25519 keypair deterministically).
     * This allows external callers to provide a seed and get repeatable key derivation.
     *
     * @param seed 32-byte seed value
     * @return true on success
     */
    bool set_from_seed(const uint8_t* seed);
    
    /*
     * Checks if this identity has a valid keypair.
     */
    bool valid() const { return valid_; }
    
    /*
     * Returns the 32-byte Ed25519 public key (IK_pub).
     */
    const uint8_t* public_key() const { return public_key_; }
    
    /*
     * Returns the 64-byte Ed25519 secret key (IK_priv).
     * SECURITY: Handle with extreme care - never log or transmit.
     */
    const uint8_t* secret_key() const { return secret_key_; }
    
    /*
     * Returns the NodeID (which equals the public key per spec).
     * NodeID := IK_pub (32 bytes)
     */
    const uint8_t* node_id() const { return public_key_; }
    
    /*
     * Returns the public key as a hex string.
     */
    std::string public_key_hex() const;
    
    /*
     * Returns the NodeID as a hex string.
     */
    std::string node_id_hex() const { return public_key_hex(); }
    
    /*
     * Signs a message using the Ed25519 secret key.
     *
     * @param data       Data to sign
     * @param len        Length of data
     * @param signature  Output buffer for 64-byte signature
     * @return true on success
     */
    bool sign(const uint8_t* data, size_t len, uint8_t* signature) const;
    
    /*
     * Verifies an Ed25519 signature using any public key.
     * Static method for verifying peer signatures.
     *
     * @param public_key  32-byte Ed25519 public key
     * @param data        Signed data
     * @param len         Length of data
     * @param signature   64-byte signature to verify
     * @return true if signature is valid
     */
    static bool verify(
        const uint8_t* public_key,
        const uint8_t* data,
        size_t len,
        const uint8_t* signature
    );
    
    /*
     * Default path for identity file.
     */
    static std::string default_path();

private:
    uint8_t public_key_[crypto::ED25519_PUBLIC_KEY_SIZE];
    uint8_t secret_key_[crypto::ED25519_SECRET_KEY_SIZE];
    bool valid_;
};

}  /* namespace gossip */

#endif  /* GOSSIP_IDENTITY_H */
