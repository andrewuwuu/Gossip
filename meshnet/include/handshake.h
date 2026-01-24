/*
 * handshake.h
 *
 * Gossip Protocol v1.0 Handshake Implementation.
 * 
 * The handshake provides mutual authentication and forward secrecy:
 * 1. Both peers exchange HELLO messages with ephemeral X25519 keys
 * 2. Derive session keys using HKDF with transcript binding
 * 3. Exchange AUTH messages with Ed25519 signatures
 * 4. Pin peer identity (TOFU)
 * 
 * See specification Section 4 for full protocol details.
 */

#ifndef GOSSIP_HANDSHAKE_H
#define GOSSIP_HANDSHAKE_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include "crypto.h"
#include "identity.h"
#include "protocol.h"

namespace gossip {

/*
 * =============================================================================
 * Handshake State Machine
 * =============================================================================
 */

enum class HandshakeState {
    INITIAL,         /* No messages exchanged */
    HELLO_SENT,      /* We sent HELLO, awaiting peer's HELLO */
    HELLO_RECEIVED,  /* We received HELLO, need to send ours or derive keys */
    KEYS_DERIVED,    /* Session keys computed, need to send/receive AUTH */
    AUTH_SENT,       /* We sent AUTH, awaiting peer's AUTH */
    COMPLETE,        /* Both AUTH messages verified successfully */
    FAILED           /* Handshake failed, connection should close */
};

/*
 * =============================================================================
 * Handshake Class
 * 
 * Manages the cryptographic handshake state for a single connection.
 * Thread-safety: NOT thread-safe. Use one Handshake per connection.
 * =============================================================================
 */

class Handshake {
public:
    /*
     * Creates a new handshake bound to the local identity.
     * Generates ephemeral X25519 keypair immediately.
     *
     * @param local_identity  Reference to node's Ed25519 identity (must outlive Handshake)
     */
    explicit Handshake(const Identity& local_identity);
    
    /*
     * Destructor securely wipes all ephemeral and derived key material.
     */
    ~Handshake();
    
    Handshake(const Handshake&) = delete;
    Handshake& operator=(const Handshake&) = delete;
    
    /*
     * =========================================================================
     * HELLO Message Handling
     * =========================================================================
     */
    
    /*
     * Creates a HELLO message for transmission.
     * Format: [ Role (1) | E_pub (32) ]
     *
     * @param is_initiator  True if we initiated the connection
     * @return HELLO payload bytes
     */
    std::vector<uint8_t> create_hello(bool is_initiator);
    
    /*
     * Processes a received HELLO message from peer.
     * Handles simultaneous open by comparing E_pub lexicographically.
     * After success, call derive_keys() to compute session keys.
     *
     * @param data  HELLO payload
     * @param len   Payload length
     * @return true if valid HELLO, false on error
     */
    bool process_hello(const uint8_t* data, size_t len);
    
    /*
     * Derives session keys after both HELLO messages are exchanged.
     * Must be called after process_hello() returns true.
     *
     * Key derivation per spec:
     *   IKM = X25519(E_priv, E_pub_peer)
     *   Salt = SHA256(HELLO_init || HELLO_resp)
     *   PRK = HKDF-Extract(Salt, IKM)
     *   K_init = HKDF-Expand(PRK, "gossip-init", 32)
     *   K_resp = HKDF-Expand(PRK, "gossip-resp", 32)
     *
     * @return true on success, false if not ready or DH failed
     */
    bool derive_keys();
    
    /*
     * =========================================================================
     * AUTH Message Handling
     * =========================================================================
     */
    
    /*
     * Creates an AUTH message for transmission.
     * Must be called after derive_keys() succeeds.
     * Format: [ IK_pub (32) | Signature (64) ]
     *
     * Signature covers: "gossip-auth" || Role || E_pub || Transcript
     *
     * @return AUTH payload bytes (encrypted by caller)
     */
    std::vector<uint8_t> create_auth();
    
    /*
     * Processes a received AUTH message from peer.
     * Verifies Ed25519 signature and extracts peer's IK_pub.
     * On success, handshake is complete.
     *
     * @param data           Decrypted AUTH payload
     * @param len            Payload length
     * @param peer_pubkey_out  Output: 32-byte peer public key (IK_pub)
     * @return true if signature valid, false on verification failure
     */
    bool process_auth(const uint8_t* data, size_t len, uint8_t* peer_pubkey_out);
    
    /*
     * =========================================================================
     * State and Key Accessors
     * =========================================================================
     */
    
    HandshakeState state() const { return state_; }
    bool is_complete() const { return state_ == HandshakeState::COMPLETE; }
    bool is_failed() const { return state_ == HandshakeState::FAILED; }
    
    /*
     * Returns our resolved role (INITIATOR or RESPONDER).
     * Valid after process_hello() returns true.
     */
    protocol::HandshakeRole role() const { return role_; }
    bool is_initiator() const { return role_ == protocol::HandshakeRole::INITIATOR; }
    
    /*
     * Returns the initiator's session key (K_init).
     * Valid after derive_keys() returns true.
     */
    const uint8_t* init_key() const { return k_init_; }
    
    /*
     * Returns the responder's session key (K_resp).
     * Valid after derive_keys() returns true.
     */
    const uint8_t* resp_key() const { return k_resp_; }
    
    /*
     * Returns our send key based on our role.
     * Initiator sends with K_init, Responder sends with K_resp.
     */
    const uint8_t* send_key() const;
    
    /*
     * Returns our receive key based on our role.
     * Initiator receives with K_resp, Responder receives with K_init.
     */
    const uint8_t* recv_key() const;
    
    /*
     * Returns our ephemeral public key.
     */
    const uint8_t* ephemeral_public_key() const { return ephemeral_public_; }

    /*
     * Checks if we need to send a HELLO response.
     * Returns true if we are RESPONDER and haven't recorded our HELLO yet.
     * Used to prevent duplicate HELLO transmission during simultaneous open.
     */
    bool needs_hello_response() const {
        return role_ == protocol::HandshakeRole::RESPONDER && hello_resp_.empty();
    }

private:
    const Identity& identity_;
    HandshakeState state_;
    protocol::HandshakeRole role_;
    bool role_set_;
    
    /* Our ephemeral X25519 keypair (wiped after key derivation) */
    uint8_t ephemeral_public_[crypto::PUBLIC_KEY_SIZE];
    uint8_t ephemeral_private_[crypto::PRIVATE_KEY_SIZE];
    
    /* Peer's ephemeral public key */
    uint8_t peer_ephemeral_[crypto::PUBLIC_KEY_SIZE];
    bool peer_ephemeral_received_;
    
    /* HELLO messages for transcript (initiator first, then responder) */
    std::vector<uint8_t> hello_init_;
    std::vector<uint8_t> hello_resp_;
    
    /* Transcript hash: SHA256(HELLO_init || HELLO_resp) */
    uint8_t transcript_hash_[crypto::HASH_SIZE];
    bool transcript_computed_;
    
    /* Derived session keys */
    uint8_t k_init_[crypto::KEY_SIZE];
    uint8_t k_resp_[crypto::KEY_SIZE];
    bool keys_derived_;
    
    /* Compute transcript hash from stored HELLOs */
    void compute_transcript();
    
    /* Wipe all sensitive material */
    void wipe_secrets();
    
    /* Build the message to sign for AUTH */
    std::vector<uint8_t> build_auth_message() const;
};

}  /* namespace gossip */

#endif  /* GOSSIP_HANDSHAKE_H */
