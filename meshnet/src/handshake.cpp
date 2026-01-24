/*
 * handshake.cpp
 *
 * Implementation of Gossip Protocol v1.0 Handshake.
 */

#include "handshake.h"
#include "logging.h"
#include <cstdio>
#include <cstring>

namespace gossip {

Handshake::Handshake(const Identity& local_identity)
    : identity_(local_identity)
    , state_(HandshakeState::INITIAL)
    , role_(protocol::HandshakeRole::INITIATOR)
    , role_set_(false)
    , peer_ephemeral_received_(false)
    , transcript_computed_(false)
    , keys_derived_(false)
{
    /* Generate ephemeral X25519 keypair */
    crypto::generate_keypair(ephemeral_public_, ephemeral_private_);
    
    /* Zero out derived keys */
    std::memset(peer_ephemeral_, 0, sizeof(peer_ephemeral_));
    std::memset(transcript_hash_, 0, sizeof(transcript_hash_));
    std::memset(k_init_, 0, sizeof(k_init_));
    std::memset(k_resp_, 0, sizeof(k_resp_));
}

Handshake::~Handshake() {
    wipe_secrets();
}

void Handshake::wipe_secrets() {
    crypto::secure_zero(ephemeral_private_, sizeof(ephemeral_private_));
    crypto::secure_zero(k_init_, sizeof(k_init_));
    crypto::secure_zero(k_resp_, sizeof(k_resp_));
    crypto::secure_zero(transcript_hash_, sizeof(transcript_hash_));
}

std::vector<uint8_t> Handshake::create_hello(bool is_initiator) {
    if (state_ != HandshakeState::INITIAL && state_ != HandshakeState::HELLO_RECEIVED) {
        return {};
    }
    
    /* HELLO format: [ Role (1) | E_pub (32) ] */
    std::vector<uint8_t> hello(protocol::HELLO_PAYLOAD_SIZE);
    
    protocol::HandshakeRole declared_role = is_initiator 
        ? protocol::HandshakeRole::INITIATOR 
        : protocol::HandshakeRole::RESPONDER;
    
    hello[0] = static_cast<uint8_t>(declared_role);
    std::memcpy(hello.data() + 1, ephemeral_public_, crypto::PUBLIC_KEY_SIZE);
    
    /* Store our HELLO for transcript */
    if (is_initiator) {
        hello_init_ = hello;
    } else {
        hello_resp_ = hello;
    }
    
    /* Track that we've set our role (may be overridden by simultaneous open) */
    if (!role_set_) {
        role_ = declared_role;
    }
    
    if (state_ == HandshakeState::INITIAL) {
        state_ = HandshakeState::HELLO_SENT;
    }
    
    return hello;
}

bool Handshake::process_hello(const uint8_t* data, size_t len) {
    if (len != protocol::HELLO_PAYLOAD_SIZE) {
        state_ = HandshakeState::FAILED;
        return false;
    }
    
    /* Parse HELLO: [ Role (1) | E_pub (32) ] */
    protocol::HandshakeRole peer_declared_role = static_cast<protocol::HandshakeRole>(data[0]);
    const uint8_t* peer_ephemeral = data + 1;
    
    /* Store peer's ephemeral public key */
    std::memcpy(peer_ephemeral_, peer_ephemeral, crypto::PUBLIC_KEY_SIZE);
    peer_ephemeral_received_ = true;
    
    /* Store peer's HELLO for transcript */
    std::vector<uint8_t> peer_hello(data, data + len);
    
    /*
     * Handle role resolution:
     * - If both declared same role (simultaneous open), compare E_pub
     * - Smaller E_pub becomes Initiator
     */
    if (state_ == HandshakeState::HELLO_SENT) {
        /* We already sent, now receiving peer's */
        if (peer_declared_role == role_) {
            /* Simultaneous open - resolve by comparing ephemeral keys */
            int cmp = protocol::compare_ephemeral_keys(ephemeral_public_, peer_ephemeral_);
            if (cmp < 0) {
                /* Our E_pub is smaller, we are Initiator */
                role_ = protocol::HandshakeRole::INITIATOR;
            } else if (cmp > 0) {
                /* Peer's E_pub is smaller, they are Initiator */
                role_ = protocol::HandshakeRole::RESPONDER;
            } else {
                /* Identical keys - this should never happen with random keys */
                state_ = HandshakeState::FAILED;
                return false;
            }
        } else {
            /* Normal case: peer declared opposite role */
            /* Keep our declared role */
        }
        role_set_ = true;
        
        /* Order HELLOs for transcript: initiator first */
        if (role_ == protocol::HandshakeRole::INITIATOR) {
            /* We are initiator, peer is responder. Store peer's hello as hello_resp_ */
            hello_resp_ = peer_hello;
        } else {
            /* We are responder, peer is initiator. Store peer's hello as hello_init_ */
            /* Note: Our hello is already in hello_resp_ if we created it, or will be later */
            if (hello_init_.empty()) {
                hello_init_ = peer_hello;
            }
        }
        
    } else if (state_ == HandshakeState::INITIAL) {
        /* We haven't sent yet, just receiving first */
        role_ = (peer_declared_role == protocol::HandshakeRole::INITIATOR)
            ? protocol::HandshakeRole::RESPONDER
            : protocol::HandshakeRole::INITIATOR;
        role_set_ = true;
        
        if (peer_declared_role == protocol::HandshakeRole::INITIATOR) {
            hello_init_ = peer_hello;
        } else {
            hello_resp_ = peer_hello;
        }
        
        state_ = HandshakeState::HELLO_RECEIVED;
        return true;
    } else {
        state_ = HandshakeState::FAILED;
        return false;
    }
    
    state_ = HandshakeState::HELLO_RECEIVED;
    return true;
}

void Handshake::compute_transcript() {
    if (hello_init_.empty() || hello_resp_.empty()) {
        return;
    }
    
    /* Transcript = SHA256(HELLO_init || HELLO_resp) */
    std::vector<std::pair<const uint8_t*, size_t>> parts;
    parts.emplace_back(hello_init_.data(), hello_init_.size());
    parts.emplace_back(hello_resp_.data(), hello_resp_.size());
    
    crypto::sha256_multi(parts, transcript_hash_);
    transcript_computed_ = true;
}

bool Handshake::derive_keys() {
    if (!peer_ephemeral_received_) {
        state_ = HandshakeState::FAILED;
        return false;
    }
    
    /* Ensure we have both HELLOs */
    if (hello_init_.empty() || hello_resp_.empty()) {
        /* Need to finalize hello storage based on role */
        if (role_ == protocol::HandshakeRole::INITIATOR && hello_init_.empty()) {
            /* Create our HELLO and store as init */
            auto our_hello = create_hello(true);
            hello_init_ = our_hello;
        } else if (role_ == protocol::HandshakeRole::RESPONDER && hello_resp_.empty()) {
            auto our_hello = create_hello(false);
            hello_resp_ = our_hello;
        }
    }
    
    /* Compute transcript hash */
    compute_transcript();
    if (!transcript_computed_) {
        state_ = HandshakeState::FAILED;
        return false;
    }
    
    /*
     * Key derivation per spec:
     *   IKM = X25519(E_priv, E_pub_peer)
     *   Salt = transcript_hash
     *   PRK = HKDF-Extract(Salt, IKM)
     *   K_init = HKDF-Expand(PRK, "gossip-init", 32)
     *   K_resp = HKDF-Expand(PRK, "gossip-resp", 32)
     */
    
    /* Step 1: Compute shared secret via X25519 */
    uint8_t ikm[crypto::SHARED_SECRET_SIZE];
    if (!crypto::derive_shared_secret(ikm, ephemeral_private_, peer_ephemeral_)) {
        crypto::secure_zero(ikm, sizeof(ikm));
        state_ = HandshakeState::FAILED;
        return false;
    }
    
    /* Step 2: HKDF-Extract with transcript as salt */
    uint8_t prk[crypto::HASH_SIZE];
    crypto::hkdf_extract(transcript_hash_, crypto::HASH_SIZE, ikm, sizeof(ikm), prk);
    
    /* Step 3: HKDF-Expand for K_init */
    crypto::hkdf_expand_label(prk, "gossip-init", k_init_);
    
    /* Step 4: HKDF-Expand for K_resp */
    crypto::hkdf_expand_label(prk, "gossip-resp", k_resp_);
    
    char key_debug[256];
    std::snprintf(key_debug, sizeof(key_debug), 
        "Keys derived. K_init=%02x%02x%02x%02x K_resp=%02x%02x%02x%02x Transcript=%02x%02x%02x%02x Shared=%02x%02x%02x%02x",
        k_init_[0], k_init_[1], k_init_[2], k_init_[3],
        k_resp_[0], k_resp_[1], k_resp_[2], k_resp_[3],
        transcript_hash_[0], transcript_hash_[1], transcript_hash_[2], transcript_hash_[3],
        ikm[0], ikm[1], ikm[2], ikm[3]
    );
    gossip::logging::debug(key_debug);

    /* Wipe IKM immediately */
    crypto::secure_zero(ikm, sizeof(ikm));
    
    /* Wipe PRK */
    crypto::secure_zero(prk, sizeof(prk));

    /* Wipe ephemeral private key - no longer needed */
    crypto::secure_zero(ephemeral_private_, sizeof(ephemeral_private_));
    
    keys_derived_ = true;
    state_ = HandshakeState::KEYS_DERIVED;
    
    return true;
}

std::vector<uint8_t> Handshake::build_auth_message() const {
    /*
     * AUTH signature input per spec:
     *   "gossip-auth" || Role || E_pub || Transcript
     */
    const char* prefix = "gossip-auth";
    size_t prefix_len = 11;
    
    std::vector<uint8_t> message;
    message.reserve(prefix_len + 1 + crypto::PUBLIC_KEY_SIZE + crypto::HASH_SIZE);
    
    /* "gossip-auth" */
    message.insert(message.end(), 
        reinterpret_cast<const uint8_t*>(prefix),
        reinterpret_cast<const uint8_t*>(prefix) + prefix_len);
    
    /* Role */
    message.push_back(static_cast<uint8_t>(role_));
    
    /* Our E_pub */
    message.insert(message.end(), ephemeral_public_, ephemeral_public_ + crypto::PUBLIC_KEY_SIZE);
    
    /* Transcript hash */
    message.insert(message.end(), transcript_hash_, transcript_hash_ + crypto::HASH_SIZE);
    
    return message;
}

std::vector<uint8_t> Handshake::create_auth() {
    if (!keys_derived_) {
        return {};
    }
    
    /* AUTH format: [ IK_pub (32) | Signature (64) ] */
    std::vector<uint8_t> auth(protocol::AUTH_PAYLOAD_SIZE);
    
    /* Copy our public key (IK_pub) */
    std::memcpy(auth.data(), identity_.public_key(), crypto::ED25519_PUBLIC_KEY_SIZE);
    
    /* Build message to sign */
    auto message = build_auth_message();
    
    /* Sign with our Ed25519 secret key */
    if (!identity_.sign(message.data(), message.size(), auth.data() + 32)) {
        state_ = HandshakeState::FAILED;
        return {};
    }
    
    state_ = HandshakeState::AUTH_SENT;
    return auth;
}

bool Handshake::process_auth(const uint8_t* data, size_t len, uint8_t* peer_pubkey_out) {
    if (len != protocol::AUTH_PAYLOAD_SIZE) {
        state_ = HandshakeState::FAILED;
        return false;
    }
    
    if (!keys_derived_) {
        state_ = HandshakeState::FAILED;
        return false;
    }
    
    /* Parse AUTH: [ IK_pub (32) | Signature (64) ] */
    const uint8_t* peer_pubkey = data;
    const uint8_t* signature = data + 32;
    
    /*
     * Build the message that peer should have signed:
     *   "gossip-auth" || PeerRole || Peer_E_pub || Transcript
     */
    const char* prefix = "gossip-auth";
    size_t prefix_len = 11;
    
    /* Peer's role is opposite of ours */
    protocol::HandshakeRole peer_role = (role_ == protocol::HandshakeRole::INITIATOR)
        ? protocol::HandshakeRole::RESPONDER
        : protocol::HandshakeRole::INITIATOR;
    
    std::vector<uint8_t> message;
    message.reserve(prefix_len + 1 + crypto::PUBLIC_KEY_SIZE + crypto::HASH_SIZE);
    
    message.insert(message.end(),
        reinterpret_cast<const uint8_t*>(prefix),
        reinterpret_cast<const uint8_t*>(prefix) + prefix_len);
    message.push_back(static_cast<uint8_t>(peer_role));
    message.insert(message.end(), peer_ephemeral_, peer_ephemeral_ + crypto::PUBLIC_KEY_SIZE);
    message.insert(message.end(), transcript_hash_, transcript_hash_ + crypto::HASH_SIZE);
    
    /* Verify signature */
    if (!Identity::verify(peer_pubkey, message.data(), message.size(), signature)) {
        state_ = HandshakeState::FAILED;
        return false;
    }
    
    /* Copy out peer's public key */
    std::memcpy(peer_pubkey_out, peer_pubkey, crypto::ED25519_PUBLIC_KEY_SIZE);
    
    state_ = HandshakeState::COMPLETE;
    return true;
}

const uint8_t* Handshake::send_key() const {
    if (!keys_derived_) {
        return nullptr;
    }
    return (role_ == protocol::HandshakeRole::INITIATOR) ? k_init_ : k_resp_;
}

const uint8_t* Handshake::recv_key() const {
    if (!keys_derived_) {
        return nullptr;
    }
    return (role_ == protocol::HandshakeRole::INITIATOR) ? k_resp_ : k_init_;
}

}  /* namespace gossip */
