/*
 * session.h
 *
 * Session state management for Gossip Protocol v1.0.
 * Each peer-to-peer connection maintains exactly one session that tracks:
 * - Directional encryption keys (send_key, recv_key) from handshake
 * - Send sequence counter (64-bit, implicit nonce construction)
 * - Receive sequence counter (strict in-order delivery)
 * 
 * Per specification Section 5:
 * - Nonce = [ Seq (8 bytes, BE) | Padding (16 zero bytes) ]
 * - Messages must arrive strictly in-order (seq_recv + 1)
 * - Session terminates when counter exhausts or on sequence error
 */

#ifndef GOSSIP_SESSION_H
#define GOSSIP_SESSION_H

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <mutex>
#include "crypto.h"
#include "protocol.h"

namespace gossip {

/*
 * Session constants matching Gossip Protocol v1.0 specification.
 */
constexpr uint64_t SESSION_SEQ_MAX = UINT64_MAX;
constexpr size_t REPLAY_WINDOW_SIZE = 64;  /* Legacy window for v0.1 mode */

/*
 * Session mode for determining key handling
 */
enum class SessionMode {
    PSK,        /* Pre-shared key mode (legacy v0.1) */
    HANDSHAKE   /* Per-connection keys from v1.0 handshake */
};

/*
 * Session
 *
 * Manages cryptographic session state for a single peer connection.
 * Supports both:
 * - v0.1 PSK mode (single symmetric key, replay window)
 * - v1.0 handshake mode (directional keys, strict ordering)
 *
 * Thread-safety:
 * - encrypt() is thread-safe (uses atomic send_seq)
 * - decrypt() uses internal locking for sequence validation
 */
class Session {
public:
    /*
     * Creates a PSK session (v0.1 compatibility).
     *
     * @param key 32-byte symmetric session key
     */
    explicit Session(const uint8_t* key);
    
    /*
     * Creates a v1.0 session with directional keys from handshake.
     *
     * @param send_key    32-byte key for our outgoing messages
     * @param recv_key    32-byte key for incoming messages
     * @param is_initiator  True if we are handshake initiator
     */
    Session(const uint8_t* send_key, const uint8_t* recv_key, bool is_initiator);

    /*
     * Destructor securely zeros all key material.
     */
    ~Session();

    /*
     * Non-copyable to prevent key duplication.
     */
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    /*
     * Move constructor and assignment.
     */
    Session(Session&& other) noexcept;
    Session& operator=(Session&& other) noexcept;

    /*
     * ==========================================================================
     * v1.0 Encryption/Decryption API (recommended)
     * Uses directional keys and implicit nonce construction.
     * ==========================================================================
     */
    
    /*
     * Encrypts a message using the send key and implicit nonce.
     * Automatically increments the send sequence counter.
     *
     * @param plaintext      Data to encrypt
     * @param plaintext_len  Length of plaintext
     * @param header_aad     8-byte frame header to use as AAD
     * @param ciphertext     Output buffer (must be plaintext_len + 16 bytes)
     * @param seq_out        Output: sequence number used for this message
     * @return true on success, false if session exhausted
     */
    bool encrypt(
        const uint8_t* plaintext,
        size_t plaintext_len,
        const uint8_t* header_aad,
        uint8_t* ciphertext,
        uint64_t& seq_out
    );

    /*
     * Decrypts a message using the receive key and implicit nonce.
     * Validates strict sequence ordering (received seq must be expected_seq).
     *
     * @param ciphertext      Encrypted data with tag
     * @param ciphertext_len  Length including 16-byte tag
     * @param header_aad      8-byte frame header used as AAD
     * @param expected_seq    The sequence number we expect (from header or counter)
     * @param plaintext       Output buffer (must be ciphertext_len - 16 bytes)
     * @return true on success, false on auth failure or sequence error
     */
    bool decrypt(
        const uint8_t* ciphertext,
        size_t ciphertext_len,
        const uint8_t* header_aad,
        uint64_t expected_seq,
        uint8_t* plaintext
    );

    /*
     * ==========================================================================
     * Legacy v0.1 API (for backwards compatibility)
     * ==========================================================================
     */
    
    /*
     * Gets the next send sequence number (legacy API).
     */
    bool next_send_seq(uint64_t& seq_out);

    /*
     * Checks if a received sequence number is valid (legacy replay window).
     */
    bool check_replay(uint64_t seq) const;

    /*
     * Updates the replay window after successful decryption (legacy).
     */
    void update_replay_window(uint64_t seq);

    /*
     * Returns the session key (PSK mode only).
     * WARNING: Handle with care - do not leak or log.
     */
    const uint8_t* key() const { return send_key_; }
    
    /*
     * Returns the send key (v1.0 mode).
     */
    const uint8_t* send_key() const { return send_key_; }
    
    /*
     * Returns the receive key (v1.0 mode).
     */
    const uint8_t* recv_key() const { return recv_key_; }

    /*
     * Checks if the session is exhausted (send sequence at max).
     */
    bool is_exhausted() const;
    
    /*
     * Returns the session mode.
     */
    SessionMode mode() const { return mode_; }
    
    /*
     * Returns whether we are the handshake initiator.
     */
    bool is_initiator() const { return is_initiator_; }
    
    /*
     * Returns the current expected receive sequence.
     */
    uint64_t expected_recv_seq() const { return recv_seq_.load(); }

private:
    SessionMode mode_;
    bool is_initiator_;
    
    /* Keys: in PSK mode both are the same, in v1.0 they differ */
    uint8_t send_key_[crypto::KEY_SIZE];
    uint8_t recv_key_[crypto::KEY_SIZE];
    
    /* Send sequence counter (atomic for thread-safety) */
    std::atomic<uint64_t> send_seq_{0};
    
    /* Receive sequence counter (strict ordering in v1.0) */
    std::atomic<uint64_t> recv_seq_{0};

    /*
     * Legacy v0.1 replay protection state
     */
    mutable std::mutex replay_mutex_;
    uint64_t recv_highest_{0};
    uint64_t recv_window_{0};  /* 64-bit bitmap */
    
    /* Build implicit nonce from sequence number */
    void build_nonce(uint64_t seq, uint8_t* nonce) const;
};

}  /* namespace gossip */

#endif  /* GOSSIP_SESSION_H */
