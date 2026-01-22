/*
 * session.h
 *
 * Session state management for Gossip Protocol v0.1.
 * Each peer-to-peer connection maintains exactly one session that tracks:
 * - Symmetric session key for encryption
 * - Send sequence counter (monotonically increasing)
 * - Receive replay window (64-message sliding window)
 */

#ifndef GOSSIP_SESSION_H
#define GOSSIP_SESSION_H

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <mutex>
#include "crypto.h"

namespace gossip {

/*
 * Session constants matching Gossip Protocol v0.1 specification.
 */
constexpr uint64_t SESSION_SEQ_MAX = UINT64_MAX;
constexpr size_t REPLAY_WINDOW_SIZE = 64;

/*
 * Session
 *
 * Manages cryptographic session state for a single peer connection.
 * Handles sequence number generation, replay detection, and key storage.
 *
 * Thread-safety:
 * - encrypt() is thread-safe (uses atomic send_seq)
 * - decrypt() is NOT thread-safe (replay window updates)
 *   Should only be called from the receive processing thread.
 */
class Session {
public:
    /*
     * Creates a new session with the given key.
     *
     * @param key 32-byte symmetric session key
     */
    explicit Session(const uint8_t* key);

    /*
     * Destructor securely zeros the key material.
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
     * Gets the next send sequence number.
     * Atomically increments the counter.
     *
     * @param seq_out Output parameter for the sequence number
     * @return true if sequence available, false if exhausted
     */
    bool next_send_seq(uint64_t& seq_out);

    /*
     * Checks if a received sequence number is valid (not a replay).
     *
     * @param seq The sequence number to check
     * @return true if valid, false if replay detected
     *
     * This function does NOT update the replay window.
     * Call update_replay_window() after successful decryption.
     */
    bool check_replay(uint64_t seq) const;

    /*
     * Updates the replay window after successful authentication.
     * Must be called AFTER decryption succeeds.
     *
     * @param seq The sequence number that was successfully received
     */
    void update_replay_window(uint64_t seq);

    /*
     * Returns the session key.
     * WARNING: Handle with care - do not leak or log.
     */
    const uint8_t* key() const { return key_; }

    /*
     * Checks if the session is exhausted (send sequence at max).
     */
    bool is_exhausted() const;

private:
    uint8_t key_[crypto::KEY_SIZE];
    std::atomic<uint64_t> send_seq_{0};

    /*
     * Replay protection state (NOT thread-safe).
     */
    mutable std::mutex replay_mutex_;
    uint64_t recv_highest_{0};
    uint64_t recv_window_{0};  /* 64-bit bitmap */
};

}  /* namespace gossip */

#endif  /* GOSSIP_SESSION_H */
