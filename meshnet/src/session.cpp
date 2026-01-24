/*
 * session.cpp
 *
 * Implementation of session state management for Gossip Protocol v1.0.
 * Supports both PSK mode (v0.1 compatibility) and handshake mode (v1.0).
 */

#include "session.h"
#include <cstring>

namespace gossip {

/*
 * PSK mode constructor (v0.1 compatibility).
 * Uses the same key for both send and receive.
 */
Session::Session(const uint8_t* key)
    : mode_(SessionMode::PSK)
    , is_initiator_(false)
{
    if (key != nullptr) {
        std::memcpy(send_key_, key, crypto::KEY_SIZE);
        std::memcpy(recv_key_, key, crypto::KEY_SIZE);  /* Same key for both directions */
    } else {
        std::memset(send_key_, 0, crypto::KEY_SIZE);
        std::memset(recv_key_, 0, crypto::KEY_SIZE);
    }
}

/*
 * Handshake mode constructor (v1.0).
 * Uses directional keys derived from HKDF.
 */
Session::Session(const uint8_t* send_key, const uint8_t* recv_key, bool is_initiator)
    : mode_(SessionMode::HANDSHAKE)
    , is_initiator_(is_initiator)
{
    /* 
     * In v1.0, the AUTH message uses sequence 0. 
     * Subsequent application messages (MSG, PING) must start at 1.
     */
    send_seq_.store(1);
    recv_seq_.store(1);

    if (send_key != nullptr) {
        std::memcpy(send_key_, send_key, crypto::KEY_SIZE);
    } else {
        std::memset(send_key_, 0, crypto::KEY_SIZE);
    }
    
    if (recv_key != nullptr) {
        std::memcpy(recv_key_, recv_key, crypto::KEY_SIZE);
    } else {
        std::memset(recv_key_, 0, crypto::KEY_SIZE);
    }
}

Session::~Session() {
    crypto::secure_zero(send_key_, crypto::KEY_SIZE);
    crypto::secure_zero(recv_key_, crypto::KEY_SIZE);
}

Session::Session(Session&& other) noexcept
    : mode_(other.mode_)
    , is_initiator_(other.is_initiator_)
    , send_seq_(other.send_seq_.load())
    , recv_seq_(other.recv_seq_.load())
    , recv_highest_(other.recv_highest_)
    , recv_window_(other.recv_window_)
{
    std::memcpy(send_key_, other.send_key_, crypto::KEY_SIZE);
    std::memcpy(recv_key_, other.recv_key_, crypto::KEY_SIZE);
    
    crypto::secure_zero(other.send_key_, crypto::KEY_SIZE);
    crypto::secure_zero(other.recv_key_, crypto::KEY_SIZE);
    other.send_seq_.store(SESSION_SEQ_MAX);
    other.recv_seq_.store(0);
    other.recv_highest_ = 0;
    other.recv_window_ = 0;
}

Session& Session::operator=(Session&& other) noexcept {
    if (this != &other) {
        crypto::secure_zero(send_key_, crypto::KEY_SIZE);
        crypto::secure_zero(recv_key_, crypto::KEY_SIZE);
        
        mode_ = other.mode_;
        is_initiator_ = other.is_initiator_;
        std::memcpy(send_key_, other.send_key_, crypto::KEY_SIZE);
        std::memcpy(recv_key_, other.recv_key_, crypto::KEY_SIZE);
        send_seq_.store(other.send_seq_.load());
        recv_seq_.store(other.recv_seq_.load());
        recv_highest_ = other.recv_highest_;
        recv_window_ = other.recv_window_;
        
        crypto::secure_zero(other.send_key_, crypto::KEY_SIZE);
        crypto::secure_zero(other.recv_key_, crypto::KEY_SIZE);
        other.send_seq_.store(SESSION_SEQ_MAX);
        other.recv_seq_.store(0);
        other.recv_highest_ = 0;
        other.recv_window_ = 0;
    }
    return *this;
}

/*
 * Build implicit nonce from sequence number.
 * Per spec: Nonce = [ Seq (8 bytes, BE) | Padding (16 zero bytes) ]
 */
void Session::build_nonce(uint64_t seq, uint8_t* nonce) const {
    protocol::build_nonce(seq, nonce);
}

/*
 * =============================================================================
 * v1.0 Encryption/Decryption API
 * =============================================================================
 */

bool Session::encrypt(
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* header_aad,
    uint8_t* ciphertext,
    uint64_t& seq_out
) {
    /* Get next sequence number */
    if (!next_send_seq(seq_out)) {
        return false;  /* Session exhausted */
    }
    
    /* Build implicit nonce from sequence */
    uint8_t nonce[protocol::NONCE_SIZE];
    build_nonce(seq_out, nonce);
    
    /* Encrypt with AEAD using frame header as AAD */
    bool result = crypto::aead_encrypt(
        send_key_,
        nonce,
        plaintext,
        plaintext_len,
        header_aad,
        protocol::FRAME_HEADER_SIZE,
        ciphertext
    );
    
    /* Securely wipe nonce */
    crypto::secure_zero(nonce, sizeof(nonce));
    
    return result;
}

bool Session::decrypt(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* header_aad,
    uint64_t expected_seq,
    uint8_t* plaintext
) {
    if (mode_ == SessionMode::HANDSHAKE) {
        /*
         * v1.0 strict ordering: sequence must be exactly what we expect.
         * No replay window, no out-of-order delivery.
         */
        uint64_t current_expected = recv_seq_.load();
        if (expected_seq != current_expected) {
            return false;  /* Sequence error */
        }
    }
    
    /* Build implicit nonce from expected sequence */
    uint8_t nonce[protocol::NONCE_SIZE];
    build_nonce(expected_seq, nonce);
    
    /* Decrypt with AEAD using frame header as AAD */
    bool result = crypto::aead_decrypt(
        recv_key_,
        nonce,
        ciphertext,
        ciphertext_len,
        header_aad,
        protocol::FRAME_HEADER_SIZE,
        plaintext
    );
    
    /* Securely wipe nonce */
    crypto::secure_zero(nonce, sizeof(nonce));
    
    if (result && mode_ == SessionMode::HANDSHAKE) {
        /* Update expected sequence for next message */
        recv_seq_.fetch_add(1);
    }
    
    return result;
}

/*
 * =============================================================================
 * Legacy v0.1 API
 * =============================================================================
 */

bool Session::next_send_seq(uint64_t& seq_out) {
    /*
     * Atomically fetch and increment, checking for exhaustion.
     * Once we hit SESSION_SEQ_MAX, the session must terminate.
     */
    uint64_t current = send_seq_.load(std::memory_order_relaxed);
    
    while (current < SESSION_SEQ_MAX) {
        if (send_seq_.compare_exchange_weak(
                current, 
                current + 1,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            seq_out = current;
            return true;
        }
    }
    
    return false;  /* Session exhausted */
}

bool Session::check_replay(uint64_t seq) const {
    std::lock_guard<std::mutex> lock(replay_mutex_);
    
    /*
     * Replay window algorithm per Gossip Protocol v0.1:
     * - Accept if seq > recv_highest (new high water mark)
     * - Reject if seq <= recv_highest - REPLAY_WINDOW_SIZE (too old)
     * - Reject if seq already seen in window (duplicate)
     * - Accept if seq in window but not yet seen
     */
    
    if (recv_highest_ == 0 && recv_window_ == 0) {
        /*
         * First packet - always accept.
         */
        return true;
    }
    
    if (seq > recv_highest_) {
        /*
         * New high water mark - always valid.
         */
        return true;
    }
    
    /*
     * Check if packet is too old (outside the window).
     */
    if (seq + REPLAY_WINDOW_SIZE <= recv_highest_) {
        return false;
    }
    
    /*
     * Check if already seen in the bitmap.
     * Position in window is relative to recv_highest.
     */
    uint64_t offset = recv_highest_ - seq;
    
    if (offset >= REPLAY_WINDOW_SIZE) {
        return false;
    }
    
    uint64_t bit = 1ULL << offset;
    if (recv_window_ & bit) {
        return false;  /* Already seen */
    }
    
    return true;
}

void Session::update_replay_window(uint64_t seq) {
    std::lock_guard<std::mutex> lock(replay_mutex_);
    
    if (recv_highest_ == 0 && recv_window_ == 0) {
        /*
         * First packet - initialize window.
         */
        recv_highest_ = seq;
        recv_window_ = 1;  /* Bit 0 represents recv_highest */
        return;
    }
    
    if (seq > recv_highest_) {
        /*
         * New high water mark - slide the window.
         */
        uint64_t shift = seq - recv_highest_;
        
        if (shift >= REPLAY_WINDOW_SIZE) {
            /*
             * New sequence is outside old window - reset.
             */
            recv_window_ = 1;
        } else {
            /*
             * Shift window and set bit 0 for new highest.
             */
            recv_window_ <<= shift;
            recv_window_ |= 1;
        }
        
        recv_highest_ = seq;
    } else {
        /*
         * Packet within existing window - set the bit.
         */
        uint64_t offset = recv_highest_ - seq;
        
        if (offset < REPLAY_WINDOW_SIZE) {
            recv_window_ |= (1ULL << offset);
        }
    }
}

bool Session::is_exhausted() const {
    return send_seq_.load(std::memory_order_relaxed) >= SESSION_SEQ_MAX;
}

}  /* namespace gossip */
