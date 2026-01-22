/*
 * session.cpp
 *
 * Implementation of session state management with replay protection.
 */

#include "session.h"
#include <cstring>

namespace gossip {

Session::Session(const uint8_t* key) {
    if (key != nullptr) {
        std::memcpy(key_, key, crypto::KEY_SIZE);
    } else {
        std::memset(key_, 0, crypto::KEY_SIZE);
    }
}

Session::~Session() {
    crypto::secure_zero(key_, crypto::KEY_SIZE);
}

Session::Session(Session&& other) noexcept
    : send_seq_(other.send_seq_.load())
    , recv_highest_(other.recv_highest_)
    , recv_window_(other.recv_window_) {
    std::memcpy(key_, other.key_, crypto::KEY_SIZE);
    crypto::secure_zero(other.key_, crypto::KEY_SIZE);
    other.send_seq_.store(SESSION_SEQ_MAX);
    other.recv_highest_ = 0;
    other.recv_window_ = 0;
}

Session& Session::operator=(Session&& other) noexcept {
    if (this != &other) {
        crypto::secure_zero(key_, crypto::KEY_SIZE);
        std::memcpy(key_, other.key_, crypto::KEY_SIZE);
        send_seq_.store(other.send_seq_.load());
        recv_highest_ = other.recv_highest_;
        recv_window_ = other.recv_window_;
        crypto::secure_zero(other.key_, crypto::KEY_SIZE);
        other.send_seq_.store(SESSION_SEQ_MAX);
        other.recv_highest_ = 0;
        other.recv_window_ = 0;
    }
    return *this;
}

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
