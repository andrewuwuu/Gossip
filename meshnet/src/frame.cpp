/*
 * frame.cpp
 *
 * Implementation of encrypted frame serialization for Gossip Protocol v0.1.
 */

#include "frame.h"
#include <cstring>
#include <arpa/inet.h>  /* For htonll/ntohll equivalents */

namespace gossip {

/*
 * Helper functions for 64-bit network byte order conversion.
 * Some systems don't have htonll/ntohll, so we implement our own.
 */
static inline uint64_t to_network_order_64(uint64_t host) {
    uint8_t bytes[8];
    bytes[0] = (host >> 56) & 0xFF;
    bytes[1] = (host >> 48) & 0xFF;
    bytes[2] = (host >> 40) & 0xFF;
    bytes[3] = (host >> 32) & 0xFF;
    bytes[4] = (host >> 24) & 0xFF;
    bytes[5] = (host >> 16) & 0xFF;
    bytes[6] = (host >> 8) & 0xFF;
    bytes[7] = host & 0xFF;
    
    uint64_t result;
    std::memcpy(&result, bytes, 8);
    return result;
}

static inline uint64_t from_network_order_64(const uint8_t* bytes) {
    return (static_cast<uint64_t>(bytes[0]) << 56) |
           (static_cast<uint64_t>(bytes[1]) << 48) |
           (static_cast<uint64_t>(bytes[2]) << 40) |
           (static_cast<uint64_t>(bytes[3]) << 32) |
           (static_cast<uint64_t>(bytes[4]) << 24) |
           (static_cast<uint64_t>(bytes[5]) << 16) |
           (static_cast<uint64_t>(bytes[6]) << 8) |
           static_cast<uint64_t>(bytes[7]);
}

void EncryptedFrame::build_aad(uint8_t version, uint8_t flags, uint64_t seq, uint8_t* aad) {
    aad[0] = version;
    aad[1] = flags;
    
    /*
     * Sequence number in big-endian (network byte order).
     */
    aad[2] = (seq >> 56) & 0xFF;
    aad[3] = (seq >> 48) & 0xFF;
    aad[4] = (seq >> 40) & 0xFF;
    aad[5] = (seq >> 32) & 0xFF;
    aad[6] = (seq >> 24) & 0xFF;
    aad[7] = (seq >> 16) & 0xFF;
    aad[8] = (seq >> 8) & 0xFF;
    aad[9] = seq & 0xFF;
}

bool EncryptedFrame::encrypt(
    Session& session,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t flags,
    std::vector<uint8_t>& frame_out
) {
    /*
     * Check payload size.
     */
    if (plaintext_len > FRAME_MAX_PAYLOAD) {
        return false;
    }

    /*
     * Get next sequence number.
     */
    uint64_t seq;
    if (!session.next_send_seq(seq)) {
        return false;  /* Session exhausted */
    }

    /*
     * Calculate total frame size.
     */
    size_t frame_size = FRAME_OVERHEAD + plaintext_len;
    frame_out.resize(frame_size);

    /*
     * Build header.
     */
    uint8_t* ptr = frame_out.data();
    ptr[0] = FRAME_VERSION;
    ptr[1] = flags;
    
    /*
     * Sequence number in big-endian.
     */
    ptr[2] = (seq >> 56) & 0xFF;
    ptr[3] = (seq >> 48) & 0xFF;
    ptr[4] = (seq >> 40) & 0xFF;
    ptr[5] = (seq >> 32) & 0xFF;
    ptr[6] = (seq >> 24) & 0xFF;
    ptr[7] = (seq >> 16) & 0xFF;
    ptr[8] = (seq >> 8) & 0xFF;
    ptr[9] = seq & 0xFF;

    /*
     * Generate random nonce.
     */
    uint8_t* nonce = ptr + FRAME_HEADER_SIZE;
    crypto::random_bytes(nonce, FRAME_NONCE_SIZE);

    /*
     * Build AAD (version | flags | seq).
     */
    uint8_t aad[FRAME_HEADER_SIZE];
    build_aad(FRAME_VERSION, flags, seq, aad);

    /*
     * Encrypt payload.
     * Output: [ciphertext (plaintext_len)] [tag (16)]
     */
    uint8_t* ciphertext = ptr + FRAME_HEADER_SIZE + FRAME_NONCE_SIZE;
    
    if (!crypto::aead_encrypt(
            session.key(),
            nonce,
            plaintext,
            plaintext_len,
            aad,
            FRAME_HEADER_SIZE,
            ciphertext)) {
        return false;
    }

    return true;
}

bool EncryptedFrame::decrypt(
    Session& session,
    const uint8_t* frame,
    size_t frame_len,
    std::vector<uint8_t>& plaintext_out,
    uint8_t& flags_out
) {
    /*
     * Step 1: Validate minimum frame size.
     */
    if (frame_len < FRAME_MIN_SIZE) {
        return false;
    }

    /*
     * Step 2: Extract and validate version.
     */
    uint8_t version = frame[0];
    if (version != FRAME_VERSION) {
        return false;  /* Version mismatch - close session */
    }

    /*
     * Step 3: Extract header fields.
     */
    uint8_t flags = frame[1];
    uint64_t seq = from_network_order_64(frame + 2);

    /*
     * Step 4: Replay check BEFORE decryption.
     */
    if (!session.check_replay(seq)) {
        return false;  /* Replay detected - silent drop */
    }

    /*
     * Step 5: Extract nonce and ciphertext.
     */
    const uint8_t* nonce = frame + FRAME_HEADER_SIZE;
    const uint8_t* ciphertext = frame + FRAME_HEADER_SIZE + FRAME_NONCE_SIZE;
    size_t ciphertext_len = frame_len - FRAME_HEADER_SIZE - FRAME_NONCE_SIZE;

    /*
     * Ciphertext includes the 16-byte tag.
     */
    if (ciphertext_len < FRAME_TAG_SIZE) {
        return false;
    }

    size_t plaintext_len = ciphertext_len - FRAME_TAG_SIZE;

    /*
     * Step 6: Build AAD.
     */
    uint8_t aad[FRAME_HEADER_SIZE];
    build_aad(version, flags, seq, aad);

    /*
     * Step 7: Attempt decryption.
     */
    std::vector<uint8_t> plaintext(plaintext_len);
    
    if (!crypto::aead_decrypt(
            session.key(),
            nonce,
            ciphertext,
            ciphertext_len,
            aad,
            FRAME_HEADER_SIZE,
            plaintext.data())) {
        return false;  /* Auth failure - silent drop */
    }

    /*
     * Step 8: Update replay window AFTER successful auth.
     */
    session.update_replay_window(seq);

    /*
     * Step 9: Deliver plaintext.
     */
    plaintext_out = std::move(plaintext);
    flags_out = flags;
    
    return true;
}

bool EncryptedFrame::validate_structure(const uint8_t* frame, size_t frame_len) {
    if (frame_len < FRAME_MIN_SIZE) {
        return false;
    }
    
    if (frame[0] != FRAME_VERSION) {
        return false;
    }
    
    return true;
}

bool EncryptedFrame::extract_header(
    const uint8_t* frame,
    size_t frame_len,
    uint8_t& version,
    uint8_t& flags,
    uint64_t& seq
) {
    if (frame_len < FRAME_HEADER_SIZE) {
        return false;
    }
    
    version = frame[0];
    flags = frame[1];
    seq = from_network_order_64(frame + 2);
    
    return true;
}

}  /* namespace gossip */
