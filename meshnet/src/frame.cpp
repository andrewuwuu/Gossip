/*
 * frame.cpp
 *
 * Implementation of encrypted frame serialization for Gossip Protocol.
 * Supports both v0.1 (legacy) and v1.0 formats.
 */

#include "frame.h"
#include <cstring>
#include <arpa/inet.h>

namespace gossip {

/*
 * Helper functions for 64-bit network byte order conversion.
 */
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

/*
 * =============================================================================
 * Legacy v0.1 EncryptedFrame Implementation
 * =============================================================================
 */

void EncryptedFrame::build_aad(uint8_t version, uint8_t flags, uint64_t seq, uint8_t* aad) {
    aad[0] = version;
    aad[1] = flags;
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
    if (plaintext_len > FRAME_MAX_PAYLOAD_LEGACY) {
        return false;
    }

    uint64_t seq;
    if (!session.next_send_seq(seq)) {
        return false;
    }

    size_t frame_size = FRAME_OVERHEAD_LEGACY + plaintext_len;
    frame_out.resize(frame_size);

    uint8_t* ptr = frame_out.data();
    ptr[0] = FRAME_VERSION_LEGACY;
    ptr[1] = flags;
    
    ptr[2] = (seq >> 56) & 0xFF;
    ptr[3] = (seq >> 48) & 0xFF;
    ptr[4] = (seq >> 40) & 0xFF;
    ptr[5] = (seq >> 32) & 0xFF;
    ptr[6] = (seq >> 24) & 0xFF;
    ptr[7] = (seq >> 16) & 0xFF;
    ptr[8] = (seq >> 8) & 0xFF;
    ptr[9] = seq & 0xFF;

    uint8_t* nonce = ptr + FRAME_HEADER_SIZE_LEGACY;
    crypto::random_bytes(nonce, FRAME_NONCE_SIZE_LEGACY);

    uint8_t aad[FRAME_HEADER_SIZE_LEGACY];
    build_aad(FRAME_VERSION_LEGACY, flags, seq, aad);

    uint8_t* ciphertext = ptr + FRAME_HEADER_SIZE_LEGACY + FRAME_NONCE_SIZE_LEGACY;
    
    if (!crypto::aead_encrypt(
            session.key(),
            nonce,
            plaintext,
            plaintext_len,
            aad,
            FRAME_HEADER_SIZE_LEGACY,
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
    if (frame_len < FRAME_MIN_SIZE_LEGACY) {
        return false;
    }

    uint8_t version = frame[0];
    if (version != FRAME_VERSION_LEGACY) {
        return false;
    }

    uint8_t flags = frame[1];
    uint64_t seq = from_network_order_64(frame + 2);

    if (!session.check_replay(seq)) {
        return false;
    }

    const uint8_t* nonce = frame + FRAME_HEADER_SIZE_LEGACY;
    const uint8_t* ciphertext = frame + FRAME_HEADER_SIZE_LEGACY + FRAME_NONCE_SIZE_LEGACY;
    size_t ciphertext_len = frame_len - FRAME_HEADER_SIZE_LEGACY - FRAME_NONCE_SIZE_LEGACY;

    if (ciphertext_len < FRAME_TAG_SIZE) {
        return false;
    }

    size_t plaintext_len = ciphertext_len - FRAME_TAG_SIZE;

    uint8_t aad[FRAME_HEADER_SIZE_LEGACY];
    build_aad(version, flags, seq, aad);

    std::vector<uint8_t> plaintext(plaintext_len);
    
    if (!crypto::aead_decrypt(
            session.key(),
            nonce,
            ciphertext,
            ciphertext_len,
            aad,
            FRAME_HEADER_SIZE_LEGACY,
            plaintext.data())) {
        return false;
    }

    session.update_replay_window(seq);

    plaintext_out = std::move(plaintext);
    flags_out = flags;
    
    return true;
}

bool EncryptedFrame::validate_structure(const uint8_t* frame, size_t frame_len) {
    if (frame_len < FRAME_MIN_SIZE_LEGACY) {
        return false;
    }
    
    if (frame[0] != FRAME_VERSION_LEGACY) {
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
    if (frame_len < FRAME_HEADER_SIZE_LEGACY) {
        return false;
    }
    
    version = frame[0];
    flags = frame[1];
    seq = from_network_order_64(frame + 2);
    
    return true;
}

/*
 * =============================================================================
 * v1.0 FrameV1 Implementation
 * =============================================================================
 */

bool FrameV1::encrypt(
    Session& session,
    protocol::MessageType type,
    const uint8_t* plaintext,
    size_t plaintext_len,
    std::vector<uint8_t>& frame_out,
    uint64_t& seq_out
) {
    if (plaintext_len > protocol::FRAME_MAX_PAYLOAD) {
        return false;
    }
    
    /* Build header */
    protocol::FrameHeader header(type, static_cast<uint32_t>(plaintext_len + crypto::TAG_SIZE));
    
    /* Convert length to network byte order for transmission */
    protocol::FrameHeader wire_header = header;
    wire_header.to_network_order();
    
    /* Allocate frame: header + ciphertext + tag */
    size_t frame_size = protocol::FRAME_HEADER_SIZE + plaintext_len + crypto::TAG_SIZE;
    frame_out.resize(frame_size);
    
    /* Copy header */
    std::memcpy(frame_out.data(), &wire_header, protocol::FRAME_HEADER_SIZE);
    
    /* Encrypt using session with header as AAD */
    uint8_t* ciphertext = frame_out.data() + protocol::FRAME_HEADER_SIZE;
    
    if (!session.encrypt(
            plaintext,
            plaintext_len,
            frame_out.data(),  /* Header as AAD */
            ciphertext,
            seq_out)) {
        return false;
    }
    
    return true;
}

bool FrameV1::encrypt_with_seq(
    const uint8_t* key,
    protocol::MessageType type,
    uint64_t seq,
    const uint8_t* plaintext,
    size_t plaintext_len,
    std::vector<uint8_t>& frame_out
) {
    if (plaintext_len > protocol::FRAME_MAX_PAYLOAD) {
        return false;
    }
    
    /* Build header */
    protocol::FrameHeader header(type, static_cast<uint32_t>(plaintext_len + crypto::TAG_SIZE));
    
    /* Convert length to network byte order */
    protocol::FrameHeader wire_header = header;
    wire_header.to_network_order();
    
    /* Allocate frame */
    size_t frame_size = protocol::FRAME_HEADER_SIZE + plaintext_len + crypto::TAG_SIZE;
    frame_out.resize(frame_size);
    
    /* Copy header */
    std::memcpy(frame_out.data(), &wire_header, protocol::FRAME_HEADER_SIZE);
    
    /* Build implicit nonce */
    uint8_t nonce[protocol::NONCE_SIZE];
    protocol::build_nonce(seq, nonce);
    
    /* Encrypt */
    uint8_t* ciphertext = frame_out.data() + protocol::FRAME_HEADER_SIZE;
    
    bool result = crypto::aead_encrypt(
        key,
        nonce,
        plaintext,
        plaintext_len,
        frame_out.data(),  /* Header as AAD */
        protocol::FRAME_HEADER_SIZE,
        ciphertext
    );
    
    crypto::secure_zero(nonce, sizeof(nonce));
    
    return result;
}

bool FrameV1::decrypt(
    Session& session,
    const uint8_t* frame,
    size_t frame_len,
    std::vector<uint8_t>& plaintext_out,
    protocol::MessageType& type_out,
    uint64_t& seq_out
) {
    /* Validate structure */
    if (!validate_structure(frame, frame_len)) {
        return false;
    }
    
    /* Extract header */
    protocol::FrameHeader header;
    if (!extract_header(frame, frame_len, header)) {
        return false;
    }
    
    /* Validate payload length */
    size_t ciphertext_len = frame_len - protocol::FRAME_HEADER_SIZE;
    if (ciphertext_len < crypto::TAG_SIZE) {
        return false;
    }
    
    size_t plaintext_len = ciphertext_len - crypto::TAG_SIZE;
    
    /* Get expected sequence for strict ordering */
    seq_out = session.expected_recv_seq();
    
    /* Decrypt using session */
    std::vector<uint8_t> plaintext(plaintext_len);
    
    if (!session.decrypt(
            frame + protocol::FRAME_HEADER_SIZE,
            ciphertext_len,
            frame,  /* Header as AAD */
            seq_out,
            plaintext.data())) {
        return false;
    }
    
    plaintext_out = std::move(plaintext);
    type_out = header.message_type();
    
    return true;
}

bool FrameV1::decrypt_with_key(
    const uint8_t* key,
    const uint8_t* frame,
    size_t frame_len,
    std::vector<uint8_t>& plaintext_out,
    protocol::MessageType& type_out
) {
    /* Validate structure */
    if (!validate_structure(frame, frame_len)) {
        return false;
    }
    
    /* Extract header */
    protocol::FrameHeader header;
    if (!extract_header(frame, frame_len, header)) {
        return false;
    }
    
    size_t ciphertext_len = frame_len - protocol::FRAME_HEADER_SIZE;
    if (ciphertext_len < crypto::TAG_SIZE) {
        return false;
    }
    
    size_t plaintext_len = ciphertext_len - crypto::TAG_SIZE;
    
    /* AUTH frame is always sequence 0 */
    uint8_t nonce[protocol::NONCE_SIZE];
    protocol::build_nonce(0, nonce);
    
    std::vector<uint8_t> plaintext(plaintext_len);
    
    bool result = crypto::aead_decrypt(
        key,
        nonce,
        frame + protocol::FRAME_HEADER_SIZE,
        ciphertext_len,
        frame,  /* Header as AAD */
        protocol::FRAME_HEADER_SIZE,
        plaintext.data()
    );
    
    crypto::secure_zero(nonce, sizeof(nonce));
    
    if (!result) {
        return false;
    }
    
    plaintext_out = std::move(plaintext);
    type_out = header.message_type();
    
    return true;
}

bool FrameV1::validate_structure(const uint8_t* frame, size_t frame_len) {
    if (frame_len < FRAME_MIN_SIZE_V1) {
        return false;
    }
    
    /* Check magic bytes */
    if (frame[0] != protocol::FRAME_MAGIC_0 || frame[1] != protocol::FRAME_MAGIC_1) {
        return false;
    }
    
    /* Check version */
    if (frame[2] != protocol::FRAME_VERSION) {
        return false;
    }
    
    return true;
}

bool FrameV1::extract_header(
    const uint8_t* frame,
    size_t frame_len,
    protocol::FrameHeader& header_out
) {
    if (frame_len < protocol::FRAME_HEADER_SIZE) {
        return false;
    }
    
    std::memcpy(&header_out, frame, protocol::FRAME_HEADER_SIZE);
    header_out.to_host_order();
    
    return header_out.is_valid();
}

std::vector<uint8_t> FrameV1::create_hello_frame(const uint8_t* hello_payload, size_t len) {
    /* HELLO is transmitted in plaintext (no encryption) */
    protocol::FrameHeader header(protocol::MessageType::HELLO, static_cast<uint32_t>(len));
    
    protocol::FrameHeader wire_header = header;
    wire_header.to_network_order();
    
    std::vector<uint8_t> frame(protocol::FRAME_HEADER_SIZE + len);
    std::memcpy(frame.data(), &wire_header, protocol::FRAME_HEADER_SIZE);
    
    if (hello_payload != nullptr && len > 0) {
        std::memcpy(frame.data() + protocol::FRAME_HEADER_SIZE, hello_payload, len);
    }
    
    return frame;
}

bool FrameV1::parse_hello_frame(
    const uint8_t* frame,
    size_t frame_len,
    std::vector<uint8_t>& payload_out
) {
    if (frame_len < protocol::FRAME_HEADER_SIZE) {
        return false;
    }
    
    protocol::FrameHeader header;
    if (!extract_header(frame, frame_len, header)) {
        return false;
    }
    
    if (header.message_type() != protocol::MessageType::HELLO) {
        return false;
    }
    
    size_t payload_len = frame_len - protocol::FRAME_HEADER_SIZE;
    if (payload_len != header.length) {
        return false;
    }
    
    payload_out.assign(
        frame + protocol::FRAME_HEADER_SIZE,
        frame + frame_len
    );
    
    return true;
}

}  /* namespace gossip */
