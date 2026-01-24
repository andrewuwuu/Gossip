/*
 * frame.h
 *
 * Encrypted frame format for Gossip Protocol.
 * Supports both v0.1 (legacy) and v1.0 formats.
 * 
 * v1.0 Wire format (recommended):
 * | header (8) | ciphertext (N) | tag (16) |
 * 
 * Header (8 bytes, used as AAD):
 * | magic (2) | version (1) | type (1) | length (4, BE) |
 * 
 * Nonce is implicit: [ seq (8 bytes, BE) | zeros (16 bytes) ]
 *
 * v0.1 Wire format (legacy):
 * | version (1) | flags (1) | seq (8) | nonce (24) | ciphertext (N) | tag (16) |
 */

#ifndef GOSSIP_FRAME_H
#define GOSSIP_FRAME_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include "crypto.h"
#include "session.h"
#include "protocol.h"

namespace gossip {

/*
 * =============================================================================
 * v0.1 Legacy Constants (for backwards compatibility)
 * =============================================================================
 */
constexpr uint8_t FRAME_VERSION_LEGACY = 0x01;
constexpr size_t FRAME_HEADER_SIZE_LEGACY = 10;   /* version + flags + seq */
constexpr size_t FRAME_NONCE_SIZE_LEGACY = crypto::NONCE_SIZE;  /* 24 bytes */
constexpr size_t FRAME_TAG_SIZE = crypto::TAG_SIZE;      /* 16 bytes */
constexpr size_t FRAME_OVERHEAD_LEGACY = FRAME_HEADER_SIZE_LEGACY + FRAME_NONCE_SIZE_LEGACY + FRAME_TAG_SIZE;  /* 50 bytes */
constexpr size_t FRAME_MIN_SIZE_LEGACY = FRAME_OVERHEAD_LEGACY;
constexpr size_t FRAME_MAX_PAYLOAD_LEGACY = 1200 - FRAME_OVERHEAD_LEGACY;  /* ~1150 bytes for UDP */

/*
 * =============================================================================
 * v1.0 Constants (per specification)
 * =============================================================================
 */
constexpr size_t FRAME_OVERHEAD_V1 = protocol::FRAME_HEADER_SIZE + crypto::TAG_SIZE;  /* 8 + 16 = 24 bytes */
constexpr size_t FRAME_MIN_SIZE_V1 = FRAME_OVERHEAD_V1;

/*
 * Frame flags (bitfield) - legacy v0.1
 */
enum FrameFlag : uint8_t {
    FRAME_FLAG_NONE       = 0x00,
    FRAME_FLAG_COMPRESSED = 0x01,  /* Reserved for future use */
};

/*
 * =============================================================================
 * EncryptedFrame - Legacy v0.1 API (unchanged for compatibility)
 * =============================================================================
 */
class EncryptedFrame {
public:
    EncryptedFrame() = default;

    /*
     * Encrypts a plaintext payload into a complete frame (legacy v0.1).
     */
    static bool encrypt(
        Session& session,
        const uint8_t* plaintext,
        size_t plaintext_len,
        uint8_t flags,
        std::vector<uint8_t>& frame_out
    );

    /*
     * Decrypts a frame and extracts the plaintext (legacy v0.1).
     */
    static bool decrypt(
        Session& session,
        const uint8_t* frame,
        size_t frame_len,
        std::vector<uint8_t>& plaintext_out,
        uint8_t& flags_out
    );

    /*
     * Validates frame structure without decrypting (legacy v0.1).
     */
    static bool validate_structure(const uint8_t* frame, size_t frame_len);

    /*
     * Extracts headers without decryption (legacy v0.1).
     */
    static bool extract_header(
        const uint8_t* frame,
        size_t frame_len,
        uint8_t& version,
        uint8_t& flags,
        uint64_t& seq
    );

private:
    static void build_aad(uint8_t version, uint8_t flags, uint64_t seq, uint8_t* aad);
};

/*
 * =============================================================================
 * FrameV1 - New v1.0 API with implicit nonce and header AAD
 * =============================================================================
 */
class FrameV1 {
public:
    /*
     * Encrypts plaintext into a v1.0 frame.
     * Uses implicit nonce construction and frame header as AAD.
     *
     * @param session       Active v1.0 session with directional keys
     * @param type          Message type (HELLO, AUTH, MSG, PING, ERR)
     * @param plaintext     Data to encrypt (or empty for HELLO)
     * @param plaintext_len Length of plaintext
     * @param frame_out     Output buffer for complete frame
     * @param seq_out       Output: sequence number used
     *
     * @return true on success, false on failure
     */
    static bool encrypt(
        Session& session,
        protocol::MessageType type,
        const uint8_t* plaintext,
        size_t plaintext_len,
        std::vector<uint8_t>& frame_out,
        uint64_t& seq_out
    );
    
    /*
     * Encrypts plaintext with a known sequence (for AUTH messages).
     * Used when sequence is predetermined (e.g., AUTH is always seq=0).
     */
    static bool encrypt_with_seq(
        const uint8_t* key,
        protocol::MessageType type,
        uint64_t seq,
        const uint8_t* plaintext,
        size_t plaintext_len,
        std::vector<uint8_t>& frame_out
    );

    /*
     * Decrypts a v1.0 frame and extracts the plaintext.
     * Validates header and uses implicit nonce.
     *
     * @param session        Active v1.0 session with directional keys
     * @param frame          Complete encrypted frame
     * @param frame_len      Length of frame
     * @param plaintext_out  Output buffer for decrypted plaintext
     * @param type_out       Output: message type
     * @param seq_out        Output: sequence number
     *
     * @return true on success, false on failure
     */
    static bool decrypt(
        Session& session,
        const uint8_t* frame,
        size_t frame_len,
        std::vector<uint8_t>& plaintext_out,
        protocol::MessageType& type_out,
        uint64_t& seq_out
    );
    
    /*
     * Decrypts a v1.0 frame with explicit key and sequence.
     * Used during handshake when session is not yet established.
     */
    static bool decrypt_with_key(
        const uint8_t* key,
        const uint8_t* frame,
        size_t frame_len,
        std::vector<uint8_t>& plaintext_out,
        protocol::MessageType& type_out
    );

    /*
     * Validates v1.0 frame structure.
     * Checks magic, version, and length.
     */
    static bool validate_structure(const uint8_t* frame, size_t frame_len);

    /*
     * Extracts v1.0 header without decryption.
     */
    static bool extract_header(
        const uint8_t* frame,
        size_t frame_len,
        protocol::FrameHeader& header_out
    );
    
    /*
     * Creates an unencrypted HELLO frame (plaintext handshake message).
     * HELLO is the only message type transmitted without encryption.
     */
    static std::vector<uint8_t> create_hello_frame(const uint8_t* hello_payload, size_t len);
    
    /*
     * Parses an unencrypted HELLO frame.
     */
    static bool parse_hello_frame(
        const uint8_t* frame,
        size_t frame_len,
        std::vector<uint8_t>& payload_out
    );
};

}  /* namespace gossip */

#endif  /* GOSSIP_FRAME_H */
