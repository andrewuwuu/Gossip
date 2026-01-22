/*
 * frame.h
 *
 * Encrypted frame format for Gossip Protocol v0.1.
 * 
 * Wire format:
 * | version (1) | flags (1) | seq (8) | nonce (24) | ciphertext (N) | tag (16) |
 *
 * AAD (Authenticated Additional Data):
 * | version (1) | flags (1) | seq (8) |
 */

#ifndef GOSSIP_FRAME_H
#define GOSSIP_FRAME_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include "crypto.h"
#include "session.h"

namespace gossip {

/*
 * Frame constants matching Gossip Protocol v0.1 specification.
 */
constexpr uint8_t FRAME_VERSION = 0x01;
constexpr size_t FRAME_HEADER_SIZE = 10;   /* version + flags + seq */
constexpr size_t FRAME_NONCE_SIZE = crypto::NONCE_SIZE;  /* 24 bytes */
constexpr size_t FRAME_TAG_SIZE = crypto::TAG_SIZE;      /* 16 bytes */
constexpr size_t FRAME_OVERHEAD = FRAME_HEADER_SIZE + FRAME_NONCE_SIZE + FRAME_TAG_SIZE;  /* 50 bytes */
constexpr size_t FRAME_MIN_SIZE = FRAME_OVERHEAD;
constexpr size_t FRAME_MAX_PAYLOAD = 1200 - FRAME_OVERHEAD;  /* ~1150 bytes for UDP */

/*
 * Frame flags (bitfield).
 */
enum FrameFlag : uint8_t {
    FRAME_FLAG_NONE       = 0x00,
    FRAME_FLAG_COMPRESSED = 0x01,  /* Reserved for future use */
};

/*
 * EncryptedFrame
 *
 * Handles serialization and deserialization of encrypted frames.
 * All cryptographic operations are performed through a Session object.
 */
class EncryptedFrame {
public:
    EncryptedFrame() = default;

    /*
     * Encrypts a plaintext payload into a complete frame.
     *
     * @param session       Active session for key and sequence
     * @param plaintext     Data to encrypt
     * @param plaintext_len Length of plaintext
     * @param flags         Frame flags
     * @param frame_out     Output buffer for the complete frame
     *
     * @return true on success, false on failure (e.g., session exhausted)
     */
    static bool encrypt(
        Session& session,
        const uint8_t* plaintext,
        size_t plaintext_len,
        uint8_t flags,
        std::vector<uint8_t>& frame_out
    );

    /*
     * Decrypts a frame and extracts the plaintext.
     *
     * @param session        Active session for key and replay checking
     * @param frame          Complete encrypted frame
     * @param frame_len      Length of frame
     * @param plaintext_out  Output buffer for decrypted plaintext
     * @param flags_out      Output for frame flags
     *
     * @return true on success, false on any failure:
     *         - Frame too short
     *         - Version mismatch
     *         - Replay detected
     *         - Authentication failure
     *
     * On failure, plaintext_out is NOT modified.
     */
    static bool decrypt(
        Session& session,
        const uint8_t* frame,
        size_t frame_len,
        std::vector<uint8_t>& plaintext_out,
        uint8_t& flags_out
    );

    /*
     * Validates frame structure without decrypting.
     * Used for quick rejection of malformed frames.
     *
     * @param frame     Frame data
     * @param frame_len Frame length
     *
     * @return true if structure is valid, false otherwise
     */
    static bool validate_structure(const uint8_t* frame, size_t frame_len);

    /*
     * Extracts headers without decryption (for logging/debugging).
     *
     * @param frame     Frame data
     * @param frame_len Frame length
     * @param version   Output for version byte
     * @param flags     Output for flags byte
     * @param seq       Output for sequence number
     *
     * @return true if extraction successful, false if frame too short
     */
    static bool extract_header(
        const uint8_t* frame,
        size_t frame_len,
        uint8_t& version,
        uint8_t& flags,
        uint64_t& seq
    );

private:
    /*
     * Constructs the AAD from header fields.
     */
    static void build_aad(uint8_t version, uint8_t flags, uint64_t seq, uint8_t* aad);
};

}  /* namespace gossip */

#endif  /* GOSSIP_FRAME_H */
