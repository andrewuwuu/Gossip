/*
 * protocol.h
 *
 * Gossip Protocol v1.0 Wire Format Definitions.
 * 
 * This header defines the canonical wire format for all protocol messages:
 * - Frame header structure (8 bytes, used as AEAD AAD)
 * - Message type enumeration
 * - Protocol constants per specification
 */

#ifndef GOSSIP_PROTOCOL_H
#define GOSSIP_PROTOCOL_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <arpa/inet.h>

namespace gossip {
namespace protocol {

/*
 * =============================================================================
 * Protocol Constants (v1.0)
 * =============================================================================
 */

/* Frame magic bytes: "GR" */
constexpr uint8_t FRAME_MAGIC_0 = 0x47;  /* 'G' */
constexpr uint8_t FRAME_MAGIC_1 = 0x52;  /* 'R' */

/* Protocol version */
constexpr uint8_t FRAME_VERSION = 0x01;

/* Frame sizes */
constexpr size_t FRAME_HEADER_SIZE = 8;      /* Magic(2) + Version(1) + Type(1) + Length(4) */
constexpr size_t FRAME_MAX_PAYLOAD = 65535;  /* Max payload per spec */

/* Tag size for AEAD (XChaCha20-Poly1305) */
constexpr size_t AEAD_TAG_SIZE = 16;

/* HELLO message constants */
constexpr size_t HELLO_EPHEM_KEY_SIZE = 32;  /* X25519 ephemeral public key */
constexpr size_t HELLO_PAYLOAD_SIZE = 1 + HELLO_EPHEM_KEY_SIZE;  /* Role(1) + E_pub(32) */

/* AUTH message constants */
constexpr size_t AUTH_PUBLIC_KEY_SIZE = 32;  /* Ed25519 IK_pub */
constexpr size_t AUTH_SIGNATURE_SIZE = 64;   /* Ed25519 signature */
constexpr size_t AUTH_PAYLOAD_SIZE = AUTH_PUBLIC_KEY_SIZE + AUTH_SIGNATURE_SIZE;  /* 96 bytes */

/* MSG message constants */
constexpr size_t MSG_ID_SIZE = 8;  /* MsgID for deduplication */

/* Handshake timeout */
constexpr int HANDSHAKE_TIMEOUT_SECONDS = 5;

/* UDP beacon constants */
constexpr int BEACON_MAX_AGE_SECONDS = 60;  /* ±60 second tolerance */

/*
 * =============================================================================
 * Message Types (Section 6 of Specification)
 * =============================================================================
 */

enum class MessageType : uint8_t {
    HELLO = 0x01,  /* Plaintext handshake initiation */
    AUTH  = 0x02,  /* Encrypted identity + signature */
    MSG   = 0x10,  /* Encrypted application message */
    PING  = 0x20,  /* Encrypted keepalive */
    ERR   = 0xFF   /* Encrypted error */
};

/*
 * Handshake roles for HELLO message
 */
enum class HandshakeRole : uint8_t {
    INITIATOR = 0x01,
    RESPONDER = 0x02
};

/*
 * Error codes for ERR message
 */
enum class ErrorCode : uint8_t {
    NONE                = 0x00,
    PROTOCOL_ERROR      = 0x01,
    HANDSHAKE_FAILED    = 0x02,
    AUTH_FAILED         = 0x03,
    SEQUENCE_ERROR      = 0x04,
    IDENTITY_MISMATCH   = 0x05,
    TIMEOUT             = 0x06
};

/*
 * =============================================================================
 * Frame Header (8 bytes)
 * 
 * Wire format: [ Magic (2) | Version (1) | Type (1) | Length (4) ]
 * This header is used as AAD for AEAD encryption.
 * =============================================================================
 */

#pragma pack(push, 1)
struct FrameHeader {
    uint8_t magic[2];     /* 0x47, 0x52 ("GR") */
    uint8_t version;      /* 0x01 */
    uint8_t type;         /* MessageType */
    uint32_t length;      /* Payload length in bytes (big-endian on wire) */
    
    /*
     * Initialize with default magic and version.
     */
    FrameHeader() 
        : magic{FRAME_MAGIC_0, FRAME_MAGIC_1}
        , version(FRAME_VERSION)
        , type(0)
        , length(0) {}
    
    /*
     * Initialize with type and length.
     */
    FrameHeader(MessageType msg_type, uint32_t payload_len)
        : magic{FRAME_MAGIC_0, FRAME_MAGIC_1}
        , version(FRAME_VERSION)
        , type(static_cast<uint8_t>(msg_type))
        , length(payload_len) {}
    
    /*
     * Validates magic bytes and version.
     */
    bool is_valid() const {
        return magic[0] == FRAME_MAGIC_0 
            && magic[1] == FRAME_MAGIC_1 
            && version == FRAME_VERSION;
    }
    
    /*
     * Converts to network byte order for transmission.
     */
    void to_network_order() {
        length = htonl(length);
    }
    
    /*
     * Converts from network byte order after reception.
     */
    void to_host_order() {
        length = ntohl(length);
    }
    
    /*
     * Returns the message type enum.
     */
    MessageType message_type() const {
        return static_cast<MessageType>(type);
    }
};
#pragma pack(pop)

static_assert(sizeof(FrameHeader) == FRAME_HEADER_SIZE, "FrameHeader must be exactly 8 bytes");

/*
 * =============================================================================
 * Nonce Construction (Section 5.1)
 * 
 * Per specification: Nonce = [ Seq (8 bytes, BE) | Padding (16 zero bytes) ]
 * Total: 24 bytes for XChaCha20
 * =============================================================================
 */

constexpr size_t NONCE_SIZE = 24;

/*
 * Builds an implicit nonce from a sequence number.
 * Nonce layout: [ seq (8 bytes, big-endian) | zeros (16 bytes) ]
 */
inline void build_nonce(uint64_t seq, uint8_t* nonce) {
    std::memset(nonce, 0, NONCE_SIZE);
    /* Big-endian sequence number in first 8 bytes */
    nonce[0] = static_cast<uint8_t>((seq >> 56) & 0xFF);
    nonce[1] = static_cast<uint8_t>((seq >> 48) & 0xFF);
    nonce[2] = static_cast<uint8_t>((seq >> 40) & 0xFF);
    nonce[3] = static_cast<uint8_t>((seq >> 32) & 0xFF);
    nonce[4] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    nonce[5] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    nonce[6] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    nonce[7] = static_cast<uint8_t>(seq & 0xFF);
}

/*
 * Compare two ephemeral public keys lexicographically.
 * Used for simultaneous open resolution: smaller E_pub = Initiator.
 * Returns negative if a < b, 0 if equal, positive if a > b.
 */
inline int compare_ephemeral_keys(const uint8_t* a, const uint8_t* b) {
    return std::memcmp(a, b, HELLO_EPHEM_KEY_SIZE);
}

}  /* namespace protocol */
}  /* namespace gossip */

#endif  /* GOSSIP_PROTOCOL_H */
