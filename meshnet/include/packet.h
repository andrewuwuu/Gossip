#ifndef GOSSIP_PACKET_H
#define GOSSIP_PACKET_H

#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <arpa/inet.h>

namespace gossip {

constexpr uint8_t MAGIC_BYTE = 0x47;  // 'G' for Gossip
constexpr uint8_t PROTOCOL_VERSION = 0x01;
constexpr size_t HEADER_SIZE = 12;
constexpr size_t MAX_PAYLOAD_SIZE = 16384;  // 16KB max

enum class PacketType : uint8_t {
    PING        = 0x01,
    PONG        = 0x02,
    DISCOVER    = 0x10,
    ANNOUNCE    = 0x11,
    MESSAGE     = 0x20,
    MESSAGE_ACK = 0x21,
    ROUTE       = 0x30,
    FORWARD     = 0x31
};

enum PacketFlag : uint8_t {
    FLAG_BROADCAST   = 0x01,
    FLAG_REQUIRE_ACK = 0x02,
    FLAG_ENCRYPTED   = 0x04,
    FLAG_COMPRESSED  = 0x08
};

#pragma pack(push, 1)
struct PacketHeader {
    uint8_t magic;
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint16_t payload_length;
    uint32_t sequence;
    uint16_t source_id;
    
    void to_network_order() {
        payload_length = htons(payload_length);
        sequence = htonl(sequence);
        source_id = htons(source_id);
    }
    
    void to_host_order() {
        payload_length = ntohs(payload_length);
        sequence = ntohl(sequence);
        source_id = ntohs(source_id);
    }
};
#pragma pack(pop)

static_assert(sizeof(PacketHeader) == HEADER_SIZE, "PacketHeader must be exactly 12 bytes");

class Packet {
public:
    Packet() = default;
    
    Packet(PacketType type, uint16_t source_id, uint8_t flags = 0)
        : header_{} {
        header_.magic = MAGIC_BYTE;
        header_.version = PROTOCOL_VERSION;
        header_.type = static_cast<uint8_t>(type);
        header_.flags = flags;
        header_.source_id = source_id;
        header_.sequence = next_sequence_++;
        header_.payload_length = 0;
    }
    
    bool set_payload(const uint8_t* data, size_t len) {
        if (len > MAX_PAYLOAD_SIZE) return false;
        payload_.assign(data, data + len);
        header_.payload_length = static_cast<uint16_t>(len);
        return true;
    }
    
    bool set_payload(const std::vector<uint8_t>& data) {
        return set_payload(data.data(), data.size());
    }
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer(HEADER_SIZE + payload_.size());
        
        PacketHeader net_header = header_;
        net_header.to_network_order();
        
        std::memcpy(buffer.data(), &net_header, HEADER_SIZE);
        if (!payload_.empty()) {
            std::memcpy(buffer.data() + HEADER_SIZE, payload_.data(), payload_.size());
        }
        
        return buffer;
    }
    
    static bool deserialize(const uint8_t* data, size_t len, Packet& out) {
        if (len < HEADER_SIZE) return false;
        
        PacketHeader header;
        std::memcpy(&header, data, HEADER_SIZE);
        header.to_host_order();
        
        if (header.magic != MAGIC_BYTE) return false;
        if (header.version != PROTOCOL_VERSION) return false;
        if (header.payload_length > MAX_PAYLOAD_SIZE) return false;
        if (len < HEADER_SIZE + header.payload_length) return false;
        
        out.header_ = header;
        out.header_.payload_length = header.payload_length;
        
        if (header.payload_length > 0) {
            out.payload_.assign(
                data + HEADER_SIZE,
                data + HEADER_SIZE + header.payload_length
            );
        } else {
            out.payload_.clear();
        }
        
        return true;
    }
    
    const PacketHeader& header() const { return header_; }
    PacketHeader& header() { return header_; }
    const std::vector<uint8_t>& payload() const { return payload_; }
    std::vector<uint8_t>& payload() { return payload_; }
    
    PacketType type() const { return static_cast<PacketType>(header_.type); }
    uint16_t source_id() const { return header_.source_id; }
    uint32_t sequence() const { return header_.sequence; }
    uint8_t flags() const { return header_.flags; }
    
    bool has_flag(PacketFlag flag) const { return (header_.flags & flag) != 0; }
    void set_flag(PacketFlag flag) { header_.flags |= flag; }
    void clear_flag(PacketFlag flag) { header_.flags &= ~flag; }
    
    size_t total_size() const { return HEADER_SIZE + payload_.size(); }

private:
    PacketHeader header_{};
    std::vector<uint8_t> payload_;
    
    static inline uint32_t next_sequence_ = 0;
};

struct MessagePayload {
    uint16_t dest_id;
    std::string username;
    std::string message;
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;
        buffer.reserve(2 + 1 + username.size() + message.size());
        
        uint16_t net_dest = htons(dest_id);
        buffer.push_back(static_cast<uint8_t>(net_dest >> 8));
        buffer.push_back(static_cast<uint8_t>(net_dest & 0xFF));
        
        buffer.push_back(static_cast<uint8_t>(username.size()));
        buffer.insert(buffer.end(), username.begin(), username.end());
        buffer.insert(buffer.end(), message.begin(), message.end());
        
        return buffer;
    }
    
    static bool deserialize(const uint8_t* data, size_t len, MessagePayload& out) {
        if (len < 3) return false;
        
        out.dest_id = ntohs(*reinterpret_cast<const uint16_t*>(data));
        uint8_t username_len = data[2];
        
        if (len < 3 + username_len) return false;
        
        out.username.assign(reinterpret_cast<const char*>(data + 3), username_len);
        out.message.assign(
            reinterpret_cast<const char*>(data + 3 + username_len),
            len - 3 - username_len
        );
        
        return true;
    }
};

}  // namespace gossip

#endif  // GOSSIP_PACKET_H
