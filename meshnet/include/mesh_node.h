#ifndef GOSSIP_MESH_NODE_H
#define GOSSIP_MESH_NODE_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <queue>

#include "packet.h"
#include "connection.h"
#include "session.h"
#include "trust_store.h"
#include "identity.h"

namespace gossip {

/*
 * PeerInfo
 * 
 * Tracks metadata about a known peer in the mesh network.
 * Used for routing and discovery state.
 */
struct PeerInfo {
    uint16_t node_id;
    std::string address;
    uint16_t port;
    int64_t last_seen;
    int hop_count;
};

/*
 * MeshEvent
 * 
 * Represents a high-level network event to be consumed by the application layer.
 * These events are queued and polled by the main application thread.
 */
struct MeshEvent {
    enum class Type {
        PEER_CONNECTED,
        PEER_DISCONNECTED,
        MESSAGE_RECEIVED,
        MESSAGE_ACK,
        ERROR
    };
    
    Type type = Type::ERROR;
    uint16_t peer_id = 0;
    std::string username;
    std::vector<uint8_t> data;
    int error_code = 0;
};

/*
 * MeshNode
 * 
 * The central controller for the P2P node.
 * Integrates:
 * - UDP Discovery: Finds peers on LAN
 * - TCP Connection Manager: Maintains reliable links
 * - Routing Logic: Forwards packets through the mesh
 * - Event System: Queues events for the application
 */
class MeshNode {
public:
    using EventCallback = std::function<void(const MeshEvent&)>;

    explicit MeshNode(uint16_t node_id);
    ~MeshNode();

    MeshNode(const MeshNode&) = delete;
    MeshNode& operator=(const MeshNode&) = delete;

    bool start(uint16_t listen_port, uint16_t discovery_port);
    void stop();
    
    bool send_message(uint16_t dest_id, const std::string& username, 
                      const std::string& message, bool require_ack = false);
    bool broadcast_message(const std::string& username, const std::string& message);
    
    bool connect_to_peer(const std::string& addr, uint16_t port);
    void discover_peers();
    
    void set_event_callback(EventCallback cb) { event_callback_ = std::move(cb); }
    
    /*
     * Sets the global cryptographic session key (PSK mode - deprecated).
     */
    void set_session(std::shared_ptr<Session> session);
    
    /*
     * Sets the node's Ed25519 identity for v1.0 handshake.
     * When identity is set, session keys are derived per-connection
     * using ephemeral X25519 Diffie-Hellman.
     */
    void set_identity(const uint8_t* public_key, const uint8_t* secret_key);
    
    /*
     * Returns the node's public key (if identity is set).
     */
    const uint8_t* public_key() const { return identity_public_key_; }
    
    /*
     * Checks if this node has an identity configured.
     */
    bool has_identity() const { return has_identity_; }
    
    uint16_t node_id() const { return node_id_; }
    std::vector<PeerInfo> get_peers() const;
    bool is_running() const { return running_.load(); }
    
    void poll_events(int timeout_ms);

private:
    uint16_t node_id_;
    uint16_t listen_port_;
    uint16_t discovery_port_;
    std::atomic<bool> running_;
    
    std::mutex events_mutex_;
    std::queue<MeshEvent> events_;
    
    std::unique_ptr<ConnectionManager> conn_manager_;
    std::shared_ptr<Session> session_;  /* deprecated: global PSK session */
    
    /*
     * Ed25519 identity (public key = NodeID, secret key = 64 bytes)
     */
    bool has_identity_ = false;
    uint8_t identity_public_key_[32];
    uint8_t identity_secret_key_[64];
    
    std::unique_ptr<Identity> identity_;
    std::unique_ptr<TrustStore> trust_store_;
    
    mutable std::mutex peers_mutex_;
    std::unordered_map<uint16_t, PeerInfo> peers_;
    

    
    EventCallback event_callback_;
    
    int discovery_socket_;
    std::unordered_set<uint32_t> seen_sequences_;
    std::mutex seen_mutex_;
    
    std::mutex pending_mutex_;
    std::unordered_map<int, std::shared_ptr<Connection>> pending_connections_;
    
    void handle_packet(std::shared_ptr<Connection> conn, const Packet& packet);
    void handle_discovery();
    Packet create_announce_packet() const;
    void send_announce(const std::string& to_addr, uint16_t to_port);
    void forward_packet(const Packet& packet, uint16_t exclude_peer);
    
    void push_event(MeshEvent event);
    bool is_duplicate(uint16_t source_id, uint32_t sequence);
    void cleanup_old_sequences();
};

}  // namespace gossip

#endif  // GOSSIP_MESH_NODE_H
