#include "mesh_node.h"
#include "logging.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <iostream>
#include "identity.h"

namespace gossip {

namespace {

int64_t current_time_ms() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();
}

uint32_t make_seq_key(uint16_t source_id, uint32_t sequence) {
    return (static_cast<uint32_t>(source_id) << 16) | (sequence & 0xFFFF);
}

}  // namespace

MeshNode::MeshNode(uint16_t node_id)
    : node_id_(node_id)
    , listen_port_(0)
    , discovery_port_(0)
    , running_(false)
    , discovery_socket_(-1) {
}

MeshNode::~MeshNode() {
    stop();
}

/*
 * Implementation: start
 * 
 * Initializes the MeshNode.
 * 1. Starts the ConnectionManager (TCP)
 * 2. Sets up connection callbacks (packet handling, disconnects)
 * 3. Creates and binds the UDP discovery socket
 */
/*
 * Implementation: set_session
 * 
 * Configures the cryptographic session and propagates it to the ConnectionManager.
 * If called before start(), the session is stored and applied later.
 */
void MeshNode::set_session(std::shared_ptr<Session> session) {
    session_ = std::move(session);
    if (conn_manager_) {
        conn_manager_->set_session(session_);
    }
}

void MeshNode::set_identity(const uint8_t* public_key, const uint8_t* secret_key) {
    if (public_key && secret_key) {
        std::memcpy(identity_public_key_, public_key, 32);
        std::memcpy(identity_secret_key_, secret_key, 64);
        has_identity_ = true;
        
        identity_ = std::make_unique<Identity>();
        identity_->set_from_keys(public_key, secret_key);
        
        trust_store_ = std::make_unique<TrustStore>();
        
        gossip::logging::info("Identity configured for v1.0 handshake");
    }
}

/*
 * Implementation: start
 * 
 * Initializes the MeshNode.
 * 1. Starts the ConnectionManager (TCP)
 * 2. Sets up connection callbacks (packet handling, disconnects)
 * 3. Creates and binds the UDP discovery socket
 */
bool MeshNode::start(uint16_t listen_port, uint16_t discovery_port) {
    listen_port_ = listen_port;
    discovery_port_ = discovery_port;
    
    conn_manager_ = std::make_unique<ConnectionManager>(listen_port);
    
    /*
     * Propagate session key if set
     */
    if (session_) {
        conn_manager_->set_session(session_);
    }
    
    conn_manager_->set_connection_callback([this](std::shared_ptr<Connection> conn) {
        conn->set_packet_callback([this, conn](const Packet& packet) {
            handle_packet(conn, packet);
        });
        
        conn->set_disconnect_callback([this, conn]() {
            MeshEvent event;
            event.type = MeshEvent::Type::PEER_DISCONNECTED;
            event.peer_id = conn->node_id();
            push_event(std::move(event));
        });
        
        /*
         * Start v1.0 Handshake as Responder
         */
        conn->set_trust_callback([this](const uint8_t* node_id, const uint8_t* pubkey) {
            if (trust_store_) {
                return !trust_store_->should_reject(pubkey, pubkey);
            }
            return true;
        });
        
        conn->set_handshake_complete_callback([this, conn](uint16_t peer_id) {
             gossip::logging::info("Handshake complete callback for peer " + std::to_string(peer_id));
             
             conn_manager_->register_connection(peer_id, conn);
             
             PeerInfo info;
             info.node_id = peer_id;
             info.address = conn->peer_addr();
             info.port = conn->peer_port();
             info.last_seen = current_time_ms();
             info.hop_count = 1;
             
             {
                 std::lock_guard<std::mutex> lock(peers_mutex_);
                 peers_[info.node_id] = info;
             }
             
             MeshEvent event;
             event.type = MeshEvent::Type::PEER_CONNECTED;
             event.peer_id = info.node_id;
             push_event(std::move(event));
        });
        
        conn->start_handshake(*identity_, false);
    });

    if (!conn_manager_->start()) {
        gossip::logging::error("ConnectionManager failed to start");
        return false;
    }
    
    discovery_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (discovery_socket_ < 0) {
        gossip::logging::error(std::string("Failed to create discovery socket: ") + strerror(errno));
        conn_manager_->stop();
        return false;
    }
    
    int opt = 1;
    setsockopt(discovery_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(discovery_socket_, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    
    int flags = fcntl(discovery_socket_, F_GETFL, 0);
    fcntl(discovery_socket_, F_SETFL, flags | O_NONBLOCK);
    
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(discovery_port);
    
    if (bind(discovery_socket_, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
        gossip::logging::error(
            "Failed to bind discovery socket to port " + std::to_string(discovery_port) + ": " + strerror(errno));
        ::close(discovery_socket_);
        discovery_socket_ = -1;
        conn_manager_->stop();
        return false;
    }
    
    running_ = true;
    gossip::logging::info("MeshNode started. Discovery on port " + std::to_string(discovery_port));
    return true;
}

void MeshNode::stop() {
    running_ = false;
    
    if (discovery_socket_ >= 0) {
        ::close(discovery_socket_);
        discovery_socket_ = -1;
    }
    
    if (conn_manager_) {
        conn_manager_->stop();
        conn_manager_.reset();
    }
    
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peers_.clear();
}

/*
 * Implementation: send_message
 * 
 * Constructs a MESSAGE packet and sends it to a specific destination.
 * - Serializes payload (dest_id, username, content)
 * - Delegates actual transmission to ConnectionManager
 */
bool MeshNode::send_message(uint16_t dest_id, const std::string& username,
                            const std::string& message, bool require_ack) {
    if (!running_) return false;
    if (message.size() > MAX_MESSAGE_LENGTH) {
        gossip::logging::warn("Message too long");
        return false;
    }
    
    gossip::logging::debug("Sending message to node " + std::to_string(dest_id));

    Packet packet(PacketType::MSG, node_id_);
    
    if (require_ack) {
        // Ack not supported in v1.0 spec table
    }
    
    MessagePayload payload;
    payload.dest_id = dest_id;
    payload.username = username;
    payload.message = message;
    
    auto payload_data = payload.serialize();
    if (!packet.set_payload(payload_data)) {
        return false;
    }
    
    bool result = conn_manager_->send_to(dest_id, packet);
    gossip::logging::debug(std::string("Send result: ") + (result ? "success" : "failed"));
    return result;
}

bool MeshNode::broadcast_message(const std::string& username, const std::string& message) {
    if (!running_) return false;
    if (message.size() > MAX_MESSAGE_LENGTH) {
        gossip::logging::warn("Message too long");
        return false;
    }

    gossip::logging::debug("Broadcasting message");
    
    Packet packet(PacketType::MSG, node_id_, FLAG_BROADCAST);
    
    MessagePayload payload;
    payload.dest_id = 0;  /* Broadcast */
    payload.username = username;
    payload.message = message;
    
    auto payload_data = payload.serialize();
    if (!packet.set_payload(payload_data)) {
        return false;
    }
    
    conn_manager_->broadcast(packet);
    return true;
}

/*
 * Implementation: connect_to_peer
 * 
 * Initiates a TCP connection to a remote peer.
 * - Establishes socket connection
 * - Registers callbacks
 * - Sends immediate ANNOUNCE packet to identify ourselves
 */
bool MeshNode::connect_to_peer(const std::string& addr, uint16_t port) {
    if (!running_) return false;
    gossip::logging::info("Connecting to peer " + addr + ":" + std::to_string(port));
    
    auto conn = conn_manager_->connect_to(addr, port);
    if (!conn) {
        gossip::logging::warn("Connection failed");
        return false;
    }
    
    /*
     * Store in pending until we get their ANNOUNCE
     */
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_connections_[conn->socket_fd()] = conn;
    }
    
    /*
     * Set up callbacks
     */
    conn->set_packet_callback([this, conn](const Packet& packet) {
        handle_packet(conn, packet);
    });
    
    conn->set_disconnect_callback([this, conn]() {
        MeshEvent event;
        event.type = MeshEvent::Type::PEER_DISCONNECTED;
        event.peer_id = conn->node_id();
        push_event(std::move(event));
    });
    
    /*
     * Start v1.0 Handshake as Initiator
     */
    if (identity_) {
        conn->set_trust_callback([this](const uint8_t* node_id, const uint8_t* pubkey) {
            if (trust_store_) {
                return !trust_store_->should_reject(pubkey, pubkey);
            }
            return true;
        });
        
        conn->set_handshake_complete_callback([this, conn](uint16_t peer_id) {
             gossip::logging::info("Handshake complete callback for peer " + std::to_string(peer_id));
             
             {
                 std::lock_guard<std::mutex> lock(pending_mutex_);
                 pending_connections_.erase(conn->socket_fd());
             }
             
             conn_manager_->register_connection(peer_id, conn);
             
             PeerInfo info;
             info.node_id = peer_id;
             info.address = conn->peer_addr();
             info.port = conn->peer_port();
             info.last_seen = current_time_ms();
             info.hop_count = 1;
             
             {
                 std::lock_guard<std::mutex> lock(peers_mutex_);
                 peers_[info.node_id] = info;
             }
             
             MeshEvent event;
             event.type = MeshEvent::Type::PEER_CONNECTED;
             event.peer_id = info.node_id;
             push_event(std::move(event));
        });
        
        conn->start_handshake(*identity_, true);
    }
    
    return true;
}

/*
 * Implementation: discover_peers
 * 
 * Broadcasts a UDP DISCOVER packet to the local network.
 * Peers receiving this will respond with their info.
 */
/*
 * Implementation: discover_peers
 * 
 * Broadcasts a UDP BEACON packet to the local network.
 * Format: [ Magic (2) | Version (1) | IK_pub (32) | Timestamp (8) | Signature (64) ] + [ Port (2) ]
 */
void MeshNode::discover_peers() {
    if (!running_ || discovery_socket_ < 0 || !has_identity_) return;
    
    /* 
     * Beacon framing constants 
     */
    constexpr uint8_t BEACON_MAGIC[2] = {0x47, 0x52}; // "GR"
    constexpr uint8_t BEACON_VERSION = 0x01;
    
    std::vector<uint8_t> beacon;
    beacon.reserve(109); // 2+1+32+8+64+2
    
    // Magic (2)
    beacon.push_back(BEACON_MAGIC[0]);
    beacon.push_back(BEACON_MAGIC[1]);
    
    // Version (1)
    beacon.push_back(BEACON_VERSION);
    
    // IK_pub (32)
    beacon.insert(beacon.end(), identity_public_key_, identity_public_key_ + 32);
    
    // Timestamp (8, Big Endian Seconds)
    uint64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    uint64_t now_be = htobe64(now_sec); // Requires endian.h or manual
    // Portable manual BE encoding for uint64
    for (int i = 7; i >= 0; --i) {
        beacon.push_back(static_cast<uint8_t>((now_sec >> (i * 8)) & 0xFF));
    }
    
    // Signature Input: Magic || Version || IK_pub || Timestamp
    if (identity_) {
        uint8_t signature[64];
        if (identity_->sign(beacon.data(), beacon.size(), signature)) {
            // Append Signature (64)
            beacon.insert(beacon.end(), signature, signature + 64);
        } else {
             gossip::logging::error("Failed to sign discovery beacon");
             return;
        }
    } else {
        return; 
    }
    
    // Append Listen Port (2, Big Endian) - Extension to spec to allow connection
    beacon.push_back(static_cast<uint8_t>((listen_port_ >> 8) & 0xFF));
    beacon.push_back(static_cast<uint8_t>(listen_port_ & 0xFF));
    
    sockaddr_in broadcast_addr{};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
    broadcast_addr.sin_port = htons(discovery_port_);
    
    sendto(discovery_socket_, beacon.data(), beacon.size(), 0,
           reinterpret_cast<sockaddr*>(&broadcast_addr), sizeof(broadcast_addr));
}

std::vector<PeerInfo> MeshNode::get_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::vector<PeerInfo> result;
    result.reserve(peers_.size());
    for (const auto& [id, info] : peers_) {
        result.push_back(info);
    }
    return result;
}

/*
 * Implementation: poll_events
 * 
 * Main driving loop for the MeshNode.
 * 1. Drives ConnectionManager poll
 * 2. Checks for UDP discovery packets
 * 3. Dispatches queued events to the application callback
 */
void MeshNode::poll_events(int timeout_ms) {
    if (!running_) return;
    
    conn_manager_->poll(timeout_ms);
    handle_discovery();
    
    std::lock_guard<std::mutex> lock(events_mutex_);
    while (!events_.empty()) {
        if (event_callback_) {
            event_callback_(events_.front());
        }
        events_.pop();
    }
}

/*
 * Implementation: handle_packet
 * 
 * Core packet processing logic.
 * - Checks for duplicates (deduplication)
 * - Dispatches based on packet type (PING, MESSAGE, ANNOUNCE, etc.)
 * - Handles routing (forwarding broadcast messages)
 */
void MeshNode::handle_packet(std::shared_ptr<Connection> conn, const Packet& packet) {
    if (is_duplicate(packet.source_id(), packet.sequence())) {
        return;
    }
    
    uint16_t from_id = packet.source_id();
    // gossip::logging::debug("Got packet type from " + std::to_string(from_id));
    
    switch (packet.type()) {
       case PacketType::PING: {
            /* 
             * Update last_seen on PING (Heartbeat).
             * v1.0 Spec doesn't define explicit PONG, so we just track liveness.
             */
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = peers_.find(from_id);
            if (it != peers_.end()) {
                it->second.last_seen = current_time_ms();
            }
            break;
        }
        
        case PacketType::MSG: {
            // gossip::logging::debug("Received MSG from " + std::to_string(from_id));
            MessagePayload msg;
            if (MessagePayload::deserialize(
                    packet.payload().data(), packet.payload().size(), msg)) {
                
                if (msg.dest_id == 0 || msg.dest_id == node_id_) {
                    MeshEvent event;
                    event.type = MeshEvent::Type::MESSAGE_RECEIVED;
                    event.peer_id = from_id;
                    event.username = msg.username;
                    event.data.assign(msg.message.begin(), msg.message.end());
                    push_event(std::move(event));
                }
                
                if (packet.has_flag(FLAG_BROADCAST) && msg.dest_id == 0) {
                    forward_packet(packet, from_id);
                }
            }
            break;
        }
        
        default:
            break;
    }
}

/*
 * Implementation: handle_discovery
 * Handles incoming v1.0 UDP Beacons.
 */
void MeshNode::handle_discovery() {
    if (discovery_socket_ < 0) return;
    
    uint8_t buffer[512];
    sockaddr_in sender_addr{};
    socklen_t addr_len = sizeof(sender_addr);
    
    while (true) {
        ssize_t n = recvfrom(discovery_socket_, buffer, sizeof(buffer), 0,
                             reinterpret_cast<sockaddr*>(&sender_addr), &addr_len);
        
        if (n < 0) {
            break;
        }
        
        // Expected size: 109 bytes (107 beacon + 2 port)
        if (n < 109) continue;
        
        // Verify Magic (GR)
        if (buffer[0] != 0x47 || buffer[1] != 0x52) continue;
        
        // Verify Version (1)
        if (buffer[2] != 0x01) continue;
        
        // Extract fields
        const uint8_t* ik_pub = buffer + 3;
        const uint8_t* timestamp_ptr = buffer + 35; // 3 + 32
        const uint8_t* signature = buffer + 43;     // 35 + 8
        const uint8_t* port_ptr = buffer + 107;     // 43 + 64
        
        // Prevent reflection (ignore own beacon)
        if (std::memcmp(ik_pub, identity_public_key_, 32) == 0) continue;
        
        // Verify Timestamp (±60s)
        uint64_t ts = 0;
        for (int i = 0; i < 8; ++i) {
            ts = (ts << 8) | timestamp_ptr[i];
        }
        
        uint64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        int64_t diff = static_cast<int64_t>(now_sec) - static_cast<int64_t>(ts);
        if (std::abs(diff) > 60) {
             // gossip::logging::warn("Rejected beacon: timestamp out of bounds");
             continue;
        }
        
        // Verify Signature
        if (identity_) {
             if (!Identity::verify(ik_pub, buffer, 43, signature)) {
                 gossip::logging::warn("Rejected beacon: invalid signature");
                 continue;
             }
        }
        
        // Extract Port
        uint16_t peer_port = (static_cast<uint16_t>(port_ptr[0]) << 8) | static_cast<uint16_t>(port_ptr[1]);
        
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, addr_str, sizeof(addr_str));
        
        // Connect logic
        if (std::memcmp(identity_public_key_, ik_pub, 32) > 0) {
             connect_to_peer(addr_str, peer_port);
        }
    }
}



void MeshNode::forward_packet(const Packet& packet, uint16_t exclude_peer) {
    // Directly broadcast the packet to all other peers
    conn_manager_->broadcast(packet, exclude_peer);
}

void MeshNode::push_event(MeshEvent event) {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.push(std::move(event));
}

bool MeshNode::is_duplicate(uint16_t source_id, uint32_t sequence) {
    uint32_t key = make_seq_key(source_id, sequence);
    
    std::lock_guard<std::mutex> lock(seen_mutex_);
    if (seen_sequences_.count(key) > 0) {
        return true;
    }
    
    seen_sequences_.insert(key);
    
    if (seen_sequences_.size() > 10000) {
        cleanup_old_sequences();
    }
    
    return false;
}

void MeshNode::cleanup_old_sequences() {
    if (seen_sequences_.size() > 5000) {
        auto it = seen_sequences_.begin();
        std::advance(it, seen_sequences_.size() / 2);
        seen_sequences_.erase(seen_sequences_.begin(), it);
    }
}



}  // namespace gossip
