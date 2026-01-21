#include "mesh_node.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <iostream>

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
bool MeshNode::start(uint16_t listen_port, uint16_t discovery_port) {
    listen_port_ = listen_port;
    discovery_port_ = discovery_port;
    
    conn_manager_ = std::make_unique<ConnectionManager>(listen_port);
    
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
        
        // Send our ANNOUNCE to the new connection
        Packet announce(PacketType::ANNOUNCE, node_id_);
        std::vector<uint8_t> payload;
        // Manual Big Endian serialization
        payload.push_back(static_cast<uint8_t>((listen_port_ >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(listen_port_ & 0xFF));
        announce.set_payload(payload);
        conn->send(announce);
    });

    if (!conn_manager_->start()) {
        std::cerr << "[ERROR] ConnectionManager failed to start" << std::endl;
        return false;
    }
    
    discovery_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (discovery_socket_ < 0) {
        std::cerr << "[ERROR] Failed to create discovery socket: " << strerror(errno) << std::endl;
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
        std::cerr << "[ERROR] Failed to bind discovery socket to port " << discovery_port << ": " << strerror(errno) << std::endl;
        ::close(discovery_socket_);
        discovery_socket_ = -1;
        conn_manager_->stop();
        return false;
    }
    
    running_ = true;
    std::cout << "[DEBUG] MeshNode started. Discovery on port " << discovery_port << std::endl;
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
        std::cout << "[DEBUG] Message too long" << std::endl;
        return false;
    }
    
    std::cout << "[DEBUG] Sending message to node " << dest_id << std::endl;

    Packet packet(PacketType::MESSAGE, node_id_);
    
    if (require_ack) {
        packet.set_flag(FLAG_REQUIRE_ACK);
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
    std::cout << "[DEBUG] Send result: " << (result ? "Success" : "Failed") << std::endl;
    return result;
}

bool MeshNode::broadcast_message(const std::string& username, const std::string& message) {
    if (!running_) return false;
    if (message.size() > MAX_MESSAGE_LENGTH) {
        std::cout << "[DEBUG] Message too long" << std::endl;
        return false;
    }

    std::cout << "[DEBUG] Broadcasting message" << std::endl;
    
    Packet packet(PacketType::MESSAGE, node_id_, FLAG_BROADCAST);
    
    MessagePayload payload;
    payload.dest_id = 0;  // Broadcast
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
    std::cout << "[DEBUG] Connecting to peer " << addr << ":" << port << std::endl;
    
    auto conn = conn_manager_->connect_to(addr, port);
    if (!conn) {
        std::cout << "[DEBUG] Connection failed" << std::endl;
        return false;
    }
    
    // Store in pending until we get their ANNOUNCE
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_connections_[conn->socket_fd()] = conn;
    }
    
    // Set up callbacks
    conn->set_packet_callback([this, conn](const Packet& packet) {
        handle_packet(conn, packet);
    });
    
    conn->set_disconnect_callback([this, conn]() {
        MeshEvent event;
        event.type = MeshEvent::Type::PEER_DISCONNECTED;
        event.peer_id = conn->node_id();
        push_event(std::move(event));
    });
    
    // Send our ANNOUNCE
    Packet announce(PacketType::ANNOUNCE, node_id_);
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>((listen_port_ >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(listen_port_ & 0xFF));
    announce.set_payload(payload);
    
    conn->send(announce);
    
    return true;
}

/*
 * Implementation: discover_peers
 * 
 * Broadcasts a UDP DISCOVER packet to the local network.
 * Peers receiving this will respond with their info.
 */
void MeshNode::discover_peers() {
    if (!running_ || discovery_socket_ < 0) return;
    std::cout << "[DEBUG] Broadcasting discovery packet" << std::endl;
    
    Packet discover(PacketType::DISCOVER, node_id_);
    
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>((listen_port_ >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(listen_port_ & 0xFF));
    discover.set_payload(payload);
    
    auto data = discover.serialize();
    
    sockaddr_in broadcast_addr{};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
    broadcast_addr.sin_port = htons(discovery_port_);
    
    sendto(discovery_socket_, data.data(), data.size(), 0,
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
    // std::cout << "[DEBUG] Got packet Type=" << (int)packet.type() << " from " << from_id << std::endl;
    
    switch (packet.type()) {
        case PacketType::PING: {
            Packet pong(PacketType::PONG, node_id_);
            conn->send(pong);
            break;
        }
        
        case PacketType::PONG: {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = peers_.find(from_id);
            if (it != peers_.end()) {
                it->second.last_seen = current_time_ms();
            }
            break;
        }
        
        case PacketType::ANNOUNCE: {
            std::cout << "[DEBUG] Received ANNOUNCE from " << from_id << std::endl;
            if (packet.payload().size() >= 2) {
                // Manual Big Endian deserialization
                const uint8_t* data = packet.payload().data();
                uint16_t peer_port = (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
                
                // Register this connection with the node ID
                conn->set_node_id(from_id);
                conn_manager_->register_connection(from_id, conn);
                
                // Remove from pending if it was there
                {
                    std::lock_guard<std::mutex> lock(pending_mutex_);
                    pending_connections_.erase(conn->socket_fd());
                }
                
                PeerInfo info;
                info.node_id = from_id;
                info.address = conn->peer_addr();
                info.port = peer_port;
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
            }
            break;
        }
        
        case PacketType::MESSAGE: {
            std::cout << "[DEBUG] Received MESSAGE from " << from_id << std::endl;
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
                    
                    if (packet.has_flag(FLAG_REQUIRE_ACK)) {
                        Packet ack(PacketType::MESSAGE_ACK, node_id_);
                        std::vector<uint8_t> ack_payload;
                        uint32_t net_seq = htonl(packet.sequence());
                        ack_payload.resize(4);
                        std::memcpy(ack_payload.data(), &net_seq, 4);
                        ack.set_payload(ack_payload);
                        conn->send(ack);
                    }
                }
                
                if (packet.has_flag(FLAG_BROADCAST) && msg.dest_id == 0) {
                    forward_packet(packet, from_id);
                }
            }
            break;
        }
        
        case PacketType::MESSAGE_ACK: {
            MeshEvent event;
            event.type = MeshEvent::Type::MESSAGE_ACK;
            event.peer_id = from_id;
            push_event(std::move(event));
            break;
        }
        
        case PacketType::FORWARD: {
            Packet inner;
            if (Packet::deserialize(packet.payload().data(), packet.payload().size(), inner)) {
                handle_packet(conn, inner);
            }
            break;
        }
        
        default:
            break;
    }
}

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
        
        Packet packet;
        if (!Packet::deserialize(buffer, n, packet)) {
            continue;
        }
        
        if (packet.source_id() == node_id_) {
            continue;
        }
        
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, addr_str, sizeof(addr_str));
        
        if (packet.type() == PacketType::DISCOVER) {
            std::cout << "[DEBUG] Got DISCOVER from " << packet.source_id() << " at " << addr_str << std::endl;
            send_announce(addr_str, ntohs(sender_addr.sin_port));
            
            if (packet.payload().size() >= 2) {
                const uint8_t* data = packet.payload().data();
                uint16_t peer_port = (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
                
                // Tie-breaker: only connect if our node_id > their node_id
                // This prevents BOTH nodes from connecting to each other simultaneously
                if (node_id_ > packet.source_id()) {
                    connect_to_peer(addr_str, peer_port);
                }
            }
        } else if (packet.type() == PacketType::ANNOUNCE) {
            std::cout << "[DEBUG] Got UDP ANNOUNCE from " << packet.source_id() << " at " << addr_str << std::endl;
            if (packet.payload().size() >= 2) {
                const uint8_t* data = packet.payload().data();
                uint16_t peer_port = (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
                
                std::lock_guard<std::mutex> lock(peers_mutex_);
                if (peers_.find(packet.source_id()) == peers_.end()) {
                    PeerInfo info;
                    info.node_id = packet.source_id();
                    info.address = addr_str;
                    info.port = peer_port;
                    info.last_seen = current_time_ms();
                    info.hop_count = 1;
                    peers_[info.node_id] = info;
                    
                    MeshEvent event;
                    event.type = MeshEvent::Type::PEER_CONNECTED;
                    event.peer_id = info.node_id;
                    push_event(std::move(event));
                }
            }
        }
    }
}

void MeshNode::send_announce(const std::string& to_addr, uint16_t to_port) {
    if (discovery_socket_ < 0) return;
    
    Packet announce(PacketType::ANNOUNCE, node_id_);
    
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>((listen_port_ >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(listen_port_ & 0xFF));
    announce.set_payload(payload);
    
    auto data = announce.serialize();
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, to_addr.c_str(), &addr.sin_addr);
    addr.sin_port = htons(to_port);
    
    sendto(discovery_socket_, data.data(), data.size(), 0,
           reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
}

void MeshNode::forward_packet(const Packet& packet, uint16_t exclude_peer) {
    Packet forward(PacketType::FORWARD, node_id_);
    auto serialized = packet.serialize();
    forward.set_payload(serialized);
    
    // Broadcast to all peers except the one we got it from
    conn_manager_->broadcast(forward, exclude_peer);
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
