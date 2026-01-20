#ifndef GOSSIP_CONNECTION_H
#define GOSSIP_CONNECTION_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <queue>

#include "packet.h"

namespace gossip {

/*
 * Connection
 * 
 * Represents a single TCP connection to a peer node.
 * Handles non-blocking I/O, packet serialization/deserialization,
 * and maintains the lifecycle of the socket connection.
 * 
 * This class is thread-safe for sending (via mutex), but receving
 * is driven by the single-threaded ConnectionManager event loop.
 */
class Connection {
public:
    enum class State {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        ERROR
    };

    using PacketCallback = std::function<void(const Packet&)>;
    using DisconnectCallback = std::function<void()>;

    Connection(int socket_fd, const std::string& peer_addr, uint16_t peer_port);
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&& other) noexcept;

    /*
     * Queues a packet for sending.
     * Thread-safe.
     * @return true if enqueued/sent successfully, false if connection broken
     */
    bool send(const Packet& packet);

    /*
     * Low-level send method. Handles partial writes and EAGAIN.
     */
    bool send_raw(const uint8_t* data, size_t len);
    
    void set_packet_callback(PacketCallback cb) { packet_callback_ = std::move(cb); }
    void set_disconnect_callback(DisconnectCallback cb) { disconnect_callback_ = std::move(cb); }
    
    /*
     * Reads available data from the socket into the receive buffer
     * and attempts to parse full packets.
     * Called by ConnectionManager when the socket is readable (EPOLLIN).
     */
    void process_incoming();
    
    int socket_fd() const { return socket_fd_; }
    const std::string& peer_addr() const { return peer_addr_; }
    uint16_t peer_port() const { return peer_port_; }
    State state() const { return state_.load(); }
    
    // Node ID (set after ANNOUNCE is received)
    uint16_t node_id() const { return node_id_; }
    void set_node_id(uint16_t id) { node_id_ = id; }
    
    void close();

private:
    int socket_fd_;
    std::string peer_addr_;
    uint16_t peer_port_;
    uint16_t node_id_ = 0;
    std::atomic<State> state_;
    
    std::vector<uint8_t> recv_buffer_;
    std::mutex send_mutex_;
    
    PacketCallback packet_callback_;
    DisconnectCallback disconnect_callback_;
    
    bool try_parse_packet();
};

/*
 * ConnectionManager
 * 
 * Manages the lifecycle of all TCP connections in the mesh.
 * - Uses epoll for high-performance non-blocking I/O redundancy
 * - Accepts incoming connections
 * - Initiates outgoing connections
 * - Routes packets to specific peers
 */
class ConnectionManager {
public:
    explicit ConnectionManager(uint16_t listen_port);
    ~ConnectionManager();

    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;

    bool start();
    void stop();
    
    std::shared_ptr<Connection> connect_to(const std::string& addr, uint16_t port);
    void register_connection(uint16_t node_id, std::shared_ptr<Connection> conn);
    void disconnect(uint16_t node_id);
    void broadcast(const Packet& packet, uint16_t exclude_node_id = 0);
    bool send_to(uint16_t node_id, const Packet& packet);
    
    void set_connection_callback(std::function<void(std::shared_ptr<Connection>)> cb) {
        connection_callback_ = std::move(cb);
    }
    
    void poll(int timeout_ms);
    
    size_t connection_count() const;
    std::vector<uint16_t> get_connected_peers() const;

private:
    uint16_t listen_port_;
    int listen_fd_;
    int epoll_fd_;
    std::atomic<bool> running_;
    
    mutable std::mutex connections_mutex_;
    std::unordered_map<uint16_t, std::shared_ptr<Connection>> connections_;
    std::unordered_map<int, uint16_t> fd_to_node_;
    std::vector<std::shared_ptr<Connection>> unregistered_connections_;
    
    std::function<void(std::shared_ptr<Connection>)> connection_callback_;
    
    void accept_connections();
    bool set_nonblocking(int fd);
};

}  // namespace gossip

#endif  // GOSSIP_CONNECTION_H
