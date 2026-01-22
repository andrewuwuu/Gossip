#include "connection.h"
#include "logging.h"

#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <sstream>

namespace gossip {

Connection::Connection(int socket_fd, const std::string& peer_addr, uint16_t peer_port)
    : socket_fd_(socket_fd)
    , peer_addr_(peer_addr)
    , peer_port_(peer_port)
    , state_(State::CONNECTED) {
    recv_buffer_.reserve(HEADER_SIZE + MAX_PAYLOAD_SIZE);
}

Connection::~Connection() {
    close();
}

Connection::Connection(Connection&& other) noexcept
    : socket_fd_(other.socket_fd_)
    , peer_addr_(std::move(other.peer_addr_))
    , peer_port_(other.peer_port_)
    , state_(other.state_.load())
    , recv_buffer_(std::move(other.recv_buffer_))
    , packet_callback_(std::move(other.packet_callback_))
    , disconnect_callback_(std::move(other.disconnect_callback_)) {
    other.socket_fd_ = -1;
    other.state_ = State::DISCONNECTED;
}

Connection& Connection::operator=(Connection&& other) noexcept {
    if (this != &other) {
        close();
        socket_fd_ = other.socket_fd_;
        peer_addr_ = std::move(other.peer_addr_);
        peer_port_ = other.peer_port_;
        state_ = other.state_.load();
        recv_buffer_ = std::move(other.recv_buffer_);
        packet_callback_ = std::move(other.packet_callback_);
        disconnect_callback_ = std::move(other.disconnect_callback_);
        
        other.socket_fd_ = -1;
        other.state_ = State::DISCONNECTED;
    }
    return *this;
}

bool Connection::send(const Packet& packet) {
    /*
     * If encryption is enabled, we wrap the payload in an EncryptedFrame.
     * Note: We copy the packet because we need to modify its payload
     * before serialization.
     */
    /*
     * Encryption Logic:
     * - Skip encryption for ANNOUNCE (key exchange handshake)
     * - Encrypt all other packets if session is active
     */
    if (session_ && packet.type() != PacketType::ANNOUNCE) {
        Packet encrypted_packet = packet;
        std::vector<uint8_t> encrypted_payload;
        
        if (!EncryptedFrame::encrypt(
                *session_,
                packet.payload().data(),
                packet.payload().size(),
                FRAME_FLAG_NONE,
                encrypted_payload)) {
            gossip::logging::error("Encryption failed");
            return false;
        }
        
        encrypted_packet.set_payload(encrypted_payload);
        auto data = encrypted_packet.serialize();
        return send_raw(data.data(), data.size());
    }

    auto data = packet.serialize();
    return send_raw(data.data(), data.size());
}

/*
 * Implementation: send_raw
 * 
 * Writes data to the non-blocking socket.
 * - Handles EAGAIN/EWOULDBLOCK by returning early (retry logic needed by caller? 
 *   Currently returns false, effectively dropping packet if socket full?)
 * - Note: This implementation busy-waits on partial writes unless EAGAIN occurs.
 *   For robust ness, partial writes should be buffered.
 */
bool Connection::send_raw(const uint8_t* data, size_t len) {
    if (state_ != State::CONNECTED || socket_fd_ < 0) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(send_mutex_);
    
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(socket_fd_, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            state_ = State::ERROR;
            return false;
        }
        sent += n;
    }
    
    return true;
}

/*
 * Implementation: process_incoming
 * 
 * Reads raw bytes from the socket into recv_buffer_.
 * - Handles non-blocking reads (loop until EAGAIN)
 * - Detects connection closure (recv == 0) and error states
 * - Triggers try_parse_packet() loop to extract full messages from stream
 */
void Connection::process_incoming() {
    if (state_ != State::CONNECTED || socket_fd_ < 0) {
        return;
    }
    
    uint8_t buffer[4096];
    
    while (true) {
        ssize_t n = ::recv(socket_fd_, buffer, sizeof(buffer), 0);
        
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            gossip::logging::error(std::string("Recv error: ") + strerror(errno));
            state_ = State::ERROR;
            if (disconnect_callback_) {
                disconnect_callback_();
            }
            return;
        }
        
        if (n == 0) {
            gossip::logging::info("Connection closed by peer");
            state_ = State::DISCONNECTED;
            if (disconnect_callback_) {
                disconnect_callback_();
            }
            return;
        }
        
        gossip::logging::debug("Received bytes: " + std::to_string(n));
        recv_buffer_.insert(recv_buffer_.end(), buffer, buffer + n);
        
        while (try_parse_packet()) {
            if (state_ != State::CONNECTED || socket_fd_ < 0) {
                return;
            }
        }
    }
}

bool Connection::try_parse_packet() {
    if (recv_buffer_.size() < HEADER_SIZE) {
        return false;
    }
    
    PacketHeader header;
    std::memcpy(&header, recv_buffer_.data(), HEADER_SIZE);
    
    /*
     * Check Magic Byte first (no endian swap needed for byte)
     */
    if (header.magic != MAGIC_BYTE) {
        std::ostringstream err;
        err << "Invalid magic byte: 0x" << std::hex << static_cast<int>(header.magic);
        gossip::logging::error(err.str());
        // Optimization: Drop 1 byte and retry to resync? Or drop connection?
        // For now, just drop connection as protocol violation
        recv_buffer_.clear(); 
        return false;
    }

    /*
     * Convert to host order to check length
     */
    PacketHeader host_header = header;
    host_header.to_host_order();
    
    size_t total_size = HEADER_SIZE + host_header.payload_length;
    if (recv_buffer_.size() < total_size) {
        /*
         * Wait for more data
         */
        return false;
    }
    
    /*
     * We have a full packet
     */
    std::vector<uint8_t> payload(
        recv_buffer_.begin() + HEADER_SIZE,
        recv_buffer_.begin() + total_size
    );
    
    /*
     * If encryption is enabled, decrypt the payload
     */
    /*
     * If encryption is enabled, decrypt the payload
     * EXCEPTION: ANNOUNCE packets are always plaintext (handshake)
     */
    if (session_ && host_header.type != static_cast<uint8_t>(PacketType::ANNOUNCE)) {
        std::vector<uint8_t> decrypted_payload;
        uint8_t flags_out;
        
        if (!EncryptedFrame::decrypt(
                *session_,
                payload.data(),
                payload.size(),
                decrypted_payload,
                flags_out)) {
            gossip::logging::error("Decryption failed (auth/replay) - dropping connection");
            recv_buffer_.clear(); // Drop connection
            state_ = State::ERROR;
            if (disconnect_callback_) disconnect_callback_();
            return false;
        }
        
        payload = std::move(decrypted_payload);
        
        // Note: Packet header payload_length will mismatch now. 
        // We construct Packet with the decrypted payload, which updates the header.
        host_header.payload_length = static_cast<uint16_t>(payload.size());
    }
    
    Packet packet(host_header, payload);
    
    /*
     * Remove from buffer
     */
    recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + total_size);
    
    if (packet_callback_) {
        packet_callback_(packet);
    }
    
    return true;
}

void Connection::close() {
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
    state_ = State::DISCONNECTED;
}

ConnectionManager::ConnectionManager(uint16_t listen_port)
    : listen_port_(listen_port)
    , listen_fd_(-1)
    , epoll_fd_(-1)
    , running_(false) {
}

ConnectionManager::~ConnectionManager() {
    stop();
}

/*
 * Implementation: start
 * 
 * Initializes the listening socket and epoll instance.
 * - Sets non-blocking mode
 * - Binds to the configured port
 * - Registers the listen socket with epoll for incoming connection events
 */
bool ConnectionManager::start() {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        gossip::logging::error(std::string("Failed to create listen socket: ") + strerror(errno));
        return false;
    }
    
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (!set_nonblocking(listen_fd_)) {
        gossip::logging::error(std::string("Failed to set listen socket non-blocking: ") + strerror(errno));
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port_);
    
    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        gossip::logging::error(
            "Failed to bind listen socket to port " + std::to_string(listen_port_) + ": " + strerror(errno));
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    
    if (listen(listen_fd_, 128) < 0) {
        gossip::logging::error(std::string("Failed to listen on socket: ") + strerror(errno));
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        gossip::logging::error(std::string("Failed to create epoll instance: ") + strerror(errno));
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, listen_fd_, &ev) < 0) {
        gossip::logging::error(std::string("Failed to add listen socket to epoll: ") + strerror(errno));
        ::close(listen_fd_);
        ::close(epoll_fd_);
        listen_fd_ = -1;
        epoll_fd_ = -1;
        return false;
    }
    
    running_ = true;
    gossip::logging::info("ConnectionManager started on port " + std::to_string(listen_port_));
    return true;
}

void ConnectionManager::stop() {
    running_ = false;
    
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& [id, conn] : connections_) {
            conn->close();
        }
        connections_.clear();
        fd_to_node_.clear();
    }
    
    if (epoll_fd_ >= 0) {
        ::close(epoll_fd_);
        epoll_fd_ = -1;
    }
    
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
}

void ConnectionManager::set_session(std::shared_ptr<Session> session) {
    session_ = std::move(session);
    
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    for (auto& [id, conn] : connections_) {
        conn->set_session(session_);
    }
    
    for (auto& conn : unregistered_connections_) {
        conn->set_session(session_);
    }
}

std::shared_ptr<Connection> ConnectionManager::connect_to(const std::string& addr, uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return nullptr;
    }
    
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, addr.c_str(), &server_addr.sin_addr) <= 0) {
        ::close(sock);
        return nullptr;
    }
    
    if (connect(sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        ::close(sock);
        return nullptr;
    }
    
    set_nonblocking(sock);
    
    int opt = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    
    auto conn = std::make_shared<Connection>(sock, addr, port);
    if (session_) {
        conn->set_session(session_);
    }
    
    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sock;
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, sock, &ev);
    
    /*
     * Add to unregistered so it gets polled for incoming data
     */
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        unregistered_connections_.push_back(conn);
    }
    
    return conn;
}

void ConnectionManager::disconnect(uint16_t node_id) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(node_id);
    if (it != connections_.end()) {
        int fd = it->second->socket_fd();
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        it->second->close();
        fd_to_node_.erase(fd);
        connections_.erase(it);
    }
}

void ConnectionManager::broadcast(const Packet& packet, uint16_t exclude_node_id) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    for (auto& [id, conn] : connections_) {
        if (id != exclude_node_id) {
            conn->send(packet);
        }
    }
}

void ConnectionManager::register_connection(uint16_t node_id, std::shared_ptr<Connection> conn) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    /*
     * Check if we already have a connection for this node
     */
    if (connections_.count(node_id) > 0) {
        auto existing = connections_[node_id];
        if (existing->state() == Connection::State::CONNECTED) {
            gossip::logging::warn("Already connected to node " + std::to_string(node_id) + ". Closing duplicate.");
            conn->close();
            return;
        } else {
            gossip::logging::info("Replacing dead connection for node " + std::to_string(node_id));
            connections_.erase(node_id);
            if (fd_to_node_.count(existing->socket_fd())) {
                fd_to_node_.erase(existing->socket_fd());
            }
        }
    }
    
    connections_[node_id] = conn;
    fd_to_node_[conn->socket_fd()] = node_id;
    
    /*
     * Remove from unregistered list
     */
    unregistered_connections_.erase(
        std::remove(unregistered_connections_.begin(), unregistered_connections_.end(), conn),
        unregistered_connections_.end()
    );
}

bool ConnectionManager::send_to(uint16_t node_id, const Packet& packet) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(node_id);
    if (it != connections_.end()) {
        return it->second->send(packet);
    }
    return false;
}

/*
 * Implementation: poll
 * 
 * Main event loop driver.
 * - Waits for epoll events (with timeout)
 * - Handles new connections on listen_fd_
 * - Dispatches incoming data events to specific Connection objects
 * - Manages thread-safety when accessing the connections map
 */
void ConnectionManager::poll(int timeout_ms) {
    if (!running_ || epoll_fd_ < 0) {
        return;
    }
    
    epoll_event events[64];
    int nfds = epoll_wait(epoll_fd_, events, 64, timeout_ms);
    
    for (int i = 0; i < nfds; ++i) {
        if (events[i].data.fd == listen_fd_) {
            accept_connections();
        } else {
            std::shared_ptr<Connection> conn_to_process;
            int fd = events[i].data.fd;
            
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                
                // First check registered connections
                auto fd_it = fd_to_node_.find(fd);
                if (fd_it != fd_to_node_.end()) {
                    auto conn_it = connections_.find(fd_it->second);
                    if (conn_it != connections_.end()) {
                        conn_to_process = conn_it->second;
                    }
                } else {
                    /*
                     * Check unregistered connections
                     */
                    for (auto& conn : unregistered_connections_) {
                        if (conn->socket_fd() == fd) {
                            conn_to_process = conn;
                            break;
                        }
                    }
                }
            }
            
            /*
             * Release lock before processing to avoid deadlock
             */
            if (conn_to_process) {
                conn_to_process->process_incoming();
            }
        }
    }
}

size_t ConnectionManager::connection_count() const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    return connections_.size();
}

std::vector<uint16_t> ConnectionManager::get_connected_peers() const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    std::vector<uint16_t> peers;
    peers.reserve(connections_.size());
    for (const auto& [id, _] : connections_) {
        peers.push_back(id);
    }
    return peers;
}

void ConnectionManager::accept_connections() {
    while (true) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(listen_fd_, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            continue;
        }
        
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, addr_str, sizeof(addr_str));
        gossip::logging::info(
            std::string("Accepted connection from ") + addr_str + ":" +
            std::to_string(ntohs(client_addr.sin_port)));

        set_nonblocking(client_fd);
        
        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        
        auto conn = std::make_shared<Connection>(
            client_fd, addr_str, ntohs(client_addr.sin_port)
        );
        
        if (session_) {
            conn->set_session(session_);
        }
        
        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = client_fd;
        epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_fd, &ev);
        
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            unregistered_connections_.push_back(conn);
        }
        
        if (connection_callback_) {
            connection_callback_(conn);
        }
    }
}

bool ConnectionManager::set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

}  // namespace gossip
