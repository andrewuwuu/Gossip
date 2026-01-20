#include "connection.h"

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
    auto data = packet.serialize();
    return send_raw(data.data(), data.size());
}

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
            std::cout << "[DEBUG] Recv error: " << strerror(errno) << std::endl;
            state_ = State::ERROR;
            if (disconnect_callback_) {
                disconnect_callback_();
            }
            return;
        }
        
        if (n == 0) {
            std::cout << "[DEBUG] Connection closed by peer" << std::endl;
            state_ = State::DISCONNECTED;
            if (disconnect_callback_) {
                disconnect_callback_();
            }
            return;
        }
        
        // std::cout << "[DEBUG] Received " << n << " bytes" << std::endl;
        recv_buffer_.insert(recv_buffer_.end(), buffer, buffer + n);
        
        while (try_parse_packet()) {
        }
    }
}

bool Connection::try_parse_packet() {
    if (recv_buffer_.size() < HEADER_SIZE) {
        return false;
    }
    
    Packet packet;
    if (!Packet::deserialize(recv_buffer_.data(), recv_buffer_.size(), packet)) {
        if (recv_buffer_[0] != MAGIC_BYTE) {
            recv_buffer_.erase(recv_buffer_.begin());
            return true;
        }
        return false;
    }
    
    size_t packet_size = packet.total_size();
    recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + packet_size);
    
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

bool ConnectionManager::start() {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::cerr << "[ERROR] Failed to create listen socket: " << strerror(errno) << std::endl;
        return false;
    }
    
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (!set_nonblocking(listen_fd_)) {
        std::cerr << "[ERROR] Failed to set listen socket non-blocking: " << strerror(errno) << std::endl;
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port_);
    
    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[ERROR] Failed to bind listen socket to port " << listen_port_ << ": " << strerror(errno) << std::endl;
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    
    if (listen(listen_fd_, 128) < 0) {
        std::cerr << "[ERROR] Failed to listen on socket: " << strerror(errno) << std::endl;
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        std::cerr << "[ERROR] Failed to create epoll instance: " << strerror(errno) << std::endl;
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, listen_fd_, &ev) < 0) {
        std::cerr << "[ERROR] Failed to add listen socket to epoll: " << strerror(errno) << std::endl;
        ::close(listen_fd_);
        ::close(epoll_fd_);
        listen_fd_ = -1;
        epoll_fd_ = -1;
        return false;
    }
    
    running_ = true;
    std::cout << "[DEBUG] ConnectionManager started on port " << listen_port_ << std::endl;
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
    
    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sock;
    epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, sock, &ev);
    
    // Add to unregistered so it gets polled for incoming data
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

void ConnectionManager::broadcast(const Packet& packet) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    for (auto& [id, conn] : connections_) {
        conn->send(packet);
    }
}

void ConnectionManager::register_connection(uint16_t node_id, std::shared_ptr<Connection> conn) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    connections_[node_id] = conn;
    fd_to_node_[conn->socket_fd()] = node_id;
    
    // Remove from unregistered list
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
            std::lock_guard<std::mutex> lock(connections_mutex_);
            int fd = events[i].data.fd;
            
            // First check registered connections
            auto fd_it = fd_to_node_.find(fd);
            if (fd_it != fd_to_node_.end()) {
                auto conn_it = connections_.find(fd_it->second);
                if (conn_it != connections_.end()) {
                    conn_it->second->process_incoming();
                }
            } else {
                // Check unregistered connections
                for (auto& conn : unregistered_connections_) {
                    if (conn->socket_fd() == fd) {
                        conn->process_incoming();
                        break;
                    }
                }
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
        std::cout << "[DEBUG] Accepted connection from " << addr_str << ":" << ntohs(client_addr.sin_port) << std::endl;

        set_nonblocking(client_fd);
        
        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        
        auto conn = std::make_shared<Connection>(
            client_fd, addr_str, ntohs(client_addr.sin_port)
        );
        
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
