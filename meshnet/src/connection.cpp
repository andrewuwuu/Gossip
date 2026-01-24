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

void Connection::start_handshake(const Identity& identity, bool is_initiator) {
    handshake_ = std::make_unique<Handshake>(identity);
    state_ = State::HANDSHAKING;
    handshake_start_ = std::chrono::steady_clock::now();
    
    if (is_initiator) {
        // gossip::logging::debug("Starting handshake as INITIATOR");
        auto hello = handshake_->create_hello(true);
        auto frame = FrameV1::create_hello_frame(hello.data(), hello.size());
        gossip::logging::debug("Sending HELLO frame, size=" + std::to_string(frame.size()));
        send_raw(frame.data(), frame.size());
    } else {
        gossip::logging::debug("Expecting handshake as RESPONDER");
        // We wait for their HELLO
    }
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
    if (session_) {
        Packet encrypted_packet = packet;
        std::vector<uint8_t> encrypted_payload;
        
        if (!EncryptedFrame::encrypt(
                *session_,
                packet.payload().data(),
                packet.payload().size(),
                FRAME_FLAG_NONE,
                encrypted_payload)) {
            gossip::logging::error("Encryption failed");
            close(); /* Close connection on critical encryption failure (e.g. key exhaustion) */
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
    /* Allow sending if Connected or Handshaking */
    if ((state_ != State::CONNECTED && state_ != State::HANDSHAKING) || socket_fd_ < 0) {
        gossip::logging::error("send_raw failed: Not connected (fd=" + std::to_string(socket_fd_) + ")");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(send_mutex_);
    
    size_t sent = 0;
    int loop_count = 0;
    while (sent < len) {
        loop_count++;
        if (loop_count > 1000) {
             gossip::logging::error("send_raw stuck in loop, breaking");
             return false; 
        }

        ssize_t n = ::send(socket_fd_, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // gossip::logging::debug("send_raw EAGAIN");
                continue;
            }
            state_ = State::ERROR;
            gossip::logging::error("Send failed: " + std::string(strerror(errno)));
            return false;
        }
        if (n == 0) {
            gossip::logging::error("Send returned 0 (connection closed?)");
            state_ = State::DISCONNECTED;
            return false;
        }
        sent += n;
        // gossip::logging::debug("send_raw wrote chunk: " + std::to_string(n));
    }
    
    gossip::logging::debug("Sent " + std::to_string(len) + " bytes total");
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
    /*
     * We need at least 2 bytes to distinguish v1.0 (GR) from Legacy (G + Ver).
     */
    if (recv_buffer_.size() < 2) {
        return false;
    }
    
    uint8_t magic0 = recv_buffer_[0];
    uint8_t magic1 = recv_buffer_[1];
    
    /*
     * Protocol v1.0 Detection: Start with "GR" (0x47 0x52)
     */
    /*
     * Protocol v1.0 Detection: Start with "GR" (0x47 0x52)
     */
    if (magic0 == protocol::FRAME_MAGIC_0 && magic1 == protocol::FRAME_MAGIC_1) {
        if (recv_buffer_.size() < protocol::FRAME_HEADER_SIZE) {
            return false;
        }
        
        protocol::FrameHeader header;
        std::memcpy(&header, recv_buffer_.data(), protocol::FRAME_HEADER_SIZE);
        header.to_host_order();
        
        // Sanity check length to avoid huge allocations/waiting
        if (header.length > protocol::FRAME_MAX_PAYLOAD + crypto::TAG_SIZE) {
             gossip::logging::error("Invalid frame length: " + std::to_string(header.length));
             close();
             return false;
        }

        size_t total_size = protocol::FRAME_HEADER_SIZE + header.length;
        if (recv_buffer_.size() < total_size) {
            return false; /* Wait for more data */
        }
        
        /* process full frame */
        if (header.message_type() == protocol::MessageType::HELLO) {
            std::vector<uint8_t> payload;
            if (FrameV1::parse_hello_frame(recv_buffer_.data(), total_size, payload)) {
                if (handshake_ && handshake_->process_hello(payload.data(), payload.size())) {
                    gossip::logging::debug("Received valid HELLO");
                    
                    /* If we are responder (or simultaneous open resolved to responder), send our HELLO now if not sent */
                    if (handshake_->state() == HandshakeState::HELLO_RECEIVED) {
                         /*
                          * If we haven't sent HELLO yet (normal responder case)
                          * create_hello() checks state internally.
                          */
                         auto hello = handshake_->create_hello(false);
                         auto frame = FrameV1::create_hello_frame(hello.data(), hello.size());
                         send_raw(frame.data(), frame.size());
                    }
                    
                    if (handshake_->derive_keys()) {
                        gossip::logging::debug("Keys derived, sending AUTH");
                        
                        auto auth_payload = handshake_->create_auth();
                        std::vector<uint8_t> auth_frame;
                        
                        /* Encrypt AUTH with K_init/K_resp and explicit seq=0 */
                        if (FrameV1::encrypt_with_seq(
                                handshake_->send_key(),
                                protocol::MessageType::AUTH,
                                0, /* Auth is always seq 0 */
                                auth_payload.data(),
                                auth_payload.size(),
                                auth_frame)) {
                            send_raw(auth_frame.data(), auth_frame.size());
                        }
                    }
                } else {
                    gossip::logging::error("Handshake HELLO failed");
                    close();
                    return false;
                }
            }
        } else if (header.message_type() == protocol::MessageType::AUTH) {
            std::vector<uint8_t> decrypted;
            protocol::MessageType type;
            
            /* Use handshake keys to decrypt AUTH */
            if (handshake_ && handshake_->state() == HandshakeState::KEYS_DERIVED) {
                if (FrameV1::decrypt_with_key(
                        handshake_->recv_key(),
                        recv_buffer_.data(),
                        total_size,
                        decrypted,
                        type)) {
                    
                    uint8_t peer_pubkey[crypto::ED25519_PUBLIC_KEY_SIZE];
                    if (handshake_->process_auth(decrypted.data(), decrypted.size(), peer_pubkey)) {
                        /* Check TrustStore if callback set */
                        if (trust_callback_) {
                            if (!trust_callback_(nullptr, peer_pubkey)) {
                                gossip::logging::error("Trust validation failed for peer");
                                close();
                                return false;
                            }
                        }
                        
                        gossip::logging::info("Handshake complete! Authenticated peer.");
                        
                        /* Set Node ID from handshake (First 2 bytes of PubKey is simplistic but matches legacy uint16) */
                        uint16_t peer_id = (static_cast<uint16_t>(peer_pubkey[0]) << 8) | static_cast<uint16_t>(peer_pubkey[1]);
                        node_id_ = peer_id;

                        if (handshake_complete_callback_) {
                            handshake_complete_callback_(peer_id);
                        }
                        
                        /* Create session */
                        session_ = std::make_shared<Session>(
                            handshake_->send_key(),
                            handshake_->recv_key(),
                            handshake_->is_initiator()
                        );
                        state_ = State::CONNECTED;
                        
                        // Set Node ID from handshake? 
                        // Actually NodeID is first 2 bytes of PubKey (IK_pub) in this simplified model?
                        // Or we need to ask TrustStore.
                        // For now, let's just proceed.
                    } else {
                        gossip::logging::error("AUTH verification failed");
                        close();
                        return false;
                    }
                } else {
                    gossip::logging::error("AUTH decryption failed");
                    close();
                    return false;
                }
            }
        } else if (session_) {
            /* Application Data (MSG, PING, etc) */
            std::vector<uint8_t> decrypted;
            protocol::MessageType type;
            uint64_t seq;
            
            if (FrameV1::decrypt(*session_, recv_buffer_.data(), total_size, decrypted, type, seq)) {
                 if (type == protocol::MessageType::MSG) {
                     /* Convert to legacy Packet for callback compatibility */
                     /* MessagePayload format: DestID(2) | Len(1) | User | Msg */
                     
                     Packet packet; 
                     packet.header().magic = MAGIC_BYTE;
                     packet.header().version = PROTOCOL_VERSION;
                     packet.header().type = static_cast<uint8_t>(PacketType::MSG);
                     packet.header().source_id = node_id_; /* We might not know source ID yet? */
                     packet.set_payload(decrypted);
                     
                     if (packet_callback_) packet_callback_(packet);
                 }
            }
        }
        
        recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + total_size);
        return true;
    }

    /*
     * Invalid magic bytes or legacy protocol.
     * We strictly require v1.0 (GR) magic.
     */
    gossip::logging::error("Invalid magic bytes (legacy?): " + std::to_string(magic0) + " " + std::to_string(magic1));
    close();
    return false;
}

void Connection::close() {
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
    state_ = State::DISCONNECTED;
}

bool Connection::check_timeout() {
    if (state_ == State::HANDSHAKING) {
        auto now = std::chrono::steady_clock::now();
        if (now - handshake_start_ > HANDSHAKE_TIMEOUT) {
            gossip::logging::warn("Handshake timed out");
            close();
            return true;
        }
    }
    return false;
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
    ev.events = EPOLLIN; /* Level Triggered for safety */
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
    
    /* Check timeouts for all connections periodically */
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        
        /* Check registered connections */
        for (auto it = connections_.begin(); it != connections_.end();) {
            if (it->second->check_timeout()) {
                gossip::logging::info("Closing timed out connection " + std::to_string(it->first));
                /* Timeout closed the connection, just clean up map */
                fd_to_node_.erase(it->second->socket_fd());
                it = connections_.erase(it);
            } else {
                ++it;
            }
        }
        
        /* Check unregistered connections */
        for (auto it = unregistered_connections_.begin(); it != unregistered_connections_.end();) {
            if ((*it)->check_timeout()) {
                gossip::logging::info("Closing timed out unregistered connection");
                it = unregistered_connections_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
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
        ev.events = EPOLLIN; /* Level Triggered for safety */
        ev.data.fd = client_fd;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            gossip::logging::error("Failed to add client to epoll: " + std::string(strerror(errno)));
            ::close(client_fd);
            continue;
        }
        
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

}  /* namespace gossip */
