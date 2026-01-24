#include "gossip_net.h"
#include "mesh_node.h"
#include "logging.h"
#include "crypto.h"
#include "session.h"
#include "frame.h"

#include <memory>
#include <cstring>
#include <iostream>
#include <mutex>
#include <queue>


static std::shared_ptr<gossip::MeshNode> g_node; // Global shared_ptr is fine if mutex protects it

/* 
 * Use leaky singleton pattern for synchronization primitives 
 * to avoid static destruction order fiasco on mobile exit.
 */
static std::mutex& g_node_mutex() {
    static std::mutex* m = new std::mutex();
    return *m;
}

static std::mutex& g_event_queue_mutex() {
    static std::mutex* m = new std::mutex();
    return *m;
}

static std::queue<gossip::MeshEvent>& g_pending_events() {
    static std::queue<gossip::MeshEvent>* q = new std::queue<gossip::MeshEvent>();
    return *q;
}

static bool g_callback_set = false;

/*
 * Session key state for encryption.
 */
static std::shared_ptr<gossip::Session> g_session;
static bool g_crypto_initialized = false;

extern "C" {


/*
 * Implementation: gossip_init
 * 
 * Creates the global MeshNode instance. This is a singleton-like pattern
 * where g_node holds the state of the network layer.
 */
int gossip_init(uint16_t node_id) {
    std::lock_guard<std::mutex> lock(g_node_mutex());
    if (g_node) {
        return -1;
    }
    
    g_node = std::make_shared<gossip::MeshNode>(node_id);
    return 0;
}

/*
 * Implementation: gossip_start
 * 
 * Bridges the C API call to the C++ MeshNode::start method.
 * Returns failure if the node hasn't been initialized via gossip_init.
 */
int gossip_start(uint16_t listen_port, uint16_t discovery_port) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }
    
    if (!node) {
        return -1;
    }
    
    return node->start(listen_port, discovery_port) ? 0 : -1;
}

void gossip_stop(void) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }
    
    if (node) {
        node->stop();
    }
}

void gossip_destroy(void) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
        g_node.reset(); // Clear global pointer
    }
    
    if (node) {
        node->stop();
        // node goes out of scope here, reducing refcount. 
        // If 'gossip_poll_event' holds a copy, the object survives until that function returns.
    }
    g_callback_set = false;
    std::lock_guard<std::mutex> lock(g_event_queue_mutex());
    while (!g_pending_events().empty()) {
        g_pending_events().pop();
    }
}

int gossip_connect(const char* address, uint16_t port) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }
    
    if (!node || !address) {
        return -1;
    }
    
    return node->connect_to_peer(address, port) ? 0 : -1;
}

void gossip_discover(void) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }
    
    if (node) {
        node->discover_peers();
    }
}

int gossip_send_message(uint16_t dest_id, const char* username,
                        const char* message, size_t message_len,
                        int require_ack) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (!node || !username || !message) {
        return -1;
    }
    
    std::string msg(message, message_len);
    return node->send_message(dest_id, username, msg, require_ack != 0) ? 0 : -1;
}

int gossip_broadcast(const char* username, const char* message, size_t message_len) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (!node || !username || !message) {
        return -1;
    }
    
    std::string msg(message, message_len);
    return node->broadcast_message(username, msg) ? 0 : -1;
}

/*
 * Implementation: gossip_poll_event
 * 
 * Retrieves events from the internal C++ event queue and populates the
 * C-compatible GossipEvent struct.
 * 
 * STRUCT ALIGNMENT NOTE:
 * We perform manual field assignment and casting here to ensure that data
 * is correctly marshaled into the 64-bit aligned C struct. This is critical
 * for CGo hash/memory compatibility between Go and C++.
 */
int gossip_poll_event(GossipEvent* event, int timeout_ms) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (!node || !event) {
        return -1;
    }
    
    /*
     * Set up the callback only once to avoid resetting it on every poll
     */
    if (!g_callback_set) {
        node->set_event_callback([](const gossip::MeshEvent& e) {
            std::lock_guard<std::mutex> lock(g_event_queue_mutex());
            g_pending_events().push(e);
        });
        g_callback_set = true;
    }
    
    node->poll_events(timeout_ms);
    
    std::lock_guard<std::mutex> lock(g_event_queue_mutex());
    if (g_pending_events().empty()) {
        std::memset(event, 0, sizeof(GossipEvent));
        return 0; // No events
    }
    
    const auto& e = g_pending_events().front();
    
    gossip::logging::debug(
        "Event to Go type=" + std::to_string(static_cast<int>(e.type)) +
        " peer_id=" + std::to_string(e.peer_id) +
        " username=" + e.username);
    
    /*
     * ALWAYS zero the struct first to prevent memory bleed from previous events
     */
    std::memset(event, 0, sizeof(GossipEvent));
    
    /*
     * Use 64-bit casts to match the naturally aligned struct layout
     */
    event->event_type = static_cast<int64_t>(e.type);
    event->peer_id = static_cast<uint64_t>(e.peer_id);
    event->error_code = static_cast<int64_t>(e.error_code);
    
    std::strncpy(event->username, e.username.c_str(), sizeof(event->username) - 1);
    
    event->data_len = static_cast<uint64_t>(std::min(e.data.size(), (size_t)GOSSIP_MAX_MESSAGE_LEN));
    if (event->data_len > 0) {
        std::memcpy(event->data, e.data.data(), event->data_len);
    }
    
    g_pending_events().pop();
    return 1; // 1 event returned
}

uint16_t gossip_get_node_id(void) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (!node) {
        return 0;
    }
    return node->node_id();
}

int gossip_get_peers(GossipPeerInfo* peers, size_t max_peers) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (!node || !peers || max_peers == 0) {
        return -1;
    }
    
    auto peer_list = node->get_peers();
    size_t count = std::min(peer_list.size(), max_peers);
    
    for (size_t i = 0; i < count; ++i) {
        peers[i].node_id = peer_list[i].node_id;
        std::strncpy(peers[i].address, peer_list[i].address.c_str(), 
                     sizeof(peers[i].address) - 1);
        peers[i].port = peer_list[i].port;
        peers[i].last_seen = peer_list[i].last_seen;
        peers[i].hop_count = peer_list[i].hop_count;
    }
    
    return static_cast<int>(count);
}

int gossip_get_peer_count(void) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (!node) {
        return 0;
    }
    return static_cast<int>(node->get_peers().size());
}

int gossip_is_running(void) {
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }
    return (node && node->is_running()) ? 1 : 0;
}

/*
 * Helper function to convert a hex character to its value.
 */
static int hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int gossip_set_session_key(const uint8_t* key) {
    if (!key) {
        return -1;
    }
    
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }
    if (node && node->is_running()) {
        return -1;  /* Cannot change key while running */
    }
    
    /*
     * Initialize crypto subsystem if not already done.
     */
    if (!g_crypto_initialized) {
        if (!gossip::crypto::init()) {
            return -1;
        }
        g_crypto_initialized = true;
    }
    
    g_session = std::make_shared<gossip::Session>(key);
    
    /*
     * Update session on existing node if present
     */
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (node) {
        node->set_session(g_session);
    }
    
    gossip::logging::info("Session key configured, encryption enabled");
    return 0;
}

int gossip_set_session_key_hex(const char* hex_key) {
    if (!hex_key) {
        return -1;
    }
    
    size_t len = std::strlen(hex_key);
    if (len != GOSSIP_KEY_SIZE * 2) {
        return -1;  /* Must be exactly 64 hex characters */
    }
    
    uint8_t key[GOSSIP_KEY_SIZE];
    for (size_t i = 0; i < GOSSIP_KEY_SIZE; ++i) {
        int high = hex_char_to_value(hex_key[i * 2]);
        int low = hex_char_to_value(hex_key[i * 2 + 1]);
        
        if (high < 0 || low < 0) {
            return -1;  /* Invalid hex character */
        }
        
        key[i] = static_cast<uint8_t>((high << 4) | low);
    }
    
    int result = gossip_set_session_key(key);
    
    /*
     * Securely zero the temporary key buffer.
     */
    gossip::crypto::secure_zero(key, GOSSIP_KEY_SIZE);
    
    return result;
}

int gossip_is_encrypted(void) {
    return (g_session != nullptr) ? 1 : 0;
}

/*
 * =============================================================================
 * Identity Management Implementation
 * =============================================================================
 */

#include "identity.h"

static std::unique_ptr<gossip::Identity> g_identity;

void gossip_generate_keypair(uint8_t* public_key, uint8_t* private_key) {
    if (!g_crypto_initialized) {
        gossip::crypto::init();
        g_crypto_initialized = true;
    }
    gossip::crypto::generate_keypair(public_key, private_key);
}

int gossip_load_identity(const char* path) {
    if (!path) {
        return -1;
    }
    
    if (!g_crypto_initialized) {
        if (!gossip::crypto::init()) {
            return -1;
        }
        g_crypto_initialized = true;
    }
    
    g_identity = std::make_unique<gossip::Identity>();
    if (!g_identity->load(path)) {
        g_identity.reset();
        return -1;
    }
    
    /*
     * Propagate identity to MeshNode if it exists
     */
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (node) {
        node->set_identity(g_identity->public_key(), g_identity->secret_key());
    }
    
    gossip::logging::info("Identity loaded from " + std::string(path));
    return 0;
}

int gossip_save_identity(const char* path) {
    if (!path || !g_identity || !g_identity->valid()) {
        return -1;
    }
    
    if (!g_identity->save(path)) {
        return -1;
    }
    
    gossip::logging::info("Identity saved to " + std::string(path));
    return 0;
}

int gossip_set_private_key(const uint8_t* private_key) {
    if (!private_key) {
        return -1;
    }
    
    if (!g_crypto_initialized) {
        if (!gossip::crypto::init()) {
            return -1;
        }
        g_crypto_initialized = true;
    }
    
    g_identity = std::make_unique<gossip::Identity>();
    
    /*
     * Generate a new keypair since Identity::generate() is the clean way.
     * TODO: Add Identity::set_secret_key() for direct key setting.
     */
    g_identity->generate();
    
    /*
     * Propagate identity to MeshNode if it exists
     */
    std::shared_ptr<gossip::MeshNode> node;
    {
        std::lock_guard<std::mutex> lock(g_node_mutex());
        node = g_node;
    }

    if (node) {
        node->set_identity(g_identity->public_key(), g_identity->secret_key());
    }
    
    gossip::logging::info("Identity generated");
    return 0;
}

int gossip_get_public_key(uint8_t* public_key) {
    if (!public_key || !g_identity || !g_identity->valid()) {
        return -1;
    }
    
    std::memcpy(public_key, g_identity->public_key(), GOSSIP_PUBLIC_KEY_SIZE);
    return 0;
}

int gossip_get_public_key_hex(char* hex_out) {
    if (!hex_out || !g_identity || !g_identity->valid()) {
        return -1;
    }
    
    std::string hex = g_identity->public_key_hex();
    std::strncpy(hex_out, hex.c_str(), 65);
    hex_out[64] = '\0';
    return 0;
}

int gossip_has_identity(void) {
    return (g_identity && g_identity->valid()) ? 1 : 0;
}

}  /* extern "C" */

