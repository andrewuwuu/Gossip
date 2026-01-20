#include "gossip_net.h"
#include "mesh_node.h"

#include <memory>
#include <cstring>
#include <iostream>

static std::unique_ptr<gossip::MeshNode> g_node;

extern "C" {

/*
 * Implementation: gossip_init
 * 
 * Creates the global MeshNode instance. This is a singleton-like pattern
 * where g_node holds the state of the network layer.
 */
int gossip_init(uint16_t node_id) {
    if (g_node) {
        return -1;
    }
    
    g_node = std::make_unique<gossip::MeshNode>(node_id);
    return 0;
}

/*
 * Implementation: gossip_start
 * 
 * Bridges the C API call to the C++ MeshNode::start method.
 * Returns failure if the node hasn't been initialized via gossip_init.
 */
int gossip_start(uint16_t listen_port, uint16_t discovery_port) {
    if (!g_node) {
        return -1;
    }
    
    return g_node->start(listen_port, discovery_port) ? 0 : -1;
}

void gossip_stop(void) {
    if (g_node) {
        g_node->stop();
    }
}

void gossip_destroy(void) {
    if (g_node) {
        g_node->stop();
        g_node.reset();
    }
}

int gossip_connect(const char* address, uint16_t port) {
    if (!g_node || !address) {
        return -1;
    }
    
    return g_node->connect_to_peer(address, port) ? 0 : -1;
}

void gossip_discover(void) {
    if (g_node) {
        g_node->discover_peers();
    }
}

int gossip_send_message(uint16_t dest_id, const char* username,
                        const char* message, size_t message_len,
                        int require_ack) {
    if (!g_node || !username || !message) {
        return -1;
    }
    
    std::string msg(message, message_len);
    return g_node->send_message(dest_id, username, msg, require_ack != 0) ? 0 : -1;
}

int gossip_broadcast(const char* username, const char* message, size_t message_len) {
    if (!g_node || !username || !message) {
        return -1;
    }
    
    std::string msg(message, message_len);
    return g_node->broadcast_message(username, msg) ? 0 : -1;
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
    if (!g_node || !event) {
        return -1;
    }
    
    static std::queue<gossip::MeshEvent> pending_events;
    
    // Set up the callback to capture events from the MeshNode
    g_node->set_event_callback([&](const gossip::MeshEvent& e) {
        pending_events.push(e);
    });
    
    g_node->poll_events(timeout_ms);
    
    if (pending_events.empty()) {
        std::memset(event, 0, sizeof(GossipEvent));
        return 0; // No events
    }
    
    const auto& e = pending_events.front();
    
    // DEBUG: Log every event being returned to Go
    std::cout << "[DEBUG] Event to Go: type=" << static_cast<int>(e.type) 
              << " peer_id=" << e.peer_id 
              << " username=" << e.username << std::endl;
    
    // ALWAYS zero the struct first to prevent memory bleed from previous events
    std::memset(event, 0, sizeof(GossipEvent));
    
    // Use 64-bit casts to match the naturally aligned struct layout
    event->event_type = static_cast<int64_t>(e.type);
    event->peer_id = static_cast<uint64_t>(e.peer_id);
    event->error_code = static_cast<int64_t>(e.error_code);
    
    std::strncpy(event->username, e.username.c_str(), sizeof(event->username) - 1);
    
    event->data_len = static_cast<uint64_t>(std::min(e.data.size(), (size_t)GOSSIP_MAX_MESSAGE_LEN));
    if (event->data_len > 0) {
        std::memcpy(event->data, e.data.data(), event->data_len);
    }
    
    pending_events.pop();
    return 1; // 1 event returned
}

uint16_t gossip_get_node_id(void) {
    if (!g_node) {
        return 0;
    }
    return g_node->node_id();
}

int gossip_get_peers(GossipPeerInfo* peers, size_t max_peers) {
    if (!g_node || !peers || max_peers == 0) {
        return -1;
    }
    
    auto peer_list = g_node->get_peers();
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
    if (!g_node) {
        return 0;
    }
    return static_cast<int>(g_node->get_peers().size());
}

int gossip_is_running(void) {
    return (g_node && g_node->is_running()) ? 1 : 0;
}

}  // extern "C"
