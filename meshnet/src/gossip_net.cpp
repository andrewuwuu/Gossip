#include "gossip_net.h"
#include "mesh_node.h"

#include <memory>
#include <cstring>

static std::unique_ptr<gossip::MeshNode> g_node;

extern "C" {

int gossip_init(uint16_t node_id) {
    if (g_node) {
        return -1;
    }
    
    g_node = std::make_unique<gossip::MeshNode>(node_id);
    return 0;
}

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

int gossip_poll_event(GossipEvent* event, int timeout_ms) {
    if (!g_node || !event) {
        return -1;
    }
    
    static std::queue<gossip::MeshEvent> pending_events;
    
    if (pending_events.empty()) {
        g_node->set_event_callback([](const gossip::MeshEvent& e) {
        });
        
        g_node->poll_events(timeout_ms);
    }
    
    std::memset(event, 0, sizeof(GossipEvent));
    return 0;
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
