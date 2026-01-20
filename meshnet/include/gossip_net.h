#ifndef GOSSIP_NET_H
#define GOSSIP_NET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GOSSIP_EVENT_PEER_CONNECTED    1
#define GOSSIP_EVENT_PEER_DISCONNECTED 2
#define GOSSIP_EVENT_MESSAGE_RECEIVED  3
#define GOSSIP_EVENT_MESSAGE_ACK       4
#define GOSSIP_EVENT_ERROR             5

#define GOSSIP_MAX_USERNAME_LEN  64
#define GOSSIP_MAX_MESSAGE_LEN   16384

typedef struct {
    int event_type;
    uint16_t peer_id;
    char username[GOSSIP_MAX_USERNAME_LEN];
    uint8_t data[GOSSIP_MAX_MESSAGE_LEN];
    size_t data_len;
    int error_code;
} GossipEvent;

typedef struct {
    uint16_t node_id;
    char address[46];  // IPv6 max length
    uint16_t port;
    int64_t last_seen;
    int hop_count;
} GossipPeerInfo;

int gossip_init(uint16_t node_id);

int gossip_start(uint16_t listen_port, uint16_t discovery_port);

void gossip_stop(void);

void gossip_destroy(void);

int gossip_connect(const char* address, uint16_t port);

void gossip_discover(void);

int gossip_send_message(uint16_t dest_id, const char* username,
                        const char* message, size_t message_len,
                        int require_ack);

int gossip_broadcast(const char* username, const char* message, size_t message_len);

int gossip_poll_event(GossipEvent* event, int timeout_ms);

uint16_t gossip_get_node_id(void);

int gossip_get_peers(GossipPeerInfo* peers, size_t max_peers);

int gossip_get_peer_count(void);

int gossip_is_running(void);

#ifdef __cplusplus
}
#endif

#endif  // GOSSIP_NET_H
