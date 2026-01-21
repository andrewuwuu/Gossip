#ifndef GOSSIP_NET_H
#define GOSSIP_NET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GOSSIP_EVENT_PEER_CONNECTED    0
#define GOSSIP_EVENT_PEER_DISCONNECTED 1
#define GOSSIP_EVENT_MESSAGE_RECEIVED  2
#define GOSSIP_EVENT_MESSAGE_ACK       3
#define GOSSIP_EVENT_ERROR             4

#define GOSSIP_MAX_USERNAME_LEN  64
#define GOSSIP_MAX_MESSAGE_LEN   512

/*
 * GossipEvent struct layout - NATURALLY ALIGNED for CGo compatibility
 * 
 * Uses 64-bit types for numeric fields to ensure identical 8-byte alignment
 * on both x86_64 and aarch64 without needing #pragma pack.
 * 
 * Layout (all offsets are identical across architectures):
 *   offset 0:   event_type (int64_t, 8 bytes)
 *   offset 8:   peer_id    (uint64_t, 8 bytes)
 *   offset 16:  data_len   (uint64_t, 8 bytes)
 *   offset 24:  error_code (int64_t, 8 bytes)
 *   offset 32:  username   (char[64], 64 bytes)
 *   offset 96:  data       (uint8_t[512], 512 bytes)
 * Total: 608 bytes, all fields naturally aligned.
 */
typedef struct GossipEvent {
    int64_t event_type;
    uint64_t peer_id;
    uint64_t data_len;
    int64_t error_code;
    char username[GOSSIP_MAX_USERNAME_LEN];
    uint8_t data[GOSSIP_MAX_MESSAGE_LEN];
} GossipEvent;


typedef struct GossipPeerInfo {
    uint16_t node_id;
    char address[46];  // IPv6 max length
    uint16_t port;
    int64_t last_seen;
    int hop_count;
} GossipPeerInfo;

/*
 * Initializes the gossip network with a specific node ID.
 * The node ID must be unique within the network.
 * 
 * @param node_id Unique identifier for this node (1-65535)
 * @return 0 on success, -1 on failure (e.g., already initialized)
 */
int gossip_init(uint16_t node_id);

/*
 * Starts the network layer, listening on the specified ports.
 * Launches internal threads for connection management and discovery.
 * 
 * @param listen_port TCP port to listen for incoming connections
 * @param discovery_port UDP port to use for peer discovery
 * @return 0 on success, -1 if start failed
 */
int gossip_start(uint16_t listen_port, uint16_t discovery_port);

/*
 * Stops the network layer and closes all active connections.
 * This function waits for internal threads to join.
 */
void gossip_stop(void);

/*
 * Destroys the global mesh node instance and frees resources.
 * Should be called before program exit.
 */
void gossip_destroy(void);

/*
 * Manually initiates a connection to a specific peer.
 * Useful for connecting to nodes not found via discovery (e.g., across subnets).
 * 
 * @param address IP address of the target peer
 * @param port TCP port of the target peer
 * @return 0 if connection initiation started, -1 on error
 */
int gossip_connect(const char* address, uint16_t port);

/*
 * Explicitly triggers a peer discovery broadcast.
 * This is called automatically at intervals, but can be forced manually.
 */
void gossip_discover(void);

/*
 * Sends a direct message to a specific peer.
 * 
 * @param dest_id Node ID of the recipient
 * @param username Username of the sender (for display)
 * @param message Content of the message
 * @param message_len Length of the message content
 * @param require_ack If non-zero, requests an acknowledgment (not yet implemented)
 * @return 0 on success, -1 if node not found or send failed
 */
int gossip_send_message(uint16_t dest_id, const char* username,
                        const char* message, size_t message_len,
                        int require_ack);

/*
 * Broadcasts a message to all connected peers.
 * The message will be propagated through the mesh.
 * 
 * @param username Username of the sender
 * @param message Content of the message
 * @param message_len Length of the message content
 * @return 0 on success, -1 on failure
 */
int gossip_broadcast(const char* username, const char* message, size_t message_len);

/*
 * Polls for the next available network event.
 * This function is non-blocking if timeout_ms is 0.
 * 
 * @param event Pointer to a GossipEvent struct to populate
 * @param timeout_ms Maximum time to wait in milliseconds
 * @return 1 if an event was returned, 0 if queue empty/timeout, -1 on error
 */
int gossip_poll_event(GossipEvent* event, int timeout_ms);

/*
 * Returns the local node ID.
 * @return Node ID or 0 if not initialized
 */
uint16_t gossip_get_node_id(void);

/*
 * Retrieves a list of currently connected peers.
 * 
 * @param peers Array of GossipPeerInfo structs to populate
 * @param max_peers Maximum number of peers to write
 * @return Number of peers written, or -1 on error
 */
int gossip_get_peers(GossipPeerInfo* peers, size_t max_peers);

/*
 * Returns the total number of connected peers.
 * @return Count of active connections
 */
int gossip_get_peer_count(void);

/*
 * Checks if the network layer is running.
 * @return 1 if running, 0 otherwise
 */
int gossip_is_running(void);

#ifdef __cplusplus
}
#endif

#endif  // GOSSIP_NET_H
