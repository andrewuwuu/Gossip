package meshnet

/*
#cgo CFLAGS: -I${SRCDIR}/../../meshnet/include
#cgo LDFLAGS: -L${SRCDIR}/../../meshnet/build -lgossipnet -lstdc++ -lpthread

#include "gossip_net.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var (
	ErrNotInitialized = errors.New("mesh network not initialized")
	ErrNotRunning     = errors.New("mesh network not running")
	ErrInvalidParam   = errors.New("invalid parameter")
)

const maxMessageLen = 512

type EventType int

const (
	EventPeerConnected    EventType = C.GOSSIP_EVENT_PEER_CONNECTED
	EventPeerDisconnected EventType = C.GOSSIP_EVENT_PEER_DISCONNECTED
	EventMessageReceived  EventType = C.GOSSIP_EVENT_MESSAGE_RECEIVED
	EventMessageAck       EventType = C.GOSSIP_EVENT_MESSAGE_ACK
	EventError            EventType = C.GOSSIP_EVENT_ERROR
)

type Event struct {
	Type      EventType
	PeerID    uint16
	Username  string
	Data      []byte
	ErrorCode int
}

type PeerInfo struct {
	NodeID   uint16
	Address  string
	Port     uint16
	LastSeen int64
	HopCount int
}

type MeshNet struct {
	nodeID        uint16
	initialized   bool
	running       bool
	eventCallback func(Event)
	mu            sync.RWMutex
	stopChan      chan struct{}
}

var instance *MeshNet
var once sync.Once

func New(nodeID uint16) (*MeshNet, error) {
	var err error
	once.Do(func() {
		result := C.gossip_init(C.uint16_t(nodeID))
		if result != 0 {
			err = errors.New("failed to initialize mesh network")
			return
		}
		instance = &MeshNet{
			nodeID:      nodeID,
			initialized: true,
		}
	})

	if err != nil {
		return nil, err
	}

	if instance == nil {
		return nil, errors.New("mesh network already initialized")
	}

	return instance, nil
}

func (m *MeshNet) Start(listenPort, discoveryPort uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		return ErrNotInitialized
	}

	result := C.gossip_start(C.uint16_t(listenPort), C.uint16_t(discoveryPort))
	if result != 0 {
		return errors.New("failed to start mesh network")
	}

	m.running = true
	m.stopChan = make(chan struct{})

	go m.eventLoop()

	return nil
}

func (m *MeshNet) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		close(m.stopChan)
		C.gossip_stop()
		m.running = false
	}
}

func (m *MeshNet) Destroy() {
	m.Stop()
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		C.gossip_destroy()
		m.initialized = false
	}
}

func (m *MeshNet) Connect(address string, port uint16) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return ErrNotRunning
	}

	cAddr := C.CString(address)
	defer C.free(unsafe.Pointer(cAddr))

	result := C.gossip_connect(cAddr, C.uint16_t(port))
	if result != 0 {
		return errors.New("failed to connect to peer")
	}

	return nil
}

func (m *MeshNet) Discover() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.running {
		C.gossip_discover()
	}
}

func (m *MeshNet) SendMessage(destID uint16, username, message string, requireAck bool) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return ErrNotRunning
	}

	if username == "" || message == "" {
		return ErrInvalidParam
	}

	if len(message) > maxMessageLen {
		return ErrInvalidParam
	}

	cUsername := C.CString(username)
	defer C.free(unsafe.Pointer(cUsername))

	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))

	ack := 0
	if requireAck {
		ack = 1
	}

	result := C.gossip_send_message(
		C.uint16_t(destID),
		cUsername,
		cMessage,
		C.size_t(len(message)),
		C.int(ack),
	)

	if result != 0 {
		return errors.New("failed to send message")
	}

	return nil
}

func (m *MeshNet) Broadcast(username, message string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return ErrNotRunning
	}

	if len(message) > maxMessageLen {
		return ErrInvalidParam
	}

	if username == "" || message == "" {
		return ErrInvalidParam
	}

	cUsername := C.CString(username)
	defer C.free(unsafe.Pointer(cUsername))

	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))

	result := C.gossip_broadcast(cUsername, cMessage, C.size_t(len(message)))
	if result != 0 {
		return errors.New("failed to broadcast message")
	}

	return nil
}

func (m *MeshNet) GetNodeID() uint16 {
	return uint16(C.gossip_get_node_id())
}

func (m *MeshNet) GetPeers() []PeerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return nil
	}

	count := C.gossip_get_peer_count()
	if count <= 0 {
		return nil
	}

	cPeers := make([]C.GossipPeerInfo, count)
	result := C.gossip_get_peers(&cPeers[0], C.size_t(count))
	if result <= 0 {
		return nil
	}

	peers := make([]PeerInfo, result)
	for i := 0; i < int(result); i++ {
		peers[i] = PeerInfo{
			NodeID:   uint16(cPeers[i].node_id),
			Address:  C.GoString(&cPeers[i].address[0]),
			Port:     uint16(cPeers[i].port),
			LastSeen: int64(cPeers[i].last_seen),
			HopCount: int(cPeers[i].hop_count),
		}
	}

	return peers
}

func (m *MeshNet) IsRunning() bool {
	return C.gossip_is_running() == 1
}

func (m *MeshNet) SetEventCallback(callback func(Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventCallback = callback
}

func (m *MeshNet) eventLoop() {
	var cEvent C.GossipEvent

	for {
		select {
		case <-m.stopChan:
			return
		default:
			result := C.gossip_poll_event(&cEvent, 100)
			if result == 1 {
				event := Event{
					Type:      EventType(cEvent.event_type),
					PeerID:    uint16(cEvent.peer_id),
					Username:  C.GoString(&cEvent.username[0]),
					ErrorCode: int(cEvent.error_code),
				}

				// DEBUG: Log what Go actually receives
				fmt.Printf("[DEBUG] Go received: type=%d peer_id=%d\n", event.Type, event.PeerID)

				if cEvent.data_len > 0 {
					event.Data = C.GoBytes(unsafe.Pointer(&cEvent.data[0]), C.int(cEvent.data_len))
				}

				m.mu.RLock()
				cb := m.eventCallback
				m.mu.RUnlock()

				if cb != nil {
					cb(event)
				}
			}
		}
	}
}
