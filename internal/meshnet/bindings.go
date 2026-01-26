package meshnet

/*
#cgo CFLAGS: -I${SRCDIR}/../../meshnet/include
#cgo LDFLAGS: -L${SRCDIR}/../../meshnet/build -lgossipnet -lstdc++ -lpthread -lsodium

#include "gossip_net.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"gossip/internal/logging"
	"sync"
	"unsafe"
)

var (
	ErrNotInitialized   = &GossipError{Code: -2, Message: "mesh network not initialized"}
	ErrNotRunning       = &GossipError{Code: -3, Message: "mesh network not running"}
	ErrInvalidParam     = &GossipError{Code: -4, Message: "invalid parameter"}
	ErrAlreadyRunning   = &GossipError{Code: -5, Message: "cannot change key while running"}
	ErrInvalidKeyLength = &GossipError{Code: -6, Message: "key must be 32 bytes"}
	ErrInvalidHex       = &GossipError{Code: -7, Message: "invalid hex string"}
)

type GossipError struct {
	Code    int
	Message string
}

func (e *GossipError) Error() string {
	return fmt.Sprintf("gossip error %d: %s", e.Code, e.Message)
}

const (
	maxMessageLen = 512
	KeySize       = 32 // 256-bit symmetric key
)

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
	wg            sync.WaitGroup
}

var instance *MeshNet
var once sync.Once
var initErr error

func New(nodeID uint16) (*MeshNet, error) {
	once.Do(func() {
		result := C.gossip_init(C.uint16_t(nodeID))
		if result != 0 {
			initErr = &GossipError{Code: int(result), Message: "failed to initialize mesh network"}
			return
		}
		instance = &MeshNet{
			nodeID:      nodeID,
			initialized: true,
		}
	})

	if initErr != nil {
		return nil, initErr
	}

	if instance == nil {
		return nil, &GossipError{Code: -1, Message: "mesh network initialization incomplete"}
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
		return &GossipError{Code: int(result), Message: "failed to start mesh network"}
	}

	m.running = true
	m.stopChan = make(chan struct{})

	m.wg.Add(1)
	go m.eventLoop()

	return nil
}

func (m *MeshNet) Stop() {
	m.mu.Lock()

	if m.running {
		close(m.stopChan)
		C.gossip_stop()
		m.running = false
		m.mu.Unlock() // Unlock before waiting to allow eventLoop to release read lock if needed
		m.wg.Wait()
		return
	}
	// Normal unlock if we didn't wait
	m.mu.Unlock()
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
		return &GossipError{Code: int(result), Message: "failed to connect to peer"}
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
		return &GossipError{Code: int(result), Message: "failed to send message"}
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
		return &GossipError{Code: int(result), Message: "failed to broadcast message"}
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

/*
 * SetSessionKey sets the 32-byte session key for encrypted communication.
 * Must be called AFTER New() and BEFORE Start().
 * All peers must use the same key to communicate.
 */
func (m *MeshNet) SetSessionKey(key []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.initialized {
		return ErrNotInitialized
	}

	if m.running {
		return ErrAlreadyRunning
	}

	if len(key) != KeySize {
		return ErrInvalidKeyLength
	}

	result := C.gossip_set_session_key((*C.uint8_t)(unsafe.Pointer(&key[0])))
	if result != 0 {
		return &GossipError{Code: int(result), Message: "failed to set session key"}
	}

	return nil
}

/*
 * SetSessionKeyHex sets the session key from a 64-character hex string.
 * Convenience function for loading keys from environment variables.
 */
func (m *MeshNet) SetSessionKeyHex(hexKey string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.initialized {
		return ErrNotInitialized
	}

	if m.running {
		return ErrAlreadyRunning
	}

	if len(hexKey) != KeySize*2 {
		return ErrInvalidHex
	}

	cHexKey := C.CString(hexKey)
	defer C.free(unsafe.Pointer(cHexKey))

	result := C.gossip_set_session_key_hex(cHexKey)
	if result != 0 {
		return ErrInvalidHex
	}

	return nil
}

/*
 * IsEncrypted returns true if encryption is enabled (session key has been set).
 */
func (m *MeshNet) IsEncrypted() bool {
	return C.gossip_is_encrypted() == 1
}

func (m *MeshNet) eventLoop() {
	defer m.wg.Done()
	var cEvent C.GossipEvent

	for {
		select {
		case <-m.stopChan:
			return
		default:
			// Poll with short timeout
			result := C.gossip_poll_event(&cEvent, 100)
			if result == 1 {
				event := Event{
					Type:      EventType(cEvent.event_type),
					PeerID:    uint16(cEvent.peer_id),
					Username:  C.GoString(&cEvent.username[0]),
					ErrorCode: int(cEvent.error_code),
				}

				logging.Debugf("Go received event type=%d peer_id=%d", event.Type, event.PeerID)

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

/*
 * Identity Management (PKI)
 */

const (
	PublicKeySize  = 32
	PrivateKeySize = 32
)

var (
	ErrNoIdentity = errors.New("no identity loaded")
)

// LoadIdentity loads an identity from a file path.
func (m *MeshNet) LoadIdentity(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	if C.gossip_load_identity(cPath) != 0 {
		return &GossipError{Code: -1, Message: "failed to load identity from " + path}
	}
	return nil
}

// SaveIdentity saves the current identity to a file path.
func (m *MeshNet) SaveIdentity(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	if C.gossip_save_identity(cPath) != 0 {
		return &GossipError{Code: -1, Message: "failed to save identity to " + path}
	}
	return nil
}

// GenerateIdentity generates a new keypair and stores it internally.
// You should call SaveIdentity to persist it.
func (m *MeshNet) GenerateIdentity() (publicKeyHex string, err error) {
	var pubKey [PublicKeySize]byte
	var privKey [PrivateKeySize]byte

	C.gossip_generate_keypair((*C.uint8_t)(&pubKey[0]), (*C.uint8_t)(&privKey[0]))

	// Store it in the C layer by saving to temp and loading?
	// Actually the C API stores it globally when loaded.
	// For now, we directly call set_private_key to use the generated key.
	if C.gossip_set_private_key((*C.uint8_t)(&privKey[0])) != 0 {
		return "", &GossipError{Code: -1, Message: "failed to set generated identity"}
	}

	// Get public key hex
	var hexBuf [65]C.char
	if C.gossip_get_public_key_hex(&hexBuf[0]) != 0 {
		return "", &GossipError{Code: -1, Message: "failed to get public key"}
	}

	return C.GoString(&hexBuf[0]), nil
}

// HasIdentity returns true if an identity has been loaded or generated.
func (m *MeshNet) HasIdentity() bool {
	return C.gossip_has_identity() == 1
}

// GetPublicKeyHex returns the node's public key as a hex string.
func (m *MeshNet) GetPublicKeyHex() (string, error) {
	if C.gossip_has_identity() != 1 {
		return "", ErrNoIdentity
	}

	// Get public key hex
	var hexBuf [65]C.char
	if C.gossip_get_public_key_hex(&hexBuf[0]) != 0 {
		return "", &GossipError{Code: -1, Message: "failed to get public key"}
	}

	return C.GoString(&hexBuf[0]), nil
}
