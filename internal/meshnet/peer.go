package meshnet

import (
	"fmt"
	"sync"
	"time"
)

type PeerState int

const (
	PeerStateUnknown PeerState = iota
	PeerStateConnecting
	PeerStateConnected
	PeerStateDisconnected
)

type Peer struct {
	ID       uint16
	Address  string
	Port     uint16
	State    PeerState
	Username string
	LastSeen time.Time
	HopCount int
	RTT      time.Duration
	mu       sync.RWMutex
}

func (p *Peer) String() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	name := p.Username
	if name == "" {
		name = fmt.Sprintf("Peer-%d", p.ID)
	}

	return fmt.Sprintf("%s (%s:%d)", name, p.Address, p.Port)
}

func (p *Peer) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.State == PeerStateConnected
}

func (p *Peer) UpdateLastSeen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastSeen = time.Now()
}

type PeerManager struct {
	peers map[uint16]*Peer
	mu    sync.RWMutex
}

func NewPeerManager() *PeerManager {
	return &PeerManager{
		peers: make(map[uint16]*Peer),
	}
}

func (pm *PeerManager) AddPeer(id uint16, address string, port uint16) *Peer {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if existing, ok := pm.peers[id]; ok {
		existing.mu.Lock()
		existing.Address = address
		existing.Port = port
		existing.State = PeerStateConnected
		existing.LastSeen = time.Now()
		existing.mu.Unlock()
		return existing
	}

	peer := &Peer{
		ID:       id,
		Address:  address,
		Port:     port,
		State:    PeerStateConnected,
		LastSeen: time.Now(),
	}

	pm.peers[id] = peer
	return peer
}

func (pm *PeerManager) RemovePeer(id uint16) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if peer, ok := pm.peers[id]; ok {
		peer.mu.Lock()
		peer.State = PeerStateDisconnected
		peer.mu.Unlock()
	}

	delete(pm.peers, id)
}

func (pm *PeerManager) GetPeer(id uint16) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peers[id]
}

func (pm *PeerManager) GetAllPeers() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*Peer, 0, len(pm.peers))
	for _, peer := range pm.peers {
		peers = append(peers, peer)
	}
	return peers
}

func (pm *PeerManager) GetConnectedPeers() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*Peer, 0, len(pm.peers))
	for _, peer := range pm.peers {
		if peer.IsConnected() {
			peers = append(peers, peer)
		}
	}
	return peers
}

func (pm *PeerManager) Count() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.peers)
}

func (pm *PeerManager) UpdateFromNetworkPeers(networkPeers []PeerInfo) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, np := range networkPeers {
		if existing, ok := pm.peers[np.NodeID]; ok {
			existing.mu.Lock()
			existing.Address = np.Address
			existing.Port = np.Port
			existing.LastSeen = time.Unix(0, np.LastSeen*int64(time.Millisecond))
			existing.HopCount = np.HopCount
			existing.mu.Unlock()
		} else {
			pm.peers[np.NodeID] = &Peer{
				ID:       np.NodeID,
				Address:  np.Address,
				Port:     np.Port,
				State:    PeerStateConnected,
				LastSeen: time.Unix(0, np.LastSeen*int64(time.Millisecond)),
				HopCount: np.HopCount,
			}
		}
	}
}
