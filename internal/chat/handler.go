package chat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Message struct {
	ID        string    `json:"id"`
	From      uint16    `json:"from"`
	To        uint16    `json:"to"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Broadcast bool      `json:"broadcast"`
	Delivered bool      `json:"delivered"`
}

type MessageHandler struct {
	username     string
	nodeID       uint16
	storeHistory bool
	historyPath  string

	messages    []Message
	maxMessages int

	onMessage func(Message)
	mu        sync.RWMutex
}

func NewMessageHandler(username string, nodeID uint16) *MessageHandler {
	return &MessageHandler{
		username:    username,
		nodeID:      nodeID,
		maxMessages: 1000,
	}
}

func (h *MessageHandler) SetHistoryStorage(enabled bool, path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.storeHistory = enabled
	h.historyPath = path

	if enabled && path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		if err := h.loadHistory(); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}

func (h *MessageHandler) SetMessageCallback(callback func(Message)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onMessage = callback
}

func (h *MessageHandler) HandleIncoming(fromID uint16, username string, data []byte) {
	msg := Message{
		ID:        generateMessageID(),
		From:      fromID,
		To:        h.nodeID,
		Username:  username,
		Content:   string(data),
		Timestamp: time.Now(),
		Broadcast: false,
		Delivered: true,
	}

	h.addMessage(msg)

	h.mu.RLock()
	callback := h.onMessage
	h.mu.RUnlock()

	if callback != nil {
		callback(msg)
	}
}

func (h *MessageHandler) HandleBroadcast(fromID uint16, username string, data []byte) {
	msg := Message{
		ID:        generateMessageID(),
		From:      fromID,
		To:        0,
		Username:  username,
		Content:   string(data),
		Timestamp: time.Now(),
		Broadcast: true,
		Delivered: true,
	}

	h.addMessage(msg)

	h.mu.RLock()
	callback := h.onMessage
	h.mu.RUnlock()

	if callback != nil {
		callback(msg)
	}
}

func (h *MessageHandler) CreateOutgoing(toID uint16, content string, broadcast bool) Message {
	msg := Message{
		ID:        generateMessageID(),
		From:      h.nodeID,
		To:        toID,
		Username:  h.username,
		Content:   content,
		Timestamp: time.Now(),
		Broadcast: broadcast,
		Delivered: false,
	}

	h.addMessage(msg)
	return msg
}

func (h *MessageHandler) MarkDelivered(messageID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i := range h.messages {
		if h.messages[i].ID == messageID {
			h.messages[i].Delivered = true
			break
		}
	}
}

func (h *MessageHandler) GetHistory(limit int) []Message {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if limit <= 0 || limit > len(h.messages) {
		limit = len(h.messages)
	}

	start := len(h.messages) - limit
	if start < 0 {
		start = 0
	}

	result := make([]Message, limit)
	copy(result, h.messages[start:])
	return result
}

func (h *MessageHandler) addMessage(msg Message) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.messages = append(h.messages, msg)

	if len(h.messages) > h.maxMessages {
		h.messages = h.messages[len(h.messages)-h.maxMessages:]
	}

	if h.storeHistory && h.historyPath != "" {
		go h.saveHistory()
	}
}

func (h *MessageHandler) loadHistory() error {
	data, err := os.ReadFile(h.historyPath)
	if err != nil {
		return err
	}

	var messages []Message
	if err := json.Unmarshal(data, &messages); err != nil {
		return err
	}

	h.messages = messages
	return nil
}

func (h *MessageHandler) saveHistory() {
	h.mu.RLock()
	messages := make([]Message, len(h.messages))
	copy(messages, h.messages)
	h.mu.RUnlock()

	data, err := json.MarshalIndent(messages, "", "  ")
	if err != nil {
		return
	}

	_ = os.WriteFile(h.historyPath, data, 0644)
}

func generateMessageID() string {
	var buf [8]byte
	_, _ = os.Stdin.Read(buf[:])
	return string(buf[:])
}
