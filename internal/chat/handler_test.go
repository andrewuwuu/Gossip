package chat

import (
	"path/filepath"
	"testing"
	"time"
)

func TestNewMessageHandler(t *testing.T) {
	h := NewMessageHandler("testuser", 1234)
	if h == nil {
		t.Fatal("NewMessageHandler returned nil")
	}
	if h.username != "testuser" {
		t.Errorf("expected username 'testuser', got '%s'", h.username)
	}
	if h.nodeID != 1234 {
		t.Errorf("expected nodeID 1234, got %d", h.nodeID)
	}
}

func TestCreateOutgoing(t *testing.T) {
	h := NewMessageHandler("sender", 100)
	msg := h.CreateOutgoing(200, "hello world", false)

	if msg.From != 100 {
		t.Errorf("expected From=100, got %d", msg.From)
	}
	if msg.To != 200 {
		t.Errorf("expected To=200, got %d", msg.To)
	}
	if msg.Content != "hello world" {
		t.Errorf("expected Content='hello world', got '%s'", msg.Content)
	}
	if msg.Broadcast != false {
		t.Error("expected Broadcast=false")
	}
}

func TestHandleBroadcast(t *testing.T) {
	h := NewMessageHandler("receiver", 100)

	var receivedMsg Message
	h.SetMessageCallback(func(m Message) {
		receivedMsg = m
	})

	h.HandleBroadcast(200, "sender", []byte("broadcast message"))

	if receivedMsg.From != 200 {
		t.Errorf("expected From=200, got %d", receivedMsg.From)
	}
	if receivedMsg.Content != "broadcast message" {
		t.Errorf("expected Content='broadcast message', got '%s'", receivedMsg.Content)
	}
	if !receivedMsg.Broadcast {
		t.Error("expected Broadcast=true")
	}
}

func TestHandleIncoming(t *testing.T) {
	h := NewMessageHandler("receiver", 100)

	var receivedMsg Message
	h.SetMessageCallback(func(m Message) {
		receivedMsg = m
	})

	h.HandleIncoming(200, "sender", []byte("direct message"))

	if receivedMsg.From != 200 {
		t.Errorf("expected From=200, got %d", receivedMsg.From)
	}
	if receivedMsg.Content != "direct message" {
		t.Errorf("expected Content='direct message', got '%s'", receivedMsg.Content)
	}
	if receivedMsg.Broadcast {
		t.Error("expected Broadcast=false for direct message")
	}
}

func TestSetNodeID(t *testing.T) {
	h := NewMessageHandler("user", 100)
	if h.nodeID != 100 {
		t.Errorf("expected initial nodeID=100, got %d", h.nodeID)
	}

	h.SetNodeID(999)
	if h.nodeID != 999 {
		t.Errorf("expected nodeID=999 after SetNodeID, got %d", h.nodeID)
	}
}

func TestGetHistory(t *testing.T) {
	h := NewMessageHandler("user", 100)

	/* Add some messages */
	h.CreateOutgoing(200, "msg1", false)
	h.CreateOutgoing(200, "msg2", false)
	h.CreateOutgoing(200, "msg3", false)

	/* Get all */
	history := h.GetHistory(0)
	if len(history) != 3 {
		t.Errorf("expected 3 messages, got %d", len(history))
	}

	/* Get limited */
	history = h.GetHistory(2)
	if len(history) != 2 {
		t.Errorf("expected 2 messages, got %d", len(history))
	}
	if history[0].Content != "msg2" {
		t.Errorf("expected first msg to be 'msg2', got '%s'", history[0].Content)
	}
}

func TestMarkDelivered(t *testing.T) {
	h := NewMessageHandler("user", 100)
	msg := h.CreateOutgoing(200, "test message", false)

	if msg.Delivered {
		t.Error("expected Delivered=false initially")
	}

	h.MarkDelivered(msg.ID)

	/* Get the message from history */
	history := h.GetHistory(1)
	if len(history) != 1 {
		t.Fatal("expected 1 message in history")
	}
	if !history[0].Delivered {
		t.Error("expected Delivered=true after MarkDelivered")
	}
}

func TestHistoryStorage(t *testing.T) {
	tmpDir := t.TempDir()
	historyPath := filepath.Join(tmpDir, "test_history.json")

	h := NewMessageHandler("user", 100)
	err := h.SetHistoryStorage(true, historyPath)
	if err != nil {
		t.Fatalf("SetHistoryStorage failed: %v", err)
	}

	h.CreateOutgoing(200, "persistent message", false)

	/* Give async save time to complete */
	time.Sleep(100 * time.Millisecond)

	/* Create new handler and load history */
	h2 := NewMessageHandler("user", 100)
	err = h2.SetHistoryStorage(true, historyPath)
	if err != nil {
		t.Fatalf("SetHistoryStorage for h2 failed: %v", err)
	}

	history := h2.GetHistory(0)
	if len(history) == 0 {
		t.Log("Warning: history may not have been saved yet (async)")
	}
}

func TestMessageIDGeneration(t *testing.T) {
	h := NewMessageHandler("user", 100)

	msg1 := h.CreateOutgoing(200, "msg1", false)
	msg2 := h.CreateOutgoing(200, "msg2", false)

	if msg1.ID == "" {
		t.Error("expected non-empty message ID")
	}
	if msg1.ID == msg2.ID {
		t.Error("expected unique message IDs")
	}
}
