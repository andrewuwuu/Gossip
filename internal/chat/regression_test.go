package chat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gossip/internal/config"
)

func TestCLIStopIdempotent(t *testing.T) {
	cfg := &config.Config{Username: "user"}
	cli := NewCLI(cfg)
	cli.ui = nil

	cli.Stop()
	cli.Stop()
}

func TestCLINickUpdatesHandler(t *testing.T) {
	cfg := &config.Config{Username: "old"}
	cli := NewCLI(cfg)
	cli.ui = nil
	cli.handler = NewMessageHandler(cfg.Username, 1)

	cli.handleCommand("/nick newname")

	msg := cli.handler.CreateOutgoing(2, "hello", false)
	if msg.Username != "newname" {
		t.Fatalf("expected outgoing username to be updated, got %q", msg.Username)
	}
	if cfg.Username != "newname" {
		t.Fatalf("expected config username to update, got %q", cfg.Username)
	}
}

func TestHistoryLoadRespectsMaxMessages(t *testing.T) {
	tmpDir := t.TempDir()
	historyPath := filepath.Join(tmpDir, "history.json")

	h := NewMessageHandler("user", 100)
	maxMessages := h.maxMessages
	total := maxMessages + 25

	messages := make([]Message, 0, total)
	for i := 0; i < total; i++ {
		messages = append(messages, Message{
			ID:        fmt.Sprintf("id-%d", i),
			From:      1,
			To:        2,
			Username:  "user",
			Content:   fmt.Sprintf("msg-%04d", i),
			Timestamp: time.Now(),
		})
	}

	data, err := json.Marshal(messages)
	if err != nil {
		t.Fatalf("failed to marshal test history: %v", err)
	}
	if err := os.WriteFile(historyPath, data, 0644); err != nil {
		t.Fatalf("failed to write test history: %v", err)
	}

	if err := h.SetHistoryStorage(true, historyPath); err != nil {
		t.Fatalf("SetHistoryStorage failed: %v", err)
	}

	history := h.GetHistory(0)
	if len(history) != maxMessages {
		t.Fatalf("expected %d messages after load, got %d", maxMessages, len(history))
	}

	expectedFirst := messages[total-maxMessages].Content
	if history[0].Content != expectedFirst {
		t.Fatalf("expected history to keep most recent messages, first=%q got %q", expectedFirst, history[0].Content)
	}
}

func TestHistoryConcurrentSaveValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	historyPath := filepath.Join(tmpDir, "history.json")

	h := NewMessageHandler("user", 100)
	if err := h.SetHistoryStorage(true, historyPath); err != nil {
		t.Fatalf("SetHistoryStorage failed: %v", err)
	}

	const total = 50
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h.CreateOutgoing(200, fmt.Sprintf("msg-%d", i), false)
		}(i)
	}
	wg.Wait()

	messages, err := waitForValidHistory(historyPath, 2*time.Second)
	if err != nil {
		t.Fatalf("history file never became valid JSON: %v", err)
	}
	if len(messages) > h.maxMessages {
		t.Fatalf("expected history size <= %d, got %d", h.maxMessages, len(messages))
	}
}

func TestGenerateMessageIDRandFailure(t *testing.T) {
	/* Go 1.21+ changed crypto/rand.Read to use fatal panic on failure
	 * instead of returning an error. This cannot be caught by recover().
	 * See: https://go.dev/issue/66821
	 * Skip this test on those versions.
	 */
	t.Skip("crypto/rand.Read uses fatal panic on Go 1.21+; fallback tested via timestamp ID uniqueness")
}

func waitForValidHistory(path string, timeout time.Duration) ([]Message, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var messages []Message
			if jsonErr := json.Unmarshal(data, &messages); jsonErr == nil {
				return messages, nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for valid history file")
}
