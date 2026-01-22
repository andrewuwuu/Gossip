package config

import (
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AppName       string
	NodeID        uint16
	NodePort      uint16
	DiscoveryPort uint16
	Username      string
	MaxPeers      int
	Debug         bool
	StoreHistory  bool
	HistoryPath   string
	SessionKey    string /* Optional: 64-char hex key for encryption (PSK mode) */
	IdentityPath  string /* Path to identity.key file for PKI mode */
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
	}

	cfg := &Config{
		AppName:       getEnvOrDefault("APP_NAME", "Gossip"),
		NodePort:      getEnvUint16OrDefault("NODE_PORT", 9000),
		DiscoveryPort: getEnvUint16OrDefault("DISCOVERY_PORT", 9001),
		Username:      getEnvOrDefault("USERNAME", "anonymous"),
		MaxPeers:      getEnvIntOrDefault("MAX_PEERS", 50),
		Debug:         getEnvBoolOrDefault("DEBUG", false),
		StoreHistory:  getEnvBoolOrDefault("STORE_HISTORY", false),
		HistoryPath:   getEnvOrDefault("HISTORY_PATH", ""),
		SessionKey:    os.Getenv("GOSSIP_SESSION_KEY"),
	}

	nodeIDStr := os.Getenv("NODE_ID")
	if nodeIDStr != "" {
		if id, err := strconv.ParseUint(nodeIDStr, 10, 16); err == nil {
			cfg.NodeID = uint16(id)
		}
	}

	if cfg.NodeID == 0 {
		cfg.NodeID = generateNodeID()
	}

	if cfg.StoreHistory && cfg.HistoryPath == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			cfg.HistoryPath = filepath.Join(homeDir, ".gossip", "history")
		}
	}

	/*
	 * Set default identity path: ~/.gossip/identity.key
	 */
	if cfg.IdentityPath == "" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			cfg.IdentityPath = filepath.Join(homeDir, ".gossip", "identity.key")
		} else {
			cfg.IdentityPath = ".gossip/identity.key"
		}
	}

	return cfg, nil
}

func generateNodeID() uint16 {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return uint16(os.Getpid() & 0xFFFF)
	}
	id := binary.BigEndian.Uint16(buf[:])
	if id == 0 {
		id = 1
	}
	return id
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvUint16OrDefault(key string, defaultValue uint16) uint16 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseUint(value, 10, 16); err == nil {
			return uint16(i)
		}
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}
