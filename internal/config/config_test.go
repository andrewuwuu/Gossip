package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	if cfg.AppName == "" {
		t.Error("AppName should have default value")
	}
	if cfg.NodeID == 0 {
		t.Error("NodeID should be generated if not set")
	}
}

func TestLoadWithEnvVars(t *testing.T) {
	/* Save original env values */
	origAppName := os.Getenv("APP_NAME")
	origNodePort := os.Getenv("NODE_PORT")
	origUsername := os.Getenv("USERNAME")

	/* Set test values */
	os.Setenv("APP_NAME", "TestGossip")
	os.Setenv("NODE_PORT", "8080")
	os.Setenv("USERNAME", "testuser")

	defer func() {
		/* Restore original values */
		if origAppName != "" {
			os.Setenv("APP_NAME", origAppName)
		} else {
			os.Unsetenv("APP_NAME")
		}
		if origNodePort != "" {
			os.Setenv("NODE_PORT", origNodePort)
		} else {
			os.Unsetenv("NODE_PORT")
		}
		if origUsername != "" {
			os.Setenv("USERNAME", origUsername)
		} else {
			os.Unsetenv("USERNAME")
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.AppName != "TestGossip" {
		t.Errorf("expected AppName='TestGossip', got '%s'", cfg.AppName)
	}
	if cfg.NodePort != 8080 {
		t.Errorf("expected NodePort=8080, got %d", cfg.NodePort)
	}
	if cfg.Username != "testuser" {
		t.Errorf("expected Username='testuser', got '%s'", cfg.Username)
	}
}

func TestLoadWithNodeID(t *testing.T) {
	origNodeID := os.Getenv("NODE_ID")
	os.Setenv("NODE_ID", "12345")

	defer func() {
		if origNodeID != "" {
			os.Setenv("NODE_ID", origNodeID)
		} else {
			os.Unsetenv("NODE_ID")
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.NodeID != 12345 {
		t.Errorf("expected NodeID=12345, got %d", cfg.NodeID)
	}
}

func TestGenerateNodeID(t *testing.T) {
	id1 := generateNodeID()
	id2 := generateNodeID()

	if id1 == 0 {
		t.Error("generateNodeID returned 0")
	}
	/* IDs should be random, very unlikely to be equal */
	if id1 == id2 {
		t.Log("Warning: two generated node IDs were equal (very unlikely but possible)")
	}
}

func TestGetEnvOrDefault(t *testing.T) {
	/* Test with unset env var */
	result := getEnvOrDefault("NONEXISTENT_VAR_12345", "default")
	if result != "default" {
		t.Errorf("expected 'default', got '%s'", result)
	}

	/* Test with set env var */
	os.Setenv("TEST_VAR_12345", "custom")
	defer os.Unsetenv("TEST_VAR_12345")

	result = getEnvOrDefault("TEST_VAR_12345", "default")
	if result != "custom" {
		t.Errorf("expected 'custom', got '%s'", result)
	}
}

func TestGetEnvIntOrDefault(t *testing.T) {
	/* Test with unset env var */
	result := getEnvIntOrDefault("NONEXISTENT_VAR_12345", 42)
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}

	/* Test with valid int */
	os.Setenv("TEST_INT_12345", "100")
	defer os.Unsetenv("TEST_INT_12345")

	result = getEnvIntOrDefault("TEST_INT_12345", 42)
	if result != 100 {
		t.Errorf("expected 100, got %d", result)
	}

	/* Test with invalid int */
	os.Setenv("TEST_INT_INVALID", "notanumber")
	defer os.Unsetenv("TEST_INT_INVALID")

	result = getEnvIntOrDefault("TEST_INT_INVALID", 42)
	if result != 42 {
		t.Errorf("expected 42 for invalid int, got %d", result)
	}
}

func TestGetEnvBoolOrDefault(t *testing.T) {
	/* Test with unset env var */
	result := getEnvBoolOrDefault("NONEXISTENT_VAR_12345", true)
	if result != true {
		t.Errorf("expected true, got %v", result)
	}

	/* Test with valid bool */
	os.Setenv("TEST_BOOL_12345", "false")
	defer os.Unsetenv("TEST_BOOL_12345")

	result = getEnvBoolOrDefault("TEST_BOOL_12345", true)
	if result != false {
		t.Errorf("expected false, got %v", result)
	}
}

func TestDefaultIdentityPath(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.IdentityPath == "" {
		t.Error("IdentityPath should have a default value")
	}
}
