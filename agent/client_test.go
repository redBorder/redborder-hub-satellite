package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTracerouteOutput(t *testing.T) {
	output := `traceroute to google.com (142.250.74.46), 30 hops max, 60 byte packets
 1  gateway (192.168.1.1)  0.254 ms  0.210 ms  0.198 ms
 2  10.0.0.1 (10.0.0.1)  1.120 ms  0.985 ms
 3  * * *
 4  google.com (142.250.74.46)  12.450 ms`

	res, err := parseTracerouteOutput("google.com", output)
	if err != nil {
		t.Fatalf("unexpected error parsing traceroute output: %v", err)
	}

	if res.Host != "google.com" {
		t.Errorf("expected Host to be 'google.com', got %q", res.Host)
	}

	if len(res.Hops) != 4 {
		t.Errorf("expected 4 hops, got %d", len(res.Hops))
	}

	// Test hop 1
	hop1 := res.Hops[0]
	if hop1.Hop != 1 || hop1.Host != "gateway" || hop1.IP != "192.168.1.1" {
		t.Errorf("invalid hop 1: %+v", hop1)
	}
	if len(hop1.RTTs) != 3 || hop1.RTTs[0] != 0.254 || hop1.RTTs[1] != 0.210 || hop1.RTTs[2] != 0.198 {
		t.Errorf("invalid hop 1 RTTs: %v", hop1.RTTs)
	}

	// Test hop 2 (has only 2 RTT values)
	hop2 := res.Hops[1]
	if hop2.Hop != 2 || hop2.Host != "10.0.0.1" || hop2.IP != "10.0.0.1" {
		t.Errorf("invalid hop 2: %+v", hop2)
	}
	if len(hop2.RTTs) != 2 || hop2.RTTs[0] != 1.120 || hop2.RTTs[1] != 0.985 {
		t.Errorf("invalid hop 2 RTTs: %v", hop2.RTTs)
	}

	// Test hop 3 (timeout)
	hop3 := res.Hops[2]
	if hop3.Hop != 3 || hop3.Host != "*" || hop3.IP != "*" {
		t.Errorf("invalid hop 3: %+v", hop3)
	}
	if len(hop3.RTTs) != 0 {
		t.Errorf("expected 0 RTTs for timeout hop, got %d", len(hop3.RTTs))
	}

	// Test hop 4
	hop4 := res.Hops[3]
	if hop4.Hop != 4 || hop4.Host != "google.com" || hop4.IP != "142.250.74.46" {
		t.Errorf("invalid hop 4: %+v", hop4)
	}
	if len(hop4.RTTs) != 1 || hop4.RTTs[0] != 12.450 {
		t.Errorf("invalid hop 4 RTTs: %v", hop4.RTTs)
	}
}

func TestExecuteTracerouteRealError(t *testing.T) {
	// When traceroute binary is missing or fails, it must return a real error without simulation fallback
	rawParams := json.RawMessage(`{"host": "invalid.local.domain.nonexistent", "max_hops": 30, "timeout": 1}`)
	_, err := executeTraceroute(context.Background(), rawParams)
	if err == nil {
		t.Fatalf("expected error executing traceroute with missing binary or invalid host, got nil")
	}
}

func TestNewAgentMultiURL(t *testing.T) {
	hubURLs := "ws://127.0.0.1:8080/ws , ws://127.0.0.1:8081/ws ,ws://127.0.0.1:8082/ws"
	a := NewAgent(hubURLs, "token", "agent-id", nil, "")

	if len(a.hubURLs) != 3 {
		t.Fatalf("expected 3 parsed URLs, got %d: %v", len(a.hubURLs), a.hubURLs)
	}

	expected := []string{"ws://127.0.0.1:8080/ws", "ws://127.0.0.1:8081/ws", "ws://127.0.0.1:8082/ws"}
	for i, u := range a.hubURLs {
		if u != expected[i] {
			t.Errorf("expected URL at %d to be %q, got %q", i, expected[i], u)
		}
	}

	if a.activeURLIdx != 0 {
		t.Errorf("expected initial activeURLIdx to be 0, got %d", a.activeURLIdx)
	}
}

func TestCustomCommandBinaryExecution(t *testing.T) {
	cmdCfg := CustomCommandConfig{
		Executable: "echo",
		Args:       []string{"hello", "$target"},
		ParamRules: map[string]ParamRule{
			"target": {
				Regex:    "^[a-zA-Z0-9_\\-]+$",
				Required: true,
			},
		},
		TimeoutSeconds: 5,
	}

	rawParams := json.RawMessage(`{"target": "world"}`)
	res, err := executeCustomCommand(context.Background(), "test_echo", cmdCfg, rawParams)
	if err != nil {
		t.Fatalf("unexpected error executing custom command: %v", err)
	}

	resMap, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", res)
	}

	stdout, _ := resMap["stdout"].(string)
	if !strings.Contains(stdout, "hello world") {
		t.Errorf("expected stdout to contain 'hello world', got %q", stdout)
	}

	// Test invalid parameter regex protection
	invalidParams := json.RawMessage(`{"target": "world; rm -rf /"}`)
	_, errInvalid := executeCustomCommand(context.Background(), "test_echo", cmdCfg, invalidParams)
	if errInvalid == nil {
		t.Errorf("expected security error on malicious parameter input, got nil")
	}
}

func TestCustomCommandFileRead(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "file_read_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFilePath := filepath.Join(tempDir, "app.log")
	_ = os.WriteFile(testFilePath, []byte("log line 1\nlog line 2"), 0644)

	cmdCfg := CustomCommandConfig{
		Type:         "file_read",
		AllowedPaths: []string{filepath.Join(tempDir, "*.log")},
		MaxBytes:     1024,
	}

	// Test allowed path read
	validParams := json.RawMessage(`{"path": "` + testFilePath + `"}`)
	res, err := executeCustomCommand(context.Background(), "read_log", cmdCfg, validParams)
	if err != nil {
		t.Fatalf("unexpected error reading allowed file: %v", err)
	}

	resMap, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", res)
	}

	content, _ := resMap["content"].(string)
	if content != "log line 1\nlog line 2" {
		t.Errorf("expected file content 'log line 1\\nlog line 2', got %q", content)
	}

	// Test forbidden path read (e.g. /etc/passwd or path outside allowed_paths)
	forbiddenParams := json.RawMessage(`{"path": "/etc/passwd"}`)
	_, errForbidden := executeCustomCommand(context.Background(), "read_log", cmdCfg, forbiddenParams)
	if errForbidden == nil {
		t.Errorf("expected security error when attempting to read forbidden path, got nil")
	}
}
