package hub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"redborder-hub-satellite/common"
	"strconv"
	"testing"
	"time"
)

func TestHubAuthentication(t *testing.T) {
	// Create a temp directory for authorized keys
	tempDir, err := os.MkdirTemp("", "authorized_keys_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate agent key pair
	priv, pub, err := common.GenerateAndSaveEd25519Keys(
		filepath.Join(tempDir, "agent-test.key"),
		filepath.Join(tempDir, "agent-test.pub"),
	)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	pubKeyBytes := pub

	h := NewHub("my-secret-token", "my-registration-token", tempDir, false, nil, "", false)

	t.Run("Valid Token Authentication for Unregistered Agent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", "agent-unregistered")
		req.Header.Set("X-Agent-Token", "my-secret-token")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		// A valid token auth request should bypass auth and reach WebSocket upgrade.
		// Since this is a plain HTTP request (not WS), upgrade should fail with Bad Request (400)
		// rather than Unauthorized (401).
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected StatusBadRequest (400) from upgrade failure, got %d", rec.Code)
		}
	})

	t.Run("Token-Only Auth Rejected for Key-Registered Agent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", "agent-test") // agent-test has agent-test.pub registered
		req.Header.Set("X-Agent-Token", "my-secret-token")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected StatusUnauthorized (401), got %d", rec.Code)
		}
	})

	t.Run("Invalid Token Authentication", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", "agent-test")
		req.Header.Set("X-Agent-Token", "wrong-token")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected StatusUnauthorized (401), got %d", rec.Code)
		}
	})

	t.Run("Valid Signature Authentication", func(t *testing.T) {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sig := common.SignChallenge(priv, "agent-test", timestamp)

		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", "agent-test")
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", sig)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		// Should bypass auth and fail at upgrade step (400 Bad Request)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected StatusBadRequest (400) from upgrade failure, got %d", rec.Code)
		}
	})

	t.Run("Replay Attack / Expired Timestamp Rejected", func(t *testing.T) {
		// Timestamp is 5 minutes ago (outside the 2-minute skew limit)
		timestamp := strconv.FormatInt(time.Now().Add(-5*time.Minute).Unix(), 10)
		sig := common.SignChallenge(priv, "agent-test", timestamp)

		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", "agent-test")
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", sig)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected StatusUnauthorized (401), got %d", rec.Code)
		}
	})

	t.Run("Invalid Signature Rejected", func(t *testing.T) {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		// Sign using a completely new key, not registered under agent-test.pub
		_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
		sig := common.SignChallenge(wrongPriv, "agent-test", timestamp)

		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", "agent-test")
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", sig)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected StatusUnauthorized (401), got %d", rec.Code)
		}
	})

	t.Run("Invalid Agent ID Format (Directory Traversal attempt)", func(t *testing.T) {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sig := common.SignChallenge(priv, "agent-test", timestamp)

		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", "../agent-test") // Traversal chars
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", sig)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected StatusBadRequest (400) due to validation failure, got %d", rec.Code)
		}
	})

	t.Run("Alternative base64 format for public key", func(t *testing.T) {
		// Create a separate agent
		agentID := "agent-b64"
		pubBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)
		
		// Save the public key as simple base64 text instead of PEM
		err := os.WriteFile(filepath.Join(tempDir, agentID+".pub"), []byte(pubBase64), 0644)
		if err != nil {
			t.Fatalf("failed to write base64 public key: %v", err)
		}

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sig := common.SignChallenge(priv, agentID, timestamp)

		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", sig)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		// Should bypass auth and fail at upgrade step (400 Bad Request)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected StatusBadRequest (400) from upgrade failure, got %d", rec.Code)
		}
	})

	t.Run("Bootstrap Auto-Registration Success", func(t *testing.T) {
		// Generate a new key pair for an unregistered agent
		newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
		agentID := "unregistered-agent-auto"

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sig := common.SignChallenge(newPriv, agentID, timestamp)
		pubKeyB64 := base64.StdEncoding.EncodeToString(newPub)

		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", sig)
		req.Header.Set("X-Agent-PublicKey", pubKeyB64)
		req.Header.Set("X-Agent-Token", "my-registration-token")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		// Should auto-register, write file, and bypass to upgrade (400 Bad Request)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected StatusBadRequest (400) from auto-registration success, got %d", rec.Code)
		}

		// Verify file was written
		keyPath := filepath.Join(tempDir, agentID+".pub")
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			t.Errorf("expected public key file %s to be written on auto-registration, but it does not exist", keyPath)
		}

		// Verify subsequent connection without the registration token succeeds using the saved key!
		nextTimestamp := strconv.FormatInt(time.Now().Unix(), 10)
		nextSig := common.SignChallenge(newPriv, agentID, nextTimestamp)

		nextReq := httptest.NewRequest("GET", "/ws", nil)
		nextReq.Header.Set("X-Agent-ID", agentID)
		nextReq.Header.Set("X-Agent-Timestamp", nextTimestamp)
		nextReq.Header.Set("X-Agent-Signature", nextSig)

		nextRec := httptest.NewRecorder()
		h.ServeHTTP(nextRec, nextReq)

		if nextRec.Code != http.StatusBadRequest {
			t.Errorf("expected StatusBadRequest (400) on subsequent connection using registered key, got %d", nextRec.Code)
		}
	})

	t.Run("Bootstrap Auto-Registration Failure - Invalid Token", func(t *testing.T) {
		newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
		agentID := "unregistered-agent-fail-token"

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sig := common.SignChallenge(newPriv, agentID, timestamp)
		pubKeyB64 := base64.StdEncoding.EncodeToString(newPub)

		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", sig)
		req.Header.Set("X-Agent-PublicKey", pubKeyB64)
		req.Header.Set("X-Agent-Token", "wrong-registration-token")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected StatusUnauthorized (401) on registration with bad token, got %d", rec.Code)
		}
	})

	t.Run("Bootstrap Auto-Registration Failure - Signature Mismatch", func(t *testing.T) {
		newPub, _, _ := ed25519.GenerateKey(rand.Reader)
		agentID := "unregistered-agent-fail-sig"

		// Sign using a DIFFERENT key than the one we are attempting to register!
		_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sig := common.SignChallenge(wrongPriv, agentID, timestamp)
		pubKeyB64 := base64.StdEncoding.EncodeToString(newPub)

		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Agent-Timestamp", timestamp)
		req.Header.Set("X-Agent-Signature", sig)
		req.Header.Set("X-Agent-PublicKey", pubKeyB64)
		req.Header.Set("X-Agent-Token", "my-registration-token")

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected StatusUnauthorized (401) on registration with bad signature, got %d", rec.Code)
		}
	})

	t.Run("Handle submit_metric Request", func(t *testing.T) {
		h := NewHub("my-secret-token", "my-registration-token", tempDir, false, nil, "", false)

		conn := &AgentConnection{
			ID:   "test-agent-metrics",
			send: make(chan []byte, 1),
			hub:  h,
		}

		sub := common.MetricSubmission{
			TaskID:    "ping-test",
			AgentID:   "test-agent-metrics",
			Method:    "ping",
			Timestamp: time.Now().Unix(),
			Result:    json.RawMessage(`{"host": "8.8.8.8"}`),
		}

		req := common.RPCRequest{
			JSONRPC: "2.0",
			Method:  "submit_metric",
			ID:      "req-1",
		}
		req.Params, _ = json.Marshal(sub)
		rawReq, _ := json.Marshal(req)

		conn.handleIncomingMessage(rawReq)

		select {
		case respBytes := <-conn.send:
			var resp common.RPCResponse
			if err := json.Unmarshal(respBytes, &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}
			if resp.Error != nil {
				t.Errorf("expected no error, got: %s", resp.Error.Message)
			}
			var result string
			_ = json.Unmarshal(resp.Result, &result)
			if result != "success" {
				t.Errorf("expected result to be 'success', got %s", result)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("timed out waiting for response in send channel")
		}
	})
}

func TestHubClustering(t *testing.T) {
	tempDirA, _ := os.MkdirTemp("", "keys_hub_a")
	defer os.RemoveAll(tempDirA)
	tempDirB, _ := os.MkdirTemp("", "keys_hub_b")
	defer os.RemoveAll(tempDirB)

	var hubA, hubB *Hub

	muxB := http.NewServeMux()
	serverB := httptest.NewServer(muxB)
	defer serverB.Close()

	muxA := http.NewServeMux()
	serverA := httptest.NewServer(muxA)
	defer serverA.Close()

	hubA = NewHub("secret-cluster-token", "reg-token", tempDirA, true, []string{serverB.URL}, serverA.URL, true)
	hubB = NewHub("secret-cluster-token", "reg-token", tempDirB, true, []string{serverA.URL}, serverB.URL, true)

	muxA.HandleFunc("/internal/register-peer", func(w http.ResponseWriter, r *http.Request) {
		var reg common.PeerRegistration
		if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
			t.Errorf("A: failed to decode register-peer: %v", err)
			return
		}
		hubA.AddPeer(reg.URL)
		_ = json.NewEncoder(w).Encode(hubA.GetPeers())
	})
	muxA.HandleFunc("/internal/sync-key", func(w http.ResponseWriter, r *http.Request) {
		var req common.KeySyncRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("A: failed to decode sync-key: %v", err)
			return
		}
		if err := hubA.SavePeerPublicKey(req.AgentID, req.PublicKey); err != nil {
			t.Errorf("A: SavePeerPublicKey failed: %v", err)
		}
	})
	muxA.HandleFunc("/internal/sync-schedule", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			type ScheduleSyncRequest struct {
				Schedule common.JobSchedule `json:"schedule"`
				Token    string             `json:"token"`
			}
			var req ScheduleSyncRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			hubA.SavePeerSchedule(req.Schedule)
		} else if r.Method == http.MethodDelete {
			id := r.URL.Query().Get("id")
			hubA.DeletePeerSchedule(id)
		}
	})

	muxB.HandleFunc("/internal/register-peer", func(w http.ResponseWriter, r *http.Request) {
		var reg common.PeerRegistration
		if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
			t.Errorf("B: failed to decode register-peer: %v", err)
			return
		}
		hubB.AddPeer(reg.URL)
		_ = json.NewEncoder(w).Encode(hubB.GetPeers())
	})
	muxB.HandleFunc("/internal/sync-key", func(w http.ResponseWriter, r *http.Request) {
		var req common.KeySyncRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("B: failed to decode sync-key: %v", err)
			return
		}
		if err := hubB.SavePeerPublicKey(req.AgentID, req.PublicKey); err != nil {
			t.Errorf("B: SavePeerPublicKey failed: %v", err)
		}
	})
	muxB.HandleFunc("/internal/sync-schedule", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			type ScheduleSyncRequest struct {
				Schedule common.JobSchedule `json:"schedule"`
				Token    string             `json:"token"`
			}
			var req ScheduleSyncRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			hubB.SavePeerSchedule(req.Schedule)
		} else if r.Method == http.MethodDelete {
			id := r.URL.Query().Get("id")
			hubB.DeletePeerSchedule(id)
		}
	})

	// 1. Test Peer Registration (Announce Hub A to Hub B)
	hubA.RegisterWithPeers()
	time.Sleep(100 * time.Millisecond)

	peersB := hubB.GetPeers()
	found := false
	for _, p := range peersB {
		if p == serverA.URL {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected Hub B to have registered Hub A (%s), active peers: %v", serverA.URL, peersB)
	}

	// 2. Test Key Synchronization (Broadcast key from Hub A to Hub B)
	agentID := "agent-cluster-test"
	testPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyB64 := base64.StdEncoding.EncodeToString(testPub)

	hubA.BroadcastKeySync(agentID, pubKeyB64)
	time.Sleep(100 * time.Millisecond)

	syncedKeyPath := filepath.Join(tempDirB, agentID+".pub")
	if _, err := os.Stat(syncedKeyPath); os.IsNotExist(err) {
		t.Fatalf("Expected Hub B to have written synced public key to %s, but file does not exist", syncedKeyPath)
	}

	loadedKey, err := common.LoadPublicKeyFromFile(syncedKeyPath)
	if err != nil {
		t.Fatalf("Failed to load synced key from Hub B: %v", err)
	}

	if !bytes.Equal(loadedKey, testPub) {
		t.Error("Expected synced public key bytes to match original public key")
	}

	// 3. Test Schedule Synchronization (Add schedule on Hub A, verify it synced to Hub B)
	testSched := common.JobSchedule{
		ID:              "sched-cluster-test",
		AgentID:         agentID,
		Method:          "ping",
		ScheduleType:    "interval",
		IntervalSeconds: 10,
		Params:          json.RawMessage(`{"host":"8.8.8.8"}`),
	}

	// This will internally save the schedule and broadcast it to Hub B
	_ = hubA.AddSchedule(testSched)
	time.Sleep(100 * time.Millisecond)

	// Check if Hub B received it
	hubB.schedulesMu.RLock()
	s, exists := hubB.schedules[testSched.ID]
	hubB.schedulesMu.RUnlock()

	if !exists {
		t.Fatalf("Expected Hub B to have synchronized schedule %s from Hub A, but it was not found", testSched.ID)
	}

	if s.IntervalSeconds != 10 || s.Method != "ping" {
		t.Errorf("Synchronized schedule properties on Hub B do not match: %+v", s)
	}

	// Delete schedule on Hub A
	hubA.DeleteSchedule(testSched.ID)
	time.Sleep(100 * time.Millisecond)

	// Verify Hub B deleted it
	hubB.schedulesMu.RLock()
	_, exists = hubB.schedules[testSched.ID]
	hubB.schedulesMu.RUnlock()

	if exists {
		t.Error("Expected Hub B to have deleted synchronized schedule after deletion on Hub A, but it still exists")
	}
}

func TestDynamicThirdPeer(t *testing.T) {
	tempDirA, _ := os.MkdirTemp("", "keys_hub_a_dynamic")
	defer os.RemoveAll(tempDirA)
	tempDirB, _ := os.MkdirTemp("", "keys_hub_b_dynamic")
	defer os.RemoveAll(tempDirB)
	tempDirC, _ := os.MkdirTemp("", "keys_hub_c_dynamic")
	defer os.RemoveAll(tempDirC)

	var hubA, hubB, hubC *Hub

	// Muxes and HTTP test servers
	muxA := http.NewServeMux()
	serverA := httptest.NewServer(muxA)
	defer serverA.Close()

	muxB := http.NewServeMux()
	serverB := httptest.NewServer(muxB)
	defer serverB.Close()

	muxC := http.NewServeMux()
	serverC := httptest.NewServer(muxC)
	defer serverC.Close()

	// 1. Start Hub A and Hub B knowing only about each other
	hubA = NewHub("secret-cluster-token", "reg-token", tempDirA, true, []string{serverB.URL}, serverA.URL, true)
	hubB = NewHub("secret-cluster-token", "reg-token", tempDirB, true, []string{serverA.URL}, serverB.URL, true)

	// Handlers for dynamic registration
	muxA.HandleFunc("/internal/register-peer", func(w http.ResponseWriter, r *http.Request) {
		var reg common.PeerRegistration
		_ = json.NewDecoder(r.Body).Decode(&reg)
		hubA.AddPeer(reg.URL)
		_ = json.NewEncoder(w).Encode(hubA.GetPeers())
	})
	muxB.HandleFunc("/internal/register-peer", func(w http.ResponseWriter, r *http.Request) {
		var reg common.PeerRegistration
		_ = json.NewDecoder(r.Body).Decode(&reg)
		hubB.AddPeer(reg.URL)
		_ = json.NewEncoder(w).Encode(hubB.GetPeers())
	})
	muxC.HandleFunc("/internal/register-peer", func(w http.ResponseWriter, r *http.Request) {
		var reg common.PeerRegistration
		_ = json.NewDecoder(r.Body).Decode(&reg)
		hubC.AddPeer(reg.URL)
		_ = json.NewEncoder(w).Encode(hubC.GetPeers())
	})

	// Register Hub A and B together
	hubA.RegisterWithPeers()
	time.Sleep(50 * time.Millisecond)

	// 2. Start Hub C knowing ONLY about Hub A (Hub B is completely unplanned)
	hubC = NewHub("secret-cluster-token", "reg-token", tempDirC, true, []string{serverA.URL}, serverC.URL, true)

	// Hub C registers with Hub A
	hubC.RegisterWithPeers()
	time.Sleep(150 * time.Millisecond) // Wait for transitive propagation

	// Verify that Hub B learned about Hub C dynamically!
	peersB := hubB.GetPeers()
	foundCInB := false
	for _, p := range peersB {
		if p == serverC.URL {
			foundCInB = true
			break
		}
	}
	if !foundCInB {
		t.Errorf("Expected Hub B to have discovered Hub C (%s) dynamically, active peers on B: %v", serverC.URL, peersB)
	}

	// Verify that Hub C learned about Hub B dynamically!
	peersC := hubC.GetPeers()
	foundBInC := false
	for _, p := range peersC {
		if p == serverB.URL {
			foundBInC = true
			break
		}
	}
	if !foundBInC {
		t.Errorf("Expected Hub C to have discovered Hub B (%s) dynamically, active peers on C: %v", serverB.URL, peersC)
	}
}

func TestToWSURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://localhost:8080", "ws://localhost:8080/ws"},
		{"http://localhost:8080/", "ws://localhost:8080/ws"},
		{"http://localhost:8080/ws", "ws://localhost:8080/ws"},
		{"https://cluster-peer.internal", "wss://cluster-peer.internal/ws"},
		{"https://cluster-peer.internal/ws", "wss://cluster-peer.internal/ws"},
	}

	for _, tc := range tests {
		got := toWSURL(tc.input)
		if got != tc.expected {
			t.Errorf("toWSURL(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestPeerStateResyncWhenPeerReconnects(t *testing.T) {
	tempDirA, _ := os.MkdirTemp("", "keys_hub_resync_a")
	defer os.RemoveAll(tempDirA)
	tempDirB, _ := os.MkdirTemp("", "keys_hub_resync_b")
	defer os.RemoveAll(tempDirB)

	muxB := http.NewServeMux()
	serverB := httptest.NewServer(muxB)
	defer serverB.Close()

	muxA := http.NewServeMux()
	serverA := httptest.NewServer(muxA)
	defer serverA.Close()

	hubA := NewHub("secret-token", "reg-token", tempDirA, true, []string{serverB.URL}, serverA.URL, true)
	hubB := NewHub("secret-token", "reg-token", tempDirB, true, []string{serverA.URL}, serverB.URL, true)

	muxA.HandleFunc("/internal/sync-key", func(w http.ResponseWriter, r *http.Request) {
		var req common.KeySyncRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = hubA.SavePeerPublicKey(req.AgentID, req.PublicKey)
	})

	muxB.HandleFunc("/internal/sync-key", func(w http.ResponseWriter, r *http.Request) {
		var req common.KeySyncRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = hubB.SavePeerPublicKey(req.AgentID, req.PublicKey)
	})

	muxB.HandleFunc("/internal/register-peer", func(w http.ResponseWriter, r *http.Request) {
		var reg common.PeerRegistration
		_ = json.NewDecoder(r.Body).Decode(&reg)
		hubB.AddPeer(reg.URL)
		_ = json.NewEncoder(w).Encode(hubB.GetPeers())
	})

	// 1. Create a key on Hub B while Hub A is offline / not registered yet
	agentID := "offline-agent-test"
	testPub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Save key locally on Hub B
	keyPathB := filepath.Join(tempDirB, agentID+".pub")
	_ = common.SavePublicKeyPEM(keyPathB, testPub)

	// 2. Hub A now comes online and registers with Hub B
	hubA.RegisterWithPeers()
	time.Sleep(150 * time.Millisecond)

	// 3. Verify that Hub A received the key for offline-agent-test!
	keyPathA := filepath.Join(tempDirA, agentID+".pub")
	if _, err := os.Stat(keyPathA); os.IsNotExist(err) {
		t.Fatalf("Expected Hub A to receive synced key for %s upon reconnecting, but file does not exist", agentID)
	}

	loadedKey, err := common.LoadPublicKeyFromFile(keyPathA)
	if err != nil {
		t.Fatalf("Failed to load synced key on Hub A: %v", err)
	}

	if !bytes.Equal(loadedKey, testPub) {
		t.Error("Expected synced key bytes on Hub A to match key generated on Hub B")
	}
}

func TestClusterDispatchProxying(t *testing.T) {
	tempDirA, _ := os.MkdirTemp("", "keys_hub_dispatch_a")
	defer os.RemoveAll(tempDirA)
	tempDirB, _ := os.MkdirTemp("", "keys_hub_dispatch_b")
	defer os.RemoveAll(tempDirB)

	muxB := http.NewServeMux()
	serverB := httptest.NewServer(muxB)
	defer serverB.Close()

	muxA := http.NewServeMux()
	serverA := httptest.NewServer(muxA)
	defer serverA.Close()

	hubA := NewHub("secret-token", "reg-token", tempDirA, true, []string{serverB.URL}, serverA.URL, true)

	// Mock /dispatch on serverB that handles proxied requests
	muxB.HandleFunc("/dispatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AgentID string `json:"agent_id"`
			Method  string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.AgentID == "proxyD" {
			_ = json.NewEncoder(w).Encode(common.RPCResponse{
				JSONRPC: "2.0",
				Result:  json.RawMessage(`{"status":"success_from_hub_b"}`),
				ID:      "test-1",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "agent not connected",
				"code":  404,
			})
		}
	})

	// Dispatch from Hub A to proxyD (which is NOT connected to Hub A, but peer Hub B is configured)
	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()
	rpcResp, err := hubA.DispatchJob(reqCtx, "proxyD", "ping", nil)
	if err != nil {
		t.Fatalf("Expected Hub A to proxy dispatch request to Hub B successfully, got error: %v", err)
	}

	if rpcResp == nil || string(rpcResp.Result) != `{"status":"success_from_hub_b"}` {
		t.Errorf("Expected RPC response from Hub B, got %+v", rpcResp)
	}
}
