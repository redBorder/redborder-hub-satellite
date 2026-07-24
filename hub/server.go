package hub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"redborder-hub-satellite/common"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512 * 1024 // 512 KB
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			// In a production environment, you should validate the Origin header
			// to prevent Cross-Site WebSocket Hijacking.
			return true
		},
	}

	agentIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
)

// AgentConnection represents a persistent WebSocket connection to a remote agent.
type AgentConnection struct {
	ID        string
	conn      *websocket.Conn
	send      chan []byte
	hub       *Hub
	done      chan struct{}
	closeOnce sync.Once

	// Atomic request ID generator for Hub-initiated requests
	requestID uint64

	// Track pending JSON-RPC requests on this connection
	pendingMu sync.Mutex
	pending   map[string]chan *common.RPCResponse
}

// NewAgentConnection creates a new connection state.
func NewAgentConnection(id string, conn *websocket.Conn, hub *Hub) *AgentConnection {
	return &AgentConnection{
		ID:      id,
		conn:    conn,
		send:    make(chan []byte, 256),
		hub:     hub,
		done:    make(chan struct{}),
		pending: make(map[string]chan *common.RPCResponse),
	}
}

// Close gracefully closes the agent connection.
func (c *AgentConnection) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		c.conn.Close()
		c.hub.unregister(c.ID)

		// Terminate all pending RPC calls on this connection
		c.pendingMu.Lock()
		for _, ch := range c.pending {
			close(ch)
		}
		c.pending = nil
		c.pendingMu.Unlock()
		log.Printf("Agent connection closed: %s", c.ID)
	})
}

// NextRequestID returns a unique ID for JSON-RPC messages.
func (c *AgentConnection) NextRequestID() string {
	id := atomic.AddUint64(&c.requestID, 1)
	return fmt.Sprintf("%s-%d", c.ID, id)
}

// readPump pumps messages from the websocket connection to the hub.
func (c *AgentConnection) readPump() {
	defer func() {
		c.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		if c.hub.debug {
			log.Printf("[DEBUG] Received Pong from Agent %s", c.ID)
		}
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Agent %s read error: %v", c.ID, err)
			}
			break
		}

		c.handleIncomingMessage(message)
	}
}

// writePump pumps messages from the hub to the websocket connection.
func (c *AgentConnection) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()

	for {
		select {
		case <-c.done:
			return
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("Agent %s write error: %v", c.ID, err)
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if c.hub.debug {
				log.Printf("[DEBUG] Sending Ping to Agent %s", c.ID)
			}
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Agent %s ping error: %v", c.ID, err)
				return
			}
		}
	}
}

// handleIncomingMessage parses messages received from the Agent.
func (c *AgentConnection) handleIncomingMessage(message []byte) {
	if c.hub.debug {
		log.Printf("[DEBUG] Received message from Agent %s: %s", c.ID, string(message))
	}
	// First check if it is a JSON-RPC response
	var resp common.RPCResponse
	if err := json.Unmarshal(message, &resp); err == nil && resp.ID != nil && (resp.Result != nil || resp.Error != nil) {
		if idStr, ok := resp.ID.(string); ok {
			c.pendingMu.Lock()
			ch, exists := c.pending[idStr]
			if exists {
				delete(c.pending, idStr)
				c.pendingMu.Unlock()
				ch <- &resp
				close(ch)
				return
			}
			c.pendingMu.Unlock()
			return // Ignore or debug log async confirmations
		}
	}

	// Check if it's a request instead (in case Agents send requests to Hub)
	var req common.RPCRequest
	if err := json.Unmarshal(message, &req); err == nil && req.Method != "" {
		if req.Method == "submit_metric" {
			var sub common.MetricSubmission
			if err := json.Unmarshal(req.Params, &sub); err == nil {
				log.Printf("Hub received metric submission from Agent %s: Task=%s, Method=%s, Timestamp=%d", c.ID, sub.TaskID, sub.Method, sub.Timestamp)
				if c.hub.debug {
					log.Printf("[DEBUG] Metric Result: %s", string(sub.Result))
					if sub.Error != "" {
						log.Printf("[DEBUG] Metric Error: %s", sub.Error)
					}
				}

				resp, _ := common.NewRPCResponse(req.ID, "success")
				rawResp, _ := json.Marshal(resp)
				select {
				case c.send <- rawResp:
				default:
					log.Printf("Dropped response payload for agent %s: channel full", c.ID)
				}
				return
			}
		}

		log.Printf("Hub received unhandled request from Agent %s: %s", c.ID, req.Method)
		errResp := common.NewRPCErrorResponse(req.ID, common.ErrMethodNotFound, "Method not supported on Hub", nil)
		rawErr, _ := json.Marshal(errResp)
		select {
		case c.send <- rawErr:
		default:
			log.Printf("Dropped response payload for agent %s: channel full", c.ID)
		}
		return
	}

	log.Printf("Hub received unhandled or invalid message from Agent %s: %s", c.ID, string(message))
}

// Hub manages the active agent connections and routes jobs.
type Hub struct {
	mu                sync.RWMutex
	connections       map[string]*AgentConnection
	authToken         string
	registrationToken string
	authorizedKeysDir string
	debug             bool
	schedulesMu       sync.RWMutex
	schedules         map[string]common.JobSchedule
	peersMu           sync.RWMutex
	peers             map[string]bool
	myURL             string
	advertisePeers    bool
}

// NewHub creates a new Hub instance.
func NewHub(authToken, registrationToken, authorizedKeysDir string, debug bool, seedPeers []string, myURL string, advertisePeers bool) *Hub {
	peersMap := make(map[string]bool)
	for _, p := range seedPeers {
		if p != "" {
			peersMap[p] = true
		}
	}
	return &Hub{
		connections:       make(map[string]*AgentConnection),
		authToken:         authToken,
		registrationToken: registrationToken,
		authorizedKeysDir: authorizedKeysDir,
		debug:             debug,
		schedules:         make(map[string]common.JobSchedule),
		peers:             peersMap,
		myURL:             myURL,
		advertisePeers:    advertisePeers,
	}
}

// register adds a connection to the hub.
func (h *Hub) register(conn *AgentConnection) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// If a connection already exists with this ID, close it
	if old, exists := h.connections[conn.ID]; exists {
		log.Printf("Replacing existing connection for Agent %s", conn.ID)
		old.Close()
	}

	h.connections[conn.ID] = conn
	log.Printf("Agent connected: %s", conn.ID)
	return nil
}

// unregister removes a connection from the hub.
func (h *Hub) unregister(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.connections, id)
}

// GetConnectedAgents returns a list of currently connected agent IDs.
func (h *Hub) GetConnectedAgents() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	agents := make([]string, 0, len(h.connections))
	for id := range h.connections {
		agents = append(agents, id)
	}
	return agents
}

// AddSchedule registers a new scheduled job and triggers synchronization to the Agent.
func (h *Hub) AddSchedule(sched common.JobSchedule) error {
	h.schedulesMu.Lock()
	h.schedules[sched.ID] = sched
	h.schedulesMu.Unlock()

	h.SyncAgentSchedules(sched.AgentID)
	h.BroadcastScheduleSync(sched)
	return nil
}

// DeleteSchedule removes a scheduled job and updates the Agent.
func (h *Hub) DeleteSchedule(id string) {
	h.schedulesMu.Lock()
	sched, exists := h.schedules[id]
	if exists {
		delete(h.schedules, id)
	}
	h.schedulesMu.Unlock()

	if exists {
		h.SyncAgentSchedules(sched.AgentID)
		h.BroadcastScheduleDelete(id)
	}
}

// SavePeerSchedule saves a schedule synchronized from a peer Hub without rebroadcasting.
func (h *Hub) SavePeerSchedule(sched common.JobSchedule) {
	h.schedulesMu.Lock()
	h.schedules[sched.ID] = sched
	h.schedulesMu.Unlock()

	h.SyncAgentSchedules(sched.AgentID)
}

// DeletePeerSchedule deletes a schedule synchronized from a peer Hub without rebroadcasting.
func (h *Hub) DeletePeerSchedule(id string) {
	h.schedulesMu.Lock()
	sched, exists := h.schedules[id]
	if exists {
		delete(h.schedules, id)
	}
	h.schedulesMu.Unlock()

	if exists {
		h.SyncAgentSchedules(sched.AgentID)
	}
}

// BroadcastScheduleSync sends a newly added or updated schedule to all peer Hubs.
func (h *Hub) BroadcastScheduleSync(sched common.JobSchedule) {
	peers := h.GetPeers()
	if len(peers) == 0 {
		return
	}

	for _, p := range peers {
		if p == h.myURL {
			continue
		}
		go func(peerURL string) {
			url := fmt.Sprintf("%s/internal/sync-schedule", peerURL)
			if h.debug {
				log.Printf("[DEBUG] Broadcasting schedule %s sync to peer Hub: %s", sched.ID, url)
			}

			type ScheduleSyncRequest struct {
				Schedule common.JobSchedule `json:"schedule"`
				Token    string             `json:"token"`
			}
			req := ScheduleSyncRequest{
				Schedule: sched,
				Token:    h.authToken,
			}
			data, _ := json.Marshal(req)
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
			if err != nil {
				log.Printf("Failed to broadcast schedule sync to peer Hub %s: %v", peerURL, err)
				return
			}
			resp.Body.Close()
		}(p)
	}
}

// BroadcastScheduleDelete sends a schedule deletion request to all peer Hubs.
func (h *Hub) BroadcastScheduleDelete(id string) {
	peers := h.GetPeers()
	if len(peers) == 0 {
		return
	}

	for _, p := range peers {
		if p == h.myURL {
			continue
		}
		go func(peerURL string) {
			url := fmt.Sprintf("%s/internal/sync-schedule?id=%s&token=%s", peerURL, id, h.authToken)
			if h.debug {
				log.Printf("[DEBUG] Broadcasting schedule %s deletion to peer Hub: %s", id, url)
			}

			req, err := http.NewRequest(http.MethodDelete, url, nil)
			if err != nil {
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("Failed to broadcast schedule delete to peer Hub %s: %v", peerURL, err)
				return
			}
			resp.Body.Close()
		}(p)
	}
}

// GetSchedules returns all registered schedules.
func (h *Hub) GetSchedules() []common.JobSchedule {
	h.schedulesMu.RLock()
	defer h.schedulesMu.RUnlock()

	list := make([]common.JobSchedule, 0, len(h.schedules))
	for _, s := range h.schedules {
		list = append(list, s)
	}
	return list
}

// GetWebSocketPeerURLs returns the client-facing WebSocket URLs of all known Hub peers.
func (h *Hub) GetWebSocketPeerURLs() []string {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()

	urls := []string{}
	if h.myURL != "" {
		urls = append(urls, toWSURL(h.myURL))
	}
	for p := range h.peers {
		urls = append(urls, toWSURL(p))
	}
	return urls
}

func toWSURL(httpURL string) string {
	ws := httpURL
	if strings.HasPrefix(ws, "https://") {
		ws = "wss://" + strings.TrimPrefix(ws, "https://")
	} else if strings.HasPrefix(ws, "http://") {
		ws = "ws://" + strings.TrimPrefix(ws, "http://")
	}
	if !strings.HasSuffix(ws, "/ws") {
		ws = strings.TrimSuffix(ws, "/") + "/ws"
	}
	return ws
}

// PushFailoverURLs sends the list of active Hub WebSocket URLs to a connected Agent.
func (h *Hub) PushFailoverURLs(agentID string) {
	h.mu.RLock()
	conn, exists := h.connections[agentID]
	h.mu.RUnlock()
	if !exists {
		return
	}

	wsURLs := h.GetWebSocketPeerURLs()
	if len(wsURLs) == 0 {
		return
	}

	reqID := fmt.Sprintf("failover-%d", time.Now().UnixNano())
	req := common.RPCRequest{
		JSONRPC: "2.0",
		Method:  "update_failover_urls",
	}
	req.Params, _ = json.Marshal(wsURLs)
	req.ID = reqID

	rawReq, err := json.Marshal(req)
	if err != nil {
		log.Printf("Failed to marshal update_failover_urls for Agent %s: %v", agentID, err)
		return
	}

	select {
	case conn.send <- rawReq:
		if h.debug {
			log.Printf("[DEBUG] Pushed %d failover URLs to Agent %s", len(wsURLs), agentID)
		}
	default:
		log.Printf("Failed to push failover URLs to Agent %s: channel full", agentID)
	}
}

// SyncAgentSchedules pushes the active schedules for a specific agent over WebSocket.
func (h *Hub) SyncAgentSchedules(agentID string) {
	h.mu.RLock()
	conn, exists := h.connections[agentID]
	h.mu.RUnlock()

	if !exists {
		return
	}

	h.schedulesMu.RLock()
	var agentScheds []common.ScheduledTask
	for _, s := range h.schedules {
		if s.AgentID == agentID {
			var interval int
			if s.ScheduleType == "interval" {
				interval = s.IntervalSeconds
			} else if s.ScheduleType == "at" {
				timeDiff := s.RunAt - time.Now().Unix()
				if timeDiff < 0 {
					continue // past schedule
				}
				interval = int(timeDiff)
			} // "once" is interval = 0, meaning run once immediately

			agentScheds = append(agentScheds, common.ScheduledTask{
				ID:              s.ID,
				IntervalSeconds: interval,
				Method:          s.Method,
				Params:          s.Params,
			})
		}
	}
	h.schedulesMu.RUnlock()

	reqID := fmt.Sprintf("sync-%d", time.Now().UnixNano())
	req := common.RPCRequest{
		JSONRPC: "2.0",
		Method:  "sync_schedules",
		ID:      reqID,
	}
	req.Params, _ = json.Marshal(agentScheds)

	rawReq, err := json.Marshal(req)
	if err != nil {
		log.Printf("Failed to marshal sync_schedules for Agent %s: %v", agentID, err)
		return
	}

	select {
	case conn.send <- rawReq:
		if h.debug {
			log.Printf("[DEBUG] Dispatched sync_schedules to Agent %s (%d tasks)", agentID, len(agentScheds))
		}
	default:
		log.Printf("Failed to send sync_schedules to Agent %s: channel full", agentID)
	}
}

// AddPeer registers a new peer Hub dynamically.
// AddPeer registers a new peer Hub dynamically and synchronizes state to it.
func (h *Hub) AddPeer(peerURL string) {
	if peerURL == "" || peerURL == h.myURL {
		return
	}

	h.peersMu.Lock()
	exists := h.peers[peerURL]
	h.peers[peerURL] = true
	h.peersMu.Unlock()

	log.Printf("Peer Hub connected/registered: %s. Synchronizing state...", peerURL)
	go h.SyncAllToPeer(peerURL)

	if !exists && h.myURL != "" {
		// Announce self to this new peer to form a bidirectional relationship
		go func() {
			reg := common.PeerRegistration{
				URL:   h.myURL,
				Token: h.authToken,
			}
			data, _ := json.Marshal(reg)
			url := fmt.Sprintf("%s/internal/register-peer", peerURL)
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
			if err != nil {
				log.Printf("Failed to announce self to newly discovered peer Hub %s: %v", peerURL, err)
				return
			}
			resp.Body.Close()
		}()
	}
}

// GetPeers returns the list of all active peer Hubs.
func (h *Hub) GetPeers() []string {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()
	list := make([]string, 0, len(h.peers))
	for p := range h.peers {
		list = append(list, p)
	}
	return list
}

// SyncAllToPeer synchronizes all local authorized public keys and job schedules to a peer Hub.
func (h *Hub) SyncAllToPeer(peerURL string) {
	if peerURL == "" || peerURL == h.myURL {
		return
	}

	// 1. Synchronize all authorized public keys from local keys directory
	if h.authorizedKeysDir != "" {
		files, err := os.ReadDir(h.authorizedKeysDir)
		if err == nil {
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".pub") {
					agentID := strings.TrimSuffix(file.Name(), ".pub")
					keyPath := filepath.Join(h.authorizedKeysDir, file.Name())
					pubKey, errLoad := common.LoadPublicKeyFromFile(keyPath)
					if errLoad == nil {
						pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)
						req := common.KeySyncRequest{
							AgentID:   agentID,
							PublicKey: pubKeyB64,
							Token:     h.authToken,
						}
						data, _ := json.Marshal(req)
						url := fmt.Sprintf("%s/internal/sync-key", peerURL)
						resp, errPost := http.Post(url, "application/json", bytes.NewBuffer(data))
						if errPost == nil {
							resp.Body.Close()
							if h.debug {
								log.Printf("[DEBUG] Synced key for agent %q to peer Hub %s", agentID, peerURL)
							}
						}
					}
				}
			}
		}
	}

	// 2. Synchronize all active schedules
	schedules := h.GetSchedules()
	for _, sched := range schedules {
		type ScheduleSyncRequest struct {
			Schedule common.JobSchedule `json:"schedule"`
			Token    string             `json:"token"`
		}
		req := ScheduleSyncRequest{
			Schedule: sched,
			Token:    h.authToken,
		}
		data, _ := json.Marshal(req)
		url := fmt.Sprintf("%s/internal/sync-schedule", peerURL)
		resp, errPost := http.Post(url, "application/json", bytes.NewBuffer(data))
		if errPost == nil {
			resp.Body.Close()
			if h.debug {
				log.Printf("[DEBUG] Synced schedule %q to peer Hub %s", sched.ID, peerURL)
			}
		}
	}
}

// RegisterWithPeers registers this Hub node dynamically with all seed/discovered peers and syncs state.
func (h *Hub) RegisterWithPeers() {
	if h.myURL == "" {
		return
	}

	peers := h.GetPeers()
	for _, p := range peers {
		if p == h.myURL {
			continue
		}
		go func(peerURL string) {
			reg := common.PeerRegistration{
				URL:   h.myURL,
				Token: h.authToken, // reuse the cluster authToken
			}
			data, _ := json.Marshal(reg)

			url := fmt.Sprintf("%s/internal/register-peer", peerURL)
			if h.debug {
				log.Printf("[DEBUG] Connecting/registering with peer Hub: %s", url)
			}
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
			if err != nil {
				log.Printf("Failed to register with peer Hub %s: %v", peerURL, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				log.Printf("Successfully registered with peer Hub: %s. Synchronizing state...", peerURL)
				// Synchronize all existing keys and schedules to the peer
				go h.SyncAllToPeer(peerURL)

				// Learn their peers list
				var peerList []string
				if err := json.NewDecoder(resp.Body).Decode(&peerList); err == nil {
					for _, newPeer := range peerList {
						if newPeer != h.myURL {
							h.AddPeer(newPeer)
						}
					}
				}
			} else {
				log.Printf("Failed to register with peer Hub %s, status: %d", peerURL, resp.StatusCode)
			}
		}(p)
	}
}

// BroadcastKeySync sends a newly registered Agent key to all other Hub peers.
func (h *Hub) BroadcastKeySync(agentID string, pubKeyB64 string) {
	peers := h.GetPeers()
	if len(peers) == 0 {
		return
	}

	for _, p := range peers {
		if p == h.myURL {
			continue
		}
		go func(peerURL string) {
			req := common.KeySyncRequest{
				AgentID:   agentID,
				PublicKey: pubKeyB64,
				Token:     h.authToken,
			}
			data, _ := json.Marshal(req)
			url := fmt.Sprintf("%s/internal/sync-key", peerURL)
			if h.debug {
				log.Printf("[DEBUG] Broadcasting Agent %s key sync to peer Hub: %s", agentID, url)
			}
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
			if err != nil {
				log.Printf("Failed to broadcast key sync to peer Hub %s: %v", peerURL, err)
				return
			}
			resp.Body.Close()
		}(p)
	}
}

// SavePeerPublicKey writes a synced public key from a peer Hub to local disk.
func (h *Hub) SavePeerPublicKey(agentID string, pubKeyB64 string) error {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	if errDir := os.MkdirAll(h.authorizedKeysDir, 0755); errDir != nil {
		return fmt.Errorf("failed to create keys directory: %w", errDir)
	}

	keyPath := filepath.Join(h.authorizedKeysDir, agentID+".pub")
	err = common.SavePublicKeyPEM(keyPath, ed25519.PublicKey(pubKeyBytes))
	if err != nil {
		return fmt.Errorf("failed to save public key to file: %w", err)
	}

	log.Printf("Agent %q public key synchronized from peer Hub. Saved to %s.", agentID, keyPath)
	return nil
}

// DispatchJobToPeer forwards a job dispatch request to a peer Hub in the cluster.
func (h *Hub) DispatchJobToPeer(ctx context.Context, peerURL string, agentID string, method string, params interface{}) (*common.RPCResponse, error) {
	var reqBody struct {
		AgentID string      `json:"agent_id"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params"`
	}
	reqBody.AgentID = agentID
	reqBody.Method = method
	reqBody.Params = params

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/dispatch", peerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-Proxy", "true") // Prevent forwarding loops

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach peer Hub %s: %w", peerURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var rpcResp common.RPCResponse
		if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
			return nil, fmt.Errorf("failed to decode RPC response from peer: %w", err)
		}
		return &rpcResp, nil
	}

	type errResp struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	var errBody errResp
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err == nil && errBody.Error != "" {
		return nil, errors.New(errBody.Error)
	}

	return nil, fmt.Errorf("peer Hub %s returned status %d", peerURL, resp.StatusCode)
}

// DispatchJob sends a JSON-RPC request to a specific agent and waits for the response.
// If the agent is not connected locally, it automatically forwards the request to cluster peers.
func (h *Hub) DispatchJob(ctx context.Context, agentID string, method string, params interface{}, allowProxy ...bool) (*common.RPCResponse, error) {
	shouldProxy := true
	if len(allowProxy) > 0 {
		shouldProxy = allowProxy[0]
	}

	h.mu.RLock()
	agent, ok := h.connections[agentID]
	h.mu.RUnlock()
	if !ok {
		if shouldProxy {
			peers := h.GetPeers()
			for _, peerURL := range peers {
				if peerURL == h.myURL {
					continue
				}
				log.Printf("Agent %q not connected locally. Forwarding dispatch request to peer Hub %s...", agentID, peerURL)
				rpcResp, err := h.DispatchJobToPeer(ctx, peerURL, agentID, method, params)
				if err == nil && rpcResp != nil {
					return rpcResp, nil
				}
			}
		}
		return nil, fmt.Errorf("agent %q is not connected", agentID)
	}

	reqID := agent.NextRequestID()

	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal params: %w", err)
	}

	req := common.RPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  rawParams,
		ID:      reqID,
	}

	rawReq, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Register pending channel for the response
	ch := make(chan *common.RPCResponse, 1)
	agent.pendingMu.Lock()
	if agent.pending == nil {
		agent.pendingMu.Unlock()
		return nil, errors.New("agent connection is closed")
	}
	agent.pending[reqID] = ch
	agent.pendingMu.Unlock()

	// Ensure cleanup if context gets canceled or function exits
	defer func() {
		agent.pendingMu.Lock()
		if agent.pending != nil {
			delete(agent.pending, reqID)
		}
		agent.pendingMu.Unlock()
	}()

	// Send to agent write queue
	if h.debug {
		log.Printf("[DEBUG] Sending request to Agent %s: %s", agentID, string(rawReq))
	}
	select {
	case agent.send <- rawReq:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-agent.done:
		return nil, errors.New("agent disconnected before request could be sent")
	}

	// Wait for response
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errors.New("agent connection closed while waiting for response")
		}
		if h.debug {
			rawResp, _ := json.Marshal(resp)
			log.Printf("[DEBUG] Received response from Agent %s: %s", agentID, string(rawResp))
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ServeHTTP implements the http.Handler interface for handling WebSocket connection requests.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Validate agent ID first (required for both key and token validation)
	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		agentID = r.URL.Query().Get("agent_id")
	}

	if agentID == "" {
		log.Printf("Rejected connection from %s: missing agent ID", r.RemoteAddr)
		http.Error(w, "Bad Request: X-Agent-ID header or agent_id query param required", http.StatusBadRequest)
		return
	}

	// Validate agent ID format to prevent directory traversal when loading keys
	if !agentIDRegex.MatchString(agentID) {
		log.Printf("Rejected connection from %s: invalid agent ID format %q", r.RemoteAddr, agentID)
		http.Error(w, "Bad Request: invalid agent ID format", http.StatusBadRequest)
		return
	}

	// 2. Authenticate connection request
	signature := r.Header.Get("X-Agent-Signature")
	if signature == "" {
		signature = r.URL.Query().Get("signature")
	}

	timestampStr := r.Header.Get("X-Agent-Timestamp")
	if timestampStr == "" {
		timestampStr = r.URL.Query().Get("timestamp")
	}

	if signature != "" && timestampStr != "" {
		// Use asymmetric signature auth
		if h.authorizedKeysDir == "" {
			log.Printf("Rejected connection from %s: signature provided but authorized keys directory not configured on Hub", r.RemoteAddr)
			http.Error(w, "Unauthorized: signature auth not supported by Hub", http.StatusUnauthorized)
			return
		}

		// 2.1 Verify Timestamp skew (prevent replay attacks)
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			log.Printf("Rejected connection from %s: invalid timestamp format %q", r.RemoteAddr, timestampStr)
			http.Error(w, "Unauthorized: invalid timestamp", http.StatusUnauthorized)
			return
		}

		now := time.Now().Unix()
		skew := now - timestamp
		if skew < 0 {
			skew = -skew
		}
		if skew > 120 { // 2 minutes max skew
			log.Printf("Rejected connection from %s: replay protection rejected timestamp %q (skew %d seconds)", r.RemoteAddr, timestampStr, skew)
			http.Error(w, "Unauthorized: timestamp expired", http.StatusUnauthorized)
			return
		}

		// 2.2 Load Agent public key
		keyPath := filepath.Join(h.authorizedKeysDir, agentID+".pub")
		pubKey, err := common.LoadPublicKeyFromFile(keyPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Retrieve the registration token from headers or query parameters
				regToken := r.Header.Get("X-Agent-Token")
				if regToken == "" {
					regToken = r.URL.Query().Get("token")
				}

				pubKeyBase64 := r.Header.Get("X-Agent-PublicKey")
				if pubKeyBase64 == "" {
					pubKeyBase64 = r.URL.Query().Get("public_key")
				}

				expectedRegToken := h.registrationToken
				if expectedRegToken == "" {
					expectedRegToken = h.authToken
				}

				if expectedRegToken != "" && regToken == expectedRegToken && pubKeyBase64 != "" {
					// Validate public key payload
					pubKeyBytes, decodeErr := base64.StdEncoding.DecodeString(pubKeyBase64)
					if decodeErr != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
						log.Printf("Rejected auto-registration from %s for agent %q: invalid base64 public key", r.RemoteAddr, agentID)
						http.Error(w, "Unauthorized: invalid registration public key", http.StatusUnauthorized)
						return
					}

					// Verify challenge signature first using this candidate public key to prove private key possession
					candidateKey := ed25519.PublicKey(pubKeyBytes)
					if !common.VerifyChallenge(candidateKey, agentID, timestampStr, signature) {
						log.Printf("Rejected auto-registration from %s for agent %q: challenge signature verification failed", r.RemoteAddr, agentID)
						http.Error(w, "Unauthorized: registration signature verification failed", http.StatusUnauthorized)
						return
					}

					// Ensure authorized keys directory exists
					if errDir := os.MkdirAll(h.authorizedKeysDir, 0755); errDir != nil {
						log.Printf("Internal error creating authorized keys directory %s: %v", h.authorizedKeysDir, errDir)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					// Save public key
					if errSave := common.SavePublicKeyPEM(keyPath, candidateKey); errSave != nil {
						log.Printf("Internal error saving registered public key to %s: %v", keyPath, errSave)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					log.Printf("Agent %q automatically registered successfully. Public key saved to %s.", agentID, keyPath)
					h.BroadcastKeySync(agentID, pubKeyBase64)
					pubKey = candidateKey
				} else {
					log.Printf("Rejected connection from %s: public key file not found for agent %q at %s, and registration token was missing or invalid", r.RemoteAddr, agentID, keyPath)
					http.Error(w, "Unauthorized: agent key not authorized", http.StatusUnauthorized)
					return
				}
			} else {
				log.Printf("Rejected connection from %s: failed to load public key for agent %q from %s: %v", r.RemoteAddr, agentID, keyPath, err)
				http.Error(w, "Unauthorized: unauthorized agent key", http.StatusUnauthorized)
				return
			}
		}

		// 2.3 Verify challenge signature
		if !common.VerifyChallenge(pubKey, agentID, timestampStr, signature) {
			log.Printf("Rejected connection from %s: invalid signature for agent %q", r.RemoteAddr, agentID)
			http.Error(w, "Unauthorized: signature verification failed", http.StatusUnauthorized)
			return
		}

		log.Printf("Agent %q successfully authenticated via asymmetric key signature.", agentID)

	} else {
		// Fallback to token authentication
		// If a public key is registered for this agentID, mandate signature authentication to prevent identity takeover
		if h.authorizedKeysDir != "" {
			keyPath := filepath.Join(h.authorizedKeysDir, agentID+".pub")
			if _, err := os.Stat(keyPath); err == nil {
				log.Printf("Rejected connection from %s: agent %q is registered with a public key but attempted token-only authentication", r.RemoteAddr, agentID)
				http.Error(w, "Unauthorized: signature authentication required for registered agent", http.StatusUnauthorized)
				return
			}
		}

		token := r.Header.Get("X-Agent-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if h.authToken == "" || token != h.authToken {
			log.Printf("Rejected connection from %s: unauthorized token", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		log.Printf("Agent %q successfully authenticated via token.", agentID)
	}

	// 3. Upgrade to websocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection from %s: %v", r.RemoteAddr, err)
		return
	}

	// 4. Register connection
	agentConn := NewAgentConnection(agentID, conn, h)
	if err := h.register(agentConn); err != nil {
		log.Printf("Failed to register agent %s: %v", agentID, err)
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, err.Error()))
		conn.Close()
		return
	}

	// 5. Start read and write pumps
	go agentConn.writePump()
	go agentConn.readPump()

	// 6. Push active schedules to the Agent
	h.SyncAgentSchedules(agentID)

	// 7. Push active Hub failover URLs to the Agent if enabled
	if h.advertisePeers {
		h.PushFailoverURLs(agentID)
	}
}
