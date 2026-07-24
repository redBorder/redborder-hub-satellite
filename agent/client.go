package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"redborder-hub-satellite/common"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 512 * 1024 // 512 KB
)

// Agent manages the client WebSocket connection and job execution.
type Agent struct {
	hubURLs            []string
	activeURLIdx       int
	token              string
	id                 string
	privateKey         ed25519.PrivateKey
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
	isClosed           bool
	mu                 sync.Mutex
	session            *agentSession
	cache              *DiskCache
	serverSchedules    []common.ScheduledTask
	triggerFlush       chan struct{}
	schedCtx           context.Context
	schedCancel        context.CancelFunc
	schedulesCachePath string
	insecureSkipVerify bool
	customCommands     map[string]CustomCommandConfig
}

// NewAgent creates a new Agent instance.
func NewAgent(hubURL, token, id string, privateKey ed25519.PrivateKey, cachePath string) *Agent {
	ctx, cancel := context.WithCancel(context.Background())
	if cachePath == "" {
		cachePath = "redborder-satellite-cache.json"
	}
	schedulesCachePath := "redborder-satellite-schedules.json"

	var urls []string
	for _, u := range strings.Split(hubURL, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		urls = []string{"ws://localhost:8080/ws"}
	}

	a := &Agent{
		hubURLs:            urls,
		activeURLIdx:       0,
		token:              token,
		id:                 id,
		privateKey:         privateKey,
		ctx:                ctx,
		cancel:             cancel,
		cache:              NewDiskCache(cachePath),
		triggerFlush:       make(chan struct{}, 1),
		schedulesCachePath: schedulesCachePath,
	}

	// Load previously synchronized server schedules from cache file
	if data, err := os.ReadFile(schedulesCachePath); err == nil {
		var loaded []common.ScheduledTask
		if err := json.Unmarshal(data, &loaded); err == nil {
			a.serverSchedules = loaded
			log.Printf("Loaded %d cached server schedules from disk", len(loaded))
		}
	}

	return a
}

// SetCustomCommands configures the custom command execution engine registry.
func (a *Agent) SetCustomCommands(cmds map[string]CustomCommandConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.customCommands = cmds
}

// SetInsecureSkipVerify configures whether TLS certificate verification is bypassed.
func (a *Agent) SetInsecureSkipVerify(insecure bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.insecureSkipVerify = insecure
}

// Start initiates the reconnection loop. It blocks until the context is canceled.
func (a *Agent) Start() {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	a.mu.Lock()
	a.schedCtx, a.schedCancel = context.WithCancel(a.ctx)
	a.mu.Unlock()

	a.startServerScheduler()
	go a.startFlushLoop()

	for {
		select {
		case <-a.ctx.Done():
			log.Println("Agent stopping...")
			return
		default:
		}

		a.mu.Lock()
		currentURL := a.hubURLs[a.activeURLIdx]
		a.mu.Unlock()

		log.Printf("Connecting to Hub at %s...", currentURL)
		err := a.connectAndRun(currentURL, func() {
			backoff = 1 * time.Second
		})
		if err != nil {
			a.mu.Lock()
			a.activeURLIdx = (a.activeURLIdx + 1) % len(a.hubURLs)
			nextURL := a.hubURLs[a.activeURLIdx]
			a.mu.Unlock()

			log.Printf("Connection error: %v. Switched target Hub to %s. Reconnecting in %v...", err, nextURL, backoff)
			select {
			case <-a.ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff with ceiling
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			// Reset backoff on successful session
			backoff = 1 * time.Second
		}
	}
}

// Stop stops the agent and closes any active connections.
func (a *Agent) Stop() {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return
	}
	a.isClosed = true
	session := a.session
	a.mu.Unlock()

	a.cancel()

	if session != nil {
		_ = session.Close()
	}

	a.wg.Wait()
	log.Println("Agent stopped gracefully.")
}

// agentSession holds the active WebSocket connection and handles thread-safe writing.
type agentSession struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// Close closes the WebSocket connection thread-safely.
func (s *agentSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close()
}

// WriteMessage sends a WebSocket message thread-safely.
func (s *agentSession) WriteMessage(messageType int, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return s.conn.WriteMessage(messageType, data)
}

func (a *Agent) connectAndRun(url string, onConnect func()) error {
	headers := http.Header{}
	headers.Set("X-Agent-Token", a.token)
	headers.Set("X-Agent-ID", a.id)

	if a.privateKey != nil {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := common.SignChallenge(a.privateKey, a.id, timestamp)
		headers.Set("X-Agent-Timestamp", timestamp)
		headers.Set("X-Agent-Signature", signature)

		pubKeyBytes := a.privateKey.Public().(ed25519.PublicKey)
		headers.Set("X-Agent-PublicKey", base64.StdEncoding.EncodeToString(pubKeyBytes))
	}

	a.mu.Lock()
	insecure := a.insecureSkipVerify
	a.mu.Unlock()

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}

	conn, resp, err := dialer.DialContext(a.ctx, url, headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial failed with status %s (%d): %w", resp.Status, resp.StatusCode, err)
		}
		return fmt.Errorf("dial failed: %w", err)
	}
	defer func() {
		a.mu.Lock()
		a.session = nil
		a.mu.Unlock()
		conn.Close()
	}()

	log.Printf("Connected successfully to Hub. Session established.")
	if onConnect != nil {
		onConnect()
	}

	session := &agentSession{conn: conn}
	a.mu.Lock()
	a.session = session
	a.mu.Unlock()

	// Trigger immediate flush of cached metrics upon connection
	select {
	case a.triggerFlush <- struct{}{}:
	default:
	}

	// Set up deadlines and keepalives.
	// Since Server initiates pings, we listen for pings and respond with pong.
	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))

	// Override the default ping handler to ensure it writes the pong message
	// under the connection's write mutex.
	conn.SetPingHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return session.WriteMessage(websocket.PongMessage, []byte(appData))
	})

	// Add worker WaitGroup to track running job goroutines during connection teardown
	var jobWg sync.WaitGroup
	defer jobWg.Wait()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Connection closed unexpectedly: %v", err)
			} else {
				log.Printf("Read error: %v", err)
			}
			return err
		}

		jobWg.Add(1)
		go func(msg []byte) {
			defer jobWg.Done()
			a.handleRequest(msg, session)
		}(message)
	}
}

func (a *Agent) handleRequest(message []byte, session *agentSession) {
	// First check if it is a JSON-RPC response (from submit_metric confirmations)
	var responseCheck common.RPCResponse
	if err := json.Unmarshal(message, &responseCheck); err == nil && (responseCheck.Result != nil || responseCheck.Error != nil) {
		// fire-and-forget logic
		return
	}

	var req common.RPCRequest
	if err := json.Unmarshal(message, &req); err != nil {
		log.Printf("Failed to unmarshal JSON-RPC request: %v", err)
		errResp := common.NewRPCErrorResponse(nil, common.ErrParseError, "Parse error", err.Error())
		raw, _ := json.Marshal(errResp)
		_ = session.WriteMessage(websocket.TextMessage, raw)
		return
	}

	// Validate JSON-RPC 2.0 version
	if req.JSONRPC != "2.0" {
		errResp := common.NewRPCErrorResponse(req.ID, common.ErrInvalidRequest, "Invalid Request: missing or invalid jsonrpc version", nil)
		raw, _ := json.Marshal(errResp)
		_ = session.WriteMessage(websocket.TextMessage, raw)
		return
	}

	log.Printf("Received job request: ID=%v, Method=%s", req.ID, req.Method)

	var result interface{}
	var runErr error

	// Dispatch to the proper execution handler
	switch req.Method {
	case "sync_schedules":
		var newScheds []common.ScheduledTask
		if err := json.Unmarshal(req.Params, &newScheds); err != nil {
			log.Printf("Failed to unmarshal sync_schedules params: %v", err)
			errResp := common.NewRPCErrorResponse(req.ID, common.ErrInvalidParams, "Invalid params", err.Error())
			raw, _ := json.Marshal(errResp)
			_ = session.WriteMessage(websocket.TextMessage, raw)
			return
		}

		a.SyncSchedules(newScheds)

		resp, _ := common.NewRPCResponse(req.ID, "success")
		raw, _ := json.Marshal(resp)
		_ = session.WriteMessage(websocket.TextMessage, raw)
		return

	case "update_failover_urls":
		var newURLs []string
		if err := json.Unmarshal(req.Params, &newURLs); err != nil {
			log.Printf("Failed to unmarshal update_failover_urls params: %v", err)
			errResp := common.NewRPCErrorResponse(req.ID, common.ErrInvalidParams, "Invalid params", err.Error())
			raw, _ := json.Marshal(errResp)
			_ = session.WriteMessage(websocket.TextMessage, raw)
			return
		}

		if len(newURLs) > 0 {
			a.mu.Lock()
			a.hubURLs = newURLs
			a.activeURLIdx = 0
			a.mu.Unlock()
			log.Printf("Updated local failover Hub list from server: %v", newURLs)
		}

		resp, _ := common.NewRPCResponse(req.ID, "success")
		raw, _ := json.Marshal(resp)
		_ = session.WriteMessage(websocket.TextMessage, raw)
		return

	case "ping":
		result, runErr = executePing(a.ctx, req.Params)
	case "snmpwalk":
		result, runErr = executeSNMPWalk(a.ctx, req.Params)
	case "snmpget", "snmp":
		result, runErr = executeSNMPGet(a.ctx, req.Params)
	case "traceroute":
		result, runErr = executeTraceroute(a.ctx, req.Params)
	default:
		a.mu.Lock()
		cmdCfg, exists := a.customCommands[req.Method]
		a.mu.Unlock()

		if exists {
			result, runErr = executeCustomCommand(a.ctx, req.Method, cmdCfg, req.Params)
		} else {
			runErr = fmt.Errorf("method not found: %s", req.Method)
			errResp := common.NewRPCErrorResponse(req.ID, common.ErrMethodNotFound, runErr.Error(), nil)
			raw, _ := json.Marshal(errResp)
			_ = session.WriteMessage(websocket.TextMessage, raw)
			return
		}
	}

	var resp *common.RPCResponse
	if runErr != nil {
		log.Printf("Job execution failed: ID=%v, Error=%v", req.ID, runErr)
		resp = common.NewRPCErrorResponse(req.ID, common.ErrInternalError, runErr.Error(), nil)
	} else {
		log.Printf("Job execution succeeded: ID=%v", req.ID)
		var err error
		resp, err = common.NewRPCResponse(req.ID, result)
		if err != nil {
			log.Printf("Failed to format response payload: %v", err)
			resp = common.NewRPCErrorResponse(req.ID, common.ErrInternalError, "Failed to marshal response result", nil)
		}
	}

	rawResp, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to marshal full response: %v", err)
		return
	}

	if err := session.WriteMessage(websocket.TextMessage, rawResp); err != nil {
		log.Printf("Failed to send response back to Hub: %v", err)
	}
}

// --- Job Execution Handlers ---

func executePing(ctx context.Context, rawParams json.RawMessage) (interface{}, error) {
	var params common.PingParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil, fmt.Errorf("failed to parse params: %w", err)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	result, err := runPingCommand(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("ping execution failed: %w", err)
	}
	return result, nil
}

func runPingCommand(ctx context.Context, params common.PingParams) (*common.PingResult, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(params.Timeout)*time.Second)
	defer cancel()

	// Linux ping syntax: ping -c <count> -W <timeout_seconds> <host>
	cmd := exec.CommandContext(timeoutCtx, "ping", "-c", strconv.Itoa(params.Count), "-W", strconv.Itoa(params.Timeout), params.Host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ping command failed (exit status %v, output: %q)", err, string(out))
	}

	return parsePingOutput(params.Host, string(out))
}

func parsePingOutput(host string, output string) (*common.PingResult, error) {
	result := &common.PingResult{
		Host:      host,
		RawOutput: output,
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "packets transmitted") {
			// Format: "4 packets transmitted, 4 received, 0% packet loss, time 3062ms"
			parts := strings.Split(line, ",")
			if len(parts) >= 3 {
				// Parse transmitted
				txPart := strings.TrimSpace(strings.ReplaceAll(parts[0], "packets transmitted", ""))
				tx, _ := strconv.Atoi(txPart)
				result.PacketsSent = tx

				// Parse received
				rxPart := strings.TrimSpace(strings.ReplaceAll(parts[1], "received", ""))
				rx, _ := strconv.Atoi(rxPart)
				result.PacketsReceived = rx

				// Parse loss
				lossPart := strings.TrimSpace(strings.ReplaceAll(parts[2], "packet loss", ""))
				lossPart = strings.ReplaceAll(lossPart, "%", "")
				loss, _ := strconv.ParseFloat(lossPart, 64)
				result.PacketLoss = loss
			}
		} else if strings.HasPrefix(line, "rtt min/avg/max/mdev") || strings.HasPrefix(line, "round-trip min/avg/max/stddev") {
			// Format: "rtt min/avg/max/mdev = 0.031/0.045/0.061/0.012 ms"
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				statsPart := strings.TrimSpace(parts[1])
				statsPart = strings.ReplaceAll(statsPart, " ms", "")
				stats := strings.Split(statsPart, "/")
				if len(stats) >= 3 {
					result.MinRTT, _ = strconv.ParseFloat(stats[0], 64)
					result.AvgRTT, _ = strconv.ParseFloat(stats[1], 64)
					result.MaxRTT, _ = strconv.ParseFloat(stats[2], 64)
				}
			}
		}
	}

	// Fallback if parsing missed totals but ping succeeded
	if result.PacketsSent == 0 {
		return nil, errors.New("failed to parse ping command output statistics")
	}

	return result, nil
}

func executeSNMPWalk(ctx context.Context, rawParams json.RawMessage) (interface{}, error) {
	var params common.SNMPWalkParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil, fmt.Errorf("failed to parse params: %w", err)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	result, err := runSNMPWalkCommand(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("snmpwalk execution failed: %w", err)
	}
	return result, nil
}

func runSNMPWalkCommand(ctx context.Context, params common.SNMPWalkParams) (*common.SNMPWalkResult, error) {
	if _, err := exec.LookPath("snmpwalk"); err != nil {
		return nil, errors.New("snmpwalk command not found in PATH")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(params.Timeout)*time.Second)
	defer cancel()

	cliArgs := params.BuildCLIArgs()
	cmd := exec.CommandContext(timeoutCtx, "snmpwalk", cliArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("snmpwalk failed (exit status %v, output: %q)", err, string(out))
	}

	return parseSNMPWalkOutput(params.Target, params.OID, string(out))
}

func executeSNMPGet(ctx context.Context, rawParams json.RawMessage) (interface{}, error) {
	var params common.SNMPGetParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil, fmt.Errorf("failed to parse params: %w", err)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	result, err := runSNMPGetCommand(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("snmpget execution failed: %w", err)
	}
	return result, nil
}

func runSNMPGetCommand(ctx context.Context, params common.SNMPGetParams) (*common.SNMPGetResult, error) {
	if _, err := exec.LookPath("snmpget"); err != nil {
		return nil, errors.New("snmpget command not found in PATH")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(params.Timeout)*time.Second)
	defer cancel()

	cliArgs := params.BuildCLIArgs()
	cmd := exec.CommandContext(timeoutCtx, "snmpget", cliArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("snmpget failed (exit status %v, output: %q)", err, string(out))
	}

	return parseSNMPWalkOutput(params.Target, params.OID, string(out))
}

func parseSNMPWalkOutput(target string, reqOID string, output string) (*common.SNMPWalkResult, error) {
	result := &common.SNMPWalkResult{
		Target:    target,
		OID:       reqOID,
		RawOutput: output,
		Entries:   []common.SNMPWalkEntry{},
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			oid := strings.TrimSpace(parts[0])
			valPart := strings.TrimSpace(parts[1])

			typeVal := strings.SplitN(valPart, ":", 2)
			var valType, val string
			if len(typeVal) == 2 {
				valType = strings.TrimSpace(typeVal[0])
				val = strings.TrimSpace(typeVal[1])
			} else {
				valType = "UNKNOWN"
				val = valPart
			}

			result.Entries = append(result.Entries, common.SNMPWalkEntry{
				OID:   oid,
				Type:  valType,
				Value: val,
			})
		}
	}

	return result, nil
}

func executeTraceroute(ctx context.Context, rawParams json.RawMessage) (interface{}, error) {
	var params common.TracerouteParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil, fmt.Errorf("failed to parse params: %w", err)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	result, err := runTracerouteCommand(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("traceroute execution failed: %w", err)
	}
	return result, nil
}

func runTracerouteCommand(ctx context.Context, params common.TracerouteParams) (*common.TracerouteResult, error) {
	if _, err := exec.LookPath("traceroute"); err != nil {
		return nil, errors.New("traceroute command not found in PATH")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(params.Timeout)*time.Second)
	defer cancel()

	// Command: traceroute -w <timeout> -m <max_hops> <host>
	cmd := exec.CommandContext(timeoutCtx, "traceroute", "-w", strconv.Itoa(params.Timeout), "-m", strconv.Itoa(params.MaxHops), params.Host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("traceroute failed (exit status %v, output: %q)", err, string(out))
	}

	return parseTracerouteOutput(params.Host, string(out))
}

func parseTracerouteOutput(host string, output string) (*common.TracerouteResult, error) {
	result := &common.TracerouteResult{
		Host:      host,
		RawOutput: output,
		Hops:      []common.TracerouteHop{},
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "traceroute to") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		hopNum, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		hop := common.TracerouteHop{
			Hop:  hopNum,
			RTTs: []float64{},
		}

		if fields[1] == "*" {
			hop.Host = "*"
			hop.IP = "*"
			result.Hops = append(result.Hops, hop)
			continue
		}

		hop.Host = fields[1]
		rttStartIndex := 2
		if len(fields) > 2 && strings.HasPrefix(fields[2], "(") && strings.HasSuffix(fields[2], ")") {
			hop.IP = strings.Trim(fields[2], "()")
			rttStartIndex = 3
		} else {
			hop.IP = hop.Host
		}

		for i := rttStartIndex; i < len(fields); i++ {
			token := fields[i]
			if token == "*" {
				continue
			}
			if val, err := strconv.ParseFloat(token, 64); err == nil {
				if i+1 < len(fields) && fields[i+1] == "ms" {
					hop.RTTs = append(hop.RTTs, val)
					i++
				}
			}
		}

		result.Hops = append(result.Hops, hop)
	}

	return result, nil
}

func (a *Agent) startServerScheduler() {
	if len(a.serverSchedules) == 0 {
		return
	}

	for _, task := range a.serverSchedules {
		go func(t common.ScheduledTask) {
			if t.IntervalSeconds <= 0 {
				log.Printf("[Server Schedule] Running one-off task %q (%s) immediately", t.ID, t.Method)
				a.runScheduledTask(t)
				return
			}

			interval := time.Duration(t.IntervalSeconds) * time.Second
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			log.Printf("[Server Schedule] Starting scheduler for task %q (%s, every %d seconds)", t.ID, t.Method, t.IntervalSeconds)

			// Run initially after 1 second
			select {
			case <-a.schedCtx.Done():
				return
			case <-time.After(1 * time.Second):
				a.runScheduledTask(t)
			}

			for {
				select {
				case <-a.schedCtx.Done():
					return
				case <-ticker.C:
					a.runScheduledTask(t)
				}
			}
		}(task)
	}
}

func (a *Agent) SyncSchedules(newScheds []common.ScheduledTask) {
	a.mu.Lock()
	defer a.mu.Unlock()

	log.Printf("Synchronizing %d server schedules from Hub...", len(newScheds))

	// Save to local cache file
	if data, err := json.Marshal(newScheds); err == nil {
		_ = os.WriteFile(a.schedulesCachePath, data, 0600)
	}

	a.serverSchedules = newScheds

	// Stop any currently running server schedules
	if a.schedCancel != nil {
		a.schedCancel()
	}

	// Create a new context for these server schedules
	a.schedCtx, a.schedCancel = context.WithCancel(a.ctx)

	// Start new server schedules
	a.startServerScheduler()
}

func (a *Agent) runScheduledTask(t common.ScheduledTask) {
	log.Printf("Executing scheduled task %q...", t.ID)

	var result interface{}
	var err error

	switch t.Method {
	case "ping":
		result, err = executePing(a.ctx, t.Params)
	case "snmpwalk":
		result, err = executeSNMPWalk(a.ctx, t.Params)
	case "snmpget", "snmp":
		result, err = executeSNMPGet(a.ctx, t.Params)
	case "traceroute":
		result, err = executeTraceroute(a.ctx, t.Params)
	default:
		a.mu.Lock()
		cmdCfg, exists := a.customCommands[t.Method]
		a.mu.Unlock()

		if exists {
			result, err = executeCustomCommand(a.ctx, t.Method, cmdCfg, t.Params)
		} else {
			log.Printf("Skipping scheduled task %q: unknown method %q", t.ID, t.Method)
			return
		}
	}

	var rawResult json.RawMessage
	var errStr string
	if err != nil {
		errStr = err.Error()
	} else if result != nil {
		rawResult, _ = json.Marshal(result)
	}

	submission := common.MetricSubmission{
		TaskID:    t.ID,
		AgentID:   a.id,
		Method:    t.Method,
		Timestamp: time.Now().Unix(),
		Result:    rawResult,
		Error:     errStr,
	}

	if err := a.cache.Add(submission); err != nil {
		log.Printf("Failed to cache scheduled task %q result: %v", t.ID, err)
	} else {
		// Signal immediate flush attempt
		select {
		case a.triggerFlush <- struct{}{}:
		default:
		}
	}
}

func (a *Agent) startFlushLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.flushCache()
		case <-a.triggerFlush:
			a.flushCache()
		}
	}
}

func (a *Agent) flushCache() {
	a.mu.Lock()
	session := a.session
	a.mu.Unlock()

	if session == nil {
		return // Not connected
	}

	subs, err := a.cache.PopAll()
	if err != nil || len(subs) == 0 {
		return
	}

	log.Printf("Flushing %d cached job results to Hub...", len(subs))

	sentCount := 0
	for _, sub := range subs {
		reqID := fmt.Sprintf("metric-%d-%s", sub.Timestamp, sub.TaskID)
		req := common.RPCRequest{
			JSONRPC: "2.0",
			Method:  "submit_metric",
			ID:      reqID,
		}
		req.Params, _ = json.Marshal(sub)

		rawReq, err := json.Marshal(req)
		if err != nil {
			log.Printf("Failed to marshal metric submission: %v", err)
			continue
		}

		if err := session.WriteMessage(websocket.TextMessage, rawReq); err != nil {
			log.Printf("Failed to send metric submission to Hub: %v", err)
			break
		}
		sentCount++
	}

	if sentCount > 0 {
		if err := a.cache.RemoveOldest(sentCount); err != nil {
			log.Printf("Failed to update disk cache: %v", err)
		}
	}
}

// --- Custom Command Engine ---

func executeCustomCommand(ctx context.Context, methodName string, cmdCfg CustomCommandConfig, rawParams json.RawMessage) (interface{}, error) {
	var paramMap map[string]interface{}
	if len(rawParams) > 0 && string(rawParams) != "null" {
		if err := json.Unmarshal(rawParams, &paramMap); err != nil {
			return nil, fmt.Errorf("invalid parameters JSON for custom command %q: %w", methodName, err)
		}
	}
	if paramMap == nil {
		paramMap = make(map[string]interface{})
	}

	if cmdCfg.Type == "file_read" {
		return executeFileRead(cmdCfg, paramMap)
	}

	return executeCustomBinary(ctx, methodName, cmdCfg, paramMap)
}

func executeFileRead(cmdCfg CustomCommandConfig, params map[string]interface{}) (interface{}, error) {
	pathVal, ok := params["path"].(string)
	if !ok || pathVal == "" {
		pathVal, ok = params["file"].(string)
	}
	if !ok || pathVal == "" {
		return nil, errors.New("missing required parameter 'path' or 'file'")
	}

	cleanPath := filepath.Clean(pathVal)

	matched := false
	if len(cmdCfg.AllowedPaths) == 0 {
		return nil, errors.New("no allowed_paths configured for this file_read command")
	}
	for _, pattern := range cmdCfg.AllowedPaths {
		cleanPattern := filepath.Clean(pattern)
		if m, err := filepath.Match(cleanPattern, cleanPath); err == nil && m {
			matched = true
			break
		}
		if strings.HasPrefix(cleanPath, cleanPattern) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("access to file %q is forbidden by configuration", cleanPath)
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access file %q: %w", cleanPath, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("path %q is a directory, not a file", cleanPath)
	}

	maxBytes := cmdCfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024 // 1 MB default limit
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %q: %w", cleanPath, err)
	}
	defer file.Close()

	buf := make([]byte, maxBytes)
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("failed to read file %q: %w", cleanPath, err)
	}

	return map[string]interface{}{
		"path":       cleanPath,
		"size_bytes": info.Size(),
		"read_bytes": n,
		"content":    string(buf[:n]),
		"truncated":  info.Size() > int64(n),
	}, nil
}

func executeCustomBinary(ctx context.Context, methodName string, cmdCfg CustomCommandConfig, params map[string]interface{}) (interface{}, error) {
	if cmdCfg.Executable == "" {
		return nil, fmt.Errorf("no executable path configured for custom command %q", methodName)
	}

	for paramName, rule := range cmdCfg.ParamRules {
		val, exists := params[paramName]
		if !exists || val == nil {
			if rule.Required {
				return nil, fmt.Errorf("missing required parameter %q for command %q", paramName, methodName)
			}
			continue
		}
		strVal := fmt.Sprintf("%v", val)

		if len(rule.AllowedValues) > 0 {
			allowed := false
			for _, v := range rule.AllowedValues {
				if v == strVal {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("invalid value %q for parameter %q (allowed values: %v)", strVal, paramName, rule.AllowedValues)
			}
		}

		if rule.Regex != "" {
			re, err := regexp.Compile(rule.Regex)
			if err != nil {
				return nil, fmt.Errorf("invalid regex rule in config for parameter %q: %w", paramName, err)
			}
			if !re.MatchString(strVal) {
				return nil, fmt.Errorf("parameter %q value %q fails security validation regex %q", paramName, strVal, rule.Regex)
			}
		}
	}

	finalArgs := make([]string, 0, len(cmdCfg.Args))
	for _, arg := range cmdCfg.Args {
		if strings.HasPrefix(arg, "$") {
			paramName := strings.TrimPrefix(arg, "$")
			val, exists := params[paramName]
			if exists && val != nil {
				finalArgs = append(finalArgs, fmt.Sprintf("%v", val))
			}
		} else {
			finalArgs = append(finalArgs, arg)
		}
	}

	timeoutSec := cmdCfg.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, cmdCfg.Executable, finalArgs...)
	if len(cmdCfg.Env) > 0 {
		cmd.Env = append(os.Environ(), cmdCfg.Env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	durationMs := time.Since(startTime).Milliseconds()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("failed to execute command %q (%s): %w", methodName, cmdCfg.Executable, err)
		}
	}

	maxBytes := cmdCfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 512 * 1024
	}

	outStr := stdout.String()
	errStr := stderr.String()
	if int64(len(outStr)) > maxBytes {
		outStr = outStr[:maxBytes] + "\n...[truncated]"
	}
	if int64(len(errStr)) > maxBytes {
		errStr = errStr[:maxBytes] + "\n...[truncated]"
	}

	return map[string]interface{}{
		"executable":  cmdCfg.Executable,
		"args":        finalArgs,
		"exit_code":   exitCode,
		"duration_ms": durationMs,
		"stdout":      outStr,
		"stderr":      errStr,
	}, nil
}
