package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"redborder-hub-satellite/common"
	"redborder-hub-satellite/hub"
)

type errorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Error: message,
		Code:  statusCode,
	})
}

func main() {
	// 1. Define command-line flags
	configPath := flag.String("config", "", "Path to JSON configuration file")
	tokenFlag := flag.String("token", "super-secret-agent-token", "Secret authentication token (fallback)")
	regTokenFlag := flag.String("reg-token", "", "Token used for auto-registering new public keys (fallback)")
	addrFlag := flag.String("addr", ":8080", "TCP address to listen on (fallback)")
	keysDirFlag := flag.String("keys-dir", "authorized_keys", "Directory containing authorized agent public keys (fallback)")
	debugFlag := flag.Bool("debug", false, "Enable verbose debug logging")
	peersFlag := flag.String("peers", "", "Comma-separated seed peer URLs (fallback)")
	myURLFlag := flag.String("my-url", "", "Public URL of this Hub instance (fallback)")
	advertisePeersFlag := flag.Bool("advertise-peers", true, "Advertise cluster peers to connected agents (fallback)")
	flag.Parse()

	var finalAddr, finalToken, finalRegToken, finalKeysDir string
	var finalDebug bool
	var finalPeers []string
	var finalMyURL string
	var finalAdvertisePeers bool

	// 2. Resolve config from file if path is specified
	if *configPath != "" {
		log.Printf("Loading configuration from file: %s", *configPath)
		cfg, err := hub.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Error loading config file: %v", err)
		}
		finalAddr = cfg.Addr
		finalToken = cfg.AuthToken
		finalRegToken = cfg.RegistrationToken
		finalKeysDir = cfg.AuthorizedKeysDir
		finalDebug = cfg.Debug
		finalPeers = cfg.Peers
		finalMyURL = cfg.MyURL
		finalAdvertisePeers = cfg.AdvertisePeers
	} else {
		// Use CLI flags / Env vars as fallback
		finalAddr = *addrFlag
		finalToken = os.Getenv("REDBORDER_AUTH_TOKEN")
		if finalToken == "" {
			finalToken = *tokenFlag
		}
		finalRegToken = os.Getenv("REDBORDER_REG_TOKEN")
		if finalRegToken == "" {
			finalRegToken = *regTokenFlag
		}
		finalKeysDir = *keysDirFlag
		finalDebug = *debugFlag
		finalMyURL = *myURLFlag
		finalAdvertisePeers = *advertisePeersFlag
		if *peersFlag != "" {
			for _, p := range strings.Split(*peersFlag, ",") {
				finalPeers = append(finalPeers, strings.TrimSpace(p))
			}
		}
	}

	h := hub.NewHub(finalToken, finalRegToken, finalKeysDir, finalDebug, finalPeers, finalMyURL, finalAdvertisePeers)

	// HTTP routes
	// 1. WebSocket connection endpoint for satellites
	http.Handle("/ws", h)

	// 2. Control/Management endpoint to list active satellites
	http.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		agents := h.GetConnectedAgents()
		_ = json.NewEncoder(w).Encode(agents)
	})

	// 3. Control/Management endpoint to dispatch jobs to satellites
	http.HandleFunc("/dispatch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			AgentID string          `json:"agent_id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.AgentID == "" || req.Method == "" {
			writeJSONError(w, "agent_id and method are required fields", http.StatusBadRequest)
			return
		}

		// Allow slightly longer timeout for executions (15 seconds)
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		isProxy := r.Header.Get("X-Cluster-Proxy") == "true"
		allowProxy := !isProxy

		resp, err := h.DispatchJob(ctx, req.AgentID, req.Method, req.Params, allowProxy)
		if err != nil {
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "is not connected") {
				status = http.StatusNotFound
			} else if strings.Contains(err.Error(), "context deadline exceeded") {
				status = http.StatusGatewayTimeout
			}
			writeJSONError(w, err.Error(), status)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 4. REST endpoint to list, create, and delete job schedules
	http.HandleFunc("/schedules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			scheds := h.GetSchedules()
			_ = json.NewEncoder(w).Encode(scheds)

		case http.MethodPost:
			var sched common.JobSchedule
			if err := json.NewDecoder(r.Body).Decode(&sched); err != nil {
				writeJSONError(w, "Invalid JSON body", http.StatusBadRequest)
				return
			}

			if sched.ID == "" || sched.AgentID == "" || sched.Method == "" || sched.ScheduleType == "" {
				writeJSONError(w, "id, agent_id, method, and schedule_type are required fields", http.StatusBadRequest)
				return
			}

			if sched.ScheduleType != "once" && sched.ScheduleType != "interval" && sched.ScheduleType != "at" {
				writeJSONError(w, "schedule_type must be 'once', 'interval', or 'at'", http.StatusBadRequest)
				return
			}

			if sched.ScheduleType == "interval" && sched.IntervalSeconds <= 0 {
				writeJSONError(w, "interval_seconds must be > 0 for interval schedules", http.StatusBadRequest)
				return
			}

			if sched.ScheduleType == "at" && sched.RunAt <= 0 {
				writeJSONError(w, "run_at timestamp must be > 0 for at schedules", http.StatusBadRequest)
				return
			}

			if err := h.AddSchedule(sched); err != nil {
				writeJSONError(w, fmt.Sprintf("Failed to add schedule: %v", err), http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "Schedule created"})

		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			if id == "" {
				writeJSONError(w, "Missing 'id' query parameter", http.StatusBadRequest)
				return
			}

			h.DeleteSchedule(id)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "Schedule deleted"})

		default:
			writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// 5. Internal endpoint to register peer Hubs dynamically
	http.HandleFunc("/internal/register-peer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var reg common.PeerRegistration
		if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
			writeJSONError(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if reg.URL == "" || reg.Token == "" {
			writeJSONError(w, "url and token are required fields", http.StatusBadRequest)
			return
		}

		// Simple shared-token auth for peer hubs
		if reg.Token != finalToken {
			writeJSONError(w, "Unauthorized peer registration", http.StatusUnauthorized)
			return
		}

		h.AddPeer(reg.URL)

		// Respond with the list of currently known peers
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.GetPeers())
	})

	// 6. Internal endpoint to synchronize keys from peer Hubs
	http.HandleFunc("/internal/sync-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req common.KeySyncRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.AgentID == "" || req.PublicKey == "" || req.Token == "" {
			writeJSONError(w, "agent_id, public_key, and token are required fields", http.StatusBadRequest)
			return
		}

		// Simple shared-token auth for peer hubs
		if req.Token != finalToken {
			writeJSONError(w, "Unauthorized key synchronization", http.StatusUnauthorized)
			return
		}

		if err := h.SavePeerPublicKey(req.AgentID, req.PublicKey); err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "Key synchronized"})
	})

	// 7. Internal endpoint to synchronize schedules from peer Hubs
	http.HandleFunc("/internal/sync-schedule", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			type ScheduleSyncRequest struct {
				Schedule common.JobSchedule `json:"schedule"`
				Token    string             `json:"token"`
			}
			var req ScheduleSyncRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, "Invalid JSON body", http.StatusBadRequest)
				return
			}
			if req.Token != finalToken {
				writeJSONError(w, "Unauthorized schedule synchronization", http.StatusUnauthorized)
				return
			}
			h.SavePeerSchedule(req.Schedule)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "Schedule synchronized"})

		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			token := r.URL.Query().Get("token")
			if id == "" {
				writeJSONError(w, "Missing 'id' query parameter", http.StatusBadRequest)
				return
			}
			if token != finalToken {
				writeJSONError(w, "Unauthorized schedule deletion", http.StatusUnauthorized)
				return
			}
			h.DeletePeerSchedule(id)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "Schedule synchronized delete"})

		default:
			writeJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Start background peer sync loop to maintain mesh connectivity and state sync with peers
	go func() {
		// Initial attempt after startup
		time.Sleep(1 * time.Second)
		h.RegisterWithPeers()

		// Periodic background retry loop every 15 seconds
		ticker := time.NewTicker(15 * time.Second)
		for range ticker.C {
			h.RegisterWithPeers()
		}
	}()

	log.Printf("redborder-hub Server listening on HTTP %s...", finalAddr)
	log.Printf("  WebSocket satellite endpoint: ws://localhost%s/ws", finalAddr)
	log.Printf("  API Get Connected Satellites: GET http://localhost%s/agents", finalAddr)
	log.Printf("  API Dispatch Job to Satellite: POST http://localhost%s/dispatch", finalAddr)
	log.Printf("  API Manage Schedules: GET/POST/DELETE http://localhost%s/schedules", finalAddr)
	if finalMyURL != "" {
		log.Printf("  Hub Public URL: %s", finalMyURL)
	}
	if len(finalPeers) > 0 {
		log.Printf("  Cluster Seed Peers: %v", finalPeers)
	}
	
	if err := http.ListenAndServe(finalAddr, nil); err != nil {
		log.Fatalf("Server ListenAndServe failed: %v", err)
	}
}
