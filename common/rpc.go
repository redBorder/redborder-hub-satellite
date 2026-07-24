package common

import "encoding/json"

// RPCRequest represents a JSON-RPC 2.0 request payload.
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

// RPCResponse represents a JSON-RPC 2.0 response payload.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Predefined JSON-RPC error codes
const (
	ErrParseError     = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternalError  = -32603
)

// NewRPCResponse creates a successful RPC response.
func NewRPCResponse(id interface{}, result interface{}) (*RPCResponse, error) {
	rawResult, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &RPCResponse{
		JSONRPC: "2.0",
		Result:  rawResult,
		ID:      id,
	}, nil
}

// NewRPCErrorResponse creates an error RPC response.
func NewRPCErrorResponse(id interface{}, code int, message string, data interface{}) *RPCResponse {
	return &RPCResponse{
		JSONRPC: "2.0",
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
}

// ScheduledTask defines a periodic job schedule on the Agent.
type ScheduledTask struct {
	ID              string          `json:"id"`
	IntervalSeconds int             `json:"interval_seconds"`
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params"`
}

// MetricSubmission represents the payload sent by the Agent to report cached or scheduled task results.
type MetricSubmission struct {
	TaskID    string          `json:"task_id"`
	AgentID   string          `json:"agent_id"`
	Method    string          `json:"method"`
	Timestamp int64           `json:"timestamp"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// JobSchedule defines a schedule configured on the Hub for a specific Agent.
type JobSchedule struct {
	ID              string          `json:"id"`
	AgentID         string          `json:"agent_id"`
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params"`
	ScheduleType    string          `json:"schedule_type"` // "once", "interval", "at"
	IntervalSeconds int             `json:"interval_seconds,omitempty"`
	RunAt           int64           `json:"run_at,omitempty"` // Unix timestamp
}

// PeerRegistration contains connection information announced by peer Hubs on startup.
type PeerRegistration struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// KeySyncRequest represents a public key synchronization command broadcast to peer Hubs.
type KeySyncRequest struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
	Token     string `json:"token"`
}
