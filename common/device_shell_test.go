package common

import (
	"strings"
	"testing"
)

func TestDeviceShellParamsValidate(t *testing.T) {
	valid := func() DeviceShellParams {
		return DeviceShellParams{
			Host:     "10.0.0.1",
			Username: "admin",
			Password: "secret",
			Commands: []string{"terminal length 0", "show running-config"},
			PromptResponses: []DeviceShellPromptResponse{
				{Pattern: `(?i)password:\s*\z`, Response: "secret\n"},
			},
		}
	}

	params := valid()
	if err := params.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if params.Port != 22 || params.ConnectTimeout != 20 || params.IdleTimeout != 20 || params.MaxSession != 180 {
		t.Errorf("defaults not applied: port=%d connect=%d idle=%d max=%d",
			params.Port, params.ConnectTimeout, params.IdleTimeout, params.MaxSession)
	}
	if len(params.CompiledPrompts) != 1 {
		t.Errorf("CompiledPrompts has %d entries, want 1", len(params.CompiledPrompts))
	}

	tests := []struct {
		name    string
		modify  func(*DeviceShellParams)
		wantErr string
	}{
		{"empty host", func(p *DeviceShellParams) { p.Host = " " }, "host cannot be empty"},
		{"unsafe host", func(p *DeviceShellParams) { p.Host = "10.0.0.1; rm -rf /" }, "invalid or unsafe host"},
		{"bad port", func(p *DeviceShellParams) { p.Port = 70000 }, "port must be"},
		{"empty username", func(p *DeviceShellParams) { p.Username = "" }, "username cannot be empty"},
		{"no commands", func(p *DeviceShellParams) { p.Commands = nil }, "at least one command"},
		{"line break in command", func(p *DeviceShellParams) { p.Commands = []string{"show run\nreload"} }, "line breaks"},
		{"invalid pattern", func(p *DeviceShellParams) {
			p.PromptResponses = []DeviceShellPromptResponse{{Pattern: `(?<=x)`, Response: ""}}
		}, "invalid prompt pattern"},
		{"empty pattern", func(p *DeviceShellParams) {
			p.PromptResponses = []DeviceShellPromptResponse{{Pattern: "", Response: ""}}
		}, "prompt pattern must be"},
		{"idle timeout too long", func(p *DeviceShellParams) { p.IdleTimeout = 301 }, "idle_timeout exceeds"},
		{"session too long", func(p *DeviceShellParams) { p.MaxSession = 901 }, "max_session exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := valid()
			tt.modify(&p)
			err := p.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
