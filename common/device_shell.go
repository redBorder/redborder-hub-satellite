package common

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	deviceShellMaxCommands        = 20
	deviceShellMaxPromptResponses = 20
	deviceShellMaxPatternLength   = 512
	deviceShellMaxResponseLength  = 1024
)

// DeviceShellPromptResponse is one "answer this prompt" rule for a device_shell job:
// whenever the device's latest output ends matching Pattern (Go RE2 syntax), Response is
// typed back. Rules are tried in order and only the first match is answered.
type DeviceShellPromptResponse struct {
	Pattern  string `json:"pattern"`
	Response string `json:"response"`
}

// DeviceShellParams defines the input parameters for a device_ssh_shell job: an
// interactive (pty-backed) SSH session to a network device that types Commands in order
// and answers prompts, for device CLIs that reject the SSH "exec" channel request.
type DeviceShellParams struct {
	Host            string                      `json:"host"`
	Port            int                         `json:"port"` // Default 22
	Username        string                      `json:"username"`
	Password        string                      `json:"password"`
	Commands        []string                    `json:"commands"`
	PromptResponses []DeviceShellPromptResponse `json:"prompt_responses"`
	ConnectTimeout  int                         `json:"connect_timeout"` // Default 20, Max 60 (seconds)
	IdleTimeout     int                         `json:"idle_timeout"`    // Default 20, Max 300 (seconds)
	MaxSession      int                         `json:"max_session"`     // Default 180, Max 900 (seconds)

	// CompiledPrompts holds PromptResponses' patterns, compiled by Validate.
	CompiledPrompts []*regexp.Regexp `json:"-"`
}

// Validate checks if the device shell parameters are safe and valid, and compiles the
// prompt patterns.
func (d *DeviceShellParams) Validate() error {
	d.Host = strings.TrimSpace(d.Host)
	if d.Host == "" {
		return errors.New("host cannot be empty")
	}
	if net.ParseIP(d.Host) == nil && !hostnameRegex.MatchString(d.Host) {
		return errors.New("invalid or unsafe host address")
	}

	if d.Port == 0 {
		d.Port = 22
	} else if d.Port < 1 || d.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}

	d.Username = strings.TrimSpace(d.Username)
	if d.Username == "" {
		return errors.New("username cannot be empty")
	}

	if len(d.Commands) == 0 {
		return errors.New("at least one command is required")
	}
	if len(d.Commands) > deviceShellMaxCommands {
		return fmt.Errorf("too many commands (max %d)", deviceShellMaxCommands)
	}
	for _, command := range d.Commands {
		// Each command is typed followed by a newline; an embedded one would sneak in
		// an extra command.
		if strings.ContainsAny(command, "\r\n") {
			return errors.New("commands cannot contain line breaks")
		}
	}

	if len(d.PromptResponses) > deviceShellMaxPromptResponses {
		return fmt.Errorf("too many prompt responses (max %d)", deviceShellMaxPromptResponses)
	}
	d.CompiledPrompts = make([]*regexp.Regexp, 0, len(d.PromptResponses))
	for _, rule := range d.PromptResponses {
		if rule.Pattern == "" || len(rule.Pattern) > deviceShellMaxPatternLength {
			return fmt.Errorf("prompt pattern must be between 1 and %d characters", deviceShellMaxPatternLength)
		}
		if len(rule.Response) > deviceShellMaxResponseLength {
			return fmt.Errorf("prompt response exceeds %d characters", deviceShellMaxResponseLength)
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid prompt pattern %q: %w", rule.Pattern, err)
		}
		d.CompiledPrompts = append(d.CompiledPrompts, re)
	}

	var err error
	if d.ConnectTimeout, err = defaultedTimeout("connect_timeout", d.ConnectTimeout, 20, 60); err != nil {
		return err
	}
	if d.IdleTimeout, err = defaultedTimeout("idle_timeout", d.IdleTimeout, 20, 300); err != nil {
		return err
	}
	if d.MaxSession, err = defaultedTimeout("max_session", d.MaxSession, 180, 900); err != nil {
		return err
	}

	return nil
}

func defaultedTimeout(name string, value, def, max int) (int, error) {
	if value <= 0 {
		return def, nil
	}
	if value > max {
		return 0, fmt.Errorf("%s exceeds maximum allowed value (%d seconds)", name, max)
	}
	return value, nil
}

// DeviceShellResult is the outcome of a device_ssh_shell job. The raw session transcript
// (everything the device printed, echoes and prompts included) is returned gzipped and
// base64-encoded so a large device config still fits in a single hub message; parsing
// it is left to the caller.
type DeviceShellResult struct {
	Transcript         string `json:"transcript"`
	TranscriptEncoding string `json:"transcript_encoding"` // "gzip+base64"
	TranscriptBytes    int    `json:"transcript_bytes"`
	Truncated          bool   `json:"truncated"`
	// EndReason is why the session was ended: "idle" (no output for idle_timeout),
	// "max_session", "closed" (the device closed it) or "truncated".
	EndReason string `json:"end_reason"`
	// DisconnectError is set when the connection was torn down abruptly rather than
	// closed cleanly; the transcript up to that point is still returned.
	DisconnectError string `json:"disconnect_error,omitempty"`
}
