package agent

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"redborder-hub-satellite/common"
)

func validDeviceShellParams(t *testing.T, rules ...common.DeviceShellPromptResponse) common.DeviceShellParams {
	t.Helper()
	params := common.DeviceShellParams{
		Host:            "127.0.0.1",
		Username:        "admin",
		Password:        "secret",
		Commands:        []string{"show running-config"},
		PromptResponses: rules,
	}
	if err := params.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	return params
}

func TestPromptResponse(t *testing.T) {
	params := validDeviceShellParams(t,
		common.DeviceShellPromptResponse{Pattern: `(?i)password:\s*\z`, Response: "secret\n"},
		common.DeviceShellPromptResponse{Pattern: `\?\s*\z`, Response: "\n"},
	)

	tests := []struct {
		name     string
		pending  string
		want     string
		wantSeen bool
	}{
		{"first matching rule wins", "Password: ", "secret\n", true},
		{"confirm prompt", "Destination filename [x.cfg]? ", "\n", true},
		{"escape sequences after the prompt are ignored", "Destination filename []?\x1b[24;1H\x1b[K", "\n", true},
		{"CRLF line endings", "Copy?\r\n", "\n", true},
		{"no prompt at the end", "Password: \r\nswitch# ", "", false},
		{"prompt earlier than the window is not answered", "Password:" + strings.Repeat("x", 300), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, seen := promptResponse([]byte(tt.pending), params)
			if got != tt.want || seen != tt.wantSeen {
				t.Errorf("promptResponse(%q) = %q, %v; want %q, %v", tt.pending, got, seen, tt.want, tt.wantSeen)
			}
		})
	}
}

// fakeSwitch is a minimal interactive switch CLI over SSH: it echoes typed lines (but not
// the password), asks for a destination filename and a password on "copy", prints a
// config on "show running-config", and closes the session on "exit".
type fakeSwitch struct {
	listener net.Listener
	mu       sync.Mutex
	received []string
}

func startFakeSwitch(t *testing.T) *fakeSwitch {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "admin" && string(password) == "secret" {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sw := &fakeSwitch{listener: listener}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go sw.serve(conn, config)
		}
	}()
	return sw
}

func (sw *fakeSwitch) port() int {
	return sw.listener.Addr().(*net.TCPAddr).Port
}

func (sw *fakeSwitch) lines() []string {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return append([]string(nil), sw.received...)
}

func (sw *fakeSwitch) serve(conn net.Conn, config *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range requests {
				_ = req.Reply(req.Type == "pty-req" || req.Type == "shell", nil)
				if req.Type == "shell" {
					go sw.cli(channel)
				}
			}
		}()
	}
}

func (sw *fakeSwitch) cli(channel ssh.Channel) {
	defer channel.Close()
	reader := bufio.NewReader(channel)
	readLine := func(echo bool) (string, bool) {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", false
		}
		line = strings.TrimRight(line, "\r\n")
		sw.mu.Lock()
		sw.received = append(sw.received, line)
		sw.mu.Unlock()
		if echo {
			io.WriteString(channel, line+"\r\n")
		} else {
			io.WriteString(channel, "\r\n")
		}
		return line, true
	}

	io.WriteString(channel, "switch# ")
	for {
		line, ok := readLine(true)
		if !ok {
			return
		}
		switch {
		case line == "exit":
			return
		case line == "show running-config":
			io.WriteString(channel, "hostname sw1\r\n -- MORE -- ")
			// A pager takes a single key, not a line.
			if key, err := reader.ReadByte(); err != nil || key != ' ' {
				return
			}
			io.WriteString(channel, "\x1b[24;1Hend\r\n")
		case strings.HasPrefix(line, "copy "):
			io.WriteString(channel, "Destination filename [sw1.cfg]? ")
			readLine(true)
			// Split across two writes, like devices that send long prompts in pieces.
			io.WriteString(channel, "Pass")
			io.WriteString(channel, "word: ")
			readLine(false)
			io.WriteString(channel, "Copied\r\n")
		}
		io.WriteString(channel, "switch# ")
	}
}

func decodeTranscript(t *testing.T, result *common.DeviceShellResult) string {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(result.Transcript)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != result.TranscriptBytes {
		t.Errorf("transcript_bytes = %d, decoded %d", result.TranscriptBytes, len(raw))
	}
	return string(raw)
}

func TestRunDeviceShellAnswersPromptsOnce(t *testing.T) {
	sw := startFakeSwitch(t)
	params := common.DeviceShellParams{
		Host:     "127.0.0.1",
		Port:     sw.port(),
		Username: "admin",
		Password: "secret",
		Commands: []string{"copy running-config sftp://ftp-x@10.0.0.1/incoming/a.cfg"},
		PromptResponses: []common.DeviceShellPromptResponse{
			{Pattern: `(?i)-{2,3}\s*\(?more\)?\s*-{2,3}`, Response: " "},
			{Pattern: `(?i)password:\s*\z`, Response: "secret\n"},
			{Pattern: `\?\s*\z`, Response: "\n"},
		},
		IdleTimeout: 1,
	}
	if err := params.Validate(); err != nil {
		t.Fatal(err)
	}

	result, err := runDeviceShell(context.Background(), params)
	if err != nil {
		t.Fatalf("runDeviceShell() error = %v", err)
	}
	if result.EndReason != "idle" {
		t.Errorf("end_reason = %q, want idle", result.EndReason)
	}

	want := []string{"copy running-config sftp://ftp-x@10.0.0.1/incoming/a.cfg", "", "secret"}
	if got := sw.lines(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("device received %q, want %q", got, want)
	}
	if transcript := decodeTranscript(t, result); !strings.Contains(transcript, "Copied") {
		t.Errorf("transcript %q does not contain the copy result", transcript)
	}
}

func TestRunDeviceShellPagesThroughOutput(t *testing.T) {
	sw := startFakeSwitch(t)
	params := common.DeviceShellParams{
		Host:     "127.0.0.1",
		Port:     sw.port(),
		Username: "admin",
		Password: "secret",
		Commands: []string{"show running-config"},
		PromptResponses: []common.DeviceShellPromptResponse{
			{Pattern: `(?i)-{2,3}\s*\(?more\)?\s*-{2,3}`, Response: " "},
		},
		IdleTimeout: 1,
	}
	if err := params.Validate(); err != nil {
		t.Fatal(err)
	}

	result, err := runDeviceShell(context.Background(), params)
	if err != nil {
		t.Fatalf("runDeviceShell() error = %v", err)
	}
	transcript := decodeTranscript(t, result)
	if !strings.Contains(transcript, "hostname sw1") || !strings.Contains(transcript, "end") {
		t.Errorf("transcript %q is missing the paged config", transcript)
	}
}

func TestRunDeviceShellReportsDeviceClose(t *testing.T) {
	sw := startFakeSwitch(t)
	params := common.DeviceShellParams{
		Host:        "127.0.0.1",
		Port:        sw.port(),
		Username:    "admin",
		Password:    "secret",
		Commands:    []string{"exit"},
		IdleTimeout: 5,
	}
	if err := params.Validate(); err != nil {
		t.Fatal(err)
	}

	result, err := runDeviceShell(context.Background(), params)
	if err != nil {
		t.Fatalf("runDeviceShell() error = %v", err)
	}
	if result.EndReason != "closed" {
		t.Errorf("end_reason = %q, want closed", result.EndReason)
	}
	if transcript := decodeTranscript(t, result); !strings.Contains(transcript, "exit") {
		t.Errorf("transcript %q is missing the command echo", transcript)
	}
}

func TestRunDeviceShellRejectsBadCredentials(t *testing.T) {
	sw := startFakeSwitch(t)
	params := common.DeviceShellParams{
		Host:           "127.0.0.1",
		Port:           sw.port(),
		Username:       "admin",
		Password:       "wrong",
		Commands:       []string{"show running-config"},
		ConnectTimeout: 5,
	}
	if err := params.Validate(); err != nil {
		t.Fatal(err)
	}

	if _, err := runDeviceShell(context.Background(), params); err == nil {
		t.Fatal("runDeviceShell() with a wrong password succeeded")
	}
}
