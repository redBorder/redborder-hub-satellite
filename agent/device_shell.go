package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"redborder-hub-satellite/common"
)

const (
	// Only this much of the latest output is matched against the prompt patterns.
	deviceShellPromptWindow = 200
	// Stop reading once a transcript grows past this, rather than buffer without limit.
	deviceShellMaxTranscriptBytes = 16 * 1024 * 1024
	// The encoded transcript has to fit in one hub message (maxMessageSize, 512 KB)
	// together with the JSON-RPC envelope.
	deviceShellMaxEncodedBytes = 480 * 1024
)

var (
	shellLineEndingRegex = regexp.MustCompile(`\r\n?`)
	shellCSIRegex        = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
	shellFeEscapeRegex   = regexp.MustCompile(`\x1b[@-_]`)
)

func executeDeviceShell(ctx context.Context, rawParams json.RawMessage) (interface{}, error) {
	var params common.DeviceShellParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil, fmt.Errorf("failed to parse params: %w", err)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	result, err := runDeviceShell(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("device shell failed: %w", err)
	}
	return result, nil
}

// deviceShellClientConfig authenticates with the password both as "password" and as the
// answer to every "keyboard-interactive" question (many switches only offer the latter),
// and appends the insecure algorithms, lowest priority, so older switches still shipping
// in the field (SHA1 key exchanges, CBC ciphers) can be reached.
func deviceShellClientConfig(params common.DeviceShellParams) *ssh.ClientConfig {
	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()
	password := params.Password

	return &ssh.ClientConfig{
		User: params.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: append(supported.HostKeys, insecure.HostKeys...),
		Timeout:           time.Duration(params.ConnectTimeout) * time.Second,
		Config: ssh.Config{
			KeyExchanges: append(supported.KeyExchanges, insecure.KeyExchanges...),
			Ciphers:      append(supported.Ciphers, insecure.Ciphers...),
			MACs:         append(supported.MACs, insecure.MACs...),
		},
	}
}

func dialDeviceShell(ctx context.Context, params common.DeviceShellParams) (*ssh.Client, error) {
	address := net.JoinHostPort(params.Host, strconv.Itoa(params.Port))
	timeout := time.Duration(params.ConnectTimeout) * time.Second

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("could not connect to %s: %w", address, err)
	}

	// Bound the SSH handshake and authentication too, not just the TCP connect.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, deviceShellClientConfig(params))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH handshake with %s failed: %w", address, err)
	}
	_ = conn.SetDeadline(time.Time{})

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// runDeviceShell opens a pty-backed shell, types params.Commands, answers prompts as the
// device prints them, and ends the session once the device goes quiet for idle_timeout
// (the device is done and back at its prompt), max_session elapses, or the device
// closes it. Large outputs paged screen by screen can take a while, hence an idle
// timeout rather than a flat deadline.
func runDeviceShell(ctx context.Context, params common.DeviceShellParams) (*common.DeviceShellResult, error) {
	client, err := dialDeviceShell(ctx, params)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("could not open an SSH session channel: %w", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := session.RequestPty("dumb", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		return nil, errors.New("could not allocate a pty for the interactive SSH session")
	}
	if err := session.Shell(); err != nil {
		return nil, errors.New("could not start an interactive shell session")
	}

	done := make(chan struct{})
	defer close(done)
	output, readErrs := readShellOutput(done, stdout, stderr)

	for _, command := range params.Commands {
		if _, err := io.WriteString(stdin, command+"\n"); err != nil {
			return nil, fmt.Errorf("could not send command to the device: %w", err)
		}
	}

	transcript, endReason, err := driveShell(ctx, params, stdin, output)
	if err != nil {
		return nil, err
	}

	result := &common.DeviceShellResult{
		TranscriptEncoding: "gzip+base64",
		TranscriptBytes:    len(transcript),
		Truncated:          endReason == "truncated",
		EndReason:          endReason,
	}
	if endReason == "closed" {
		select {
		case readErr := <-readErrs:
			result.DisconnectError = readErr.Error()
		default:
		}
	}

	encoded, err := encodeTranscript(transcript)
	if err != nil {
		return nil, err
	}
	if len(encoded) > deviceShellMaxEncodedBytes {
		return nil, fmt.Errorf("transcript too large to return (%d bytes, %d compressed)", len(transcript), len(encoded))
	}
	result.Transcript = encoded

	return result, nil
}

// readShellOutput merges stdout and stderr chunks into one channel, closed once both
// streams end. A read error other than a clean EOF (abrupt disconnect) is reported on
// the second channel. Closing done stops the readers once nobody consumes the output.
func readShellOutput(done <-chan struct{}, streams ...io.Reader) (<-chan []byte, <-chan error) {
	output := make(chan []byte, 64)
	readErrs := make(chan error, len(streams))

	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(r io.Reader) {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					select {
					case output <- append([]byte(nil), buf[:n]...):
					case <-done:
						return
					}
				}
				if err != nil {
					if !errors.Is(err, io.EOF) {
						readErrs <- err
					}
					return
				}
			}
		}(stream)
	}
	go func() {
		wg.Wait()
		close(output)
	}()

	return output, readErrs
}

// driveShell accumulates the transcript and answers prompts until the session ends,
// returning the transcript and why it ended.
func driveShell(ctx context.Context, params common.DeviceShellParams, stdin io.Writer,
	output <-chan []byte) ([]byte, string, error) {
	var transcript []byte
	// Transcript length right after our last prompt answer; see promptResponse.
	answeredUpto := 0

	idleTimeout := time.Duration(params.IdleTimeout) * time.Second
	deadline := time.Now().Add(time.Duration(params.MaxSession) * time.Second)
	lastActivity := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case chunk, ok := <-output:
			if !ok {
				return transcript, "closed", nil
			}
			if len(transcript)+len(chunk) > deviceShellMaxTranscriptBytes {
				return transcript, "truncated", nil
			}
			transcript = append(transcript, chunk...)
			lastActivity = time.Now()

			// A failed answer means the device is closing the session; keep draining
			// until it does, and let the caller judge the transcript.
			if response, ok := promptResponse(transcript[answeredUpto:], params); ok {
				_, _ = io.WriteString(stdin, response)
				answeredUpto = len(transcript)
			}
		case <-ticker.C:
			now := time.Now()
			if now.After(deadline) {
				return transcript, "max_session", nil
			}
			if now.Sub(lastActivity) >= idleTimeout {
				return transcript, "idle", nil
			}
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
}

// promptResponse returns the answer for the first prompt rule matching the tail of
// pending, the output received since our last answer. Matching on the accumulated tail
// rather than the latest chunk catches prompts split across reads; only looking past
// the last answer keeps a prompt whose answer isn't echoed (a password) from being
// answered twice. CRs and ANSI/VT100 escapes are stripped first, since some devices
// redraw the line right after a prompt even on a "dumb" terminal.
func promptResponse(pending []byte, params common.DeviceShellParams) (string, bool) {
	window := pending
	if len(window) > deviceShellPromptWindow {
		window = window[len(window)-deviceShellPromptWindow:]
	}
	window = shellLineEndingRegex.ReplaceAll(window, []byte("\n"))
	window = shellCSIRegex.ReplaceAll(window, nil)
	window = shellFeEscapeRegex.ReplaceAll(window, nil)

	for i, re := range params.CompiledPrompts {
		if re.Match(window) {
			return params.PromptResponses[i].Response, true
		}
	}
	return "", false
}

func encodeTranscript(transcript []byte) (string, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(transcript); err != nil {
		return "", fmt.Errorf("could not compress transcript: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("could not compress transcript: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
