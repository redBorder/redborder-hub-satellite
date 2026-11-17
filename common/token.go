package common

import (
	"fmt"
	"strings"
)

// insecureTokens lists well-known example or legacy default tokens that must
// never be accepted as a real secret.
var insecureTokens = []string{
	"super-secret-agent-token",
	"my-secret-token",
	"your-secure-registration-token",
	"changeme",
	"change_me",
}

// ValidateAuthToken returns an error if the token is empty or is one of the
// well-known default/example values shipped in documentation and packaging.
func ValidateAuthToken(token string) error {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return fmt.Errorf("authentication token is not set")
	}
	for _, bad := range insecureTokens {
		if strings.EqualFold(trimmed, bad) {
			return fmt.Errorf("authentication token %q is a well-known default; generate a unique one (e.g. openssl rand -hex 32)", trimmed)
		}
	}
	return nil
}
