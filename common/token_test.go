package common

import "testing"

func TestValidateAuthToken(t *testing.T) {
	bad := []string{"", "   ", "super-secret-agent-token", "CHANGE_ME", "change_me", "your-secure-registration-token", " my-secret-token "}
	for _, tok := range bad {
		if err := ValidateAuthToken(tok); err == nil {
			t.Errorf("expected token %q to be rejected", tok)
		}
	}
	good := []string{"4f9c1d7a8b2e6035c1a9d4e7f0b3a6c85d2e1f09a7b4c3d6e8f1a2b5c7d9e0f1"}
	for _, tok := range good {
		if err := ValidateAuthToken(tok); err != nil {
			t.Errorf("expected token to be accepted, got %v", err)
		}
	}
}
