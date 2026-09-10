package common

import "testing"

func TestPingParamsValidate(t *testing.T) {
	tests := []struct {
		name    string
		params  PingParams
		wantErr bool
	}{
		{
			name: "Valid IP",
			params: PingParams{
				Host:    "127.0.0.1",
				Count:   4,
				Timeout: 5,
			},
			wantErr: false,
		},
		{
			name: "Valid Hostname",
			params: PingParams{
				Host:    "google.com",
				Count:   4,
				Timeout: 5,
			},
			wantErr: false,
		},
		{
			name: "Shell injection host",
			params: PingParams{
				Host:    "127.0.0.1; rm -rf /",
				Count:   4,
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "Host with spaces",
			params: PingParams{
				Host:    "127.0.0.1 -w 10",
				Count:   4,
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "Empty host",
			params: PingParams{
				Host:    "",
				Count:   4,
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "Count too high",
			params: PingParams{
				Host:    "127.0.0.1",
				Count:   100,
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "Timeout too high",
			params: PingParams{
				Host:    "127.0.0.1",
				Count:   4,
				Timeout: 100,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("PingParams.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSNMPWalkParamsValidate(t *testing.T) {
	tests := []struct {
		name    string
		params  SNMPWalkParams
		wantErr bool
	}{
		{
			name: "Valid IP and OID",
			params: SNMPWalkParams{
				Target:    "192.168.1.1",
				Community: "public",
				OID:       "1.3.6.1.2.1",
				Timeout:   5,
			},
			wantErr: false,
		},
		{
			name: "Valid target with port",
			params: SNMPWalkParams{
				Target:    "192.168.1.1:161",
				Community: "public",
				OID:       "1.3.6.1.2.1",
				Timeout:   5,
			},
			wantErr: false,
		},
		{
			name: "Invalid OID",
			params: SNMPWalkParams{
				Target:    "192.168.1.1",
				Community: "public",
				OID:       "1.3.6.1.2.1; rm -rf /",
				Timeout:   5,
			},
			wantErr: true,
		},
		{
			name: "Shell injection community",
			params: SNMPWalkParams{
				Target:    "192.168.1.1",
				Community: "public; inject",
				OID:       "1.3.6.1.2.1",
				Timeout:   5,
			},
			wantErr: true,
		},
		{
			name: "Valid SNMP v3 authPriv",
			params: SNMPWalkParams{
				Version:        "3",
				Target:         "10.0.0.5",
				SecName:        "adminUser",
				SecLevel:       "authPriv",
				AuthProtocol:   "SHA-256",
				AuthPassphrase: "myAuthPassword123",
				PrivProtocol:   "AES-256",
				PrivPassphrase: "myPrivPassword456",
				OID:            "1.3.6.1.2.1.1.1",
				Timeout:        5,
			},
			wantErr: false,
		},
		{
			name: "SNMP v3 missing username (sec_name)",
			params: SNMPWalkParams{
				Version:        "3",
				Target:         "10.0.0.5",
				SecName:        "",
				SecLevel:       "noAuthNoPriv",
				OID:            "1.3.6.1.2.1.1.1",
				Timeout:        5,
			},
			wantErr: true,
		},
		{
			name: "SNMP v3 missing auth passphrase for authNoPriv",
			params: SNMPWalkParams{
				Version:      "3",
				Target:       "10.0.0.5",
				SecName:      "adminUser",
				SecLevel:     "authNoPriv",
				AuthProtocol: "SHA",
				OID:          "1.3.6.1.2.1.1.1",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("SNMPWalkParams.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSNMPParamsBuildCLIArgs(t *testing.T) {
	p := SNMPParams{
		Version:        "3",
		Target:         "10.0.0.5",
		SecName:        "adminUser",
		SecLevel:       "authPriv",
		AuthProtocol:   "SHA-256",
		AuthPassphrase: "authPassword",
		PrivProtocol:   "AES",
		PrivPassphrase: "privPassword",
		ContextName:    "myContext",
		OID:            "1.3.6.1.2.1",
		Timeout:        10,
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	args := p.BuildCLIArgs()
	expectedArgs := []string{
		"-v", "3",
		"-u", "adminUser",
		"-l", "authPriv",
		"-a", "SHA-256",
		"-A", "authPassword",
		"-x", "AES",
		"-X", "privPassword",
		"-n", "myContext",
		"-t", "10",
		"10.0.0.5",
		"1.3.6.1.2.1",
	}

	if len(args) != len(expectedArgs) {
		t.Fatalf("expected %d args, got %d: %v", len(expectedArgs), len(args), args)
	}

	for i, arg := range args {
		if arg != expectedArgs[i] {
			t.Errorf("arg[%d] = %q, want %q", i, arg, expectedArgs[i])
		}
	}
}

func TestTracerouteParamsValidate(t *testing.T) {
	tests := []struct {
		name    string
		params  TracerouteParams
		wantErr bool
	}{
		{
			name: "Valid IP",
			params: TracerouteParams{
				Host:    "1.1.1.1",
				MaxHops: 30,
				Timeout: 5,
			},
			wantErr: false,
		},
		{
			name: "Valid Hostname",
			params: TracerouteParams{
				Host:    "google.com",
				MaxHops: 30,
				Timeout: 5,
			},
			wantErr: false,
		},
		{
			name: "Shell injection host",
			params: TracerouteParams{
				Host:    "127.0.0.1; rm -rf /",
				MaxHops: 30,
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "Host with spaces",
			params: TracerouteParams{
				Host:    "127.0.0.1 -m 5",
				MaxHops: 30,
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "Empty host",
			params: TracerouteParams{
				Host:    "",
				MaxHops: 30,
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "MaxHops too high",
			params: TracerouteParams{
				Host:    "127.0.0.1",
				MaxHops: 100,
				Timeout: 5,
			},
			wantErr: true,
		},
		{
			name: "Timeout too high",
			params: TracerouteParams{
				Host:    "127.0.0.1",
				MaxHops: 30,
				Timeout: 100,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("TracerouteParams.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVMwareDiscoverParamsValidate(t *testing.T) {
	tests := []struct {
		name    string
		params  VMwareDiscoverParams
		wantErr bool
	}{
		{
			name: "Valid IP and credentials",
			params: VMwareDiscoverParams{
				Host:     "192.168.1.50",
				Username: "root",
				Password: "secretpassword",
				Timeout:  30,
			},
			wantErr: false,
		},
		{
			name: "Valid Hostname with port",
			params: VMwareDiscoverParams{
				Host:     "esxi.local:443",
				Username: "admin",
				Password: "password",
				Timeout:  60,
			},
			wantErr: false,
		},
		{
			name: "Empty Host",
			params: VMwareDiscoverParams{
				Host:     "",
				Username: "root",
				Password: "password",
				Timeout:  30,
			},
			wantErr: true,
		},
		{
			name: "Unsafe Host injection",
			params: VMwareDiscoverParams{
				Host:     "192.168.1.50; rm -rf /",
				Username: "root",
				Password: "password",
				Timeout:  30,
			},
			wantErr: true,
		},
		{
			name: "Empty Username",
			params: VMwareDiscoverParams{
				Host:     "192.168.1.50",
				Username: "",
				Password: "password",
				Timeout:  30,
			},
			wantErr: true,
		},
		{
			name: "Empty Password",
			params: VMwareDiscoverParams{
				Host:     "192.168.1.50",
				Username: "root",
				Password: "",
				Timeout:  30,
			},
			wantErr: true,
		},
		{
			name: "Timeout too high",
			params: VMwareDiscoverParams{
				Host:     "192.168.1.50",
				Username: "root",
				Password: "password",
				Timeout:  500,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("VMwareDiscoverParams.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
