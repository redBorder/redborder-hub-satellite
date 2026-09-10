package common

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Regex for validating domain names / hostnames safely.
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	
	// Regex for validating SNMP OIDs (e.g. 1.3.6.1.2.1.1 or .1.3.6.1.2.1.1).
	oidRegex = regexp.MustCompile(`^\.?([0-9]+\.)*[0-9]+$`)

	// Regex for community strings (restricting to safe alphanumeric, dashes, and underscores).
	communityRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

	// Regex for SNMP v3 security parameters.
	secNameRegex        = regexp.MustCompile(`^[a-zA-Z0-9_\-\.@]+$`)
	authProtocolRegex   = regexp.MustCompile(`^(MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)$`)
	privProtocolRegex   = regexp.MustCompile(`^(DES|AES|AES-128|AES-192|AES-256)$`)
	safePassphraseRegex = regexp.MustCompile(`^[^\s"';|&<>` + "`" + `]+$`)
	contextNameRegex    = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
	engineIDRegex       = regexp.MustCompile(`^(0x)?[a-zA-Z0-9]+$`)
)

// PingParams defines the input parameters for a Ping job.
type PingParams struct {
	Host    string `json:"host"`
	Count   int    `json:"count"`   // Default 4, Max 10
	Timeout int    `json:"timeout"` // Default 5, Max 15 (seconds)
}

// Validate checks if the Ping parameters are safe and within valid bounds.
func (p *PingParams) Validate() error {
	p.Host = strings.TrimSpace(p.Host)
	if p.Host == "" {
		return errors.New("host cannot be empty")
	}

	// Validate Host is either a valid IP address or a safe hostname
	if net.ParseIP(p.Host) == nil {
		if !hostnameRegex.MatchString(p.Host) {
			return errors.New("invalid or unsafe host name")
		}
	}

	if p.Count <= 0 {
		p.Count = 4
	} else if p.Count > 10 {
		return errors.New("ping count exceeds maximum allowed value (10)")
	}

	if p.Timeout <= 0 {
		p.Timeout = 5
	} else if p.Timeout > 15 {
		return errors.New("ping timeout exceeds maximum allowed value (15 seconds)")
	}

	return nil
}

// PingResult represents the structured results of a Ping job.
type PingResult struct {
	Host            string  `json:"host"`
	PacketsSent     int     `json:"packets_sent"`
	PacketsReceived int     `json:"packets_received"`
	PacketLoss      float64 `json:"packet_loss_percentage"`
	MinRTT          float64 `json:"min_rtt_ms"`
	AvgRTT          float64 `json:"avg_rtt_ms"`
	MaxRTT          float64 `json:"max_rtt_ms"`
	RawOutput       string  `json:"raw_output,omitempty"`
}

// SNMPParams defines the input parameters for SNMP jobs (v1, v2c, and v3).
type SNMPParams struct {
	Version        string `json:"version"`         // "1", "2c" (default), or "3"
	Target         string `json:"target"`          // Target IP / hostname
	Community      string `json:"community"`       // Default "public" (for v1/v2c)
	OID            string `json:"oid"`             // Default ".1.3.6"
	Timeout        int    `json:"timeout"`         // Default 5, Max 15 (seconds)

	// SNMP v3 parameters
	SecLevel       string `json:"sec_level"`       // "noAuthNoPriv", "authNoPriv", "authPriv"
	SecName        string `json:"sec_name"`        // Username / Security Name (-u)
	AuthProtocol   string `json:"auth_protocol"`   // "MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512" (-a)
	AuthPassphrase string `json:"auth_passphrase"` // Auth Passphrase (-A)
	PrivProtocol   string `json:"priv_protocol"`   // "DES", "AES", "AES-128", "AES-192", "AES-256" (-x)
	PrivPassphrase string `json:"priv_passphrase"` // Priv Passphrase (-X)
	ContextName    string `json:"context_name"`    // Context Name (-n)
	EngineID       string `json:"engine_id"`       // Engine ID (-e)
}

// SNMPWalkParams defines the input parameters for an SNMPWalk job.
type SNMPWalkParams = SNMPParams

// SNMPGetParams defines the input parameters for an SNMPGet / SNMP job.
type SNMPGetParams = SNMPParams

// Validate checks if the SNMP parameters are safe and within valid bounds.
func (s *SNMPParams) Validate() error {
	s.Target = strings.TrimSpace(s.Target)
	if s.Target == "" {
		return errors.New("target cannot be empty")
	}

	// Target can be an IP or a hostname, possibly with a port (e.g. 192.168.1.1:161)
	host, _, err := net.SplitHostPort(s.Target)
	if err != nil {
		host = s.Target // No port specified
	}

	if net.ParseIP(host) == nil {
		if !hostnameRegex.MatchString(host) {
			return errors.New("invalid or unsafe target address")
		}
	}

	s.Version = strings.TrimSpace(strings.ToLower(s.Version))
	if s.Version == "" || s.Version == "v2c" {
		s.Version = "2c"
	} else if s.Version == "v1" {
		s.Version = "1"
	} else if s.Version == "v3" {
		s.Version = "3"
	}

	if s.Version != "1" && s.Version != "2c" && s.Version != "3" {
		return errors.New("invalid SNMP version (must be 1, 2c, or 3)")
	}

	if s.Version == "1" || s.Version == "2c" {
		s.Community = strings.TrimSpace(s.Community)
		if s.Community == "" {
			s.Community = "public"
		} else if !communityRegex.MatchString(s.Community) {
			return errors.New("invalid community string (only alphanumeric, underscores, and dashes allowed)")
		}
	} else if s.Version == "3" {
		s.SecName = strings.TrimSpace(s.SecName)
		if s.SecName == "" {
			return errors.New("sec_name (username) is required for SNMP v3")
		}
		if !secNameRegex.MatchString(s.SecName) {
			return errors.New("invalid sec_name format")
		}

		s.SecLevel = strings.TrimSpace(s.SecLevel)
		if s.SecLevel == "" {
			if s.PrivPassphrase != "" {
				s.SecLevel = "authPriv"
			} else if s.AuthPassphrase != "" {
				s.SecLevel = "authNoPriv"
			} else {
				s.SecLevel = "noAuthNoPriv"
			}
		}

		switch strings.ToLower(s.SecLevel) {
		case "noauthnopriv":
			s.SecLevel = "noAuthNoPriv"
		case "authnopriv":
			s.SecLevel = "authNoPriv"
		case "authpriv":
			s.SecLevel = "authPriv"
		default:
			return errors.New("invalid sec_level (must be noAuthNoPriv, authNoPriv, or authPriv)")
		}

		if s.SecLevel == "authNoPriv" || s.SecLevel == "authPriv" {
			s.AuthProtocol = strings.TrimSpace(strings.ToUpper(s.AuthProtocol))
			if s.AuthProtocol == "" {
				s.AuthProtocol = "SHA"
			}
			if s.AuthProtocol == "SHA1" {
				s.AuthProtocol = "SHA"
			} else if s.AuthProtocol == "SHA256" {
				s.AuthProtocol = "SHA-256"
			} else if s.AuthProtocol == "SHA384" {
				s.AuthProtocol = "SHA-384"
			} else if s.AuthProtocol == "SHA512" {
				s.AuthProtocol = "SHA-512"
			}

			if !authProtocolRegex.MatchString(s.AuthProtocol) {
				return errors.New("invalid auth_protocol (must be MD5, SHA, SHA-224, SHA-256, SHA-384, or SHA-512)")
			}

			if s.AuthPassphrase == "" {
				return errors.New("auth_passphrase is required when sec_level is authNoPriv or authPriv")
			}
			if !safePassphraseRegex.MatchString(s.AuthPassphrase) {
				return errors.New("auth_passphrase contains invalid characters")
			}
		}

		if s.SecLevel == "authPriv" {
			s.PrivProtocol = strings.TrimSpace(strings.ToUpper(s.PrivProtocol))
			if s.PrivProtocol == "" {
				s.PrivProtocol = "AES"
			}
			if s.PrivProtocol == "AES128" {
				s.PrivProtocol = "AES-128"
			} else if s.PrivProtocol == "AES192" {
				s.PrivProtocol = "AES-192"
			} else if s.PrivProtocol == "AES256" {
				s.PrivProtocol = "AES-256"
			}

			if !privProtocolRegex.MatchString(s.PrivProtocol) {
				return errors.New("invalid priv_protocol (must be DES, AES, AES-128, AES-192, or AES-256)")
			}

			if s.PrivPassphrase == "" {
				return errors.New("priv_passphrase is required when sec_level is authPriv")
			}
			if !safePassphraseRegex.MatchString(s.PrivPassphrase) {
				return errors.New("priv_passphrase contains invalid characters")
			}
		}

		s.ContextName = strings.TrimSpace(s.ContextName)
		if s.ContextName != "" && !contextNameRegex.MatchString(s.ContextName) {
			return errors.New("invalid context_name format")
		}

		s.EngineID = strings.TrimSpace(s.EngineID)
		if s.EngineID != "" && !engineIDRegex.MatchString(s.EngineID) {
			return errors.New("invalid engine_id format")
		}
	}

	s.OID = strings.TrimSpace(s.OID)
	if s.OID == "" {
		s.OID = ".1.3.6"
	} else if !oidRegex.MatchString(s.OID) {
		return errors.New("invalid OID format")
	}

	if s.Timeout <= 0 {
		s.Timeout = 5
	} else if s.Timeout > 15 {
		return errors.New("snmp timeout exceeds maximum allowed value (15 seconds)")
	}

	return nil
}

// BuildCLIArgs builds the command line argument slice for net-snmp commands (snmpwalk / snmpget).
func (s *SNMPParams) BuildCLIArgs() []string {
	var args []string
	if s.Version == "3" {
		args = append(args, "-v", "3", "-u", s.SecName)
		if s.SecLevel != "" {
			args = append(args, "-l", s.SecLevel)
		}
		if s.SecLevel == "authNoPriv" || s.SecLevel == "authPriv" {
			if s.AuthProtocol != "" {
				args = append(args, "-a", s.AuthProtocol)
			}
			if s.AuthPassphrase != "" {
				args = append(args, "-A", s.AuthPassphrase)
			}
		}
		if s.SecLevel == "authPriv" {
			if s.PrivProtocol != "" {
				args = append(args, "-x", s.PrivProtocol)
			}
			if s.PrivPassphrase != "" {
				args = append(args, "-X", s.PrivPassphrase)
			}
		}
		if s.ContextName != "" {
			args = append(args, "-n", s.ContextName)
		}
		if s.EngineID != "" {
			args = append(args, "-e", s.EngineID)
		}
	} else {
		ver := s.Version
		if ver == "" {
			ver = "2c"
		}
		comm := s.Community
		if comm == "" {
			comm = "public"
		}
		args = append(args, "-v", ver, "-c", comm)
	}

	args = append(args, "-t", strconv.Itoa(s.Timeout), s.Target, s.OID)
	return args
}

// SNMPWalkEntry represents a single OID-Value pair returned by SNMPWalk or SNMPGet.
type SNMPWalkEntry struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// SNMPWalkResult represents the structured results of an SNMPWalk job.
type SNMPWalkResult struct {
	Target    string          `json:"target"`
	OID       string          `json:"oid"`
	Entries   []SNMPWalkEntry `json:"entries"`
	RawOutput string          `json:"raw_output,omitempty"`
}

// SNMPGetEntry represents a single OID-Value pair returned by SNMPGet.
type SNMPGetEntry = SNMPWalkEntry

// SNMPGetResult represents the structured results of an SNMPGet job.
type SNMPGetResult = SNMPWalkResult

// TracerouteParams defines the input parameters for a Traceroute job.
type TracerouteParams struct {
	Host    string `json:"host"`
	MaxHops int    `json:"max_hops"` // Default 30, Max 64
	Timeout int    `json:"timeout"`  // Default 5, Max 15 (seconds)
}

// Validate checks if the Traceroute parameters are safe and within valid bounds.
func (t *TracerouteParams) Validate() error {
	t.Host = strings.TrimSpace(t.Host)
	if t.Host == "" {
		return errors.New("host cannot be empty")
	}

	// Validate Host is either a valid IP address or a safe hostname
	if net.ParseIP(t.Host) == nil {
		if !hostnameRegex.MatchString(t.Host) {
			return errors.New("invalid or unsafe host name")
		}
	}

	if t.MaxHops <= 0 {
		t.MaxHops = 30
	} else if t.MaxHops > 64 {
		return errors.New("traceroute max hops exceeds maximum allowed value (64)")
	}

	if t.Timeout <= 0 {
		t.Timeout = 5
	} else if t.Timeout > 15 {
		return errors.New("traceroute timeout exceeds maximum allowed value (15 seconds)")
	}

	return nil
}

// TracerouteHop represents a single hop in a traceroute path.
type TracerouteHop struct {
	Hop  int       `json:"hop"`
	Host string    `json:"host"`
	IP   string    `json:"ip"`
	RTTs []float64 `json:"rtts_ms"`
}

// TracerouteResult represents the structured results of a Traceroute job.
type TracerouteResult struct {
	Host      string          `json:"host"`
	Hops      []TracerouteHop `json:"hops"`
	RawOutput string          `json:"raw_output,omitempty"`
}

// VMwareDiscoverParams defines the input parameters for a VMware ESXi VM discovery job.
type VMwareDiscoverParams struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
	Timeout  int    `json:"timeout"` // Default 30, Max 300 (seconds)
}

// Validate checks if the VMware discovery parameters are safe and valid.
func (v *VMwareDiscoverParams) Validate() error {
	v.Host = strings.TrimSpace(v.Host)
	if v.Host == "" {
		return errors.New("host cannot be empty")
	}

	host, _, err := net.SplitHostPort(v.Host)
	if err != nil {
		host = v.Host
	}

	if net.ParseIP(host) == nil {
		if !hostnameRegex.MatchString(host) {
			return errors.New("invalid or unsafe host address")
		}
	}

	v.Username = strings.TrimSpace(v.Username)
	if v.Username == "" {
		return errors.New("username cannot be empty")
	}

	if v.Password == "" {
		return errors.New("password cannot be empty")
	}

	if v.Timeout <= 0 {
		v.Timeout = 30
	} else if v.Timeout > 300 {
		return errors.New("timeout exceeds maximum allowed value (300 seconds)")
	}

	return nil
}

// VMwareVM represents a single discovered virtual machine.
type VMwareVM struct {
	Moref      string `json:"moref"`
	Name       string `json:"name"`
	PowerState string `json:"power_state"`
}

// VMwareDiscoverResult represents the structured results of a VMware ESXi VM discovery job.
type VMwareDiscoverResult struct {
	Host      string     `json:"host"`
	VMs       []VMwareVM `json:"vms"`
	RawOutput string     `json:"raw_output,omitempty"`
}
