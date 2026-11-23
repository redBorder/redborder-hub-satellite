package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"redborder-hub-satellite/agent"
	"redborder-hub-satellite/common"
)

func main() {
	// 1. Define command-line flags
	configPath := flag.String("config", "", "Path to JSON configuration file")
	hubURL := flag.String("hub", "ws://localhost:8080/ws", "WebSocket Hub connection URL (fallback)")
	token := flag.String("token", "", "Agent registration token, required until the agent key is enrolled (fallback)")
	agentID := flag.String("id", "satellite-site-a", "Unique identifier for this Spoke Satellite (fallback)")
	privateKeyPath := flag.String("key", "redborder-satellite.key", "Path to Agent private key file (fallback)")
	insecureFlag := flag.Bool("insecure", false, "Bypass TLS certificate verification for self-signed certificates (fallback)")
	flag.Parse()

	var finalHubURL, finalToken, finalAgentID, finalPrivateKeyPath string
	var finalCachePath string
	var finalInsecure bool
	var cfg *agent.Config

	// 2. Load configuration from file if path is specified
	if *configPath != "" {
		log.Printf("Loading configuration from file: %s", *configPath)
		var err error
		cfg, err = agent.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Error loading config file: %v", err)
		}
		finalHubURL = cfg.HubURL
		finalToken = cfg.AuthToken
		finalAgentID = cfg.AgentID
		finalPrivateKeyPath = cfg.PrivateKeyPath
		finalCachePath = cfg.CachePath
		finalInsecure = cfg.InsecureSkipVerify || *insecureFlag
	} else {
		// Use CLI flags as fallback
		finalHubURL = *hubURL
		finalToken = *token
		finalAgentID = *agentID
		finalPrivateKeyPath = *privateKeyPath
		finalInsecure = *insecureFlag
	}

	// The token is only needed to enrol a new key (or when no key is used);
	// an already enrolled agent authenticates with its signature.
	keyEnrolled := false
	if finalPrivateKeyPath != "" {
		if _, err := os.Stat(finalPrivateKeyPath); err == nil {
			keyEnrolled = true
		}
	}
	if !keyEnrolled {
		if err := common.ValidateAuthToken(finalToken); err != nil {
			log.Fatalf("Cannot start: %v. Set auth_token in the config file or -token to the registration token of your hub cluster.", err)
		}
	}

	var finalKey ed25519.PrivateKey
	if finalPrivateKeyPath != "" {
		if _, err := os.Stat(finalPrivateKeyPath); os.IsNotExist(err) {
			log.Printf("Agent private key file %s not found. Generating a new Ed25519 key pair...", finalPrivateKeyPath)
			pubPath := finalPrivateKeyPath + ".pub"
			priv, pub, err := common.GenerateAndSaveEd25519Keys(finalPrivateKeyPath, pubPath)
			if err != nil {
				log.Fatalf("Failed to generate and save key pair: %v", err)
			}
			log.Printf("Generated key pair successfully:")
			log.Printf("  Private Key: %s", finalPrivateKeyPath)
			log.Printf("  Public Key:  %s", pubPath)
			log.Printf("  Base64 Public Key for registration:")
			log.Printf("  ==================================================")
			log.Printf("  %s", base64.StdEncoding.EncodeToString(pub))
			log.Printf("  ==================================================")
			finalKey = priv
		} else {
			priv, err := common.LoadPrivateKeyPEM(finalPrivateKeyPath)
			if err != nil {
				log.Fatalf("Failed to load agent private key: %v", err)
			}
			finalKey = priv
			log.Printf("Loaded agent private key from %s", finalPrivateKeyPath)
		}
	}

	log.Printf("Starting redborder-satellite %q...", finalAgentID)
	
	a := agent.NewAgent(finalHubURL, finalToken, finalAgentID, finalKey, finalCachePath)
	if finalInsecure {
		log.Printf("WARNING: TLS certificate verification is disabled (-insecure / insecure_skip_verify)")
		a.SetInsecureSkipVerify(true)
	}
	if cfg != nil && len(cfg.Commands) > 0 {
		log.Printf("Loaded %d custom command definitions from config", len(cfg.Commands))
		a.SetCustomCommands(cfg.Commands)
	}

	// Set up OS signal interception for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal. Stopping satellite gracefully...")
		a.Stop()
	}()

	// Start agent reconnection loop (blocks until stopped/canceled)
	a.Start()
}
