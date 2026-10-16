// Command relay is the compiled (Go) replacement for oneme_client.py: it runs
// on the Raspberry Pi, waits for an incoming call, and acts as the encrypted
// TCP relay for the SOCKS5 caller.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"calltunnel/internal/callclient"
	"calltunnel/internal/logx"
	"calltunnel/internal/tunnelcrypto"
)

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func loadOrCreate(path string) callclient.Config {
	if data, err := os.ReadFile(path); err == nil {
		var cfg callclient.Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "bad config %s: %v\n", path, err)
			os.Exit(1)
		}
		if cfg.DeviceID == "" {
			cfg.DeviceID = newUUID()
		}
		return cfg
	}
	cfg := callclient.Config{Token: "YOUR_ONEME_AUTH_TOKEN", DeviceID: newUUID()}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(path, out, 0o600)
	return cfg
}

func main() {
	cfgPath := flag.String("config", "config.json", "path to config JSON file")
	secret := flag.String("secret", "", "AES encryption secret passphrase")
	flag.StringVar(secret, "s", "", "shorthand for -secret")
	privKey := flag.String("privkey", "", "asymmetric private key (hex)")
	allowedPeers := flag.String("allowed-peers", "", "comma-separated allowed caller public keys (hex)")
	dnsServer := flag.String("dns", "", "custom DNS server (e.g. 77.88.8.8, 1.1.1.1)")
	insecure := flag.Bool("k", false, "skip TLS certificate verification")
	flag.BoolVar(insecure, "insecure", false, "skip TLS certificate verification")
	genKey := flag.Bool("gen-key", false, "generate new Curve25519 (X25519) keypair and exit")
	flag.Parse()

	if *genKey {
		pPriv, pPub, err := tunnelcrypto.GenerateKeypair()
		if err != nil {
			log.Fatalf("failed to generate keypair: %v", err)
		}
		fmt.Printf("Generated X25519 Keypair:\n")
		fmt.Printf("  Private Key: %s\n", pPriv)
		fmt.Printf("  Public Key:  %s\n", pPub)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime)
	// Never let a slow/stuck log sink (journald, ssh, pipe) block the data path.
	logOut := logx.NewNonBlocking(os.Stderr, 4096)
	log.SetOutput(logOut)
	cfg := loadOrCreate(*cfgPath)
	if *dnsServer != "" {
		cfg.DNS = *dnsServer
	}
	if *insecure {
		cfg.InsecureSkipVerify = true
	}
	if *secret != "" {
		cfg.TunnelSecret = *secret
	}
	if *privKey != "" {
		cfg.PrivateKey = *privKey
	}
	if *allowedPeers != "" {
		for _, p := range strings.Split(*allowedPeers, ",") {
			if tp := strings.TrimSpace(p); tp != "" {
				cfg.AllowedPeers = append(cfg.AllowedPeers, tp)
			}
		}
	}
	if cfg.TunnelSecret == "" {
		cfg.TunnelSecret = tunnelcrypto.DefaultTunnelSecret
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		if ctx.Err() != nil {
			break
		}
		c := callclient.New(cfg)
		if err := c.Run(ctx); err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("[Relay Error] %v", err)
			log.Println("[Relay Auto-Reconnect] Retrying in 3s...")
			select {
			case <-ctx.Done():
				break
			case <-time.After(3 * time.Second):
			}
		} else {
			break
		}
	}
	log.Println("Terminated by user.")
	logOut.Flush(2 * time.Second)
}
