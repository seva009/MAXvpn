// Command caller is the compiled (Go) replacement for oneme_caller.py: it runs
// on the client device (PC, Android/Termux, iPhone/macOS, etc.), calls the relay
// over OneMe WebRTC, and opens a local SOCKS5 proxy server.
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
	"strconv"
	"syscall"
	"time"

	"calltunnel/internal/caller"
	"calltunnel/internal/logx"
	"calltunnel/internal/tunnelcrypto"
)

const (
	defaultConfigCaller = "config_caller.json"
	defaultConfigMain   = "config.json"
)

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func loadOrCreateConfig(path string) (caller.Config, string) {
	if path == "" {
		if _, err := os.Stat(defaultConfigCaller); err == nil {
			path = defaultConfigCaller
		} else if _, err := os.Stat(defaultConfigMain); err == nil {
			path = defaultConfigMain
		} else {
			path = defaultConfigCaller
		}
	}

	if data, err := os.ReadFile(path); err == nil {
		var cfg caller.Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "bad config %s: %v\n", path, err)
			os.Exit(1)
		}
		if cfg.DeviceID == "" && cfg.DeviceIDAlt == "" {
			cfg.DeviceID = newUUID()
		}
		return cfg, path
	}

	// Create template
	cfg := caller.Config{
		CalleeID:      0,
		Token:         "YOUR_CALLER_AUTH_TOKEN",
		DeviceID:      newUUID(),
		PrivateKey:    "",
		PeerPublicKey: "",
		TunnelSecret:  tunnelcrypto.DefaultTunnelSecret,
		ProxyHost:     "127.0.0.1",
		ProxyPort:     1080,
		Mode:          "proxy",
		AudioOnly:     false,
		IsVideo:       true,
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(path, out, 0o600)
	return cfg, path
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] [callee_id]\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}

	cfgPath := flag.String("config", "", "path to config JSON file (default: config_caller.json)")
	flag.StringVar(cfgPath, "c", "", "shorthand for -config")

	token := flag.String("token", "", "caller account auth token")
	flag.StringVar(token, "t", "", "shorthand for -token")

	deviceID := flag.String("device-id", "", "caller device UUID")
	flag.StringVar(deviceID, "d", "", "shorthand for -device-id")

	proxyHost := flag.String("proxy-host", "", "local SOCKS5 proxy bind address (default: 127.0.0.1)")
	proxyPort := flag.Int("proxy-port", 0, "local SOCKS5 proxy port (default: 1080)")
	flag.IntVar(proxyPort, "p", 0, "shorthand for -proxy-port")

	secret := flag.String("secret", "", "AES encryption secret passphrase")
	flag.StringVar(secret, "s", "", "shorthand for -secret")

	privKey := flag.String("privkey", "", "asymmetric Curve25519 private key (hex)")
	peerPubKey := flag.String("peer-pubkey", "", "relay Curve25519 public key (hex)")

	audioOnly := flag.Bool("audio-only", false, "start call as audio-only instead of video call")
	dns := flag.String("dns", "", "custom DNS server (e.g. 77.88.8.8 or 1.1.1.1)")
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
	logOut := logx.NewNonBlocking(os.Stderr, 4096)
	log.SetOutput(logOut)

	cfg, usedPath := loadOrCreateConfig(*cfgPath)

	// Override config with flags
	if *token != "" {
		cfg.Token = *token
	}
	if *deviceID != "" {
		cfg.DeviceID = *deviceID
	}
	if *proxyHost != "" {
		cfg.ProxyHost = *proxyHost
	}
	if *proxyPort != 0 {
		cfg.ProxyPort = *proxyPort
	}
	if *secret != "" {
		cfg.TunnelSecret = *secret
	}
	if *privKey != "" {
		cfg.PrivateKey = *privKey
	}
	if *peerPubKey != "" {
		cfg.PeerPublicKey = *peerPubKey
	}
	if *dns != "" {
		cfg.DNS = *dns
	}
	if *insecure {
		cfg.InsecureSkipVerify = true
	}
	if *audioOnly {
		cfg.AudioOnly = true
		cfg.IsVideo = false
	} else if cfg.AudioOnly {
		cfg.IsVideo = false
	} else {
		cfg.IsVideo = true
	}

	// Positional callee ID argument
	if args := flag.Args(); len(args) > 0 {
		if id, err := strconv.ParseInt(args[0], 10, 64); err == nil {
			cfg.CalleeID = id
		}
	}

	if cfg.Token == "" || cfg.Token == "YOUR_CALLER_AUTH_TOKEN" {
		fmt.Fprintf(os.Stderr, "ERROR: Caller auth token is missing!\n"+
			"Please specify -token <TOKEN> or set 'token' in %s.\n"+
			"You can get the token from browser LocalStorage: localStorage.getItem('__oneme_auth')\n", usedPath)
		os.Exit(1)
	}

	if cfg.CalleeID == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: Target callee ID is missing!\n"+
			"Please pass as argument: %s <callee_user_id>\n"+
			"or set 'callee_id' in %s.\n", os.Args[0], usedPath)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		if ctx.Err() != nil {
			break
		}
		c := caller.New(cfg)
		if err := c.Run(ctx); err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("[Caller Error] %v", err)
			log.Println("[Caller Auto-Reconnect] Retrying in 3s...")
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
