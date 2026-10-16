package caller

import (
	"testing"

	"calltunnel/internal/tunnelcrypto"
)

func TestCallerInitConfig(t *testing.T) {
	callerPrivHex, callerPubHex, err := tunnelcrypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair caller: %v", err)
	}
	relayPrivHex, relayPubHex, err := tunnelcrypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair relay: %v", err)
	}

	callerPub, _ := tunnelcrypto.ParseKey(callerPubHex)
	relayPriv, _ := tunnelcrypto.ParseKey(relayPrivHex)

	cfg := Config{
		CalleeID:      12345678,
		Token:         "test_token",
		PrivateKey:    callerPrivHex,
		PeerPublicKey: relayPubHex,
	}

	c := New(cfg)
	if c.cfg.CalleeID != 12345678 {
		t.Fatalf("unexpected CalleeID: %d", c.cfg.CalleeID)
	}
	if c.cfg.ProxyHost != "127.0.0.1" {
		t.Fatalf("unexpected ProxyHost: %s", c.cfg.ProxyHost)
	}
	if c.cfg.ProxyPort != 1080 {
		t.Fatalf("unexpected ProxyPort: %d", c.cfg.ProxyPort)
	}
	if !c.cfg.IsVideo {
		t.Fatalf("expected IsVideo=true by default")
	}
	if len(c.privKey) != 32 {
		t.Fatalf("expected 32-byte private key, got %d", len(c.privKey))
	}
	if len(c.peerPubKey) != 32 {
		t.Fatalf("expected 32-byte peer public key, got %d", len(c.peerPubKey))
	}

	// Verify authenticated knock UUID generation
	knockUUID, err := tunnelcrypto.ComputeKnockUUID(c.privKey, c.peerPubKey, 0)
	if err != nil {
		t.Fatalf("ComputeKnockUUID: %v", err)
	}
	if len(knockUUID) != 36 {
		t.Fatalf("unexpected knock UUID length: %s", knockUUID)
	}

	// Relay verification check: relay verifies with its private key against allowed caller public keys
	if !tunnelcrypto.VerifyKnockUUID(relayPriv, [][]byte{callerPub}, knockUUID, 60) {
		t.Fatalf("knock UUID verification failed on relay")
	}
}

func TestCallerAudioOnly(t *testing.T) {
	cfg := Config{
		CalleeID:  12345678,
		Token:     "test_token",
		AudioOnly: true,
	}
	c := New(cfg)
	if c.cfg.IsVideo {
		t.Fatalf("expected IsVideo=false when AudioOnly=true")
	}
}
