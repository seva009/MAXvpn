// Package tunnelcrypto handles authenticated encryption and key exchange
// for tunnel packets. It supports legacy symmetric secret as well as
// zero-trust asymmetric Curve25519 (X25519) authentication with call knocking
// and in-band forward-secret session key exchange.
package tunnelcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Protocol command opcodes - identical values to Python tunnel_crypto.py
const (
	CmdConnect       = 1  // [conn_id: 4B][port: 2B][host: UTF-8]
	CmdConnectOK     = 2  // [conn_id: 4B]
	CmdConnectFail   = 3  // [conn_id: 4B][error_msg: UTF-8]
	CmdData          = 4  // [conn_id: 4B][payload: bytes]
	CmdClose         = 5  // [conn_id: 4B]
	CmdPing          = 6  // [conn_id: 4B][timestamp: 8B]
	CmdPong          = 7  // [conn_id: 4B][timestamp: 8B]
	CmdHandshakeInit = 10 // Handshake init from caller to relay
	CmdHandshakeResp = 11 // Handshake response from relay to caller

	DefaultTunnelSecret = "oneme_webrtc_aes_tunnel_key"
)

// TunnelCrypto handles AES-256-GCM authenticated encryption for tunnel packets.
// In legacy mode, txAead and rxAead share the same key.
// In asymmetric session mode, txAead and rxAead use distinct directional keys.
type TunnelCrypto struct {
	txAead cipher.AEAD
	rxAead cipher.AEAD
}

// New derives symmetric AES-256 key from secret via SHA-256 (legacy mode).
func New(secret string) (*TunnelCrypto, error) {
	if secret == "" {
		secret = DefaultTunnelSecret
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("tunnelcrypto: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tunnelcrypto: cipher.NewGCM: %w", err)
	}
	return &TunnelCrypto{txAead: aead, rxAead: aead}, nil
}

// NewSessionCrypto initializes TunnelCrypto with separate transmit and receive keys.
func NewSessionCrypto(txKey, rxKey []byte) (*TunnelCrypto, error) {
	txBlock, err := aes.NewCipher(txKey)
	if err != nil {
		return nil, fmt.Errorf("tunnelcrypto: tx cipher: %w", err)
	}
	txAead, err := cipher.NewGCM(txBlock)
	if err != nil {
		return nil, fmt.Errorf("tunnelcrypto: tx gcm: %w", err)
	}

	rxBlock, err := aes.NewCipher(rxKey)
	if err != nil {
		return nil, fmt.Errorf("tunnelcrypto: rx cipher: %w", err)
	}
	rxAead, err := cipher.NewGCM(rxBlock)
	if err != nil {
		return nil, fmt.Errorf("tunnelcrypto: rx gcm: %w", err)
	}
	return &TunnelCrypto{txAead: txAead, rxAead: rxAead}, nil
}

// Encrypt encrypts a packet using txAead with a random 12-byte nonce.
func (t *TunnelCrypto) Encrypt(msgType byte, connID uint32, payload []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("tunnelcrypto: rand nonce: %w", err)
	}
	plaintext := make([]byte, 5+len(payload))
	plaintext[0] = msgType
	binary.BigEndian.PutUint32(plaintext[1:5], connID)
	copy(plaintext[5:], payload)

	ciphertext := t.txAead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt decrypts a packet using rxAead.
func (t *TunnelCrypto) Decrypt(data []byte) (msgType byte, connID uint32, payload []byte, err error) {
	if len(data) < 33 {
		return 0, 0, nil, fmt.Errorf("tunnelcrypto: packet too short for AES-GCM decrypt: %d bytes", len(data))
	}
	nonce := data[:12]
	ciphertext := data[12:]
	plaintext, err := t.rxAead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("tunnelcrypto: decrypt/auth failed: %w", err)
	}
	if len(plaintext) < 5 {
		return 0, 0, nil, fmt.Errorf("tunnelcrypto: plaintext too short: %d bytes", len(plaintext))
	}
	msgType = plaintext[0]
	connID = binary.BigEndian.Uint32(plaintext[1:5])
	payload = plaintext[5:]
	return msgType, connID, payload, nil
}

// PackConnectPayload packs host:port for CmdConnect.
func PackConnectPayload(host string, port uint16) []byte {
	out := make([]byte, 2+len(host))
	binary.BigEndian.PutUint16(out[:2], port)
	copy(out[2:], host)
	return out
}

// UnpackConnectPayload unpacks host:port for CmdConnect.
func UnpackConnectPayload(payload []byte) (host string, port uint16, err error) {
	if len(payload) < 2 {
		return "", 0, fmt.Errorf("tunnelcrypto: connect payload too short")
	}
	port = binary.BigEndian.Uint16(payload[:2])
	host = string(payload[2:])
	return host, port, nil
}

// hkdfSHA256 implements RFC 5869 HKDF using SHA-256.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	hExtract := hmac.New(sha256.New, salt)
	hExtract.Write(ikm)
	prk := hExtract.Sum(nil)

	out := make([]byte, 0, length)
	var prev []byte
	counter := byte(1)
	for len(out) < length {
		hExp := hmac.New(sha256.New, prk)
		if len(prev) > 0 {
			hExp.Write(prev)
		}
		hExp.Write(info)
		hExp.Write([]byte{counter})
		prev = hExp.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:length]
}

// GenerateKeypair generates a new X25519 keypair and returns (privateHex, publicHex).
func GenerateKeypair() (privHex, pubHex string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(priv.Bytes()), hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

// ParseKey parses a 32-byte key from a hex string or base64 string.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("invalid key: must be 32 bytes (64 hex characters or base64)")
}

// ComputeKnockUUID generates a UUIDv4 containing an authenticated knock token for caller.
func ComputeKnockUUID(privKey, peerPubKey []byte, ts int64) (string, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubKey)
	if err != nil {
		return "", fmt.Errorf("invalid peer public key: %w", err)
	}
	dhStatic, err := priv.ECDH(peerPub)
	if err != nil {
		return "", fmt.Errorf("ecdh static: %w", err)
	}

	if ts == 0 {
		ts = time.Now().Unix()
	}

	kKnock := hkdfSHA256(dhStatic, []byte("calltunnel-knock-salt"), []byte("calltunnel-knock"), 32)
	tsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tsBytes, uint32(ts))

	h := hmac.New(sha256.New, kKnock)
	h.Write(tsBytes)
	tag := h.Sum(nil)[:12]

	raw := make([]byte, 16)
	copy(raw[:4], tsBytes)
	copy(raw[4:], tag)
	raw[6] = (raw[6] & 0x0f) | 0x40 // Version 4
	raw[8] = (raw[8] & 0x3f) | 0x80 // RFC 4122 variant

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

// VerifyKnockUUID verifies whether uuidStr contains a valid knock token from an allowed peer.
func VerifyKnockUUID(privKey []byte, allowedPubKeys [][]byte, uuidStr string, windowSec int64) bool {
	clean := strings.ReplaceAll(strings.TrimSpace(uuidStr), "-", "")
	if len(clean) != 32 {
		return false
	}
	raw, err := hex.DecodeString(clean)
	if err != nil || len(raw) != 16 {
		return false
	}

	ts := int64(binary.BigEndian.Uint32(raw[:4]))
	now := time.Now().Unix()
	if windowSec <= 0 {
		windowSec = 60
	}
	if now-ts > windowSec || ts-now > windowSec {
		return false
	}

	priv, err := ecdh.X25519().NewPrivateKey(privKey)
	if err != nil {
		return false
	}

	tsBytes := raw[:4]
	for _, peerPubBytes := range allowedPubKeys {
		peerPub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
		if err != nil {
			continue
		}
		dhStatic, err := priv.ECDH(peerPub)
		if err != nil {
			continue
		}
		kKnock := hkdfSHA256(dhStatic, []byte("calltunnel-knock-salt"), []byte("calltunnel-knock"), 32)
		h := hmac.New(sha256.New, kKnock)
		h.Write(tsBytes)
		tag := h.Sum(nil)[:12]

		expected := make([]byte, 16)
		copy(expected[:4], tsBytes)
		copy(expected[4:], tag)
		expected[6] = (expected[6] & 0x0f) | 0x40
		expected[8] = (expected[8] & 0x3f) | 0x80

		if subtle.ConstantTimeCompare(raw, expected) == 1 {
			return true
		}
	}
	return false
}

// HandshakeInitiator executes client-side handshake over WebRTC DataChannel.
type HandshakeInitiator struct {
	privKey       []byte
	peerPubKey    []byte
	ephemeralPriv *ecdh.PrivateKey
	ephemeralPub  []byte
	dh1           []byte
	dh2           []byte
}

func NewHandshakeInitiator(privKey, peerPubKey []byte) (*HandshakeInitiator, error) {
	if len(privKey) != 32 || len(peerPubKey) != 32 {
		return nil, fmt.Errorf("keys must be 32 bytes")
	}
	return &HandshakeInitiator{privKey: privKey, peerPubKey: peerPubKey}, nil
}

func (h *HandshakeInitiator) CreateInitPacket() ([]byte, error) {
	ePriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	h.ephemeralPriv = ePriv
	h.ephemeralPub = ePriv.PublicKey().Bytes()

	priv, err := ecdh.X25519().NewPrivateKey(h.privKey)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()

	peerPub, err := ecdh.X25519().NewPublicKey(h.peerPubKey)
	if err != nil {
		return nil, err
	}

	dh1, err := ePriv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	h.dh1 = dh1

	k1 := hkdfSHA256(dh1, h.ephemeralPub, []byte("calltunnel-hs1"), 32)
	block1, _ := aes.NewCipher(k1)
	gcm1, _ := cipher.NewGCM(block1)
	nonce1 := make([]byte, 12)
	_, _ = rand.Read(nonce1)
	c1 := gcm1.Seal(nil, nonce1, pub, nil)

	dh2, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	h.dh2 = dh2

	k2 := hkdfSHA256(dh2, c1[:16], []byte("calltunnel-hs2"), 32)
	block2, _ := aes.NewCipher(k2)
	gcm2, _ := cipher.NewGCM(block2)
	nonce2 := make([]byte, 12)
	_, _ = rand.Read(nonce2)

	tsEntropy := make([]byte, 24)
	binary.BigEndian.PutUint64(tsEntropy[:8], uint64(time.Now().Unix()))
	_, _ = rand.Read(tsEntropy[8:])
	c2 := gcm2.Seal(nil, nonce2, tsEntropy, nil)

	out := make([]byte, 1+32+12+len(c1)+12+len(c2))
	out[0] = CmdHandshakeInit
	copy(out[1:33], h.ephemeralPub)
	copy(out[33:45], nonce1)
	copy(out[45:45+len(c1)], c1)
	copy(out[45+len(c1):57+len(c1)], nonce2)
	copy(out[57+len(c1):], c2)
	return out, nil
}

func (h *HandshakeInitiator) ProcessRespPacket(respBytes []byte) (*TunnelCrypto, error) {
	if len(respBytes) != 79 || respBytes[0] != CmdHandshakeResp {
		return nil, fmt.Errorf("invalid handshake response size or opcode")
	}
	eRelay := respBytes[1:33]
	nonce3 := respBytes[33:45]
	c3 := respBytes[45:]

	relayEPub, err := ecdh.X25519().NewPublicKey(eRelay)
	if err != nil {
		return nil, err
	}
	dh3, err := h.ephemeralPriv.ECDH(relayEPub)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(h.privKey)
	if err != nil {
		return nil, err
	}
	dh4, err := priv.ECDH(relayEPub)
	if err != nil {
		return nil, err
	}

	ikmResp := append(append([]byte(nil), dh3...), dh4...)
	saltResp := append(append([]byte(nil), h.ephemeralPub...), eRelay...)
	kResp := hkdfSHA256(ikmResp, saltResp, []byte("calltunnel-resp"), 32)

	bResp, _ := aes.NewCipher(kResp)
	gResp, _ := cipher.NewGCM(bResp)
	plain, err := gResp.Open(nil, nonce3, c3, nil)
	if err != nil || string(plain) != "CALLTUNNEL_AUTH_OK" {
		return nil, fmt.Errorf("invalid confirmation tag from relay")
	}

	sessionIKM := append(append(append(append([]byte(nil), h.dh1...), h.dh2...), dh3...), dh4...)
	sessionSalt := append(append([]byte(nil), h.ephemeralPub...), eRelay...)
	kC2R := hkdfSHA256(sessionIKM, sessionSalt, []byte("calltunnel-key-c2r"), 32)
	kR2C := hkdfSHA256(sessionIKM, sessionSalt, []byte("calltunnel-key-r2c"), 32)

	// Caller sends with kC2R, receives with kR2C
	return NewSessionCrypto(kC2R, kR2C)
}

// HandshakeResponder executes relay-side handshake over WebRTC DataChannel.
type HandshakeResponder struct {
	privKey        []byte
	allowedPubKeys [][]byte
	mu             sync.Mutex
	lastSeenTS     map[string]int64
}

func NewHandshakeResponder(privKey []byte, allowedPubKeys [][]byte) (*HandshakeResponder, error) {
	if len(privKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	}
	return &HandshakeResponder{
		privKey:        privKey,
		allowedPubKeys: allowedPubKeys,
		lastSeenTS:     make(map[string]int64),
	}, nil
}

func (h *HandshakeResponder) ProcessInitPacket(initBytes []byte) ([]byte, *TunnelCrypto, error) {
	if len(initBytes) != 145 || initBytes[0] != CmdHandshakeInit {
		return nil, nil, fmt.Errorf("invalid handshake init packet size or opcode")
	}
	eCaller := initBytes[1:33]
	nonce1 := initBytes[33:45]
	c1 := initBytes[45:93]
	nonce2 := initBytes[93:105]
	c2 := initBytes[105:145]

	priv, err := ecdh.X25519().NewPrivateKey(h.privKey)
	if err != nil {
		return nil, nil, err
	}
	callerEPub, err := ecdh.X25519().NewPublicKey(eCaller)
	if err != nil {
		return nil, nil, err
	}

	dh1, err := priv.ECDH(callerEPub)
	if err != nil {
		return nil, nil, err
	}

	k1 := hkdfSHA256(dh1, eCaller, []byte("calltunnel-hs1"), 32)
	block1, _ := aes.NewCipher(k1)
	gcm1, _ := cipher.NewGCM(block1)
	callerPubBytes, err := gcm1.Open(nil, nonce1, c1, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt caller public key: %w", err)
	}

	matched := false
	for _, allowed := range h.allowedPubKeys {
		if subtle.ConstantTimeCompare(callerPubBytes, allowed) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		return nil, nil, fmt.Errorf("caller public key %x is not authorized", callerPubBytes)
	}

	callerPub, err := ecdh.X25519().NewPublicKey(callerPubBytes)
	if err != nil {
		return nil, nil, err
	}
	dh2, err := priv.ECDH(callerPub)
	if err != nil {
		return nil, nil, err
	}

	k2 := hkdfSHA256(dh2, c1[:16], []byte("calltunnel-hs2"), 32)
	block2, _ := aes.NewCipher(k2)
	gcm2, _ := cipher.NewGCM(block2)
	tsEntropy, err := gcm2.Open(nil, nonce2, c2, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt timestamp payload: %w", err)
	}

	ts := int64(binary.BigEndian.Uint64(tsEntropy[:8]))
	now := time.Now().Unix()
	if now-ts > 60 || ts-now > 60 {
		return nil, nil, fmt.Errorf("expired handshake timestamp: %d (now=%d)", ts, now)
	}

	pubHex := hex.EncodeToString(callerPubBytes)
	h.mu.Lock()
	last := h.lastSeenTS[pubHex]
	if ts <= last {
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("replayed handshake timestamp: %d <= %d", ts, last)
	}
	h.lastSeenTS[pubHex] = ts
	h.mu.Unlock()

	eRelayPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	eRelayPub := eRelayPriv.PublicKey().Bytes()

	dh3, err := eRelayPriv.ECDH(callerEPub)
	if err != nil {
		return nil, nil, err
	}
	dh4, err := eRelayPriv.ECDH(callerPub)
	if err != nil {
		return nil, nil, err
	}

	ikmResp := append(append([]byte(nil), dh3...), dh4...)
	saltResp := append(append([]byte(nil), eCaller...), eRelayPub...)
	kResp := hkdfSHA256(ikmResp, saltResp, []byte("calltunnel-resp"), 32)

	bResp, _ := aes.NewCipher(kResp)
	gResp, _ := cipher.NewGCM(bResp)
	nonce3 := make([]byte, 12)
	_, _ = rand.Read(nonce3)
	c3 := gResp.Seal(nil, nonce3, []byte("CALLTUNNEL_AUTH_OK"), nil)

	respPkt := make([]byte, 1+32+12+len(c3))
	respPkt[0] = CmdHandshakeResp
	copy(respPkt[1:33], eRelayPub)
	copy(respPkt[33:45], nonce3)
	copy(respPkt[45:], c3)

	sessionIKM := append(append(append(append([]byte(nil), dh1...), dh2...), dh3...), dh4...)
	sessionSalt := append(append([]byte(nil), eCaller...), eRelayPub...)
	kC2R := hkdfSHA256(sessionIKM, sessionSalt, []byte("calltunnel-key-c2r"), 32)
	kR2C := hkdfSHA256(sessionIKM, sessionSalt, []byte("calltunnel-key-r2c"), 32)

	// Relay sends with kR2C, receives with kC2R
	crypto, err := NewSessionCrypto(kR2C, kC2R)
	if err != nil {
		return nil, nil, err
	}
	return respPkt, crypto, nil
}

