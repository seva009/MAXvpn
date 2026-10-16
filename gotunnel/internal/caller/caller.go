// Package caller ports oneme_caller.py: it logs into the OneMe gateway
// with a caller token, initiates a call to the callee ID (opcode 78),
// and hands the call parameters to a WebRTC signaling Session in Caller mode
// with an integrated SOCKS5 proxy server.
package caller

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"calltunnel/internal/netx"
	"calltunnel/internal/proto"
	"calltunnel/internal/signal"
	"calltunnel/internal/tunnelcrypto"
)

const gatewayURL = "wss://api.oneme.ru/websocket"
const userAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0"

// Config mirrors config_caller.json.
type Config struct {
	CalleeID        int64  `json:"callee_id"`
	Token           string `json:"token"`
	DeviceID        string `json:"device_id"`
	DeviceIDAlt     string `json:"deviceId"`
	PrivateKey      string `json:"private_key"`
	PeerPublicKey   string `json:"peer_public_key"`
	TunnelSecret    string `json:"tunnel_secret"`
	ProxyHost       string `json:"proxy_host"`
	ProxyPort       int    `json:"proxy_port"`
	Mode            string `json:"mode"`
	AudioOnly       bool   `json:"audio_only"`
	IsVideo            bool   `json:"is_video"`
	DNS                string `json:"dns"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Insecure           bool   `json:"insecure"`
}

type result struct {
	payload interface{}
	err     error
}

// Caller is the OneMe caller client.
type Caller struct {
	cfg        Config
	viewerID   int64
	privKey    []byte
	peerPubKey []byte

	ws      *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	seq     int16
	pending map[int16]chan result
	dead    chan struct{}
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// New creates a new OneMe Caller.
func New(cfg Config) *Caller {
	devID := cfg.DeviceID
	if devID == "" {
		devID = cfg.DeviceIDAlt
	}
	if devID == "" {
		devID = newUUID()
	}
	cfg.DeviceID = devID

	if cfg.ProxyHost == "" {
		cfg.ProxyHost = "127.0.0.1"
	}
	if cfg.ProxyPort == 0 {
		cfg.ProxyPort = 1080
	}
	if cfg.TunnelSecret == "" {
		cfg.TunnelSecret = tunnelcrypto.DefaultTunnelSecret
	}
	if cfg.AudioOnly {
		cfg.IsVideo = false
	} else if !cfg.AudioOnly && !cfg.IsVideo {
		cfg.IsVideo = true
	}

	var priv []byte
	if cfg.PrivateKey != "" {
		if k, err := tunnelcrypto.ParseKey(cfg.PrivateKey); err == nil {
			priv = k
		} else {
			log.Printf("[Auth] Warning: invalid private_key in caller config: %v", err)
		}
	}

	var peerPub []byte
	if cfg.PeerPublicKey != "" {
		if k, err := tunnelcrypto.ParseKey(cfg.PeerPublicKey); err == nil {
			peerPub = k
		} else {
			log.Printf("[Auth] Warning: invalid peer_public_key in caller config: %v", err)
		}
	}

	var dnsList []string
	if cfg.DNS != "" {
		for _, d := range strings.Split(cfg.DNS, ",") {
			if td := strings.TrimSpace(d); td != "" {
				dnsList = append(dnsList, td)
			}
		}
	}
	netx.SetupNetwork(dnsList, cfg.InsecureSkipVerify || cfg.Insecure)

	return &Caller{
		cfg:        cfg,
		privKey:    priv,
		peerPubKey: peerPub,
		pending:    make(map[int16]chan result),
		dead:       make(chan struct{}),
	}
}

func (c *Caller) nextSeq() int16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.seq
	c.seq++
	return s
}

func (c *Caller) sendCmd(opcode int16, payload interface{}) (interface{}, error) {
	seq := c.nextSeq()
	pkt, err := proto.EncodePacket(0, seq, opcode, payload)
	if err != nil {
		return nil, err
	}
	ch := make(chan result, 1)
	c.mu.Lock()
	c.pending[seq] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, seq)
		c.mu.Unlock()
	}()

	c.writeMu.Lock()
	err = c.ws.WriteMessage(websocket.BinaryMessage, pkt)
	c.writeMu.Unlock()
	if err != nil {
		return nil, err
	}

	select {
	case r := <-ch:
		return r.payload, r.err
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("timeout waiting for opcode %d response", opcode)
	}
}

func (c *Caller) resolve(seq int16, r result) bool {
	c.mu.Lock()
	ch, ok := c.pending[seq]
	c.mu.Unlock()
	if ok {
		select {
		case ch <- r:
		default:
		}
	}
	return ok
}

func (c *Caller) recvLoop(ctx context.Context) {
	defer close(c.dead)
	for {
		_, raw, err := c.ws.ReadMessage()
		if err != nil {
			if ctx.Err() != nil || strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Printf("Error in recv_loop: %v", err)
			return
		}
		pkt, err := proto.DecodePacket(raw)
		if err != nil {
			log.Printf("decode error: %v", err)
			continue
		}
		if pkt.Cmd == 3 {
			log.Printf("[OneMe Error RX] seq=%d opcode=%d: %v", pkt.Seq, pkt.Opcode, pkt.Payload)
			c.resolve(pkt.Seq, result{err: fmt.Errorf("server error for opcode %d: %v", pkt.Opcode, pkt.Payload)})
			continue
		}
		if pkt.Cmd == 1 && c.resolve(pkt.Seq, result{payload: pkt.Payload}) {
			continue
		}
		if pkt.Opcode == 1 { // server ping -> pong
			out, _ := proto.EncodePacket(1, pkt.Seq, 1, nil)
			c.writeMu.Lock()
			_ = c.ws.WriteMessage(websocket.BinaryMessage, out)
			c.writeMu.Unlock()
			continue
		}
	}
}

// Run connects to the OneMe gateway and runs the auto-redial caller loop,
// automatically reconnecting to the gateway if the connection drops.
func (c *Caller) Run(ctx context.Context) error {
	if c.cfg.Token == "" || c.cfg.Token == "YOUR_CALLER_AUTH_TOKEN" {
		return fmt.Errorf("please set your real auth token in config_caller.json (browser: localStorage.getItem('__oneme_auth'))")
	}
	if c.cfg.CalleeID == 0 {
		return fmt.Errorf("please specify callee_id to call")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err := c.runSession(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Printf("[Gateway Error] %v", err)
		}
		log.Println("[Auto-Reconnect] OneMe gateway disconnected. Reconnecting in 3s...")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
		}
	}
}

func (c *Caller) runSession(ctx context.Context) error {
	log.Printf("Connecting to OneMe gateway: %s...", gatewayURL)
	hdr := http.Header{}
	hdr.Set("Origin", "https://web.max.ru")
	hdr.Set("User-Agent", userAgent)
	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = netx.TLSConfig(c.cfg.InsecureSkipVerify || c.cfg.Insecure)
	ws, _, err := dialer.DialContext(ctx, gatewayURL, hdr)
	if err != nil {
		return fmt.Errorf("dial gateway: %w", err)
	}
	defer ws.Close()

	c.mu.Lock()
	c.ws = ws
	c.pending = make(map[int16]chan result)
	c.dead = make(chan struct{})
	c.mu.Unlock()

	log.Println("Connected to wss://api.oneme.ru/websocket!")

	go c.recvLoop(ctx)

	// Keepalive ping loop: send WebSocket ping every 20s to prevent NAT/firewall idle timeouts
	pingStop := make(chan struct{})
	defer close(pingStop)
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.writeMu.Lock()
				_ = ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second))
				c.writeMu.Unlock()
			case <-c.dead:
				return
			case <-pingStop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Step 1: Session Init (Opcode 6)
	initPayload := map[string]interface{}{
		"userAgent": map[string]interface{}{
			"deviceType":      "WEB",
			"pushDeviceType":  "WEBPUSH",
			"locale":          "ru",
			"deviceLocale":    "ru",
			"osVersion":       "Linux",
			"deviceName":      "Firefox",
			"headerUserAgent": userAgent,
			"isPwa":           false,
			"appVersion":      "26.10.3",
			"screen":          "1920x1080 1.0x",
			"timezone":        "Europe/Moscow",
		},
		"deviceId": c.cfg.DeviceID,
	}
	if _, err := c.sendCmd(proto.OpcodeInit, initPayload); err != nil {
		return fmt.Errorf("init: %w", err)
	}

	// Step 2: Login with auth token (Opcode 19)
	loginPayload := map[string]interface{}{
		"token":      c.cfg.Token,
		"chatsCount": 15,
	}
	resLogin, err := c.sendCmd(proto.OpcodeLogin, loginPayload)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	name := fmt.Sprint(c.viewerID)
	if m, ok := resLogin.(map[string]interface{}); ok {
		if p, ok := m["profile"].(map[string]interface{}); ok {
			if ct, ok := p["contact"].(map[string]interface{}); ok {
				if id, ok := toInt64(ct["id"]); ok {
					c.viewerID = id
				}
				if n := firstStr(ct["name"], ct["firstName"]); n != "" {
					name = n
				} else {
					name = fmt.Sprint(c.viewerID)
				}
			}
		}
	}
	if name == "" || name == "0" {
		name = fmt.Sprint(c.viewerID)
	}
	log.Printf("Logged in successfully as caller '%s' (ID: %d)!", name, c.viewerID)

	// Step 3: Auto-redial loop
	const redialDelay = 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.dead:
			return fmt.Errorf("gateway connection lost")
		default:
		}

		var convID string
		if len(c.privKey) == 32 && len(c.peerPubKey) == 32 {
			knockUUID, err := tunnelcrypto.ComputeKnockUUID(c.privKey, c.peerPubKey, 0)
			if err != nil {
				log.Printf("[Auth] Error computing knock UUID: %v, falling back to random UUID", err)
				convID = newUUID()
			} else {
				convID = knockUUID
				log.Printf("[Auth] Generated authenticated Call Knock conversationId: %s", convID)
			}
		} else {
			convID = newUUID()
		}

		internalParamsBytes, _ := json.Marshal(map[string]interface{}{
			"deviceId":        c.cfg.DeviceID,
			"sdkVersion":      "2.8.13-beta.6",
			"clientAppKey":    "",
			"platform":        "WEB",
			"protocolVersion": 5,
			"domainId":        "",
			"capabilities":    "6A03F",
		})

		log.Printf("Calling user ID %d (isVideo=%v, conversationId: %s)...", c.cfg.CalleeID, c.cfg.IsVideo, convID)
		callResRaw, err := c.sendCmd(proto.OpcodeStartCall, map[string]interface{}{
			"conversationId": convID,
			"calleeIds":      []int64{c.cfg.CalleeID},
			"internalParams": string(internalParamsBytes),
			"isVideo":        c.cfg.IsVideo,
		})
		if err != nil {
			log.Printf("Failed to start call: %v", err)
			log.Printf("[Auto-Redial] Retrying in %v...", redialDelay)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(redialDelay):
				continue
			}
		}

		callRes, ok := callResRaw.(map[string]interface{})
		if !ok {
			log.Printf("Unexpected call response payload: %T", callResRaw)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(redialDelay):
				continue
			}
		}

		if rejected, ok := callRes["rejectedParticipants"].([]interface{}); ok && len(rejected) > 0 {
			log.Printf("Call was rejected by server: %v", rejected)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(redialDelay):
				continue
			}
		}

		paramsRaw, ok := callRes["internalCallerParams"].(string)
		if !ok || paramsRaw == "" {
			log.Printf("Missing internalCallerParams in response: %v", callRes)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(redialDelay):
				continue
			}
		}

		var callerParams map[string]interface{}
		if err := json.Unmarshal([]byte(paramsRaw), &callerParams); err != nil {
			log.Printf("Failed to unmarshal internalCallerParams: %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(redialDelay):
				continue
			}
		}

		endpoint, _ := callerParams["endpoint"].(string)
		log.Printf("Call initiated successfully! Endpoint: %.80s...", endpoint)

		u, err := url.Parse(endpoint)
		var okUserID string
		var callToken string
		if err == nil {
			q := u.Query()
			okUserID = q.Get("userId")
			callToken = q.Get("token")
		}
		if okUserID == "" {
			okUserID = fmt.Sprint(c.viewerID)
		}

		log.Printf("Connecting to WebRTC media as caller (OkCDN userId: %s)...", okUserID)

		sess, err := signal.New(signal.Config{
			UserID:              okUserID,
			ConvID:              convID,
			Token:               callToken,
			RemoteParticipantID: fmt.Sprint(c.cfg.CalleeID),
			VCP:                 callerParams,
			IsCaller:            true,
			IsVideo:             c.cfg.IsVideo,
			TunnelSecret:        c.cfg.TunnelSecret,
			PrivateKey:          c.privKey,
			PeerPublicKey:       c.peerPubKey,
			ProxyHost:           c.cfg.ProxyHost,
			ProxyPort:           c.cfg.ProxyPort,
		})
		if err != nil {
			log.Printf("Failed to create WebRTC session: %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(redialDelay):
				continue
			}
		}

		if err := sess.Run(ctx); err != nil {
			log.Printf("WebRTC session error: %v", err)
		}

		if ctx.Err() != nil {
			return nil
		}

		select {
		case <-c.dead:
			return fmt.Errorf("gateway connection lost")
		default:
		}

		log.Printf("\n======================================================================\n" +
			"[Auto-Redial] Session ended (TURN credentials expired or call closed).\n" +
			"Redialing in 2s with fresh credentials...\n" +
			"======================================================================\n")

		select {
		case <-ctx.Done():
			return nil
		case <-c.dead:
			return fmt.Errorf("gateway connection lost")
		case <-time.After(redialDelay):
		}
	}
}

func toInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int:
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	case float64:
		return int64(n), true
	case *big.Int:
		return n.Int64(), true
	case *proto.BigIntExt:
		return toInt64(n.Value)
	case string:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64); err == nil {
			return parsed, true
		}
	case fmt.Stringer:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(n.String()), 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func firstStr(vs ...interface{}) string {
	for _, v := range vs {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
