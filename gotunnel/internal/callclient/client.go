// Package callclient ports oneme_client.py: it logs into the OneMe gateway
// with a saved token, listens for incoming calls (opcode 137), and hands each
// one to a WebRTC signaling Session that acts as the tunnel relay.
package callclient

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net/http"
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

// Config mirrors config.json of the Python client.
type Config struct {
	ViewerID     int64    `json:"viewer_id"`
	ViewerIDAlt  string   `json:"viewerId"`
	Token        string   `json:"token"`
	DeviceID     string   `json:"device_id"`
	DeviceIDAlt  string   `json:"deviceId"`
	Mode         string   `json:"mode"`
	TunnelSecret string   `json:"tunnel_secret"`
	PrivateKey   string   `json:"private_key"`
	AllowedPeers []string `json:"allowed_peers"`
	DNS                string   `json:"dns"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	Insecure           bool     `json:"insecure"`
}

type Client struct {
	cfg          Config
	viewerID     int64
	privKey      []byte
	allowedPeers [][]byte

	ws      *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	seq     int16
	pending map[int16]chan result
	dead    chan struct{} // closed when the gateway read loop exits
}

type result struct {
	payload interface{}
	err     error
}

func New(cfg Config) *Client {
	vid := cfg.ViewerID
	if vid == 0 && cfg.ViewerIDAlt != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(cfg.ViewerIDAlt), 10, 64); err == nil {
			vid = v
		}
	}
	devID := cfg.DeviceID
	if devID == "" {
		devID = cfg.DeviceIDAlt
	}
	cfg.DeviceID = devID

	var priv []byte
	if cfg.PrivateKey != "" {
		if k, err := tunnelcrypto.ParseKey(cfg.PrivateKey); err == nil {
			priv = k
		} else {
			log.Printf("[Auth] Warning: invalid private_key in config: %v", err)
		}
	}

	var allowed [][]byte
	for _, p := range cfg.AllowedPeers {
		if k, err := tunnelcrypto.ParseKey(p); err == nil {
			allowed = append(allowed, k)
		} else {
			log.Printf("[Auth] Warning: invalid allowed peer key %q: %v", p, err)
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

	return &Client{
		cfg:          cfg,
		viewerID:     vid,
		privKey:      priv,
		allowedPeers: allowed,
		pending:      map[int16]chan result{},
		dead:         make(chan struct{}),
	}
}

func (c *Client) nextSeq() int16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.seq
	c.seq++
	return s
}

// sendCmd mirrors send_cmd (10 s response timeout).
func (c *Client) sendCmd(opcode int16, payload interface{}) (interface{}, error) {
	seq := c.nextSeq()
	pkt, err := proto.EncodePacket(0, seq, opcode, payload)
	if err != nil {
		return nil, err
	}
	ch := make(chan result, 1)
	c.mu.Lock()
	c.pending[seq] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, seq); c.mu.Unlock() }()

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

// Run mirrors OneMeClient.run().
// Run connects to the OneMe gateway and listens for incoming calls indefinitely,
// automatically reconnecting to the gateway if the connection drops.
func (c *Client) Run(ctx context.Context) error {
	if c.cfg.Token == "" || c.cfg.Token == "YOUR_ONEME_AUTH_TOKEN" {
		return fmt.Errorf("please set your real auth token in config.json (browser: localStorage.getItem('__oneme_auth'))")
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
			log.Printf("[Relay Gateway Error] %v", err)
		}
		log.Println("[Auto-Reconnect] OneMe gateway disconnected. Reconnecting in 3s...")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
		}
	}
}

func (c *Client) runSession(ctx context.Context) error {
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

	// Step 1: session init (opcode 6)
	_, err = c.sendCmd(proto.OpcodeInit, map[string]interface{}{
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
	})
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}

	// Step 2: login (opcode 19)
	res, err := c.sendCmd(proto.OpcodeLogin, map[string]interface{}{"token": c.cfg.Token, "chatsCount": 15})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	name := fmt.Sprint(c.viewerID)
	if m, ok := res.(map[string]interface{}); ok {
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
	log.Printf("Logged in successfully as '%s' (ID: %d)! Listening for incoming calls...", name, c.viewerID)

	select {
	case <-ctx.Done():
		return nil
	case <-c.dead:
		return fmt.Errorf("gateway connection lost")
	}
}

func (c *Client) recvLoop(ctx context.Context) {
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
		if pkt.Opcode == proto.OpcodeIncomingCall {
			log.Println(">>> INCOMING CALL RECEIVED (opcode 137)! <<<")
			if m, ok := pkt.Payload.(map[string]interface{}); ok {
				go c.handleIncomingCall(ctx, m)
			}
		}
	}
}

func (c *Client) resolve(seq int16, r result) bool {
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

// handleIncomingCall mirrors _handle_incoming_call.
func (c *Client) handleIncomingCall(ctx context.Context, info map[string]interface{}) {
	convID := fmt.Sprint(info["conversationId"])
	callerID := ""
	if v, ok := toInt64(info["callerId"]); ok {
		callerID = fmt.Sprint(v)
	}
	log.Printf("Handling incoming call from caller=%s, conv_id=%s", callerID, convID)

	// Step 0: Call Knocking verification (Rule 1: Pre-call screening)
	if len(c.privKey) == 32 && len(c.allowedPeers) > 0 {
		if !tunnelcrypto.VerifyKnockUUID(c.privKey, c.allowedPeers, convID, 60) {
			log.Printf("[Auth] REJECTING call from caller=%s, conv_id=%s: knock token verification failed! Line kept free.", callerID, convID)
			return
		}
		log.Printf("[Auth] Call knock token VERIFIED successfully for conv_id=%s", convID)
	}

	var vcp map[string]interface{}
	if raw, ok := info["vcp"].(string); ok && raw != "" {
		v, err := proto.DecodeVCP(raw)
		if err != nil {
			log.Printf("Failed to decode vcp: %v", err)
		} else {
			vcp = v
			log.Printf("Decoded call params! STUN=%v, TURN=%v", v["stne"], v["trne"])
		}
	}
	if vcp == nil {
		vcp = map[string]interface{}{}
	}

	token, _ := vcp["tkn"].(string)
	if token == "" {
		log.Println("Requesting WebRTC call token (opcode 158 fallback)...")
		res, err := c.sendCmd(proto.OpcodeGetCallToken, map[string]interface{}{})
		if err != nil {
			log.Printf("get call token failed: %v", err)
			return
		}
		if m, ok := res.(map[string]interface{}); ok {
			token, _ = m["token"].(string)
		}
	}

	// trnu = "<timestamp>:<ok_calls_user_id>"; OkCDN needs that id, not the chat id.
	userID := ""
	if trnu, ok := vcp["trnu"].(string); ok {
		if parts := strings.Split(trnu, ":"); len(parts) > 1 {
			userID = parts[1]
		}
	}
	if userID == "" {
		userID = fmt.Sprint(c.viewerID)
	}
	short := token
	if len(short) > 15 {
		short = short[:15]
	}
	log.Printf("Using call token: %s... for OkCDN userId: %s", short, userID)

	isVideo := true
	if v, ok := info["isVideo"].(bool); ok {
		isVideo = v
	}
	sess, err := signal.New(signal.Config{
		UserID: userID, ConvID: convID, Token: token,
		RemoteParticipantID: callerID, VCP: vcp,
		IsVideo: isVideo, TunnelSecret: c.cfg.TunnelSecret,
		PrivateKey: c.privKey, AllowedPeers: c.allowedPeers,
	})
	if err != nil {
		log.Printf("Error creating WebRTC session: %v", err)
		return
	}
	log.Println("Starting WebRTC connection and DataChannel listener...")
	if err := sess.Run(ctx); err != nil {
		log.Printf("Error during WebRTC call: %v", err)
		return
	}
	log.Println("Call finished!")
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
