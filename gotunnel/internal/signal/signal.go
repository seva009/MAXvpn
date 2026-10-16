// Package signal handles WebRTC signaling over wss://videowebrtc.okcdn.ru/ws2
// and manages the Pion WebRTC PeerConnection and DataChannel.
// It supports both Caller mode (connecting local SOCKS5 proxy to relay)
// and Callee mode (connecting remote relay to Internet).
package signal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/ice/v2"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v3"

	"calltunnel/internal/logx"
	"calltunnel/internal/netx"
	"calltunnel/internal/relay"
	"calltunnel/internal/socks5"
	"calltunnel/internal/tunnelcrypto"
)

var stripCandRe = regexp.MustCompile(`(?m)^(a=candidate:|a=end-of-candidates).*\r?\n?`)
var ufragRe = regexp.MustCompile(`\s+ufrag\s+\S+`)

// Config holds everything needed for the WebRTC signaling session.
type Config struct {
	UserID              string
	ConvID              string
	Token               string
	RemoteParticipantID string
	VCP                 map[string]interface{}
	IsCaller            bool
	IsVideo             bool
	TunnelSecret        string
	PrivateKey          []byte
	AllowedPeers        [][]byte // For callee: allowed caller public keys
	PeerPublicKey       []byte   // For caller: relay public key
	ProxyHost           string   // For caller: SOCKS5 bind host
	ProxyPort           int      // For caller: SOCKS5 bind port
}

// Session is the Go equivalent of OKWebRTCSignaling.
type Session struct {
	cfg Config

	mu            sync.Mutex
	ws            *websocket.Conn
	wsWriteMu     sync.Mutex
	seq           int
	remotePID     string
	pc            *webrtc.PeerConnection
	dc            *webrtc.DataChannel
	dcSendMu      sync.Mutex
	tunnel        *relay.TunnelRelay
	socks5Server  *socks5.Server
	initiator     *tunnelcrypto.HandshakeInitiator
	responder     *tunnelcrypto.HandshakeResponder
	watchdogTimer *time.Timer
	done          chan struct{}
	doneOnce      sync.Once
	connected     chan struct{}
	connOnce      sync.Once
	offerOnce     sync.Once
	pendingCand   []webrtc.ICECandidateInit
	remoteSet     bool
}

// New creates a new WebRTC signaling Session.
func New(cfg Config) (*Session, error) {
	s := &Session{
		cfg:       cfg,
		seq:       1,
		done:      make(chan struct{}),
		connected: make(chan struct{}),
	}
	s.setRemotePID(cfg.RemoteParticipantID)
	if cfg.VCP == nil {
		s.cfg.VCP = map[string]interface{}{}
	}

	var servers []webrtc.ICEServer

	// Caller format: VCP["stun"] and VCP["turn"]
	if stunMap, ok := s.cfg.VCP["stun"].(map[string]interface{}); ok {
		if urls, ok := stunMap["urls"].([]interface{}); ok {
			var uStrs []string
			for _, u := range urls {
				if us, ok := u.(string); ok {
					uStrs = append(uStrs, us)
				}
			}
			if len(uStrs) > 0 {
				servers = append(servers, webrtc.ICEServer{URLs: uStrs})
			}
		}
	}
	if turnMap, ok := s.cfg.VCP["turn"].(map[string]interface{}); ok {
		if urls, ok := turnMap["urls"].([]interface{}); ok {
			var uStrs []string
			for _, u := range urls {
				if us, ok := u.(string); ok {
					uStrs = append(uStrs, us)
				}
			}
			if len(uStrs) > 0 {
				servers = append(servers, webrtc.ICEServer{
					URLs:       uStrs,
					Username:   str(turnMap["username"]),
					Credential: str(turnMap["credential"]),
				})
			}
		}
	}

	// Callee format: VCP["stne"] and VCP["trne"]
	if stne := str(s.cfg.VCP["stne"]); stne != "" {
		servers = append(servers, webrtc.ICEServer{URLs: strings.Split(stne, ",")})
	}
	if trne := str(s.cfg.VCP["trne"]); trne != "" {
		servers = append(servers, webrtc.ICEServer{
			URLs:       strings.Split(trne, ","),
			Username:   str(s.cfg.VCP["trnu"]),
			Credential: str(s.cfg.VCP["trnp"]),
		})
	}

	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}
	se := webrtc.SettingEngine{}
	se.SetNet(netx.NewPionNet())
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetSCTPMaxReceiveBufferSize(4 * 1024 * 1024)
	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.Writer = logx.NewNonBlocking(os.Stderr, 4096)
	loggerFactory.DefaultLogLevel = logging.LogLevelWarn
	se.LoggerFactory = loggerFactory
	api := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se))
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: servers})
	if err != nil {
		return nil, fmt.Errorf("signal: new peer connection: %w", err)
	}
	s.pc = pc

	pc.OnSignalingStateChange(func(st webrtc.SignalingState) {
		log.Printf("[WebRTC] Signaling state: %s", st)
	})
	pc.OnICEConnectionStateChange(func(st webrtc.ICEConnectionState) {
		log.Printf("[WebRTC] ICE state: %s", st)
		if st == webrtc.ICEConnectionStateFailed || st == webrtc.ICEConnectionStateClosed {
			s.finish()
		}
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		log.Printf("[WebRTC] Connection state: %s", st)
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			s.finish()
		}
	})

	if s.cfg.IsCaller {
		// Audio transceiver needed for OkCDN call signaling
		_, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{
			Direction: webrtc.RTPTransceiverDirectionSendrecv,
		})
		if err != nil {
			return nil, fmt.Errorf("signal: add audio transceiver: %w", err)
		}
		ordered := true
		dc, err := pc.CreateDataChannel("tunnel_poc", &webrtc.DataChannelInit{
			Ordered: &ordered,
		})
		if err != nil {
			return nil, fmt.Errorf("signal: create datachannel: %w", err)
		}
		s.setupDataChannel(dc)
	} else {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			log.Printf("[WebRTC] Incoming DataChannel received: label=%s", dc.Label())
			s.setupDataChannel(dc)
		})
	}

	return s, nil
}

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (s *Session) finish() { s.doneOnce.Do(func() { close(s.done) }) }

// sendChannelBytes serializes DataChannel sends using dcSendMu to preserve frame ordering.
func (s *Session) sendChannelBytes(data []byte) bool {
	s.dcSendMu.Lock()
	defer s.dcSendMu.Unlock()

	s.mu.Lock()
	dc := s.dc
	s.mu.Unlock()
	if dc == nil {
		log.Printf("[DataChannel TX warning]: dc is nil, dropped %d bytes", len(data))
		return false
	}
	if dc.ReadyState() != webrtc.DataChannelStateOpen {
		log.Printf("[DataChannel TX warning]: readyState is %s (not open), dropped %d bytes", dc.ReadyState(), len(data))
		return false
	}
	if err := dc.Send(data); err != nil {
		log.Printf("[DataChannel TX error]: %v", err)
		return false
	}
	return true
}

func (s *Session) getBufferedAmount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dc == nil {
		return 0
	}
	return s.dc.BufferedAmount()
}

// setupDataChannel configures handlers on the WebRTC DataChannel.
func (s *Session) setupDataChannel(dc *webrtc.DataChannel) {
	s.mu.Lock()
	s.dc = dc

	if s.cfg.IsCaller {
		isAsym := len(s.cfg.PrivateKey) == 32 && len(s.cfg.PeerPublicKey) == 32
		if isAsym {
			init, err := tunnelcrypto.NewHandshakeInitiator(s.cfg.PrivateKey, s.cfg.PeerPublicKey)
			if err != nil {
				s.mu.Unlock()
				log.Printf("[Auth] Failed to initialize handshake initiator: %v", err)
				s.finish()
				return
			}
			s.initiator = init
		}
	} else {
		isAsym := len(s.cfg.PrivateKey) == 32 && len(s.cfg.AllowedPeers) > 0
		if isAsym {
			resp, err := tunnelcrypto.NewHandshakeResponder(s.cfg.PrivateKey, s.cfg.AllowedPeers)
			if err != nil {
				s.mu.Unlock()
				log.Printf("[Auth] Failed to initialize handshake responder: %v", err)
				s.finish()
				return
			}
			s.responder = resp
			log.Println("[Auth] Asymmetric authentication enabled. Awaiting Handshake Init (3s timeout)...")
			s.watchdogTimer = time.AfterFunc(3*time.Second, func() {
				s.mu.Lock()
				authenticated := s.tunnel != nil
				s.mu.Unlock()
				if !authenticated {
					log.Println("[Auth] Handshake timeout (3s)! Terminating unauthorized call.")
					s.finish()
				}
			})
		} else if s.tunnel == nil {
			crypto, err := tunnelcrypto.New(s.cfg.TunnelSecret)
			if err != nil {
				s.mu.Unlock()
				log.Printf("[Tunnel] crypto init failed: %v", err)
				s.finish()
				return
			}
			s.tunnel = relay.New(crypto, s.sendChannelBytes, s.getBufferedAmount)
			log.Println("[REMOTE RELAY ACTIVE] Ready to forward decrypted traffic to Internet!")
		}
	}
	s.mu.Unlock()

	dc.OnOpen(func() {
		log.Println("[WebRTC DataChannel] OPENED successfully!")
		if s.cfg.IsCaller {
			s.mu.Lock()
			initiator := s.initiator
			s.mu.Unlock()
			if initiator != nil {
				initPkt, err := initiator.CreateInitPacket()
				if err != nil {
					log.Printf("[Auth] Failed to create init packet: %v", err)
					s.finish()
					return
				}
				log.Println("[Auth] Sending Curve25519 Handshake Init to relay...")
				s.sendChannelBytes(initPkt)
				s.watchdogTimer = time.AfterFunc(3*time.Second, func() {
					s.mu.Lock()
					authenticated := s.socks5Server != nil
					s.mu.Unlock()
					if !authenticated {
						log.Println("[Auth] Handshake response timeout (3s) from relay! Closing connection.")
						s.finish()
					}
				})
			} else {
				crypto, err := tunnelcrypto.New(s.cfg.TunnelSecret)
				if err != nil {
					log.Printf("[Tunnel] crypto init failed: %v", err)
					s.finish()
					return
				}
				s.startSocks5(crypto)
			}
		}
	})

	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		if m.IsString {
			s.handleControlMessage(string(m.Data))
			return
		}

		if s.cfg.IsCaller {
			s.mu.Lock()
			server := s.socks5Server
			initiator := s.initiator
			s.mu.Unlock()

			if server == nil && initiator != nil {
				crypto, err := initiator.ProcessRespPacket(m.Data)
				if err != nil {
					log.Printf("[Auth] Handshake verification failed: %v. Closing connection!", err)
					s.finish()
					return
				}
				s.mu.Lock()
				if s.watchdogTimer != nil {
					s.watchdogTimer.Stop()
				}
				s.mu.Unlock()
				log.Println("[Auth] Handshake SUCCESSFUL! Caller and relay mutually authenticated.")
				s.startSocks5(crypto)
				return
			}

			if server != nil {
				server.HandleChannelPacket(m.Data)
			}
			return
		}

		// Callee branch:
		s.mu.Lock()
		tunnel := s.tunnel
		responder := s.responder
		s.mu.Unlock()

		if tunnel == nil && responder != nil {
			respPkt, crypto, err := responder.ProcessInitPacket(m.Data)
			if err != nil {
				log.Printf("[Auth] Handshake verification failed: %v. Dropping call!", err)
				s.finish()
				return
			}
			s.sendChannelBytes(respPkt)
			s.mu.Lock()
			if s.watchdogTimer != nil {
				s.watchdogTimer.Stop()
			}
			s.tunnel = relay.New(crypto, s.sendChannelBytes, s.getBufferedAmount)
			s.mu.Unlock()
			log.Println("[Auth] Handshake SUCCESSFUL! Caller authenticated.")
			log.Println("[REMOTE RELAY ACTIVE] Ready to forward decrypted traffic to Internet!")
			return
		}

		if tunnel != nil {
			tunnel.HandleChannelPacket(m.Data)
		}
	})

	dc.OnError(func(err error) {
		log.Printf("[WebRTC DataChannel ERROR]: %v", err)
	})
	dc.OnClose(func() {
		log.Println("[WebRTC DataChannel] Closed.")
		s.finish()
	})
}

func (s *Session) startSocks5(crypto *tunnelcrypto.TunnelCrypto) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socks5Server != nil {
		return
	}
	server := socks5.New(socks5.Config{
		Crypto:            crypto,
		SendPacket:        s.sendChannelBytes,
		GetBufferedAmount: s.getBufferedAmount,
		Host:              s.cfg.ProxyHost,
		Port:              s.cfg.ProxyPort,
	})
	s.socks5Server = server
	go func() {
		if err := server.Start(); err != nil {
			log.Printf("[SOCKS5] Server start error: %v", err)
			s.finish()
			return
		}
		log.Printf("\n======================================================================\n"+
			"[SOCKS5 PROXY ACTIVE] Listening on %s:%d\n"+
			"Traffic is encrypted and tunneled over WebRTC!\n"+
			"Test from another terminal:\n"+
			"  curl -x socks5h://%s:%d https://api.ipify.org\n"+
			"======================================================================\n",
			s.cfg.ProxyHost, s.cfg.ProxyPort, s.cfg.ProxyHost, s.cfg.ProxyPort)
	}()
}

func (s *Session) handleControlMessage(msg string) {
	switch msg {
	case "ping":
		s.mu.Lock()
		dc := s.dc
		s.mu.Unlock()
		if dc != nil && dc.ReadyState() == webrtc.DataChannelStateOpen {
			_ = dc.SendText("pong")
		}
	case "pong":
	}
}

func (s *Session) sendCommand(name string, params map[string]interface{}) error {
	s.mu.Lock()
	ws := s.ws
	seq := s.seq
	s.seq++
	s.mu.Unlock()
	if ws == nil {
		return nil
	}
	payload := map[string]interface{}{"command": name, "sequence": seq}
	for k, v := range params {
		payload[k] = v
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	s.wsWriteMu.Lock()
	defer s.wsWriteMu.Unlock()
	return ws.WriteMessage(websocket.TextMessage, b)
}

func parseParticipantID(v interface{}) (interface{}, string) {
	if v == nil {
		return "", ""
	}
	switch val := v.(type) {
	case int64:
		return val, strconv.FormatInt(val, 10)
	case int:
		return int64(val), strconv.Itoa(val)
	case json.Number:
		if i, err := val.Int64(); err == nil {
			return i, val.String()
		}
		return val.String(), val.String()
	case float64:
		i := int64(val)
		return i, strconv.FormatInt(i, 10)
	case string:
		s := strings.TrimSpace(val)
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, s
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			i := int64(f)
			return i, strconv.FormatInt(i, 10)
		}
		return s, s
	}
	s := fmt.Sprint(v)
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, s
	}
	return s, s
}

func (s *Session) setRemotePID(v interface{}) {
	if v == nil {
		return
	}
	_, strVal := parseParticipantID(v)
	if strVal != "" && strVal != s.cfg.UserID {
		s.remotePID = strVal
	}
}

func (s *Session) targetParticipantID() interface{} {
	val, _ := parseParticipantID(s.remotePID)
	return val
}

func (s *Session) buildURL() string {
	tgt := "accept"
	if s.cfg.IsCaller {
		tgt = "start"
	}
	params := map[string]string{
		"userId":         s.cfg.UserID,
		"entityType":     "USER",
		"deviceIdx":      "0",
		"conversationId": s.cfg.ConvID,
		"token":          s.cfg.Token,
		"platform":       "WEB",
		"appVersion":     "26.10.3",
		"version":        "5",
		"device":         "browser",
		"capabilities":   "6A03F",
		"clientType":     "one_me",
		"tgt":            tgt,
	}
	raw := str(s.cfg.VCP["endpoint"])
	if raw == "" {
		raw = str(s.cfg.VCP["wse"])
	}
	if raw == "" {
		raw = "wss://videowebrtc.okcdn.ru/ws2"
	}
	u, err := url.Parse(raw)
	if err != nil {
		u, _ = url.Parse("wss://videowebrtc.okcdn.ru/ws2")
	}
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	for k, vs := range u.Query() {
		q.Set(k, vs[0])
	}
	for _, k := range []string{"tgt", "appVersion", "platform", "version", "device", "capabilities", "clientType", "deviceIdx"} {
		q.Set(k, params[k])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Run executes the WebRTC signaling and maintains the session.
func (s *Session) Run(ctx context.Context) error {
	wsURL := s.buildURL()
	log.Printf("Connecting to WebRTC signaling: %.100s...", wsURL)
	ws, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("signal: dial ws2: %w", err)
	}
	s.mu.Lock()
	s.ws = ws
	s.mu.Unlock()
	log.Println("[Signaling] Connected to ws2!")

	go s.listenLoop(ws)

	if !s.cfg.IsCaller {
		select {
		case <-s.connected:
		case <-time.After(3 * time.Second):
			log.Println("[Signaling] Timeout waiting for 'connection' greeting, sending accept-call anyway...")
		}
		log.Printf("[Signaling] Sending accept-call (isAudioEnabled=True, isVideoEnabled=%v)...", s.cfg.IsVideo)
		_ = s.sendCommand("accept-call", map[string]interface{}{
			"mediaSettings": map[string]interface{}{"isAudioEnabled": true, "isVideoEnabled": s.cfg.IsVideo},
		})
	}

	log.Println("[Signaling] WebRTC session established and running indefinitely.")
	kaStop := make(chan struct{})
	go s.keepalive(kaStop)

	select {
	case <-s.done:
	case <-ctx.Done():
	}
	close(kaStop)

	s.mu.Lock()
	t := s.tunnel
	srv := s.socks5Server
	s.mu.Unlock()
	if t != nil {
		t.Stop()
	}
	if srv != nil {
		srv.Stop()
	}

	log.Println("[Signaling] Sending hangup...")
	_ = s.sendCommand("hangup", map[string]interface{}{"reason": "HUNGUP", "hangupType": "HUNGUP"})
	time.Sleep(500 * time.Millisecond)
	_ = ws.Close()
	_ = s.pc.Close()
	log.Println("[Signaling] WebRTC session closed.")
	return nil
}

func (s *Session) keepalive(stop chan struct{}) {
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	var tick int
	var lastRx, lastTx uint64
	var stallCount int
	for {
		select {
		case <-stop:
			return
		case <-s.done:
			return
		case <-tk.C:
			tick++
			s.mu.Lock()
			dc, ws, tunnel, srv := s.dc, s.ws, s.tunnel, s.socks5Server
			s.mu.Unlock()

			if tick%3 == 0 { // every 15 s
				if dc != nil && dc.ReadyState() == webrtc.DataChannelStateOpen {
					_ = dc.SendText("ping")
				}
				if ws != nil {
					s.wsWriteMu.Lock()
					_ = ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second))
					s.wsWriteMu.Unlock()
				}
			}

			var sctpStats string
			if sctpTransport := s.pc.SCTP(); sctpTransport != nil {
				if assoc := sctpTransport.Association(); assoc != nil {
					sctpStats = fmt.Sprintf(" cwnd=%d rwnd=%d srtt=%.1fms inflight=%d pending=%d",
						assoc.CWND(), assoc.RWND(), assoc.SRTT(), assoc.InflightBytes(), assoc.PendingBytes())
				}
			}

			if s.cfg.IsCaller {
				if srv != nil && dc != nil {
					rxP, txP, rxB, txB, conns := srv.Stats()
					log.Printf("[Health] ice=%s conn=%s dc=%s conns=%d buffered=%dB%s rx=%dpkt/%dB tx=%dpkt/%dB (+%dB rx, +%dB tx in 5s)",
						s.pc.ICEConnectionState(), s.pc.ConnectionState(), dc.ReadyState(), conns,
						dc.BufferedAmount(), sctpStats, rxP, rxB, txP, txB, rxB-lastRx, txB-lastTx)
					lastRx, lastTx = rxB, txB
				}
			} else {
				if tunnel != nil && dc != nil {
					rxP, txP, rxB, txB, conns := tunnel.Stats()
					log.Printf("[Health] ice=%s conn=%s dc=%s conns=%d buffered=%dB%s rx=%dpkt/%dB tx=%dpkt/%dB (+%dB rx, +%dB tx in 5s)",
						s.pc.ICEConnectionState(), s.pc.ConnectionState(), dc.ReadyState(), conns,
						dc.BufferedAmount(), sctpStats, rxP, rxB, txP, txB, rxB-lastRx, txB-lastTx)
					if conns > 0 && rxB == lastRx && txB == lastTx && tick > 1 {
						stallCount++
						if stallCount%3 == 0 {
							log.Printf("[Health] NOTICE: %d open connection(s) idle (%ds)", conns, stallCount*5)
						}
					} else {
						stallCount = 0
					}
					lastRx, lastTx = rxB, txB
				}
			}
		}
	}
}

func (s *Session) listenLoop(ws *websocket.Conn) {
	defer s.finish()
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			log.Printf("[Signaling Error] %v", err)
			return
		}
		text := string(raw)
		if text == "ping" {
			s.wsWriteMu.Lock()
			_ = ws.WriteMessage(websocket.TextMessage, []byte("pong"))
			s.wsWriteMu.Unlock()
			continue
		}
		if text == "pong" {
			continue
		}
		var msg map[string]interface{}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&msg); err != nil {
			continue
		}
		switch str(msg["type"]) {
		case "error":
			errName := str(msg["error"])
			log.Printf("[Signaling Error RX] %v: %v", errName, msg["message"])
			if errName == "conversation-ended" || errName == "call-not-found" {
				return
			}
		case "notification":
			if s.handleNotification(msg) {
				return
			}
		}
	}
}

func (s *Session) sendOffer() {
	s.offerOnce.Do(func() {
		go func() {
			target := s.targetParticipantID()
			log.Printf("[WebRTC] Creating SDP offer for remote participant %v...", target)
			offer, err := s.pc.CreateOffer(nil)
			if err != nil {
				log.Printf("[WebRTC] CreateOffer failed: %v", err)
				s.finish()
				return
			}
			gather := webrtc.GatheringCompletePromise(s.pc)
			if err := s.pc.SetLocalDescription(offer); err != nil {
				log.Printf("[WebRTC] SetLocalDescription failed: %v", err)
				s.finish()
				return
			}
			select {
			case <-gather:
			case <-time.After(1500 * time.Millisecond):
			}
			local := s.pc.LocalDescription().SDP
			target = s.targetParticipantID()
			stripped := stripCandRe.ReplaceAllString(local, "")
			log.Printf("[WebRTC] Sending SDP offer to %v...", target)
			_ = s.sendCommand("transmit-data", map[string]interface{}{
				"participantId": target,
				"data": map[string]interface{}{
					"sdp":            map[string]interface{}{"type": "offer", "sdp": stripped},
					"animojiVersion": 1,
				},
			})

			seen := map[string]bool{}
			for _, line := range strings.Split(strings.ReplaceAll(local, "\r\n", "\n"), "\n") {
				if !strings.HasPrefix(line, "a=candidate:") {
					continue
				}
				c := strings.TrimSpace(line[2:])
				if strings.Contains(c, " typ host") || seen[c] {
					continue
				}
				seen[c] = true
				_ = s.sendCommand("transmit-data", map[string]interface{}{
					"participantId": target,
					"data": map[string]interface{}{
						"candidate": map[string]interface{}{"candidate": c, "sdpMid": "0", "sdpMLineIndex": 0},
					},
				})
			}
		}()
	})
}

func (s *Session) handleNotification(msg map[string]interface{}) bool {
	switch str(msg["notification"]) {
	case "connection":
		log.Println("[Signaling] Connection established with call endpoint!")
		s.connOnce.Do(func() { close(s.connected) })
		if conv, ok := msg["conversation"].(map[string]interface{}); ok {
			if parts, ok := conv["participants"].([]interface{}); ok {
				for _, p := range parts {
					pm, _ := p.(map[string]interface{})
					if pm["id"] != nil {
						s.setRemotePID(pm["id"])
						if s.cfg.IsCaller && str(pm["state"]) == "ACCEPTED" {
							s.sendOffer()
						}
					}
				}
			}
		}
	case "accepted-call", "registered-peer":
		s.setRemotePID(msg["participantId"])
		if s.cfg.IsCaller {
			s.sendOffer()
		}
	case "participant-state-changed":
		st := str(msg["state"])
		if st == "" {
			st = str(msg["participantState"])
		}
		if st == "ACCEPTED" {
			s.setRemotePID(msg["participantId"])
			if s.cfg.IsCaller {
				s.sendOffer()
			}
		}
	case "transmitted-data":
		s.handleTransmittedData(msg)
	case "hungup":
		log.Println("[Signaling] Remote side hung up.")
		return true
	}
	return false
}

func (s *Session) handleTransmittedData(msg map[string]interface{}) {
	s.setRemotePID(msg["participantId"])
	data, _ := msg["data"].(map[string]interface{})
	if sdpInfo, ok := data["sdp"].(map[string]interface{}); ok {
		s.handleRemoteSDP(sdpInfo)
		return
	}
	if cand := data["candidate"]; cand != nil {
		var candStr string
		if cm, ok := cand.(map[string]interface{}); ok {
			candStr = str(cm["candidate"])
		} else {
			candStr = str(cand)
		}
		if candStr != "" {
			s.addRemoteCandidate(candStr)
		}
	}
}

func (s *Session) handleRemoteSDP(info map[string]interface{}) {
	sdpType := str(info["type"])
	sdpStr := str(info["sdp"])
	log.Printf("[WebRTC] Remote SDP %s received!", sdpType)
	if sdpType == "offer" {
		if err := s.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdpStr}); err != nil {
			log.Printf("[WebRTC] SetRemoteDescription failed: %v", err)
			s.finish()
			return
		}
		answer, err := s.pc.CreateAnswer(nil)
		if err != nil {
			log.Printf("[WebRTC] CreateAnswer failed: %v", err)
			s.finish()
			return
		}
		gather := webrtc.GatheringCompletePromise(s.pc)
		if err := s.pc.SetLocalDescription(answer); err != nil {
			log.Printf("[WebRTC] SetLocalDescription failed: %v", err)
			s.finish()
			return
		}
		select {
		case <-gather:
		case <-time.After(1500 * time.Millisecond):
		}
		local := s.pc.LocalDescription().SDP
		target := s.targetParticipantID()
		stripped := stripCandRe.ReplaceAllString(local, "")
		log.Printf("[WebRTC] Sending local SDP answer to %v...", target)
		_ = s.sendCommand("transmit-data", map[string]interface{}{
			"participantId": target,
			"data": map[string]interface{}{
				"sdp":            map[string]interface{}{"type": "answer", "sdp": stripped},
				"animojiVersion": 1,
			},
		})

		seen := map[string]bool{}
		for _, line := range strings.Split(strings.ReplaceAll(local, "\r\n", "\n"), "\n") {
			if !strings.HasPrefix(line, "a=candidate:") {
				continue
			}
			c := strings.TrimSpace(line[2:])
			if strings.Contains(c, " typ host") || seen[c] {
				continue
			}
			seen[c] = true
			_ = s.sendCommand("transmit-data", map[string]interface{}{
				"participantId": target,
				"data": map[string]interface{}{
					"candidate": map[string]interface{}{"candidate": c, "sdpMid": "0", "sdpMLineIndex": 0},
				},
			})
		}
		s.flushPendingCandidates()
	} else if sdpType == "answer" {
		if s.pc.SignalingState() != webrtc.SignalingStateHaveLocalOffer {
			log.Printf("[WebRTC] Duplicate or unexpected remote SDP answer received while signaling state is %s, ignoring", s.pc.SignalingState())
			return
		}
		if err := s.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdpStr}); err != nil {
			log.Printf("[WebRTC] SetRemoteDescription failed: %v", err)
			s.finish()
			return
		}
		s.flushPendingCandidates()
	}
}

func (s *Session) flushPendingCandidates() {
	s.mu.Lock()
	s.remoteSet = true
	pend := s.pendingCand
	s.pendingCand = nil
	s.mu.Unlock()
	for _, c := range pend {
		if err := s.pc.AddICECandidate(c); err != nil {
			log.Printf("[WebRTC] Failed to add candidate: %v", err)
		}
	}
}

func (s *Session) addRemoteCandidate(candStr string) {
	if ufragRe.MatchString(candStr) {
		log.Printf("[WebRTC] Stripping OkCDN 'ufrag' extension from candidate")
		candStr = ufragRe.ReplaceAllString(candStr, "")
	}
	candStr = strings.TrimPrefix(candStr, "a=")
	mid := "0"
	idx := uint16(0)
	init := webrtc.ICECandidateInit{Candidate: candStr, SDPMid: &mid, SDPMLineIndex: &idx}

	s.mu.Lock()
	if !s.remoteSet {
		s.pendingCand = append(s.pendingCand, init)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if err := s.pc.AddICECandidate(init); err != nil {
		log.Printf("[WebRTC] Failed to add candidate: %v", err)
	}
}
