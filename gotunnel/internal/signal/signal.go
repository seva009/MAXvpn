// Package signal ports the callee ("remote relay") half of webrtc_call.py:
// signaling over wss://videowebrtc.okcdn.ru/ws2 and the WebRTC PeerConnection
// / DataChannel that carries the encrypted tunnel packets into the relay.
//
// The signaling protocol (commands, notifications, SDP/candidate munging) is
// kept identical to the Python implementation. The aiortc/aioice monkey
// patches in the Python file are NOT ported: they work around aiortc
// internals and have no equivalent in pion (see docs, "Known differences").
package signal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v3"

	"calltunnel/internal/relay"
	"calltunnel/internal/tunnelcrypto"
)

var stripCandRe = regexp.MustCompile(`(?m)^(a=candidate:|a=end-of-candidates).*\r?\n?`)
var ufragRe = regexp.MustCompile(`\s+ufrag\s+\S+`)

// Config holds everything OKWebRTCSignaling.__init__ needed for the callee.
type Config struct {
	UserID              string
	ConvID              string
	Token               string
	RemoteParticipantID string
	VCP                 map[string]interface{}
	IsVideo             bool
	TunnelSecret        string
	PrivateKey          []byte
	AllowedPeers        [][]byte
}

// Session is the Go equivalent of OKWebRTCSignaling (callee, proxy mode).
type Session struct {
	cfg Config

	mu            sync.Mutex
	ws            *websocket.Conn
	wsWriteMu     sync.Mutex
	seq           int
	remotePID     string
	pc            *webrtc.PeerConnection
	dc            *webrtc.DataChannel
	tunnel        *relay.TunnelRelay
	responder     *tunnelcrypto.HandshakeResponder
	watchdogTimer *time.Timer
	done          chan struct{}
	doneOnce      sync.Once
	connected     chan struct{}
	connOnce      sync.Once
	pendingCand   []webrtc.ICECandidateInit
	remoteSet     bool
}

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

	// Default codecs are needed so pion can answer the caller's m=audio line.
	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}
	se := webrtc.SettingEngine{}
	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = logging.LogLevelWarn
	loggerFactory.ScopeLevels = map[string]logging.LogLevel{
		"sctp":        logging.LogLevelDebug,
		"datachannel": logging.LogLevelDebug,
		"ortc":        logging.LogLevelDebug,
	}
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
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		log.Printf("[WebRTC] Incoming DataChannel received: label=%s", dc.Label())
		s.setupDataChannel(dc)
	})
	return s, nil
}

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (s *Session) finish() { s.doneOnce.Do(func() { close(s.done) }) }

// sendChannelBytes mirrors send_channel_bytes.
func (s *Session) sendChannelBytes(data []byte) bool {
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

// setupDataChannel mirrors setup_datachannel (proxy mode, callee).
func (s *Session) setupDataChannel(dc *webrtc.DataChannel) {
	s.mu.Lock()
	s.dc = dc
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
		// Ready before any packet can arrive, like the Python version.
		s.tunnel = relay.New(crypto, s.sendChannelBytes, s.getBufferedAmount)
		log.Println("[REMOTE RELAY ACTIVE] Ready to forward decrypted traffic to Internet!")
	}
	s.mu.Unlock()

	dc.OnOpen(func() { log.Println("[WebRTC DataChannel] OPENED successfully!") })
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		if m.IsString {
			s.handleControlMessage(string(m.Data))
			return
		}

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

// handleControlMessage mirrors _handle_proxy_control_message.
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
		"tgt":            "accept",
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
	for k, vs := range u.Query() { // existing params override...
		q.Set(k, vs[0])
	}
	for _, k := range []string{"tgt", "appVersion", "platform", "version", "device", "capabilities", "clientType", "deviceIdx"} {
		q.Set(k, params[k]) // ...except these forced keys
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Run mirrors OKWebRTCSignaling.run() for is_caller=False, mode="proxy".
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

	select {
	case <-s.connected:
	case <-time.After(3 * time.Second):
		log.Println("[Signaling] Timeout waiting for 'connection' greeting, sending accept-call anyway...")
	}
	log.Printf("[Signaling] Sending accept-call (isAudioEnabled=True, isVideoEnabled=%v)...", s.cfg.IsVideo)
	_ = s.sendCommand("accept-call", map[string]interface{}{
		"mediaSettings": map[string]interface{}{"isAudioEnabled": true, "isVideoEnabled": s.cfg.IsVideo},
	})

	log.Println("[Signaling] WebRTC proxy session established and running indefinitely.")
	kaStop := make(chan struct{})
	go s.keepalive(kaStop)

	select {
	case <-s.done:
	case <-ctx.Done():
	}
	close(kaStop)

	s.mu.Lock()
	t := s.tunnel
	s.mu.Unlock()
	if t != nil {
		t.Stop()
	}

	log.Println("[Signaling] Sending hangup...")
	_ = s.sendCommand("hangup", map[string]interface{}{"reason": "HUNGUP", "hangupType": "HUNGUP"})
	time.Sleep(500 * time.Millisecond)
	_ = ws.Close()
	_ = s.pc.Close()
	log.Println("[Signaling] WebRTC session closed.")
	return nil
}

// keepalive mirrors _proxy_keepalive_loop (15 s).
func (s *Session) keepalive(stop chan struct{}) {
	tk := time.NewTicker(15 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-s.done:
			return
		case <-tk.C:
			s.mu.Lock()
			dc, ws := s.dc, s.ws
			s.mu.Unlock()
			if dc != nil && dc.ReadyState() == webrtc.DataChannelStateOpen {
				_ = dc.SendText("ping")
			}
			if ws != nil {
				s.wsWriteMu.Lock()
				_ = ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(5*time.Second))
				s.wsWriteMu.Unlock()
			}
		}
	}
}

// listenLoop mirrors _listen_loop (callee-relevant branches).
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

// handleNotification returns true if the session should end.
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
					}
				}
			}
		}
	case "accepted-call", "registered-peer":
		s.setRemotePID(msg["participantId"])
	case "participant-state-changed":
		if msg["state"] == "ACCEPTED" || msg["participantState"] == "ACCEPTED" {
			s.setRemotePID(msg["participantId"])
		}
	case "transmitted-data":
		s.handleTransmittedData(msg)
	case "hungup":
		log.Println("[Signaling] Remote side hung up.")
		return true
	}
	return false
}

// handleTransmittedData mirrors _handle_transmitted_data.
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
	if sdpType != "offer" {
		return
	}
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
	select { // python waits up to 30*0.05 s
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

	// Trickle srflx/relay candidates only (host skipped, as in Python).
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

	// Flush candidates that arrived before the remote description was set.
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
	// pion has no per-connection remote ufrag override; strip the OkCDN
	// "ufrag" extension so the candidate parses.
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
