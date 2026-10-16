// Package socks5 implements a local SOCKS5 proxy server that multiplexes
// client TCP connections into encrypted packets over a WebRTC DataChannel.
// It is the Go replacement for socks5_server.py.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"calltunnel/internal/tunnelcrypto"
)

// ChunkSize matches the WebRTC DataChannel frame size in tunnel_relay / socks5_server.py.
const ChunkSize = 16384

// SendPacketFunc hands an already-encrypted packet to the DataChannel for transmission.
type SendPacketFunc func(packet []byte) bool

// GetBufferedAmountFunc returns the current WebRTC DataChannel buffered bytes.
type GetBufferedAmountFunc func() uint64

// Config defines the configuration for the SOCKS5 proxy server.
type Config struct {
	Crypto            *tunnelcrypto.TunnelCrypto
	SendPacket        SendPacketFunc
	GetBufferedAmount GetBufferedAmountFunc
	Host              string
	Port              int
}

type connectResult struct {
	ok  bool
	err string
}

type clientConn struct {
	connID    uint32
	nc        net.Conn
	cancel    context.CancelFunc
	writeChan chan []byte
}

// Server is the SOCKS5 proxy server.
type Server struct {
	cfg        Config
	listener   net.Listener
	mu         sync.Mutex
	running    bool
	nextConnID atomic.Uint32

	pendingConnects map[uint32]chan connectResult
	activeConns     map[uint32]*clientConn

	rxPackets atomic.Uint64
	txPackets atomic.Uint64
	rxBytes   atomic.Uint64
	txBytes   atomic.Uint64
}

// New creates a new SOCKS5 proxy server.
func New(cfg Config) *Server {
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 1080
	}
	s := &Server{
		cfg:             cfg,
		pendingConnects: make(map[uint32]chan connectResult),
		activeConns:     make(map[uint32]*clientConn),
	}
	s.nextConnID.Store(1)
	return s
}

// Start binds to the configured host:port and begins accepting client connections.
func (s *Server) Start() error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5: listen %s: %w", addr, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.running = true
	s.mu.Unlock()

	log.Printf("[SOCKS5] Local proxy server listening on %s", ln.Addr().String())
	go s.acceptLoop(ln)
	return nil
}

// Addr returns the bound network address of the listener, or nil if not listening.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Stats returns cumulative packet/byte counters and open connection count.
func (s *Server) Stats() (rxPkts, txPkts, rxBytes, txBytes uint64, conns int) {
	s.mu.Lock()
	conns = len(s.activeConns)
	s.mu.Unlock()
	return s.rxPackets.Load(), s.txPackets.Load(), s.rxBytes.Load(), s.txBytes.Load(), conns
}

func (s *Server) send(pkt []byte) bool {
	ok := s.cfg.SendPacket(pkt)
	if ok {
		s.txPackets.Add(1)
		s.txBytes.Add(uint64(len(pkt)))
	}
	return ok
}

// Stop shuts down the server, cancels all active client connections, and cleans up.
func (s *Server) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
	pending := s.pendingConnects
	s.pendingConnects = make(map[uint32]chan connectResult)
	active := s.activeConns
	s.activeConns = make(map[uint32]*clientConn)
	s.mu.Unlock()

	for _, ch := range pending {
		select {
		case ch <- connectResult{ok: false, err: "proxy stopped"}:
		default:
		}
	}

	for _, c := range active {
		c.cancel()
		_ = c.nc.Close()
	}
	log.Println("[SOCKS5] Local proxy stopped.")
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()
			if !running || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[SOCKS5] Accept error: %v", err)
			continue
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
		go s.handleClient(conn)
	}
}

// HandleChannelPacket is called when a decrypted packet arrives from the remote relay via DataChannel.
func (s *Server) HandleChannelPacket(raw []byte) {
	s.rxPackets.Add(1)
	s.rxBytes.Add(uint64(len(raw)))
	msgType, connID, payload, err := s.cfg.Crypto.Decrypt(raw)
	if err != nil {
		log.Printf("[SOCKS5 RX] Failed to decrypt packet: %v", err)
		return
	}

	switch msgType {
	case tunnelcrypto.CmdConnectOK:
		log.Printf("[SOCKS5 RX] CONNECT_OK for conn #%d", connID)
		s.mu.Lock()
		ch, ok := s.pendingConnects[connID]
		if ok {
			delete(s.pendingConnects, connID)
		}
		s.mu.Unlock()
		if ok {
			select {
			case ch <- connectResult{ok: true}:
			default:
			}
		}

	case tunnelcrypto.CmdConnectFail:
		errMsg := string(payload)
		log.Printf("[SOCKS5 RX] Remote connect failed for conn #%d: %s", connID, errMsg)
		s.mu.Lock()
		ch, ok := s.pendingConnects[connID]
		if ok {
			delete(s.pendingConnects, connID)
		}
		s.mu.Unlock()
		if ok {
			select {
			case ch <- connectResult{ok: false, err: errMsg}:
			default:
			}
		}

	case tunnelcrypto.CmdData:
		s.mu.Lock()
		c, ok := s.activeConns[connID]
		s.mu.Unlock()
		if ok {
			select {
			case c.writeChan <- payload:
			default:
				log.Printf("[SOCKS5] Client conn #%d write buffer full, resetting", connID)
				s.mu.Lock()
				if cur, still := s.activeConns[connID]; still && cur == c {
					delete(s.activeConns, connID)
				} else {
					ok = false
				}
				s.mu.Unlock()
				if ok {
					c.cancel()
					_ = c.nc.Close()
					if pkt, eerr := s.cfg.Crypto.Encrypt(tunnelcrypto.CmdClose, connID, nil); eerr == nil {
						s.send(pkt)
					}
				}
			}
		}

	case tunnelcrypto.CmdClose:
		log.Printf("[SOCKS5 RX] CLOSE for conn #%d", connID)
		s.mu.Lock()
		c, ok := s.activeConns[connID]
		if ok {
			delete(s.activeConns, connID)
		}
		s.mu.Unlock()
		if ok {
			c.cancel()
			_ = c.nc.Close()
		}
	}
}

func (s *Server) allocConnID() uint32 {
	for {
		id := s.nextConnID.Add(1)
		if id != 0 {
			return id
		}
	}
}

func (s *Server) handleClient(conn net.Conn) {
	connID := s.allocConnID()

	// 1. SOCKS5 greeting: VER (1B) + NMETHODS (1B) + METHODS
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		_ = conn.Close()
		return
	}
	if header[0] != 5 { // SOCKS version 5 only
		_ = conn.Close()
		return
	}

	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		_ = conn.Close()
		return
	}

	hasNoAuth := false
	for _, m := range methods {
		if m == 0 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		_, _ = conn.Write([]byte{0x05, 0xff}) // No acceptable authentication methods
		_ = conn.Close()
		return
	}

	// Respond with NO AUTH (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		_ = conn.Close()
		return
	}

	// 2. SOCKS5 request: VER (1B) + CMD (1B) + RSV (1B) + ATYP (1B)
	var reqHeader [4]byte
	if _, err := io.ReadFull(conn, reqHeader[:]); err != nil {
		_ = conn.Close()
		return
	}
	ver, cmd, _, atyp := reqHeader[0], reqHeader[1], reqHeader[2], reqHeader[3]
	if ver != 5 || cmd != 1 { // Only CONNECT (0x01) supported
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		_ = conn.Close()
		return
	}

	var host string
	switch atyp {
	case 1: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			_ = conn.Close()
			return
		}
		host = net.IP(ip[:]).String()
	case 3: // Domain name
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			_ = conn.Close()
			return
		}
		domainBytes := make([]byte, dlen[0])
		if _, err := io.ReadFull(conn, domainBytes); err != nil {
			_ = conn.Close()
			return
		}
		host = string(domainBytes)
	case 4: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			_ = conn.Close()
			return
		}
		host = net.IP(ip[:]).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		_ = conn.Close()
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		_ = conn.Close()
		return
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	_ = conn.SetReadDeadline(time.Time{})

	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		_, _ = conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Network unreachable
		_ = conn.Close()
		return
	}
	ch := make(chan connectResult, 1)
	s.pendingConnects[connID] = ch
	s.mu.Unlock()

	log.Printf("[SOCKS5] New connection #%d -> %s:%d", connID, host, port)

	// Send encrypted CONNECT command to remote relay
	connectPayload := tunnelcrypto.PackConnectPayload(host, port)
	pkt, err := s.cfg.Crypto.Encrypt(tunnelcrypto.CmdConnect, connID, connectPayload)
	if err != nil || !s.send(pkt) {
		s.mu.Lock()
		delete(s.pendingConnects, connID)
		s.mu.Unlock()
		_, _ = conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = conn.Close()
		return
	}

	// Wait for remote relay ACK (15s timeout matching remote relay dial timeout + latency)
	var connectSuccess bool
	select {
	case res := <-ch:
		connectSuccess = res.ok
	case <-time.After(15 * time.Second):
		s.mu.Lock()
		delete(s.pendingConnects, connID)
		running := s.running
		s.mu.Unlock()
		if running {
			log.Printf("[SOCKS5] Timeout waiting for connect ACK #%d -> %s:%d", connID, host, port)
		}
		connectSuccess = false
	}

	s.mu.Lock()
	running := s.running
	s.mu.Unlock()

	if !connectSuccess || !running {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connection refused
		_ = conn.Close()
		return
	}

	// SOCKS5 success reply
	log.Printf("[SOCKS5] Connected #%d -> %s:%d", connID, host, port)
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		if pktClose, eerr := s.cfg.Crypto.Encrypt(tunnelcrypto.CmdClose, connID, nil); eerr == nil {
			s.send(pktClose)
		}
		_ = conn.Close()
		return
	}

	// 3. Bidirectional streaming
	ctx, cancel := context.WithCancel(context.Background())
	writeChan := make(chan []byte, 128)
	cc := &clientConn{
		connID:    connID,
		nc:        conn,
		cancel:    cancel,
		writeChan: writeChan,
	}

	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		cancel()
		_ = conn.Close()
		return
	}
	s.activeConns[connID] = cc
	s.mu.Unlock()

	go s.clientWriterLoop(ctx, connID, conn, writeChan)
	s.clientReaderLoop(ctx, connID, conn)
}

func (s *Server) clientWriterLoop(ctx context.Context, connID uint32, nc net.Conn, writeChan <-chan []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-writeChan:
			if !ok {
				return
			}
			if _, err := nc.Write(data); err != nil {
				return
			}
		}
	}
}

func (s *Server) clientReaderLoop(ctx context.Context, connID uint32, nc net.Conn) {
	buf := make([]byte, ChunkSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Backpressure control: pause reading if outbound DataChannel SCTP buffer is congested
		if s.cfg.GetBufferedAmount != nil {
			for s.cfg.GetBufferedAmount() > 2*1024*1024 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(1 * time.Millisecond):
				}
			}
		}

		n, err := nc.Read(buf)
		if n > 0 {
			pkt, eerr := s.cfg.Crypto.Encrypt(tunnelcrypto.CmdData, connID, buf[:n])
			if eerr == nil {
				if !s.send(pkt) {
					break
				}
			}
		}
		if err != nil {
			break
		}
	}

	s.mu.Lock()
	c, ok := s.activeConns[connID]
	if ok {
		delete(s.activeConns, connID)
	}
	running := s.running
	s.mu.Unlock()

	if ok {
		c.cancel()
		_ = c.nc.Close()
	}

	if running && ctx.Err() == nil {
		if pkt, eerr := s.cfg.Crypto.Encrypt(tunnelcrypto.CmdClose, connID, nil); eerr == nil {
			log.Printf("[SOCKS5 TX] Sending CLOSE #%d", connID)
			s.send(pkt)
		}
	}
}
