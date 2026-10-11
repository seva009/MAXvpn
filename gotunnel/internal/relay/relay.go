// Package relay is a line-for-line port of tunnel_relay.py. It is the piece
// that runs on the receiving side (Raspberry Pi / server): it receives
// AES-GCM encrypted requests from the caller over the WebRTC DataChannel,
// opens outbound TCP connections to the real Internet targets, and relays
// decrypted data bidirectionally. The connection bookkeeping (conn_id ->
// socket map, CONNECT/CONNECT_OK/CONNECT_FAIL/DATA/CLOSE handling) mirrors
// the Python TunnelRelay class exactly.
package relay

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"calltunnel/internal/tunnelcrypto"
)

// ChunkSize mirrors CHUNK_SIZE in tunnel_relay.py / socks5_server.py (4 KB
// WebRTC DataChannel frame size for reduced SCTP packet loss and lower latency).
const ChunkSize = 4096

// SendPacketFunc matches the Python send_packet_fn callable: it hands an
// already-encrypted packet to the DataChannel for transmission. Returns true
// if the packet was accepted for delivery.
type SendPacketFunc func(packet []byte) bool

type conn struct {
	nc        net.Conn
	cancel    context.CancelFunc
	writeChan chan []byte
}

// GetBufferedAmountFunc returns the current WebRTC DataChannel buffered bytes.
type GetBufferedAmountFunc func() uint64

// TunnelRelay is the Go equivalent of tunnel_relay.py's TunnelRelay class.
type TunnelRelay struct {
	crypto            *tunnelcrypto.TunnelCrypto
	sendPacket        SendPacketFunc
	getBufferedAmount GetBufferedAmountFunc
	mu                sync.Mutex
	activeConns       map[uint32]*conn
	running           bool

	rxPackets atomic.Uint64
	txPackets atomic.Uint64
	rxBytes   atomic.Uint64
	txBytes   atomic.Uint64
}

// Stats returns cumulative packet/byte counters (DataChannel level, encrypted
// size) and the number of currently open target connections. Used for
// diagnostics only.
func (r *TunnelRelay) Stats() (rxPkts, txPkts, rxBytes, txBytes uint64, conns int) {
	r.mu.Lock()
	conns = len(r.activeConns)
	r.mu.Unlock()
	return r.rxPackets.Load(), r.txPackets.Load(), r.rxBytes.Load(), r.txBytes.Load(), conns
}

// send wraps sendPacket with accounting.
func (r *TunnelRelay) send(pkt []byte) bool {
	ok := r.sendPacket(pkt)
	if ok {
		r.txPackets.Add(1)
		r.txBytes.Add(uint64(len(pkt)))
	}
	return ok
}

// New constructs a TunnelRelay, mirroring TunnelRelay.__init__.
func New(crypto *tunnelcrypto.TunnelCrypto, sendPacket SendPacketFunc, getBufferedAmount GetBufferedAmountFunc) *TunnelRelay {
	return &TunnelRelay{
		crypto:            crypto,
		sendPacket:        sendPacket,
		getBufferedAmount: getBufferedAmount,
		activeConns:       make(map[uint32]*conn),
		running:           true,
	}
}

// Stop mirrors TunnelRelay.stop(): cancel every outbound connection's reader
// loop and close its socket.
func (r *TunnelRelay) Stop() {
	r.mu.Lock()
	r.running = false
	conns := r.activeConns
	r.activeConns = make(map[uint32]*conn)
	r.mu.Unlock()

	for _, c := range conns {
		c.cancel()
		_ = c.nc.Close()
	}
	log.Println("[Tunnel Relay] Stopped all active internet connections.")
}

// HandleChannelPacket mirrors TunnelRelay.handle_channel_packet: called
// whenever an encrypted packet arrives from the caller via the DataChannel.
func (r *TunnelRelay) HandleChannelPacket(raw []byte) {
	r.rxPackets.Add(1)
	r.rxBytes.Add(uint64(len(raw)))
	msgType, connID, payload, err := r.crypto.Decrypt(raw)
	if err != nil {
		log.Printf("[Tunnel Relay RX] Failed to decrypt packet: %v", err)
		return
	}

	switch msgType {
	case tunnelcrypto.CmdConnect:
		host, port, uerr := tunnelcrypto.UnpackConnectPayload(payload)
		if uerr != nil {
			log.Printf("[Tunnel Relay] Error unpacking connect payload #%d: %v", connID, uerr)
			if pkt, eerr := r.crypto.Encrypt(tunnelcrypto.CmdConnectFail, connID, []byte(uerr.Error())); eerr == nil {
				r.send(pkt)
			}
			return
		}
		log.Printf("[Tunnel Relay RX] CONNECT request #%d -> %s:%d", connID, host, port)
		go r.handleConnect(connID, host, port)

	case tunnelcrypto.CmdPing:
		// The protocol defines an encrypted PING/PONG ([conn_id][timestamp]),
		// but it used to fall through this switch unanswered, so a caller
		// that uses it as a liveness probe saw a dead tunnel. Echo it back.
		if pkt, eerr := r.crypto.Encrypt(tunnelcrypto.CmdPong, connID, payload); eerr == nil {
			r.send(pkt)
		}

	case tunnelcrypto.CmdPong:
		// nothing to do

	case tunnelcrypto.CmdData:
		r.mu.Lock()
		c, ok := r.activeConns[connID]
		r.mu.Unlock()
		if ok {
			select {
			case c.writeChan <- payload:
			default:
				// Never block Pion's OnMessage loop (it serves every
				// connection and the keepalive). But silently dropping a
				// chunk of a TCP byte stream corrupts it and leaves the
				// application hanging forever (TLS/HTTP just stop). Fail
				// loudly instead: reset this one connection so the client
				// gets a clean error and can retry.
				log.Printf("[Tunnel Relay] Target conn #%d write buffer full, resetting connection", connID)
				r.mu.Lock()
				if cur, still := r.activeConns[connID]; still && cur == c {
					delete(r.activeConns, connID)
				} else {
					ok = false
				}
				r.mu.Unlock()
				if ok {
					c.cancel()
					_ = c.nc.Close()
					if pkt, eerr := r.crypto.Encrypt(tunnelcrypto.CmdClose, connID, nil); eerr == nil {
						r.send(pkt)
					}
				}
			}
		}

	case tunnelcrypto.CmdClose:
		log.Printf("[Tunnel Relay RX] CLOSE request #%d", connID)
		r.mu.Lock()
		c, ok := r.activeConns[connID]
		if ok {
			delete(r.activeConns, connID)
		}
		r.mu.Unlock()
		if ok {
			c.cancel()
			_ = c.nc.Close()
		}
	}
}

// connWriterLoop drains the per-connection write channel and writes to the TCP socket.
func (r *TunnelRelay) connWriterLoop(ctx context.Context, connID uint32, nc net.Conn, writeChan <-chan []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-writeChan:
			if !ok {
				return
			}
			if _, err := nc.Write(data); err != nil {
				if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					log.Printf("[Tunnel Relay] Error writing to target conn #%d: %v", connID, err)
				}
				return
			}
		}
	}
}

// handleConnect mirrors TunnelRelay._handle_connect.
func (r *TunnelRelay) handleConnect(connID uint32, host string, port uint16) {
	log.Printf("[Tunnel Relay] Connecting to %s:%d for conn #%d...", host, port, connID)

	dialer := net.Dialer{
		Timeout:       5 * time.Second,
		FallbackDelay: 250 * time.Millisecond,
	}
	addr := net.JoinHostPort(host, portToString(port))
	nc, err := dialer.Dial("tcp", addr)
	if err != nil {
		log.Printf("[Tunnel Relay] Failed to connect to %s:%d for conn #%d: %v", host, port, connID, err)
		if pkt, eerr := r.crypto.Encrypt(tunnelcrypto.CmdConnectFail, connID, []byte(err.Error())); eerr == nil {
			log.Printf("[Tunnel Relay TX] Sending CONNECT_FAIL #%d", connID)
			r.send(pkt)
		}
		return
	}
	if tcpConn, ok := nc.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	log.Printf("[Tunnel Relay] CONNECTED to %s:%d for conn #%d!", host, port, connID)

	ctx, cancel := context.WithCancel(context.Background())
	writeChan := make(chan []byte, 128)
	c := &conn{nc: nc, cancel: cancel, writeChan: writeChan}

	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		cancel()
		_ = nc.Close()
		return
	}
	r.activeConns[connID] = c
	r.mu.Unlock()

	go r.connWriterLoop(ctx, connID, nc, writeChan)
	go r.remoteReaderLoop(ctx, connID, nc)

	if pkt, eerr := r.crypto.Encrypt(tunnelcrypto.CmdConnectOK, connID, nil); eerr == nil {
		log.Printf("[Tunnel Relay TX] Sending CONNECT_OK #%d", connID)
		r.send(pkt)
	}
}

// remoteReaderLoop mirrors TunnelRelay._remote_reader_loop: reads from the
// target TCP socket and ships each chunk back over the DataChannel,
// finishing with a CLOSE notification.
func (r *TunnelRelay) remoteReaderLoop(ctx context.Context, connID uint32, nc net.Conn) {
	buf := make([]byte, ChunkSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Backpressure: pause reading from target if outbound DataChannel SCTP buffer is full
		if r.getBufferedAmount != nil {
			for r.getBufferedAmount() > 512*1024 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		}

		n, err := nc.Read(buf)
		if n > 0 {
			pkt, eerr := r.crypto.Encrypt(tunnelcrypto.CmdData, connID, buf[:n])
			if eerr == nil {
				if !r.send(pkt) {
					break
				}
			}
		}
		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				log.Printf("[Tunnel Relay] Target socket closed or error #%d: %v", connID, err)
			}
			break
		}
	}

	r.mu.Lock()
	c, ok := r.activeConns[connID]
	if ok {
		delete(r.activeConns, connID)
	}
	r.mu.Unlock()
	if ok {
		c.cancel()
		_ = c.nc.Close()
	}

	if ctx.Err() == nil {
		if pkt, eerr := r.crypto.Encrypt(tunnelcrypto.CmdClose, connID, nil); eerr == nil {
			log.Printf("[Tunnel Relay TX] Sending CLOSE #%d", connID)
			r.send(pkt)
		}
	}
}

func portToString(p uint16) string {
	const digits = "0123456789"
	if p == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = digits[p%10]
		p /= 10
	}
	return string(b[i:])
}
