package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"calltunnel/internal/relay"
	"calltunnel/internal/tunnelcrypto"
)

func TestSocks5EchoThroughRelay(t *testing.T) {
	// 1. Start a TCP echo server representing the real Internet target
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	// 2. Setup TunnelCrypto (symmetric for simplicity)
	cr, err := tunnelcrypto.New("test-secret-key")
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	// Channel representing the WebRTC DataChannel in both directions
	s2r := make(chan []byte, 128)
	r2s := make(chan []byte, 128)

	// 3. Create TunnelRelay
	r := relay.New(cr, func(packet []byte) bool {
		r2s <- append([]byte(nil), packet...)
		return true
	}, nil)
	defer r.Stop()

	// 4. Create SOCKS5 Server
	s := New(Config{
		Crypto: cr,
		SendPacket: func(packet []byte) bool {
			s2r <- append([]byte(nil), packet...)
			return true
		},
		Host: "127.0.0.1",
		Port: 0, // OS assigned port
	})
	if err := s.Start(); err != nil {
		t.Fatalf("socks5 start: %v", err)
	}
	defer s.Stop()

	// Wire packets between SOCKS5 Server and TunnelRelay
	stopWire := make(chan struct{})
	defer close(stopWire)
	go func() {
		for {
			select {
			case <-stopWire:
				return
			case pkt := <-s2r:
				r.HandleChannelPacket(pkt)
			}
		}
	}()
	go func() {
		for {
			select {
			case <-stopWire:
				return
			case pkt := <-r2s:
				s.HandleChannelPacket(pkt)
			}
		}
	}()

	// 5. Connect SOCKS5 client to our SOCKS5 server
	socksAddr := s.Addr().String()
	client, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer client.Close()

	// Handshake: send greeting
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	var greetingResp [2]byte
	if _, err := io.ReadFull(client, greetingResp[:]); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}
	if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		t.Fatalf("bad greeting resp: %v", greetingResp)
	}

	// Request: CONNECT to echo server using IPv4
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(echoAddr.Port))
	req := append([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}, portBytes...)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("write connect req: %v", err)
	}

	var reqResp [10]byte
	if _, err := io.ReadFull(client, reqResp[:]); err != nil {
		t.Fatalf("read connect resp: %v", err)
	}
	if reqResp[0] != 0x05 || reqResp[1] != 0x00 {
		t.Fatalf("connect failed with status 0x%02x", reqResp[1])
	}

	// Send data through proxy and verify echo
	msg := []byte("hello encrypted tunnel world!")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write data: %v", err)
	}

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(client, recv); err != nil {
		t.Fatalf("read data: %v", err)
	}
	if !bytes.Equal(recv, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", recv, msg)
	}

	// Also test Domain Name ATYP (0x03)
	client2, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks5 2: %v", err)
	}
	defer client2.Close()

	if _, err := client2.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting 2: %v", err)
	}
	if _, err := io.ReadFull(client2, greetingResp[:]); err != nil {
		t.Fatalf("read greeting resp 2: %v", err)
	}

	domain := "127.0.0.1"
	req2 := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req2 = append(req2, []byte(domain)...)
	req2 = append(req2, portBytes...)
	if _, err := client2.Write(req2); err != nil {
		t.Fatalf("write domain connect req: %v", err)
	}

	if _, err := io.ReadFull(client2, reqResp[:]); err != nil {
		t.Fatalf("read domain connect resp: %v", err)
	}
	if reqResp[0] != 0x05 || reqResp[1] != 0x00 {
		t.Fatalf("domain connect failed with status 0x%02x", reqResp[1])
	}

	msg2 := []byte("domain name routing test works!")
	if _, err := client2.Write(msg2); err != nil {
		t.Fatalf("write data 2: %v", err)
	}
	recv2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(client2, recv2); err != nil {
		t.Fatalf("read data 2: %v", err)
	}
	if !bytes.Equal(recv2, msg2) {
		t.Fatalf("echo mismatch 2: got %q, want %q", recv2, msg2)
	}
}

func TestSocks5ConnectFail(t *testing.T) {
	cr, _ := tunnelcrypto.New("test-fail")

	s2r := make(chan []byte, 16)
	r2s := make(chan []byte, 16)

	r := relay.New(cr, func(packet []byte) bool {
		r2s <- append([]byte(nil), packet...)
		return true
	}, nil)
	defer r.Stop()

	s := New(Config{
		Crypto: cr,
		SendPacket: func(packet []byte) bool {
			s2r <- append([]byte(nil), packet...)
			return true
		},
		Host: "127.0.0.1",
		Port: 0,
	})
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()

	stopWire := make(chan struct{})
	defer close(stopWire)
	go func() {
		for {
			select {
			case <-stopWire:
				return
			case pkt := <-s2r:
				r.HandleChannelPacket(pkt)
			}
		}
	}()
	go func() {
		for {
			select {
			case <-stopWire:
				return
			case pkt := <-r2s:
				s.HandleChannelPacket(pkt)
			}
		}
	}()

	client, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	var gr [2]byte
	_, _ = io.ReadFull(client, gr[:])

	// Attempt to connect to port 1 (which will be refused)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1}
	_, _ = client.Write(req)

	var resp [10]byte
	if _, err := io.ReadFull(client, resp[:]); err != nil {
		t.Fatalf("read: %v", err)
	}
	// Expect connection failure status 0x05 (Connection refused)
	if resp[1] != 0x05 {
		t.Fatalf("expected 0x05 connection refused, got 0x%02x", resp[1])
	}
}

func TestSocks5AsymmetricMutualAuthEcho(t *testing.T) {
	// Verify that asymmetric session keys (kC2R, kR2C) work end-to-end between Socks5 and Relay
	callerPriv, callerPubHex, _ := tunnelcrypto.GenerateKeypair()
	relayPriv, relayPubHex, _ := tunnelcrypto.GenerateKeypair()

	cPrivBytes, _ := tunnelcrypto.ParseKey(callerPriv)
	cPubBytes, _ := tunnelcrypto.ParseKey(callerPubHex)
	rPrivBytes, _ := tunnelcrypto.ParseKey(relayPriv)
	rPubBytes, _ := tunnelcrypto.ParseKey(relayPubHex)

	initiator, err := tunnelcrypto.NewHandshakeInitiator(cPrivBytes, rPubBytes)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	responder, err := tunnelcrypto.NewHandshakeResponder(rPrivBytes, [][]byte{cPubBytes})
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	initPkt, err := initiator.CreateInitPacket()
	if err != nil {
		t.Fatalf("create init: %v", err)
	}

	respPkt, relayCrypto, err := responder.ProcessInitPacket(initPkt)
	if err != nil {
		t.Fatalf("process init: %v", err)
	}

	callerCrypto, err := initiator.ProcessRespPacket(respPkt)
	if err != nil {
		t.Fatalf("process resp: %v", err)
	}

	// Echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		c, _ := echoLn.Accept()
		if c != nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	echoPort, _ := strconv.Atoi(net.JoinHostPort("", "")[1:])
	_ = echoPort
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	s2r := make(chan []byte, 32)
	r2s := make(chan []byte, 32)

	r := relay.New(relayCrypto, func(p []byte) bool { r2s <- append([]byte(nil), p...); return true }, nil)
	defer r.Stop()

	s := New(Config{
		Crypto: callerCrypto,
		SendPacket: func(p []byte) bool { s2r <- append([]byte(nil), p...); return true },
		Host: "127.0.0.1",
		Port: 0,
	})
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case p := <-s2r:
				r.HandleChannelPacket(p)
			}
		}
	}()
	go func() {
		for {
			select {
			case <-stop:
				return
			case p := <-r2s:
				s.HandleChannelPacket(p)
			}
		}
	}()

	client, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	var gr [2]byte
	_, _ = io.ReadFull(client, gr[:])

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(echoAddr.Port))
	req := append([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}, portBytes...)
	_, _ = client.Write(req)

	var resp [10]byte
	if _, err := io.ReadFull(client, resp[:]); err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("status: 0x%02x", resp[1])
	}

	testPayload := []byte("zero trust x25519 mutual auth echo success!")
	_, _ = client.Write(testPayload)
	got := make([]byte, len(testPayload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, testPayload) {
		t.Fatalf("mismatch: got %q", got)
	}
}
