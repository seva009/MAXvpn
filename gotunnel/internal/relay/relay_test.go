package relay

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"calltunnel/internal/tunnelcrypto"
)

// End-to-end: act as the caller, drive the relay through encrypted packets
// and verify an echo round-trip through a real TCP server.
func TestRelayEcho(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.Copy(c, c)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)

	cr, _ := tunnelcrypto.New("s")
	var mu sync.Mutex
	var got []struct {
		typ byte
		p   []byte
	}
	r := New(cr, func(pkt []byte) bool {
		typ, _, p, err := cr.Decrypt(pkt)
		if err != nil {
			t.Error(err)
			return false
		}
		mu.Lock()
		got = append(got, struct {
			typ byte
			p   []byte
		}{typ, append([]byte(nil), p...)})
		mu.Unlock()
		return true
	}, nil)
	defer r.Stop()

	pkt, _ := cr.Encrypt(tunnelcrypto.CmdConnect, 1, tunnelcrypto.PackConnectPayload("127.0.0.1", uint16(addr.Port)))
	r.HandleChannelPacket(pkt)
	wait := func(typ byte) []byte {
		for i := 0; i < 100; i++ {
			mu.Lock()
			for _, g := range got {
				if g.typ == typ {
					mu.Unlock()
					return g.p
				}
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("no packet type %d", typ)
		return nil
	}
	wait(tunnelcrypto.CmdConnectOK)
	d, _ := cr.Encrypt(tunnelcrypto.CmdData, 1, []byte("ping-pong"))
	r.HandleChannelPacket(d)
	if string(wait(tunnelcrypto.CmdData)) != "ping-pong" {
		t.Fatal("echo mismatch")
	}
	cl, _ := cr.Encrypt(tunnelcrypto.CmdClose, 1, nil)
	r.HandleChannelPacket(cl)
}

func TestConnectFail(t *testing.T) {
	cr, _ := tunnelcrypto.New("s")
	ch := make(chan byte, 1)
	r := New(cr, func(pkt []byte) bool { typ, _, _, _ := cr.Decrypt(pkt); ch <- typ; return true }, nil)
	pkt, _ := cr.Encrypt(tunnelcrypto.CmdConnect, 9, tunnelcrypto.PackConnectPayload("127.0.0.1", 1))
	r.HandleChannelPacket(pkt)
	select {
	case typ := <-ch:
		if typ != tunnelcrypto.CmdConnectFail {
			t.Fatalf("got %d", typ)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}
