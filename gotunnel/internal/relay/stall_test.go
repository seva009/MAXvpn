package relay

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/webrtc/v3"

	"calltunnel/internal/logx"
	"calltunnel/internal/tunnelcrypto"
)

type blockedSink struct{ block chan struct{} }

func (b blockedSink) Write(p []byte) (int, error) { <-b.block; return len(p), nil }

// runDownload pushes a continuous TCP stream through a real pion DataChannel
// pair and the relay, and returns the bytes received per second.
func runDownload(t *testing.T, api *webrtc.API, secs int) []int64 {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 16384)
				for {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	cr, _ := tunnelcrypto.New("s")
	pcCaller, _ := api.NewPeerConnection(webrtc.Configuration{})
	pcRelay, _ := api.NewPeerConnection(webrtc.Configuration{})
	defer pcCaller.Close()
	defer pcRelay.Close()

	var rel *TunnelRelay
	ready := make(chan struct{})
	pcRelay.OnDataChannel(func(dc *webrtc.DataChannel) {
		rel = New(cr, func(p []byte) bool { return dc.Send(p) == nil }, func() uint64 { return dc.BufferedAmount() })
		dc.OnMessage(func(m webrtc.DataChannelMessage) { rel.HandleChannelPacket(m.Data) })
		close(ready)
	})
	dcCaller, _ := pcCaller.CreateDataChannel("t", nil)

	var rx int64
	gotOK := make(chan struct{}, 1)
	dcCaller.OnMessage(func(m webrtc.DataChannelMessage) {
		typ, _, p, err := cr.Decrypt(m.Data)
		if err != nil {
			return
		}
		switch typ {
		case tunnelcrypto.CmdConnectOK:
			gotOK <- struct{}{}
		case tunnelcrypto.CmdData:
			atomic.AddInt64(&rx, int64(len(p)))
		}
	})
	opened := make(chan struct{})
	dcCaller.OnOpen(func() { close(opened) })
	pcCaller.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			_ = pcRelay.AddICECandidate(c.ToJSON())
		}
	})
	pcRelay.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			_ = pcCaller.AddICECandidate(c.ToJSON())
		}
	})
	offer, _ := pcCaller.CreateOffer(nil)
	_ = pcCaller.SetLocalDescription(offer)
	_ = pcRelay.SetRemoteDescription(offer)
	ans, _ := pcRelay.CreateAnswer(nil)
	_ = pcRelay.SetLocalDescription(ans)
	_ = pcCaller.SetRemoteDescription(ans)

	select {
	case <-opened:
	case <-time.After(10 * time.Second):
		t.Fatal("datachannel did not open")
	}
	<-ready
	pkt, _ := cr.Encrypt(tunnelcrypto.CmdConnect, 1, tunnelcrypto.PackConnectPayload("127.0.0.1", port))
	_ = dcCaller.Send(pkt)
	<-gotOK
	defer rel.Stop()

	out := make([]int64, 0, secs)
	var last int64
	for i := 0; i < secs; i++ {
		time.Sleep(time.Second)
		cur := atomic.LoadInt64(&rx)
		out = append(out, cur-last)
		last = cur
	}
	return out
}

// Regression: pion/sctp used to log at Debug level synchronously to stdout.
// With a stuck stdout the SCTP loops blocked and the tunnel froze while ICE
// still looked alive. Through logx the sink can be completely blocked and the
// data must keep flowing.
func TestDownloadSurvivesBlockedLogSink(t *testing.T) {
	sink := blockedSink{block: make(chan struct{})}
	defer close(sink.block)

	lf := logging.NewDefaultLoggerFactory()
	lf.Writer = logx.NewNonBlocking(sink, 64)
	lf.DefaultLogLevel = logging.LogLevelWarn
	lf.ScopeLevels = map[string]logging.LogLevel{
		"sctp": logging.LogLevelDebug, "datachannel": logging.LogLevelDebug, "ortc": logging.LogLevelDebug,
	}
	se := webrtc.SettingEngine{}
	se.LoggerFactory = lf
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))

	secs := 6
	for i, n := range runDownload(t, api, secs) {
		if n == 0 {
			t.Fatalf("second %d: no data flowed (log sink blocked the data path)", i+1)
		}
	}
}

func TestPingIsAnswered(t *testing.T) {
	cr, _ := tunnelcrypto.New("s")
	ch := make(chan []byte, 1)
	typs := make(chan byte, 1)
	r := New(cr, func(pkt []byte) bool {
		typ, _, p, err := cr.Decrypt(pkt)
		if err != nil {
			t.Error(err)
			return false
		}
		typs <- typ
		ch <- p
		return true
	}, nil)
	defer r.Stop()
	ts := []byte{0, 0, 0, 0, 0, 0, 0x12, 0x34}
	pkt, _ := cr.Encrypt(tunnelcrypto.CmdPing, 0, ts)
	r.HandleChannelPacket(pkt)
	select {
	case typ := <-typs:
		if typ != tunnelcrypto.CmdPong {
			t.Fatalf("got type %d, want PONG", typ)
		}
		if p := <-ch; string(p) != string(ts) {
			t.Fatalf("pong payload %x, want %x", p, ts)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no PONG for PING")
	}
}

// A slow target must not silently lose bytes of the stream: the connection is
// reset (CLOSE) instead.
func TestOverflowResetsInsteadOfDropping(t *testing.T) {
	// target that accepts but never reads -> writer goroutine stalls
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	cr, _ := tunnelcrypto.New("s")
	types := make(chan byte, 4096)
	r := New(cr, func(pkt []byte) bool {
		if typ, _, _, err := cr.Decrypt(pkt); err == nil {
			types <- typ
		}
		return true
	}, nil)
	defer r.Stop()
	pkt, _ := cr.Encrypt(tunnelcrypto.CmdConnect, 7, tunnelcrypto.PackConnectPayload("127.0.0.1", port))
	r.HandleChannelPacket(pkt)
	select {
	case <-types: // CONNECT_OK
	case <-time.After(3 * time.Second):
		t.Fatal("no CONNECT_OK")
	}
	big := make([]byte, 4096)
	d, _ := cr.Encrypt(tunnelcrypto.CmdData, 7, big)
	// far more than socket buffers + 128-slot queue can absorb
	for i := 0; i < 20000; i++ {
		r.HandleChannelPacket(d)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case typ := <-types:
			if typ == tunnelcrypto.CmdClose {
				return
			}
		case <-deadline:
			t.Fatal("overflow did not reset the connection")
		}
	}
}
