// Package logx provides a log writer that can never block its caller.
//
// Why it exists: pion's logger (and the std "log" package) write to a
// pipe/terminal synchronously under a mutex. If stdout/stderr is slow or
// stalls (journald rate-limit, ssh session, "| tee", a paused terminal),
// every goroutine that logs blocks - including pion/sctp's read and write
// loops. The tunnel then looks "connected" (ICE/DTLS alive) while no data
// moves at all. Writing logs through this type decouples the data path from
// the log sink: if the sink cannot keep up, log lines are dropped instead.
package logx

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// NonBlocking is an io.Writer that hands data to a background goroutine
// through a bounded queue and drops it when the queue is full.
type NonBlocking struct {
	ch      chan []byte
	dropped atomic.Uint64
	pending sync.WaitGroup
}

// NewNonBlocking wraps w. queue is the max number of buffered log writes.
func NewNonBlocking(w io.Writer, queue int) *NonBlocking {
	if queue <= 0 {
		queue = 1024
	}
	n := &NonBlocking{ch: make(chan []byte, queue)}
	go func() {
		for b := range n.ch {
			if d := n.dropped.Swap(0); d > 0 {
				_, _ = w.Write([]byte("[logx] dropped log lines because the log sink is too slow\n"))
			}
			_, _ = w.Write(b)
			n.pending.Done()
		}
	}()
	return n
}

// Write never blocks.
func (n *NonBlocking) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	n.pending.Add(1)
	select {
	case n.ch <- cp:
	default:
		n.pending.Done()
		n.dropped.Add(1)
	}
	return len(p), nil
}

// Flush waits (at most timeout) until everything queued so far was written.
// Call it before os.Exit / log.Fatal so the last message is not lost.
func (n *NonBlocking) Flush(timeout time.Duration) {
	done := make(chan struct{})
	go func() { n.pending.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}
