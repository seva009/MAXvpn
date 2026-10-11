package logx

import (
	"io"
	"testing"
	"time"
)

type blockedWriter struct{ block chan struct{} }

func (b blockedWriter) Write(p []byte) (int, error) { <-b.block; return len(p), nil }

// A completely stuck sink must not block writers.
func TestNeverBlocks(t *testing.T) {
	bw := blockedWriter{block: make(chan struct{})}
	defer close(bw.block)
	n := NewNonBlocking(bw, 8)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100000; i++ {
			_, _ = n.Write([]byte("line\n"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Write blocked on a stuck sink")
	}
	var _ io.Writer = n
}
