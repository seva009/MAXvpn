// Package netx provides robust network and DNS resolution utilities,
// specifically solving Android / Termux DNS issues where Go binaries
// compiled with CGO_ENABLED=0 cannot find /etc/resolv.conf and fail.
//
// On Android/Termux, this package communicates directly with Android's
// native system DNS resolver daemon via /dev/socket/dnsproxyd (the exact
// same IPC mechanism used by Android's Bionic libc getaddrinfo).
// It also provides resilient UDP/TCP fallback racing multiple upstream
// DNS servers (Yandex, Cloudflare, Google, custom).
package netx

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/dns/dnsmessage"
)

var defaultPublicDNS = []string{
	"77.88.8.8:53", // Yandex DNS (fastest & reliable in CIS/RU)
	"1.1.1.1:53",   // Cloudflare DNS
	"8.8.8.8:53",   // Google DNS
	"77.88.8.1:53", // Yandex secondary
	"1.0.0.1:53",   // Cloudflare secondary
	"8.8.4.4:53",   // Google secondary
}

const (
	socketPath    = "/dev/socket/dnsproxyd"
	maxCmdSize    = 1024
	maxAnswerSize = 64 << 10
)

var (
	dnsMu          sync.RWMutex
	customServers  []string
	publicServers  []string
	initialized    bool
	noResNSend     atomic.Bool
	errUnknownCmd  = errors.New("androiddns: dnsproxyd does not recognize the command")
	errClosed      = errors.New("androiddns: use of closed conn")
	errNoQuery     = errors.New("androiddns: read with no complete query written")
)

// IsAndroidOrTermux reports whether the process is running on Android or in Termux.
func IsAndroidOrTermux() bool {
	if os.Getenv("TERMUX_VERSION") != "" || os.Getenv("PREFIX") != "" {
		return true
	}
	if os.Getenv("ANDROID_ROOT") != "" || os.Getenv("ANDROID_DATA") != "" {
		return true
	}
	for _, p := range []string{"/system/build.prop", "/system/bin/getprop", "/dev/__properties__"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// HasDnsProxy reports whether Android's /dev/socket/dnsproxyd socket accepts connections.
func HasDnsProxy() bool {
	c, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func getAndroidDNS() []string {
	var servers []string
	for _, prop := range []string{"net.dns1", "net.dns2", "net.dns3", "net.dns4"} {
		out, err := exec.Command("/system/bin/getprop", prop).Output()
		if err == nil {
			ipStr := strings.TrimSpace(string(out))
			if ip := net.ParseIP(ipStr); ip != nil {
				servers = append(servers, net.JoinHostPort(ipStr, "53"))
			}
		}
	}
	return servers
}

func getTermuxDNS() []string {
	var servers []string
	termuxResolv := "/data/data/com.termux/files/usr/etc/resolv.conf"
	if prefix := os.Getenv("PREFIX"); prefix != "" {
		termuxResolv = prefix + "/etc/resolv.conf"
	}
	data, err := os.ReadFile(termuxResolv)
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if ip := net.ParseIP(fields[1]); ip != nil {
						servers = append(servers, net.JoinHostPort(fields[1], "53"))
					}
				}
			}
		}
	}
	return servers
}

func getLinuxResolvConf() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if ip := net.ParseIP(fields[1]); ip != nil {
					servers = append(servers, net.JoinHostPort(fields[1], "53"))
				}
			}
		}
	}
	return servers
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" || host == "::1" || host == "127.0.0.1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SetupDNS initializes resilient DNS resolution for Android, Termux, and Linux.
func SetupDNS(userDNS []string) {
	dnsMu.Lock()
	defer dnsMu.Unlock()

	var customList []string
	var publicList []string
	seen := make(map[string]bool)

	addCustom := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if !strings.Contains(s, ":") {
			s = net.JoinHostPort(s, "53")
		}
		if !seen[s] {
			seen[s] = true
			customList = append(customList, s)
		}
	}

	addPublic := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if !strings.Contains(s, ":") {
			s = net.JoinHostPort(s, "53")
		}
		if !seen[s] {
			seen[s] = true
			publicList = append(publicList, s)
		}
	}

	for _, s := range userDNS {
		addCustom(s)
	}
	if env := os.Getenv("CALLTUNNEL_DNS"); env != "" {
		for _, s := range strings.Split(env, ",") {
			addCustom(s)
		}
	}
	for _, s := range getAndroidDNS() {
		addPublic(s)
	}
	for _, s := range getTermuxDNS() {
		addPublic(s)
	}
	for _, s := range getLinuxResolvConf() {
		if !isLoopback(s) {
			addPublic(s)
		}
	}
	for _, s := range defaultPublicDNS {
		addPublic(s)
	}

	customServers = customList
	publicServers = publicList

	if !initialized {
		initialized = true
		hasProxy := HasDnsProxy()
		if len(customServers) > 0 {
			log.Printf("[DNS] Using custom DNS: %s", strings.Join(customServers, ", "))
		} else if hasProxy {
			log.Printf("[DNS] Android system dnsproxyd detected (/dev/socket/dnsproxyd). Using native Android resolver.")
		} else if IsAndroidOrTermux() {
			log.Printf("[DNS] Android/Termux detected without dnsproxyd. Using fallback DNS: %s",
				strings.Join(publicServers[:min(3, len(publicServers))], ", "))
		}
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial:     dialStream,
	}

	net.DefaultResolver = resolver

	// Configure gorilla/websocket DefaultDialer to use our resilient resolver and robust TLS config
	websocket.DefaultDialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  resolver,
		}
		return d.DialContext(ctx, network, addr)
	}
	websocket.DefaultDialer.TLSClientConfig = TLSConfig(IsInsecureSkipVerify())
}

// SetupNetwork configures both resilient DNS and TLS certificate handling.
func SetupNetwork(userDNS []string, insecure bool) {
	SetInsecureSkipVerify(insecure)
	SetupDNS(userDNS)
	websocket.DefaultDialer.TLSClientConfig = TLSConfig(insecure)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// dialStream implements net.Resolver.Dial returning a streamConn that speaks
// standard TCP-framed DNS to Go's net.Resolver and handles the resolution via
// Android's dnsproxyd and/or concurrent upstream UDP/TCP queries.
func dialStream(ctx context.Context, network, address string) (net.Conn, error) {
	return &streamConn{}, nil
}

type streamConn struct {
	mu       sync.Mutex
	deadline time.Time
	wbuf     []byte
	rbuf     []byte
	closed   bool
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errClosed
	}
	c.wbuf = append(c.wbuf, p...)
	return len(p), nil
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errClosed
	}
	if len(c.rbuf) == 0 {
		if err := c.roundTripLocked(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *streamConn) roundTripLocked() error {
	if len(c.wbuf) < 2 {
		return errNoQuery
	}
	msgLen := int(c.wbuf[0])<<8 | int(c.wbuf[1])
	if len(c.wbuf) < 2+msgLen {
		return errNoQuery
	}
	msg := c.wbuf[2 : 2+msgLen]

	ctx := context.Background()
	var cancel context.CancelFunc
	if !c.deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, c.deadline)
		defer cancel()
	} else {
		ctx, cancel = context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
	}

	ans, err := resolveDNSQuery(ctx, msg)
	if err != nil {
		return err
	}
	c.wbuf = c.wbuf[2+msgLen:]
	c.rbuf = append([]byte{byte(len(ans) >> 8), byte(len(ans))}, ans...)
	return nil
}

func (c *streamConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *streamConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *streamConn) LocalAddr() net.Addr  { return fakeAddr{} }
func (c *streamConn) RemoteAddr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "dnsproxyd" }
func (fakeAddr) String() string  { return "dnsproxyd" }

// resolveDNSQuery executes the DNS resolution.
// Priority:
// 1. If custom DNS is specified: query custom DNS servers via UDP/TCP.
// 2. If running on Android and /dev/socket/dnsproxyd is available: query Android native daemon.
// 3. Fallback: race candidate public DNS servers via UDP/TCP.
func resolveDNSQuery(ctx context.Context, msg []byte) ([]byte, error) {
	dnsMu.RLock()
	custom := customServers
	public := publicServers
	dnsMu.RUnlock()

	// 1. If custom DNS explicitly configured, use it first
	if len(custom) > 0 {
		if ans, err := queryNetworkServers(ctx, custom, msg); err == nil {
			return ans, nil
		}
	}

	// 2. If /dev/socket/dnsproxyd is available, use Android's native system resolver
	if HasDnsProxy() {
		ans, err := queryDnsProxy(ctx, msg)
		if err == nil {
			return ans, nil
		}
		// If dnsproxyd failed, fallback to public DNS
	}

	// 3. Fallback: race public DNS servers
	if len(public) > 0 {
		ans, err := queryNetworkServers(ctx, public, msg)
		if err == nil {
			return ans, nil
		}
	}

	return nil, fmt.Errorf("all DNS resolution methods failed")
}

// -----------------------------------------------------------------------------
// Android /dev/socket/dnsproxyd Client (resnsend & getaddrinfo)
// -----------------------------------------------------------------------------

type proxyReply struct {
	net.Conn
	head [4]byte
}

func sendDnsProxyCommand(ctx context.Context, cmd string) (*proxyReply, error) {
	if len(cmd)+1 > maxCmdSize {
		return nil, fmt.Errorf("androiddns: %d byte command too large", len(cmd)+1)
	}

	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("androiddns: dial dnsproxyd: %w", err)
	}
	r := &proxyReply{Conn: c}

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}

	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()

	if _, err := c.Write([]byte(cmd + "\x00")); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("androiddns: write command: %w", err)
	}
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}

	if _, err := io.ReadFull(c, r.head[:]); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("androiddns: reading result header: %w", err)
	}
	return r, nil
}

func (r *proxyReply) textError() error {
	rest, _ := io.ReadAll(io.LimitReader(r.Conn, 256))
	text := strings.TrimRight(string(r.head[:])+string(rest), "\x00")
	if strings.HasPrefix(text, "500 Command not recognized") {
		return errUnknownCmd
	}
	return fmt.Errorf("androiddns: dnsproxyd: %q", text)
}

func queryDnsProxy(ctx context.Context, msg []byte) ([]byte, error) {
	if !noResNSend.Load() {
		ans, err := queryResNSend(ctx, msg)
		if err == nil {
			return ans, nil
		}
		if errors.Is(err, errUnknownCmd) {
			noResNSend.Store(true)
		} else {
			return nil, err
		}
	}
	return queryGetAddrInfo(ctx, msg)
}

func queryResNSend(ctx context.Context, msg []byte) ([]byte, error) {
	r, err := sendDnsProxyCommand(ctx, "resnsend 0 0 "+base64.StdEncoding.EncodeToString(msg))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	if r.head[0] >= '0' && r.head[0] <= '9' {
		return nil, r.textError()
	}
	if res := int32(binary.BigEndian.Uint32(r.head[:])); res < 0 {
		return nil, fmt.Errorf("androiddns: dnsproxyd error %d (%v)", res, syscall.Errno(-res))
	}
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("androiddns: reading answer length: %w", err)
	}
	ansLen := int32(binary.BigEndian.Uint32(buf[:]))
	if ansLen < 0 || ansLen > maxAnswerSize {
		return nil, fmt.Errorf("androiddns: bogus answer length %d", ansLen)
	}
	ans := make([]byte, ansLen)
	if _, err := io.ReadFull(r, ans); err != nil {
		return nil, fmt.Errorf("androiddns: reading answer: %w", err)
	}
	return ans, nil
}

const (
	codeDnsProxyQueryResult     = "222"
	codeDnsProxyOperationFailed = "401"
	afINET                      = 2
	afINET6                     = 10
	sockStream                  = 1
	eaiNODATA                   = 7
	eaiNONAME                   = 8
	maxSockaddrLen              = 128
	maxCanonNameLen             = 1024
)

func queryGetAddrInfo(ctx context.Context, msg []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return nil, fmt.Errorf("androiddns: parsing query: %w", err)
	}
	q, err := p.Question()
	if err != nil {
		return nil, fmt.Errorf("androiddns: parsing question: %w", err)
	}
	var family int
	switch q.Type {
	case dnsmessage.TypeA:
		family = afINET
	case dnsmessage.TypeAAAA:
		family = afINET6
	default:
		return nil, fmt.Errorf("androiddns: getaddrinfo fallback only supports A/AAAA, not %v", q.Type)
	}

	name := strings.TrimSuffix(q.Name.String(), ".")
	if name == "" || strings.ContainsFunc(name, func(r rune) bool {
		return r <= ' ' || r >= 0x7f || r == '"' || r == '\\' || r == '^'
	}) {
		return nil, fmt.Errorf("androiddns: invalid hostname %q", name)
	}

	cmd := fmt.Sprintf("getaddrinfo %s ^ 0 %d %d 0 0", name, family, sockStream)
	r, err := sendDnsProxyCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	rcode := dnsmessage.RCodeSuccess
	var addrs []netip.Addr

	switch string(r.head[:3]) {
	case codeDnsProxyQueryResult:
		addrs, err = readAddrInfoList(r)
		if err != nil {
			return nil, err
		}
	case codeDnsProxyOperationFailed:
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, fmt.Errorf("androiddns: reading getaddrinfo error: %w", err)
		}
		if n := binary.BigEndian.Uint32(buf[:4]); n != 4 {
			return nil, fmt.Errorf("androiddns: bogus getaddrinfo error length %d", n)
		}
		switch eai := int32(binary.LittleEndian.Uint32(buf[4:])); eai {
		case eaiNONAME:
			rcode = dnsmessage.RCodeNameError
		case eaiNODATA:
			// Success with no answers
		default:
			return nil, fmt.Errorf("androiddns: getaddrinfo failed with code %d", eai)
		}
	default:
		return nil, r.textError()
	}

	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class}
	for _, a := range addrs {
		switch {
		case a.Is4() && q.Type == dnsmessage.TypeA:
			err = b.AResource(rh, dnsmessage.AResource{A: a.As4()})
		case a.Is6() && q.Type == dnsmessage.TypeAAAA:
			err = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
		if err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func readAddrInfoList(r io.Reader) ([]netip.Addr, error) {
	readBE32 := func(what string) (uint32, error) {
		var be [4]byte
		if _, err := io.ReadFull(r, be[:]); err != nil {
			return 0, fmt.Errorf("reading %s: %w", what, err)
		}
		return binary.BigEndian.Uint32(be[:]), nil
	}
	readLenAndData := func(what string, maxLen uint32) ([]byte, error) {
		n, err := readBE32(what + " length")
		if err != nil {
			return nil, err
		}
		if n > maxLen {
			return nil, fmt.Errorf("bogus %s length %d", what, n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("reading %s: %w", what, err)
		}
		return buf, nil
	}
	var addrs []netip.Addr
	for {
		more, err := readBE32("addrinfo marker")
		if err != nil {
			return nil, err
		}
		if more == 0 {
			return addrs, nil
		}
		if more != 1 {
			return nil, fmt.Errorf("unsupported addrinfo layout marker %d", more)
		}
		var fields [4]uint32
		for i := range fields {
			if fields[i], err = readBE32("addrinfo field"); err != nil {
				return nil, err
			}
		}
		family := fields[1]
		sa, err := readLenAndData("sockaddr", maxSockaddrLen)
		if err != nil {
			return nil, err
		}
		if _, err := readLenAndData("canonical name", maxCanonNameLen); err != nil {
			return nil, err
		}
		var a netip.Addr
		switch {
		case family == afINET && len(sa) >= 8:
			a = netip.AddrFrom4([4]byte(sa[4:8]))
		case family == afINET6 && len(sa) >= 24:
			a = netip.AddrFrom16([16]byte(sa[8:24]))
		default:
			continue
		}
		if !slices.Contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
}

// -----------------------------------------------------------------------------
// Network Upstream Querying (UDP + TCP race)
// -----------------------------------------------------------------------------

type queryResult struct {
	ans []byte
	err error
}

func querySingleUDP(ctx context.Context, server string, msg []byte) ([]byte, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	}

	if _, err := c.Write(msg); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func querySingleTCP(ctx context.Context, server string, msg []byte) ([]byte, error) {
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	}

	req := make([]byte, 2+len(msg))
	req[0] = byte(len(msg) >> 8)
	req[1] = byte(len(msg))
	copy(req[2:], msg)

	if _, err := c.Write(req); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen > maxAnswerSize || respLen <= 0 {
		return nil, fmt.Errorf("bogus TCP DNS response length %d", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func queryNetworkServers(ctx context.Context, servers []string, msg []byte) ([]byte, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no upstream servers available")
	}

	// Limit concurrent targets to avoid socket exhaustion
	targets := servers
	if len(targets) > 4 {
		targets = targets[:4]
	}

	ctxRace, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan queryResult, len(targets)*2)

	// Launch UDP queries concurrently
	for _, s := range targets {
		go func(srv string) {
			ans, err := querySingleUDP(ctxRace, srv, msg)
			resCh <- queryResult{ans: ans, err: err}
		}(s)
	}

	// Launch TCP queries after small delay (or immediately for CIS/mobile carriers)
	for _, s := range targets[:min(2, len(targets))] {
		go func(srv string) {
			time.Sleep(200 * time.Millisecond)
			ans, err := querySingleTCP(ctxRace, srv, msg)
			resCh <- queryResult{ans: ans, err: err}
		}(s)
	}

	totalExpected := len(targets) + min(2, len(targets))
	var lastErr error
	for i := 0; i < totalExpected; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-resCh:
			if r.err == nil && len(r.ans) > 0 {
				cancel()
				return r.ans, nil
			}
			lastErr = r.err
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all upstream DNS queries failed")
}
