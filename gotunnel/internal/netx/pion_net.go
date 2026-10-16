package netx

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pion/transport/v2"
	"github.com/pion/transport/v2/stdnet"
)

// NewPionNet creates a resilient transport.Net for Pion WebRTC.
// It tries stdnet.NewNet() first; if that fails (e.g. on Android/Termux
// where netlinkrib returns "permission denied"), it provides a resilient
// network layer that discovers local IP addresses without netlink.
func NewPionNet() transport.Net {
	n, err := stdnet.NewNet()
	if err == nil {
		return n
	}

	log.Printf("[WebRTC] Standard net discovery unavailable (%v). Using Android/Termux resilient net.", err)
	rn := &ResilientNet{}
	_ = rn.updateInterfaces()
	return rn
}

// ResilientNet implements transport.Net without requiring netlink routing permissions.
type ResilientNet struct {
	mu         sync.RWMutex
	interfaces []*transport.Interface
}

var _ transport.Net = (*ResilientNet)(nil)

func (n *ResilientNet) updateInterfaces() error {
	var ifaces []*transport.Interface
	names := getSystemInterfaceNames()
	if len(names) == 0 {
		names = []string{"wlan0", "lo"}
	}

	outboundIPv4 := getOutboundIP("77.88.8.8:80")
	if outboundIPv4 == nil {
		outboundIPv4 = getOutboundIP("1.1.1.1:80")
	}
	if outboundIPv4 == nil {
		outboundIPv4 = getOutboundIP("8.8.8.8:80")
	}

	idx := 1
	for _, name := range names {
		isLo := strings.HasPrefix(name, "lo")
		flags := net.FlagUp
		if isLo {
			flags |= net.FlagLoopback
		} else {
			flags |= net.FlagBroadcast | net.FlagMulticast
		}

		ifc := transport.NewInterface(net.Interface{
			Index: idx,
			Name:  name,
			Flags: flags,
		})
		idx++

		if isLo {
			ifc.AddAddress(&net.IPNet{
				IP:   net.ParseIP("127.0.0.1"),
				Mask: net.CIDRMask(8, 32),
			})
			ifc.AddAddress(&net.IPNet{
				IP:   net.ParseIP("::1"),
				Mask: net.CIDRMask(128, 128),
			})
		} else if outboundIPv4 != nil {
			ifc.AddAddress(&net.IPNet{
				IP:   outboundIPv4,
				Mask: net.CIDRMask(24, 32),
			})
		}

		ifaces = append(ifaces, ifc)
	}

	n.mu.Lock()
	n.interfaces = ifaces
	n.mu.Unlock()
	return nil
}

func getSystemInterfaceNames() []string {
	var names []string
	seen := make(map[string]bool)

	add := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}

	// 1. Try reading /proc/net/dev (Linux / Android standard procfs)
	if f, err := os.Open("/proc/net/dev"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if idx := strings.Index(line, ":"); idx != -1 {
				name := strings.TrimSpace(line[:idx])
				add(name)
			}
		}
		_ = f.Close()
	}

	// Ensure loopback exists
	add("lo")
	return names
}

func getOutboundIP(target string) net.IP {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := d.Dial("udp", target)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if u, ok := conn.LocalAddr().(*net.UDPAddr); ok && u.IP != nil {
		if !u.IP.IsLoopback() && !u.IP.IsUnspecified() {
			return u.IP
		}
	}
	return nil
}

func (n *ResilientNet) Interfaces() ([]*transport.Interface, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.interfaces, nil
}

func (n *ResilientNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, ifc := range n.interfaces {
		if ifc.Index == index {
			return ifc, nil
		}
	}
	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}

func (n *ResilientNet) InterfaceByName(name string) (*transport.Interface, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, ifc := range n.interfaces {
		if ifc.Name == name {
			return ifc, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}

func (n *ResilientNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func (n *ResilientNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.ListenUDP(network, locAddr)
}

func (n *ResilientNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}
	return resilientTCPListener{l}, nil
}

type resilientTCPListener struct {
	*net.TCPListener
}

func (l resilientTCPListener) AcceptTCP() (transport.TCPConn, error) {
	return l.TCPListener.AcceptTCP()
}

func (n *ResilientNet) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (n *ResilientNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

func (n *ResilientNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}

func (n *ResilientNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return net.ResolveIPAddr(network, address)
}

func (n *ResilientNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr(network, address)
}

func (n *ResilientNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr(network, address)
}

type resilientDialer struct {
	*net.Dialer
}

func (d resilientDialer) Dial(network, address string) (net.Conn, error) {
	return d.Dialer.Dial(network, address)
}

func (n *ResilientNet) CreateDialer(d *net.Dialer) transport.Dialer {
	return resilientDialer{d}
}
