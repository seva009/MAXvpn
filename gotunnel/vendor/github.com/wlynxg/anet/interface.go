//go:build !android
// +build !android

package anet

import (
	"bufio"
	"net"
	"os"
	"strings"
	"time"
)

// Interfaces returns a list of the system's network interfaces.
func Interfaces() ([]net.Interface, error) {
	ifs, err := net.Interfaces()
	if err == nil && len(ifs) > 0 {
		return ifs, nil
	}
	return fallbackInterfaces(), nil
}

// InterfaceAddrs returns a list of the system's unicast interface
// addresses.
func InterfaceAddrs() ([]net.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err == nil && len(addrs) > 0 {
		return addrs, nil
	}
	var res []net.Addr
	for _, ifi := range fallbackInterfaces() {
		a, _ := InterfaceAddrsByInterface(&ifi)
		res = append(res, a...)
	}
	return res, nil
}

// InterfaceAddrsByInterface returns a list of the system's unicast
// interface addresses by specific interface.
func InterfaceAddrsByInterface(ifi *net.Interface) ([]net.Addr, error) {
	if ifi != nil {
		addrs, err := ifi.Addrs()
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
	}
	return fallbackAddrs(ifi), nil
}

func fallbackInterfaces() []net.Interface {
	var list []net.Interface
	seen := make(map[string]bool)

	add := func(name string, flags net.Flags) {
		name = strings.TrimSpace(name)
		if name != "" && !seen[name] {
			seen[name] = true
			list = append(list, net.Interface{
				Index: len(list) + 1,
				Name:  name,
				Flags: flags,
			})
		}
	}

	if f, err := os.Open("/proc/net/dev"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if idx := strings.Index(line, ":"); idx != -1 {
				name := strings.TrimSpace(line[:idx])
				flags := net.FlagUp
				if strings.HasPrefix(name, "lo") {
					flags |= net.FlagLoopback
				} else {
					flags |= net.FlagBroadcast | net.FlagMulticast
				}
				add(name, flags)
			}
		}
		_ = f.Close()
	}

	add("wlan0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast)
	add("lo", net.FlagUp|net.FlagLoopback)
	return list
}

func fallbackAddrs(ifi *net.Interface) []net.Addr {
	isLo := ifi != nil && strings.HasPrefix(ifi.Name, "lo")
	if isLo {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		}
	}

	d := net.Dialer{Timeout: 500 * time.Millisecond}
	for _, target := range []string{"77.88.8.8:80", "1.1.1.1:80", "8.8.8.8:80"} {
		if c, err := d.Dial("udp", target); err == nil {
			if u, ok := c.LocalAddr().(*net.UDPAddr); ok && u.IP != nil {
				_ = c.Close()
				return []net.Addr{
					&net.IPNet{IP: u.IP, Mask: net.CIDRMask(24, 32)},
				}
			}
			_ = c.Close()
		}
	}

	return []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
	}
}

func SetAndroidVersion(version uint) {}
