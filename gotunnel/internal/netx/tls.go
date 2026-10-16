package netx

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed certs.pem
var embeddedCertsPEM []byte

var (
	poolMu       sync.RWMutex
	globalPool   *x509.CertPool
	insecureMode bool
)

// candidateCertPaths lists possible CA bundle file locations on Linux, Android, and Termux.
var candidateCertPaths = []string{
	// Termux paths
	"/data/data/com.termux/files/usr/etc/tls/cert.pem",
	"/data/data/com.termux/files/usr/etc/ssl/cert.pem",
	"/data/data/com.termux/files/usr/etc/ssl/certs/ca-certificates.crt",
	// Linux / standard paths
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/ssl/cert.pem",
}

// candidateCertDirs lists directories with individual CA certificates (e.g. Android cacerts).
var candidateCertDirs = []string{
	"/system/etc/security/cacerts",
	"/apex/com.android.conscrypt/cacerts",
}

// BuildCertPool constructs a comprehensive root CA certificate pool combining:
// 1. Embedded Mozilla Web PKI bundle + Russian Trusted Root CAs (Минцифры)
// 2. Android system CA certificates (/system/etc/security/cacerts, APEX conscrypt)
// 3. Termux CA certificate bundles ($PREFIX/etc/tls/cert.pem)
// 4. Host OS certificates
func BuildCertPool() *x509.CertPool {
	poolMu.RLock()
	if globalPool != nil {
		p := globalPool
		poolMu.RUnlock()
		return p
	}
	poolMu.RUnlock()

	poolMu.Lock()
	defer poolMu.Unlock()

	if globalPool != nil {
		return globalPool
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	// 1. Append embedded bundle (Mozilla + Russian Trusted CA)
	if len(embeddedCertsPEM) > 0 {
		pool.AppendCertsFromPEM(embeddedCertsPEM)
	}

	// 2. Check Termux $PREFIX if available
	if prefix := os.Getenv("PREFIX"); prefix != "" {
		for _, sub := range []string{"/etc/tls/cert.pem", "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"} {
			p := prefix + sub
			if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
				pool.AppendCertsFromPEM(data)
			}
		}
	}

	// 3. Check known file paths
	for _, p := range candidateCertPaths {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			pool.AppendCertsFromPEM(data)
		}
	}

	// 4. Scan Android cert directories (.0 files)
	for _, dir := range candidateCertDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".0") || strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem") {
				filePath := filepath.Join(dir, name)
				if data, err := os.ReadFile(filePath); err == nil && len(data) > 0 {
					pool.AppendCertsFromPEM(data)
				}
			}
		}
	}

	globalPool = pool
	return pool
}

// SetInsecureSkipVerify enables or disables TLS certificate verification.
func SetInsecureSkipVerify(insecure bool) {
	poolMu.Lock()
	insecureMode = insecure
	poolMu.Unlock()
}

// IsInsecureSkipVerify returns true if certificate verification is skipped.
func IsInsecureSkipVerify() bool {
	poolMu.RLock()
	defer poolMu.RUnlock()
	return insecureMode
}

// TLSConfig returns a robust *tls.Config equipped with the combined CA root pool.
func TLSConfig(insecure bool) *tls.Config {
	if insecure {
		log.Printf("[TLS] WARNING: TLS certificate verification is disabled (insecure mode)")
	}
	return &tls.Config{
		RootCAs:            BuildCertPool(),
		InsecureSkipVerify: insecure,
	}
}
