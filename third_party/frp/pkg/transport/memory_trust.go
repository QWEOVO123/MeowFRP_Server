package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type MemoryTrust struct {
	OK         bool   `json:"ok"`
	Enabled    bool   `json:"enabled"`
	NodeID     string `json:"node_id"`
	ServerName string `json:"server_name"`
	CAPEM      string `json:"ca_pem"`
	Generation string `json:"generation"`
}

// FetchMemoryTrust uses ordinary HTTPS trust for the API and an EMPTY, isolated
// pool for FRP. No CA is installed, logged, cached globally, or written to disk.
func FetchMemoryTrust(ctx context.Context, apiURL, expectedNode string) (*tls.Config, bool, error) {
	httpsTransport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer httpsTransport.CloseIdleConnections()
	client := &http.Client{Transport: httpsTransport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("FRP trust API redirects are not allowed")
	}}
	return fetchMemoryTrust(ctx, client, apiURL, expectedNode)
}

func fetchMemoryTrust(ctx context.Context, client *http.Client, apiURL, expectedNode string) (*tls.Config, bool, error) {
	u, err := url.Parse(apiURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, false, fmt.Errorf("FRP trust API requires a valid HTTPS URL")
	}
	if expectedNode == "" {
		return nil, false, fmt.Errorf("FRP expected node identity is missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Cache-Control", "no-cache, no-store")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("HTTPS FRP trust request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("FRP trust API returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return nil, false, fmt.Errorf("invalid FRP trust response size")
	}
	var trust MemoryTrust
	// Pointer is deliberate: a missing flag must NOT authorize plaintext.
	var envelope struct {
		Enabled *bool `json:"enabled"`
		MemoryTrust
	}
	if err = json.Unmarshal(data, &envelope); err != nil || envelope.Enabled == nil {
		return nil, false, fmt.Errorf("invalid FRP trust response")
	}
	trust = envelope.MemoryTrust
	trust.Enabled = *envelope.Enabled
	if !trust.OK {
		return nil, false, fmt.Errorf("FRP trust API did not confirm success")
	}
	if trust.NodeID != expectedNode {
		return nil, false, fmt.Errorf("FRP trust response belongs to a different node")
	}
	if !trust.Enabled {
		return nil, false, nil
	} // Explicit HTTPS-confirmed server setting, never error fallback.
	if trust.CAPEM == "" || trust.ServerName == "" || trust.Generation == "" {
		return nil, false, fmt.Errorf("FRP TLS trust information is incomplete")
	}
	block, rest := pem.Decode([]byte(trust.CAPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, false, fmt.Errorf("FRP trust requires exactly one root certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil || time.Now().Before(ca.NotBefore) || time.Now().After(ca.NotAfter) {
		return nil, false, fmt.Errorf("invalid FRP root certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &tls.Config{RootCAs: roots, ServerName: trust.ServerName, MinVersion: tls.VersionTLS13, InsecureSkipVerify: false}, true, nil
}
