package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type trustRoundTrip func(*http.Request) (*http.Response, error)

func (f trustRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testFRPIdentity(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test private CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"frp.test.internal"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestMemoryTrustIsolatedRefetchedAndStrict(t *testing.T) {
	root, cert := testFRPIdentity(t)
	trust := MemoryTrust{OK: true, Enabled: true, NodeID: "node-1", ServerName: "frp.test.internal", CAPEM: root, Generation: "1"}
	var override string
	calls := 0
	client := &http.Client{Transport: trustRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.Header.Get("Cache-Control") == "" {
			t.Error("invalid API request")
		}
		data, _ := json.Marshal(trust)
		if override != "" {
			data = []byte(override)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
	})}
	fetch := func() (*tls.Config, bool, error) {
		return fetchMemoryTrust(context.Background(), client, "https://node.test/api/v1/client/frp-trust", "node-1")
	}
	cfg, enabled, err := fetch()
	if err != nil || !enabled || cfg == nil || cfg.InsecureSkipVerify || cfg.RootCAs == nil {
		t.Fatal("trust missing or insecure", err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: cfg.ServerName}); err != nil {
		t.Fatal(err)
	}
	_, foreignCert := testFRPIdentity(t)
	foreign, _ := x509.ParseCertificate(foreignCert.Certificate[0])
	if _, err = foreign.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: cfg.ServerName}); err == nil {
		t.Fatal("foreign root trusted")
	}
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(trust) }))
	defer api.Close()
	// Only the API test client trusts this test-only HTTPS CA; it must not leak into FRP.
	apiCfg, _, err := fetchMemoryTrust(context.Background(), api.Client(), api.URL, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = api.Certificate().Verify(x509.VerifyOptions{Roots: apiCfg.RootCAs}); err == nil {
		t.Fatal("API trust leaked into FRP roots")
	}
	if _, _, err = FetchMemoryTrust(context.Background(), api.URL, "node-1"); err == nil {
		t.Fatal("production API bypassed system HTTPS verification")
	}
	for _, body := range []string{`{"node_id":"node-1"}`, `{"enabled":false,"node_id":"other"}`, `{"enabled":true,"node_id":"node-1","ca_pem":"invalid","server_name":"a","generation":"1"}`, "invalid"} {
		override = body
		if _, _, err = fetch(); err == nil {
			t.Fatalf("bad response accepted: %s", body)
		}
	}
	override = ""
	trust.Enabled = false
	if cfg, enabled, err = fetch(); err == nil || enabled || cfg != nil {
		t.Fatal("plaintext must be rejected even when explicitly requested by the node", err)
	}
	trust.Enabled = true
	trust.CAPEM, _ = testFRPIdentity(t)
	trust.Generation = "2"
	if cfg, enabled, err = fetch(); err != nil || !enabled {
		t.Fatal(err)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: cfg.ServerName}); err == nil {
		t.Fatal("old trust cached after rotation")
	}
	before := calls
	if _, _, err = fetchMemoryTrust(context.Background(), client, "http://node.test/api", "node-1"); err == nil || calls != before {
		t.Fatal("HTTP trust download permitted")
	}
}
