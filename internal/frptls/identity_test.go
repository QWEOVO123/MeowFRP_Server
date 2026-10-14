package frptls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func trustConfig(p Public) *tls.Config {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(p.CAPEM))
	return &tls.Config{RootCAs: roots, ServerName: p.ServerName, MinVersion: tls.VersionTLS13}
}

func handshake(t *testing.T, serverConfig, clientConfig *tls.Config) (net.Conn, net.Conn, error) {
	t.Helper()
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	server, client := tls.Server(a, serverConfig), tls.Client(b, clientConfig)
	finished := make(chan error, 1)
	go func() {
		err := server.Handshake()
		if err != nil {
			a.Close()
		}
		finished <- err
	}()
	err := client.Handshake()
	if err != nil {
		b.Close()
	}
	serverErr := <-finished
	if err == nil {
		err = serverErr
	}
	// Close the underlying pipes directly: TLS close_notify on net.Pipe blocks.
	t.Cleanup(func() { a.Close(); b.Close() })
	return server, client, err
}

func TestIdentityPersistenceIsolationAndHotRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.frp-tls.json")
	identity, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := identity.Public(true)
	other, err := Open(filepath.Join(t.TempDir(), "other.frp-tls.json"))
	if err != nil {
		t.Fatal(err)
	}
	if other.Public(false).Fingerprint == old.Fingerprint {
		t.Fatal("nodes share a root")
	}
	if identity.Public(false).CAPEM != "" {
		t.Fatal("metadata leaked root payload")
	}
	reloaded, err := Open(path)
	if err != nil || reloaded.Public(false).Generation != old.Generation {
		t.Fatal("identity changed on restart", err)
	}
	serverConfig := identity.TLSConfig()
	server, client, err := handshake(t, serverConfig, trustConfig(old))
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Reset("command-1"); err != nil {
		t.Fatal(err)
	}
	current := identity.Public(true)
	if current.Generation == old.Generation {
		t.Fatal("reset did not rotate root")
	}
	if err := identity.Reset("command-1"); err != nil {
		t.Fatal(err)
	}
	if identity.Public(false).Generation != current.Generation {
		t.Fatal("reset retry is not idempotent")
	}
	reloaded, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Reset("command-1"); err != nil {
		t.Fatal(err)
	}
	if reloaded.Public(false).Generation != current.Generation {
		t.Fatal("durable reset ID lost")
	}
	if _, _, err = handshake(t, serverConfig, trustConfig(old)); err == nil {
		t.Fatal("old root trusted new identity")
	}
	if _, _, err = handshake(t, serverConfig, trustConfig(other.Public(true))); err == nil {
		t.Fatal("another node root accepted")
	}
	if _, _, err = handshake(t, serverConfig, trustConfig(current)); err != nil {
		t.Fatal(err)
	}
	// A live TLS channel remains usable after root/key rotation.
	server.SetDeadline(time.Now().Add(3 * time.Second))
	client.SetDeadline(time.Now().Add(3 * time.Second))
	written := make(chan error, 1)
	go func() { _, err := server.Write([]byte("x")); written <- err }()
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil || buf[0] != 'x' {
		t.Fatal("live channel interrupted", err)
	}
}

func TestCorruptIdentityFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt identity silently replaced")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "invalid" {
		t.Fatal("corrupt file overwritten without explicit reset")
	}
}

func TestExpiredLeafRenewsWithSameRootOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.json")
	identity, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	before := identity.Public(true)
	state := identity.state
	rootBlock, _ := pem.Decode([]byte(state.CAPEM))
	root, _ := x509.ParseCertificate(rootBlock.Bytes)
	caKeyBlock, _ := pem.Decode([]byte(state.CAKeyPEM))
	caKey, _ := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	leaf := *identity.certificate.Leaf
	leaf.NotBefore, leaf.NotAfter = time.Now().Add(-4*time.Minute), time.Now().Add(-time.Minute)
	leaf.SerialNumber, err = serial()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &leaf, root, identity.certificate.Leaf.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	state.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	// Historical chain verification is allowed only for loading existing material;
	// installation of a newly generated identity always verifies at the current time.
	if err := identity.install(state, false); err != nil {
		t.Fatal(err)
	}
	// Persist an expired leaf to emulate a node stopped over its expiry date.
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	after := reloaded.Public(true)
	if after.Fingerprint != before.Fingerprint || after.Generation != before.Generation || time.Until(after.NotAfter) < 300*24*time.Hour {
		t.Fatal("leaf renewal lost root or failed")
	}
	if _, _, err = handshake(t, reloaded.TLSConfig(), trustConfig(before)); err != nil {
		t.Fatal("same root cannot verify renewed leaf", err)
	}
}

func TestFailedResetKeepsActiveIdentity(t *testing.T) {
	identity, err := Open(filepath.Join(t.TempDir(), "node.json"))
	if err != nil {
		t.Fatal(err)
	}
	before := identity.Public(true)
	// A non-directory parent makes writing fail regardless of current user privileges.
	parent := filepath.Join(t.TempDir(), "not-directory")
	if err := os.WriteFile(parent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	identity.path = filepath.Join(parent, "node.json")
	if err := identity.Reset("failing-reset"); err == nil {
		t.Fatal("expected disk write failure")
	}
	if identity.Public(false).Generation != before.Generation {
		t.Fatal("failed reset replaced in-memory identity")
	}
	if _, _, err = handshake(t, identity.TLSConfig(), trustConfig(before)); err != nil {
		t.Fatal("failed reset broke connections", err)
	}
}
