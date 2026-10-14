package frpcore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"frp-control-server/internal/config"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/version"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestEmbeddedFRPTLSHotToggleAndRotationOnWire(t *testing.T) {
	plugin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"reject":true,"reject_reason":"integration-test-auth-rejection","unchange":true}`))
	}))
	defer plugin.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg := config.Config{ConfigPath: filepath.Join(t.TempDir(), "node.json"), EmbeddedFRPEnabled: true, FRPTransportTLS: true, FRPBindAddr: "127.0.0.1", FRPProxyBindAddr: "127.0.0.1", FRPServerPort: port, HTTPAddr: plugin.Listener.Addr().String(), ConnectionTuning: config.ConnectionTuning{DisableTCPMux: true}}
	m := NewManager(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer m.Close()
	if err := m.StartEmbeddedFRPS(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	clientTLS := func() *tls.Config {
		p, ready := m.TLSPublic(true)
		if !ready {
			t.Fatal("missing identity")
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM([]byte(p.CAPEM))
		return &tls.Config{RootCAs: roots, ServerName: p.ServerName, MinVersion: tls.VersionTLS13}
	}
	old := clientTLS()
	dial := func(config *tls.Config) net.Conn {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, config)
		if err != nil {
			t.Fatal("FRPS TLS handshake failed", err)
		}
		return conn
	}
	initial := dial(old)
	initial.Close()
	if err := m.ResetTLSIdentity(cfg, "reset-on-wire"); err != nil {
		t.Fatal(err)
	}
	if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, old); err == nil {
		conn.Close()
		t.Fatal("FRPS still accepts old CA after reset")
	}
	rotated := dial(clientTLS())
	rotated.Close()
	m.SetTLSRequired(false)
	if m.TLSRequired(cfg) {
		t.Fatal("runtime TLS disable ignored")
	}
	// Authentication is deliberately rejected by the mock plugin. Receiving a
	// parsed LoginResp proves plaintext reached FRPS, independently of authorization.
	login := func() (msg.Message, error) {
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := msg.WriteMsg(conn, &msg.Login{Version: version.Full(), User: "test"}); err != nil {
			return nil, err
		}
		return msg.ReadMsg(conn)
	}
	response, err := login()
	if err != nil {
		t.Fatal("TLS disable did not accept plaintext protocol", err)
	}
	if _, ok := response.(*msg.LoginResp); !ok {
		t.Fatal("no plaintext FRP response")
	}
	m.SetTLSRequired(true)
	if !m.TLSRequired(cfg) {
		t.Fatal("runtime TLS enable ignored")
	}
	if _, err := login(); err == nil {
		t.Fatal("mandatory TLS accepted plaintext")
	}
	final := dial(clientTLS())
	final.Close()
}
