package httpapi

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/security"
	frpclient "github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func testUnusedTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// Real modified FRPS + FRPC, not just calls to bookkeeping hooks. Proves an
// idle registered port prevents logout, remains usable during control faults,
// and closing the last registered port triggers the GUI reauth command.
func TestEmbeddedFRPSFaultDrainPreservesTunnelUntilLastProxyCloses(t *testing.T) {
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	s := newConnectedTestEdge(t, state)
	api := httptest.NewServer(s.Routes())
	defer api.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := s.getConfig()
	cfg.EmbeddedFRPEnabled = true
	cfg.HTTPAddr = strings.TrimPrefix(api.URL, "http://")
	cfg.FRPBindAddr = "127.0.0.1"
	cfg.FRPProxyBindAddr = "127.0.0.1"
	cfg.FRPServerPort = testUnusedTCPPort(t)
	s.setRuntime(cfg, nil)
	if err := s.core.StartEmbeddedFRPS(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	ctx = context.Background()
	_, _, guiClient, err := state.Credential(ctx, security.TokenHash("ak_secret"), "desktop", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.TouchClient(ctx, guiClient.ID, true); err != nil {
		t.Fatal(err)
	}
	s.rememberClient("ak_secret", guiClient, true)
	remotePort := testUnusedTCPPort(t)
	lease := db.RuntimeLease{LeaseID: "lease-e2e", UserID: 7, TokenID: 9, ClientID: "desktop", RuntimeTokenHash: security.TokenHash("rt_test"), Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	localPort := backend.Addr().(*net.TCPAddr).Port
	if err := state.CreateLease(ctx, lease, []db.ProxyAllocationInput{{ProxyName: "port", ProxyType: "tcp", LocalIP: "127.0.0.1", LocalPort: localPort, RemotePort: remotePort}}); err != nil {
		t.Fatal(err)
	}
	proxy := &v1.TCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "lease-e2e.port", Type: "tcp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: localPort}}, RemotePort: remotePort}
	configSource := source.NewConfigSource()
	if err := configSource.ReplaceAll([]v1.ProxyConfigurer{proxy}, nil); err != nil {
		t.Fatal(err)
	}
	tlsEnabled := false
	frpc, err := frpclient.NewService(frpclient.ServiceOptions{Common: &v1.ClientCommonConfig{ServerAddr: "127.0.0.1", ServerPort: cfg.FRPServerPort, Metadatas: map[string]string{"lease_id": lease.LeaseID, "token": "rt_test"}, Transport: v1.ClientTransportConfig{TLS: v1.TLSClientConfig{Enable: &tlsEnabled}}}, ConfigSourceAggregator: source.NewAggregator(configSource)})
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() { clientDone <- frpc.Run(context.Background()) }()
	defer func() {
		frpc.Close()
		select {
		case <-clientDone:
		case <-time.After(5 * time.Second):
			t.Error("frpc did not stop")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for s.core.ClientProxyCount(9, "desktop") != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.core.ClientProxyCount(9, "desktop") != 1 {
		t.Fatal("actual proxy did not register")
	}
	s.transitionNodeFault(true)
	if err := state.DiscardControlIdentityCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	heartbeat := httptest.NewRecorder()
	s.faultHeartbeat(heartbeat, httptest.NewRequest("POST", "/", nil), clientHeartbeatRequest{AccessToken: "ak_secret", ClientID: "desktop"})
	if strings.Contains(heartbeat.Body.String(), "reauth") || !strings.Contains(heartbeat.Body.String(), `"active_proxies":1`) {
		t.Fatalf("idle registered port was logged out: %s", heartbeat.Body.String())
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), time.Second)
	if err != nil {
		t.Fatal("registered port inaccessible during fault:", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "test" {
		t.Fatalf("fault broke data forwarding: data=%q err=%v", buffer, err)
	}
	if err := frpc.UpdateAllConfigurer(nil, nil); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for s.core.ClientProxyCount(9, "desktop") != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.core.ClientProxyCount(9, "desktop") != 0 {
		t.Fatal("actual proxy closure not counted")
	}
	final := httptest.NewRecorder()
	s.faultHeartbeat(final, httptest.NewRequest("POST", "/", nil), clientHeartbeatRequest{AccessToken: "ak_secret", ClientID: "desktop", FRPCRunning: true})
	if !strings.Contains(final.Body.String(), `"command":"reauth"`) {
		t.Fatalf("last port closed without logout: %s", final.Body.String())
	}
}
