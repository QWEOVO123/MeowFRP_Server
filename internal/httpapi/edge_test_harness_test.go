package httpapi

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/security"
)

// Real loopback mTLS stream with an in-memory controller store: no MySQL or
// production credentials. This keeps heartbeat tests in an actually online,
// identity-confirmed edge state rather than bypassing the admission guard.
type edgeTestControllerStore struct{ node db.EdgeNode }

func (s *edgeTestControllerStore) ConsumeEnrollmentToken(context.Context, string) error { return nil }
func (s *edgeTestControllerStore) UpsertEdgeNode(context.Context, db.EdgeNode) error    { return nil }
func (s *edgeTestControllerStore) TouchEdgeNode(context.Context, string, string, string) error {
	return nil
}
func (s *edgeTestControllerStore) GetEdgeNode(context.Context, string) (*db.EdgeNode, error) {
	node := s.node
	return &node, nil
}
func (*edgeTestControllerStore) CanAccessNode(context.Context, int64, string) (bool, error) {
	return true, nil
}
func (*edgeTestControllerStore) ListUsers(context.Context) ([]db.User, error) {
	return []db.User{{ID: 7, Username: "alice", Role: "user", Status: "active"}}, nil
}
func (*edgeTestControllerStore) ListAccessTokens(context.Context) ([]db.AccessToken, error) {
	return []db.AccessToken{{ID: 9, UserID: 7, TokenHash: security.TokenHash("ak_secret"), Status: "active", MaxProxyCount: 2}}, nil
}
func (*edgeTestControllerStore) ListUserResourcePolicies(context.Context) ([]db.UserResourcePolicy, error) {
	return []db.UserResourcePolicy{{UserID: 7, Enabled: true, PortStart: 6000, PortEnd: 6010, MaxPorts: 2, AllowedProtocols: []string{"tcp"}}}, nil
}
func (*edgeTestControllerStore) ListAllPortGrants(context.Context) ([]db.PortGrant, error) {
	return nil, nil
}
func (*edgeTestControllerStore) ListDPIPolicies(context.Context) ([]dpi.Policy, error) {
	return nil, nil
}
func (*edgeTestControllerStore) ListBlockedInboundIPs(context.Context) ([]db.BlockedInboundIP, error) {
	return nil, nil
}

func newConnectedTestEdge(t *testing.T, state *edgestate.Store) *Server {
	t.Helper()
	dir := t.TempDir()
	paths := cluster.PKIPaths{CAFile: filepath.Join(dir, "ca.crt"), CAKeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key")}
	if err := cluster.EnsureControllerPKI(paths, "127.0.0.1:9443"); err != nil {
		t.Fatal(err)
	}
	material, err := cluster.LoadPKIMaterial(paths)
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := cluster.NewNodeKeyAndCSR("test edge")
	if err != nil {
		t.Fatal(err)
	}
	cert, serial, _, err := cluster.SignNodeCSRMaterial(material, "test-edge", csr)
	if err != nil {
		t.Fatal(err)
	}
	controller := cluster.NewControllerServer(&edgeTestControllerStore{node: db.EdgeNode{NodeID: "test-edge", Status: "active", CertificateSerial: serial}}, paths)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := controller.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client := cluster.NewEdgeClient(controller.Addr(), "test-edge", "127.0.0.1", cluster.TLSFiles{CAPEM: material.CACertificate, CertPEM: cert, KeyPEM: key}, nil)
	client.SetSnapshotHandler(state.ApplyIdentitySnapshot)
	server := NewServer(config.Config{Mode: config.ModeEdge, ConfigState: "configured"}, nil, WithEdgeRuntime(state, client))
	done := make(chan struct{})
	go func() { defer close(done); client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("test edge did not stop")
		}
		_ = server.core.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if server.edgeOnlineForNewSessions() {
			return server
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("test edge did not become identity-ready: %s", client.LastError())
	return nil
}
