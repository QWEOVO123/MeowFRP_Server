package cluster

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
)

type memoryNodeStore struct {
	mu        sync.Mutex
	tokenHash string
	node      *db.EdgeNode
	touched   bool
	command   *db.NodeCommandRecord
	completed string
	presence  []db.EdgeClientPresence
}

func (s *memoryNodeStore) ConsumeEnrollmentToken(_ context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hash != s.tokenHash {
		return errors.New("bad token")
	}
	s.tokenHash = ""
	return nil
}
func (s *memoryNodeStore) UpsertEdgeNode(_ context.Context, node db.EdgeNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := node
	copy.Status = "active"
	s.node = &copy
	return nil
}
func (s *memoryNodeStore) GetEdgeNode(_ context.Context, id string) (*db.EdgeNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.node == nil || s.node.NodeID != id {
		return nil, db.ErrNotFound
	}
	copy := *s.node
	return &copy, nil
}
func (s *memoryNodeStore) TouchEdgeNode(_ context.Context, id, _, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.node == nil || s.node.NodeID != id {
		return db.ErrNotFound
	}
	s.touched = true
	return nil
}
func (s *memoryNodeStore) ListPendingNodeCommands(_ context.Context, nodeID string) ([]db.NodeCommandRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command != nil && s.command.NodeID == nodeID && s.completed == "" {
		return []db.NodeCommandRecord{*s.command}, nil
	}
	return nil, nil
}
func (s *memoryNodeStore) MarkNodeCommandDelivered(context.Context, string) error { return nil }
func (s *memoryNodeStore) CompleteNodeCommand(_ context.Context, nodeID, commandID, status, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.command != nil && s.command.NodeID == nodeID && s.command.CommandID == commandID {
		s.completed = status
	}
	return nil
}
func (s *memoryNodeStore) RecordNodeEvent(context.Context, string, int64, string, string, string) (bool, error) {
	return true, nil
}
func (s *memoryNodeStore) ReplaceEdgeClientPresence(_ context.Context, _ string, clients []db.EdgeClientPresence) error {
	s.mu.Lock()
	s.presence = append([]db.EdgeClientPresence(nil), clients...)
	s.mu.Unlock()
	return nil
}
func (s *memoryNodeStore) RecordEdgeDPIEvent(context.Context, string, dpi.Event) error { return nil }

func TestMTLSControlStreamRequiresIssuedNodeCertificate(t *testing.T) {
	dir := t.TempDir()
	paths := PKIPaths{CAFile: filepath.Join(dir, "ca.crt"), CAKeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key")}
	if err := EnsureControllerPKI(paths, "127.0.0.1:9443"); err != nil {
		t.Fatal(err)
	}
	material, err := LoadPKIMaterial(paths)
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := NewNodeKeyAndCSR("test edge")
	if err != nil {
		t.Fatal(err)
	}
	cert, serial, expires, err := SignNodeCSRMaterial(material, "node-test", csr)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryNodeStore{
		node:    &db.EdgeNode{NodeID: "node-test", Name: "test edge", CertificateSerial: serial, Status: "active"},
		command: &db.NodeCommandRecord{CommandID: "cmd-test", NodeID: "node-test", CommandType: "probe", PayloadJSON: `{}`, ExpiresAt: time.Now().Add(time.Minute)},
	}
	server := NewControllerServer(store, paths)
	server.SetHeartbeatInterval(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	_ = expires
	client := NewEdgeClient(server.Addr(), "node-test", "127.0.0.1", TLSFiles{CAPEM: material.CACertificate, CertPEM: cert, KeyPEM: key}, map[string]any{"reporting": map[string]bool{"client_presence": true}})
	client.SetHeartbeatProvider(func(context.Context) HeartbeatPayload {
		return HeartbeatPayload{Clients: []ClientPresence{{UserID: 7, TokenID: 9, ClientID: "desktop", FRPCRunning: true}}}
	})
	client.SetCommandHandler(func(_ context.Context, command NodeCommand) CommandResult {
		return CommandResult{CommandID: command.CommandID, Status: "succeeded"}
	})
	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()
	go client.Run(clientCtx)
	deadline := time.Now().Add(9 * time.Second)
	var touched bool
	var completed string
	var presence int
	for time.Now().Before(deadline) {
		store.mu.Lock()
		touched = store.touched
		completed = store.completed
		presence = len(store.presence)
		store.mu.Unlock()
		if client.Connected() && touched && completed == "succeeded" && presence == 1 {
			liveCtx, liveCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer liveCancel()
			result, err := server.SendCommandAndWait(liveCtx, NodeCommand{CommandID: "live-test", NodeID: "node-test", Command: "probe", Payload: []byte(`{}`), ExpiresAt: time.Now().Add(time.Second)})
			if err != nil || result.CommandID != "live-test" || result.Status != "succeeded" {
				t.Fatalf("online-only command result=%#v err=%v", result, err)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("control stream incomplete: connected=%v touched=%v command=%q presence=%d error=%s", client.Connected(), touched, completed, presence, client.LastError())
}
