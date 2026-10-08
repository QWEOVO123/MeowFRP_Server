package cluster

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"frp-control-server/internal/db"
)

func TestControllerFaultNotifiesEdgesAndRecoveryRequiresBaseline(t *testing.T) {
	s := NewControllerServer(nil, PKIPaths{})
	session := &nodeSession{nodeID: "edge", admissionProtocol: 1, cacheReady: true, send: make(chan Message, 4), lastHeartbeat: time.Now(), cancel: func() { t.Error("upgraded edge unnecessarily disconnected") }}
	s.sessions["edge"] = session
	s.SetDatabaseSuspect(true)
	s.SetDatabaseFault(true)
	message := <-session.send
	var ack HeartbeatAck
	if err := json.Unmarshal(message.Payload, &ack); err != nil {
		t.Fatal(err)
	}
	if message.Type != "controller_state" || !ack.ControllerFault {
		t.Fatalf("missing fault notice: %#v", message)
	}
	s.SetDatabaseFault(false)
	if !session.needsFull || s.DatabaseFault() || s.DatabaseUnavailable() {
		t.Fatal("recovery skipped resync or kept database fault")
	}
}

func TestControllerShortOutageDoesNotResetReadyEdgeCache(t *testing.T) {
	s := NewControllerServer(nil, PKIPaths{})
	session := &nodeSession{nodeID: "edge", admissionProtocol: 1, cacheReady: true, send: make(chan Message, 4), cancel: func() { t.Error("short outage disconnected edge") }}
	s.sessions["edge"] = session
	s.SetDatabaseSuspect(true)
	s.SetDatabaseFault(false)
	if session.needsFull {
		t.Fatal("short DB outage forced full baseline")
	}
}

func TestControllerMemoryCatalogSurvivesDatabaseFailureWithoutResurrectingDeletedNode(t *testing.T) {
	s := NewControllerServer(nil, PKIPaths{})
	s.ReplaceNodeCatalog([]db.EdgeNode{{NodeID: "online", Status: "active"}, {NodeID: "offline", Status: "active"}})
	s.SetDatabaseSuspect(true)
	if node, err := s.authorizedNode(context.Background(), "offline"); err != nil || node.NodeID != "offline" {
		t.Fatalf("offline node missing from RAM: %#v %v", node, err)
	}
	s.ForgetNode("offline")
	s.ReplaceNodeCatalog([]db.EdgeNode{{NodeID: "online", Status: "active"}, {NodeID: "offline", Status: "active"}})
	if _, err := s.authorizedNode(context.Background(), "offline"); err != db.ErrNotFound {
		t.Fatalf("deleted node resurrected: %v", err)
	}
	if len(s.NodeCatalog()) != 1 {
		t.Fatalf("unexpected memory catalog: %#v", s.NodeCatalog())
	}
}
