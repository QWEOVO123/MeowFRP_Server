package cluster

import (
	"context"
	"testing"
	"time"
)

func TestStaleNodeSessionIsReportedOffline(t *testing.T) {
	server := NewControllerServer(nil, PKIPaths{})
	server.sessions["fresh"] = &nodeSession{nodeID: "fresh", send: make(chan Message, 1), lastHeartbeat: time.Now()}
	server.sessions["stale"] = &nodeSession{nodeID: "stale", send: make(chan Message, 1), lastHeartbeat: time.Now().Add(-time.Minute)}

	if online, _ := server.NodeSession("fresh"); !online {
		t.Fatal("fresh node was reported offline")
	}
	if online, _ := server.NodeSession("stale"); online {
		t.Fatal("stale node was reported online")
	}
	connected := server.ConnectedNodes()
	if len(connected) != 1 || connected[0] != "fresh" {
		t.Fatalf("unexpected connected nodes: %#v", connected)
	}
	if server.SendCommand(NodeCommand{NodeID: "stale", CommandID: "cmd-stale"}) {
		t.Fatal("command was sent to stale node")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := server.SendCommandAndWait(ctx, NodeCommand{NodeID: "stale", CommandID: "cmd-wait"}); err == nil {
		t.Fatal("online-only command accepted stale node")
	}
}
