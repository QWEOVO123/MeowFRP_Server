package frpcore

import (
	"context"
	"net"
	"testing"
	"time"

	"frp-control-server/internal/dpi"
	"frp-control-server/internal/dpiengine"
	"github.com/fatedier/frp/pkg/dpihook"
)

type recordingInspector struct {
	called bool
	sample dpiengine.TrafficSample
}

func (i *recordingInspector) Inspect(_ context.Context, sample dpiengine.TrafficSample) dpi.Decision {
	i.called = true
	i.sample = sample
	return dpi.Decision{Action: dpi.ActionMonitor, Reason: "recorded"}
}

func TestFeedTrafficSampleUsesInspector(t *testing.T) {
	inspector := &recordingInspector{}
	manager := NewManager(inspector)
	t.Cleanup(func() { _ = manager.Close() })

	decision := manager.FeedTrafficSample(context.Background(), dpiengine.TrafficSample{
		Flow: dpiengine.FlowContext{LeaseID: "lease_1", ProxyName: "web"},
	})

	if decision.Action != dpi.ActionMonitor {
		t.Fatalf("expected monitor decision, got %s", decision.Action)
	}
	if !inspector.called {
		t.Fatal("expected inspector to be called")
	}
	if inspector.sample.Flow.ProxyName != "web" {
		t.Fatalf("expected sample proxy name to be preserved, got %q", inspector.sample.Flow.ProxyName)
	}
}

func TestProxyBindingRegistry(t *testing.T) {
	manager := NewManager(nil)
	t.Cleanup(func() { _ = manager.Close() })
	binding := ProxyBinding{LeaseID: "lease_1", ProxyName: "web", UserID: 42}
	manager.BindProxy(binding)

	got, ok := manager.LookupProxy("lease_1", "web")
	if !ok {
		t.Fatal("expected binding to exist")
	}
	if got.UserID != 42 {
		t.Fatalf("expected user 42, got %d", got.UserID)
	}

	manager.UnbindProxy("lease_1", "web")
	if _, ok := manager.LookupProxy("lease_1", "web"); ok {
		t.Fatal("expected binding to be removed")
	}
}

func TestUDPFlowLimitAndCleanup(t *testing.T) {
	manager := NewManager(nil)
	t.Cleanup(func() { _ = manager.Close() })
	manager.SetUDPFlowTimeout(time.Minute)
	manager.mu.Lock()
	manager.maxUDPFlows = 2
	manager.mu.Unlock()

	for _, remoteAddr := range []string{"192.0.2.1:1001", "192.0.2.2:1002", "192.0.2.3:1003"} {
		manager.ObserveUDPFlow(context.Background(), dpihook.ConnectionInfo{
			LeaseID:    "lease_1",
			ProxyName:  "dns",
			ProxyType:  "udp",
			RemoteAddr: remoteAddr,
		})
	}

	manager.mu.RLock()
	flowCount := len(manager.udpFlows)
	manager.mu.RUnlock()
	if flowCount != 2 {
		t.Fatalf("expected UDP flow limit of 2, got %d", flowCount)
	}

	manager.mu.Lock()
	for key, flow := range manager.udpFlows {
		flow.LastSeenAt = time.Now().Add(-2 * time.Minute)
		manager.udpFlows[key] = flow
	}
	manager.mu.Unlock()
	if removed := manager.cleanupExpiredUDPFlows(time.Now()); removed != 2 {
		t.Fatalf("expected 2 expired UDP flows to be removed, got %d", removed)
	}
}

func TestListConnectionsUsesReadOnlySnapshot(t *testing.T) {
	manager := NewManager(nil)
	t.Cleanup(func() { _ = manager.Close() })
	manager.SetUDPFlowTimeout(time.Hour)
	manager.mu.Lock()
	manager.udpFlows["expired"] = ActiveConnection{
		ID:         "udp_1",
		Protocol:   "udp",
		LastSeenAt: time.Now().Add(-time.Minute),
	}
	manager.mu.Unlock()

	if connections := manager.ListConnections(time.Second); len(connections) != 0 {
		t.Fatalf("expected expired flow to be filtered, got %d connections", len(connections))
	}
	manager.mu.RLock()
	flowCount := len(manager.udpFlows)
	manager.mu.RUnlock()
	if flowCount != 1 {
		t.Fatalf("expected listing to leave cleanup to the background worker, got %d flows", flowCount)
	}
}

func TestTerminateTCPConnectionRemovesTrackingImmediately(t *testing.T) {
	manager := NewManager(nil)
	t.Cleanup(func() { _ = manager.Close() })
	userConn, userPeer := net.Pipe()
	workConn, workPeer := net.Pipe()
	t.Cleanup(func() {
		_ = userPeer.Close()
		_ = workPeer.Close()
	})
	id := manager.RegisterTCPConnection(context.Background(), dpihook.ConnectionInfo{
		LeaseID:   "lease_1",
		ProxyName: "web",
		ProxyType: "tcp",
	}, userConn, workConn)

	if !manager.TerminateTCPConnection(id) {
		t.Fatal("expected tracked TCP connection to terminate")
	}
	manager.mu.RLock()
	_, exists := manager.tcpConnections[id]
	manager.mu.RUnlock()
	if exists {
		t.Fatal("expected terminated TCP connection to be removed immediately")
	}
}
