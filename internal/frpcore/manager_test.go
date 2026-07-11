package frpcore

import (
	"context"
	"testing"

	"frp-control-server/internal/dpi"
	"frp-control-server/internal/dpiengine"
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
