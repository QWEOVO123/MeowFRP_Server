package dpi

import (
	"context"
	"errors"
	"testing"

	"frp-control-server/internal/dpiengine"
)

type fixedEngine struct {
	result dpiengine.Result
	err    error
}

func TestExplicitEmptyDetectorListDoesNotInspectOrBlock(t *testing.T) {
	policy := DefaultPolicy()
	policy.Enabled = true
	policy.Mode = ModeBlock
	policy.EnabledDetectors = []string{}
	policy.BlockOnAnyFinding = true
	service := NewService(Options{Engine: fixedEngine{err: errors.New("engine must not be called")}, PolicyProvider: StaticPolicyProvider{Policy: policy}})
	if decision := service.Inspect(context.Background(), dpiengine.TrafficSample{}); decision.Action != ActionAllow {
		t.Fatalf("empty selection must disable detection: %#v", decision)
	}
	if got := filterFindings([]dpiengine.Finding{{Detector: "tls"}}, []string{}); len(got) != 0 {
		t.Fatalf("empty selection included findings: %#v", got)
	}
}

func TestVerifiedLeasePolicySurvivesControlPlaneFailure(t *testing.T) {
	policy := DefaultPolicy()
	policy.Enabled = true
	policy.Mode = ModeBlock
	policy.AllowTLS = false
	service := NewService(Options{Engine: fixedEngine{result: dpiengine.Result{Findings: []dpiengine.Finding{{Detector: "tls"}}}}, PolicyProvider: StaticPolicyProvider{Policy: policy}})
	flow := dpiengine.FlowContext{UserID: 7, LeaseID: "active-lease"}
	service.PrimeLease(context.Background(), flow)
	service.SetProviderUnavailable(true, false)
	if got := service.Inspect(context.Background(), dpiengine.TrafficSample{Flow: flow}); got.Action != ActionBlock || got.Reason != "tls is blocked by user dpi policy" {
		t.Fatalf("verified policy was discarded: %#v", got)
	}
	if got := service.Inspect(context.Background(), dpiengine.TrafficSample{Flow: dpiengine.FlowContext{LeaseID: "unknown"}}); got.Action != ActionBlock || got.Reason != ErrPolicySynchronizing.Error() {
		t.Fatalf("unknown lease was allowed during sync: %#v", got)
	}
	service.SetProviderUnavailable(false, false)
	policy.AllowTLS = true
	service.SetPolicyProvider(StaticPolicyProvider{Policy: policy})
	if got := service.Inspect(context.Background(), dpiengine.TrafficSample{Flow: flow}); got.Action != ActionMonitor {
		t.Fatalf("new policy not applied after recovery: %#v", got)
	}
}

func (e fixedEngine) Inspect(context.Context, dpiengine.TrafficSample) (dpiengine.Result, error) {
	return e.result, e.err
}

func TestDefaultServiceAllowsWithoutEnabledPolicy(t *testing.T) {
	service := NewService(Options{
		Engine: fixedEngine{
			result: dpiengine.Result{Findings: []dpiengine.Finding{{Detector: "tls", SNI: "blocked.example"}}},
		},
	})

	decision := service.Inspect(context.Background(), dpiengine.TrafficSample{})
	if decision.Action != ActionAllow {
		t.Fatalf("expected allow, got %s", decision.Action)
	}
}

func TestServiceBlocksWhenPolicyRequestsBlockOnFindings(t *testing.T) {
	service := NewService(Options{
		Engine: fixedEngine{
			result: dpiengine.Result{Findings: []dpiengine.Finding{{Detector: "tls", SNI: "blocked.example"}}},
		},
		PolicyProvider: StaticPolicyProvider{Policy: Policy{
			Enabled:           true,
			Mode:              ModeBlock,
			EnabledDetectors:  []string{"tls"},
			BlockOnAnyFinding: true,
		}},
	})

	decision := service.Inspect(context.Background(), dpiengine.TrafficSample{})
	if decision.Action != ActionBlock {
		t.Fatalf("expected block, got %s", decision.Action)
	}
	if decision.Finding == nil || decision.Finding.SNI != "blocked.example" {
		t.Fatalf("expected tls finding, got %#v", decision.Finding)
	}
}
