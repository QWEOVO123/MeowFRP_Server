package dpi

import (
	"context"
	"testing"

	"frp-control-server/internal/dpiengine"
)

type fixedEngine struct {
	result dpiengine.Result
	err    error
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
