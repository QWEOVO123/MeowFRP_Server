package dpi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"frp-control-server/internal/dpiengine"
)

type Action string

// Deliberate cache invalidation must not silently turn DPI into allow-all.
var ErrPolicySynchronizing = errors.New("identity policy synchronization in progress")

const (
	ActionAllow   Action = "allow"
	ActionMonitor Action = "monitor"
	ActionBlock   Action = "block"
)

type Mode string

const (
	ModeMonitor Mode = "monitor"
	ModeBlock   Mode = "block"
)

type Decision struct {
	Action   Action              `json:"action"`
	Reason   string              `json:"reason,omitempty"`
	Finding  *dpiengine.Finding  `json:"finding,omitempty"`
	Findings []dpiengine.Finding `json:"findings,omitempty"`
}

type Policy struct {
	UserID               int64    `json:"user_id"`
	Enabled              bool     `json:"enabled"`
	Mode                 Mode     `json:"mode"`
	EnabledDetectors     []string `json:"enabled_detectors"`
	BlockOnAnyFinding    bool     `json:"block_on_any_finding"`
	AllowHTTP            bool     `json:"allow_http"`
	AllowTLS             bool     `json:"allow_tls"`
	AllowQUIC            bool     `json:"allow_quic"`
	AllowEncryptedTunnel bool     `json:"allow_encrypted_tunnel"`
	MaxInspectBytes      int      `json:"max_inspect_bytes"`
	TemporaryBlockTTL    int      `json:"temporary_block_ttl_seconds"`
	EncryptedTunnelMode  Mode     `json:"encrypted_tunnel_mode"`
}

type Event struct {
	Flow       dpiengine.FlowContext `json:"flow"`
	Direction  dpiengine.Direction   `json:"direction"`
	Action     Action                `json:"action"`
	Reason     string                `json:"reason,omitempty"`
	Finding    dpiengine.Finding     `json:"finding"`
	ObservedAt time.Time             `json:"observed_at"`
}

type PolicyProvider interface {
	GetPolicy(context.Context, dpiengine.FlowContext) (Policy, error)
}

type EventSink interface {
	RecordDPIEvent(context.Context, Event)
}

type Options struct {
	Engine         dpiengine.Engine
	PolicyProvider PolicyProvider
	EventSink      EventSink
}

type Service struct {
	settingsMu          sync.RWMutex
	providerUnavailable atomic.Bool
	eventsPaused        atomic.Bool
	policyMu            sync.RWMutex
	leasePolicies       map[string]Policy
	engine              dpiengine.Engine
	policyProvider      PolicyProvider
	eventSink           EventSink
}

func NewService(opts Options) *Service {
	engine := opts.Engine
	if engine == nil {
		engine = dpiengine.NoopEngine{}
	}
	provider := opts.PolicyProvider
	if provider == nil {
		provider = StaticPolicyProvider{Policy: DefaultPolicy()}
	}
	return &Service{
		leasePolicies:  map[string]Policy{},
		engine:         engine,
		policyProvider: provider,
		eventSink:      opts.EventSink,
	}
}

func (s *Service) SetPolicyProvider(provider PolicyProvider) {
	if s == nil || provider == nil {
		return
	}
	s.settingsMu.Lock()
	s.policyProvider = provider
	s.settingsMu.Unlock()
}

// Freeze the last verified DPI policy for an already authenticated lease,
// including tunnels which have not carried traffic yet. Never used for login.
func (s *Service) PrimeLease(ctx context.Context, flow dpiengine.FlowContext) {
	if s == nil || flow.LeaseID == "" {
		return
	}
	s.settingsMu.RLock()
	provider := s.policyProvider
	s.settingsMu.RUnlock()
	if p, err := provider.GetPolicy(ctx, flow); err == nil {
		s.policyMu.Lock()
		s.leasePolicies[flow.LeaseID] = p
		s.policyMu.Unlock()
	}
}

func (s *Service) SetProviderUnavailable(unavailable, pauseEvents bool) {
	s.providerUnavailable.Store(unavailable)
	s.eventsPaused.Store(unavailable && pauseEvents)
}

func (s *Service) SetEventSink(sink EventSink) {
	if s == nil {
		return
	}
	s.settingsMu.Lock()
	s.eventSink = sink
	s.settingsMu.Unlock()
}

func DefaultPolicy() Policy {
	return Policy{
		Enabled:              false,
		Mode:                 ModeMonitor,
		EnabledDetectors:     []string{"http", "tls", "quic", "encrypted_tunnel"},
		BlockOnAnyFinding:    false,
		AllowHTTP:            true,
		AllowTLS:             true,
		AllowQUIC:            true,
		AllowEncryptedTunnel: true,
		MaxInspectBytes:      8192,
		TemporaryBlockTTL:    120,
		EncryptedTunnelMode:  ModeMonitor,
	}
}

func (s *Service) Inspect(ctx context.Context, sample dpiengine.TrafficSample) Decision {
	if s == nil {
		return Allow()
	}
	if sample.ObservedAt.IsZero() {
		sample.ObservedAt = time.Now()
	}
	if sample.PayloadLength == 0 {
		sample.PayloadLength = len(sample.Payload)
	}
	if sample.CapturedLength == 0 {
		sample.CapturedLength = len(sample.Payload)
	}

	var policy Policy
	var err error
	if s.providerUnavailable.Load() {
		err = ErrPolicySynchronizing
	} else {
		policyCtx, cancel := context.WithTimeout(ctx, time.Second)
		s.settingsMu.RLock()
		provider := s.policyProvider
		s.settingsMu.RUnlock()
		policy, err = provider.GetPolicy(policyCtx, sample.Flow)
		cancel()
	}
	if err == nil && sample.Flow.LeaseID != "" {
		s.policyMu.Lock()
		s.leasePolicies[sample.Flow.LeaseID] = policy
		s.policyMu.Unlock()
	} else if err != nil && sample.Flow.LeaseID != "" {
		s.policyMu.RLock()
		saved, ok := s.leasePolicies[sample.Flow.LeaseID]
		s.policyMu.RUnlock()
		if ok {
			policy, err = saved, nil
		}
	}
	if errors.Is(err, ErrPolicySynchronizing) {
		return Decision{Action: ActionBlock, Reason: err.Error()}
	}
	if err != nil || !policy.Enabled || len(policy.EnabledDetectors) == 0 {
		return Allow()
	}
	result, err := s.engine.Inspect(ctx, sample)
	if err != nil {
		decision := Decision{Action: ActionMonitor, Reason: "dpi engine error: " + err.Error()}
		s.record(ctx, sample, decision, dpiengine.Finding{Detector: "engine", Summary: decision.Reason})
		return decision
	}
	findings := filterFindings(result.Findings, policy.EnabledDetectors)
	if len(findings) == 0 {
		return Allow()
	}

	decision := Decision{
		Action:   ActionMonitor,
		Reason:   "dpi finding observed",
		Finding:  &findings[0],
		Findings: findings,
	}
	if policy.Mode == ModeBlock {
		if blocked, reason, finding := blockedByPolicy(policy, findings); blocked {
			decision.Action = ActionBlock
			decision.Reason = reason
			decision.Finding = &finding
		}
	}
	if decision.Action != ActionBlock && policy.Mode == ModeBlock && policy.BlockOnAnyFinding {
		decision.Action = ActionBlock
		decision.Reason = "blocked by dpi policy"
	}
	for _, finding := range findings {
		s.record(ctx, sample, decision, finding)
	}
	return decision
}

func blockedByPolicy(policy Policy, findings []dpiengine.Finding) (bool, string, dpiengine.Finding) {
	for _, finding := range findings {
		switch strings.ToLower(finding.Detector) {
		case "http":
			if !policy.AllowHTTP {
				return true, "http is blocked by user dpi policy", finding
			}
		case "tls":
			if !policy.AllowTLS {
				return true, "tls is blocked by user dpi policy", finding
			}
		case "quic":
			if !policy.AllowQUIC {
				return true, "quic is blocked by user dpi policy", finding
			}
		case "encrypted_tunnel":
			if !policy.AllowEncryptedTunnel {
				return true, "encrypted tunnel is blocked by user dpi policy", finding
			}
		}
	}
	return false, "", dpiengine.Finding{}
}

func Allow() Decision {
	return Decision{Action: ActionAllow}
}

type StaticPolicyProvider struct {
	Policy Policy
}

func (p StaticPolicyProvider) GetPolicy(context.Context, dpiengine.FlowContext) (Policy, error) {
	policy := p.Policy
	if policy.MaxInspectBytes == 0 {
		defaults := DefaultPolicy()
		policy.MaxInspectBytes = defaults.MaxInspectBytes
		policy.TemporaryBlockTTL = defaults.TemporaryBlockTTL
	}
	return policy, nil
}

func (s *Service) record(ctx context.Context, sample dpiengine.TrafficSample, decision Decision, finding dpiengine.Finding) {
	if s.eventsPaused.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	s.settingsMu.RLock()
	sink := s.eventSink
	s.settingsMu.RUnlock()
	if sink == nil {
		return
	}
	sink.RecordDPIEvent(ctx, Event{
		Flow:       sample.Flow,
		Direction:  sample.Direction,
		Action:     decision.Action,
		Reason:     decision.Reason,
		Finding:    finding,
		ObservedAt: sample.ObservedAt,
	})
}

func filterFindings(findings []dpiengine.Finding, enabledDetectors []string) []dpiengine.Finding {
	if len(findings) == 0 {
		return nil
	}
	enabled := map[string]bool{}
	for _, detector := range enabledDetectors {
		detector = strings.ToLower(strings.TrimSpace(detector))
		if detector != "" {
			enabled[detector] = true
		}
	}
	if len(enabled) == 0 {
		return nil
	}
	filtered := make([]dpiengine.Finding, 0, len(findings))
	for _, finding := range findings {
		if enabled[strings.ToLower(finding.Detector)] {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}
