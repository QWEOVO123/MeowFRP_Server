package policy

import "context"

type DecisionAction string

const (
	ActionAllow      DecisionAction = "allow"
	ActionDeny       DecisionAction = "deny"
	ActionThrottle   DecisionAction = "throttle"
	ActionDisconnect DecisionAction = "disconnect"
	ActionBanClient  DecisionAction = "ban_client"
	ActionBanToken   DecisionAction = "ban_token"
)

type Decision struct {
	Action DecisionAction `json:"action"`
	Reason string         `json:"reason,omitempty"`
}

func Allow() Decision {
	return Decision{Action: ActionAllow}
}

type Engine interface {
	BeforeClientBootstrap(context.Context, BootstrapInput) Decision
	BeforeFrpLogin(context.Context, FrpLoginInput) Decision
	BeforeProxyCreate(context.Context, ProxyCreateInput) Decision
	OnProxyStarted(context.Context, ProxyEvent)
	OnProxyClosed(context.Context, ProxyEvent)
	OnTrafficSample(context.Context, TrafficSample) Decision
	OnSecurityEvent(context.Context, SecurityEvent) Decision
}

type NoopEngine struct{}

func (NoopEngine) BeforeClientBootstrap(context.Context, BootstrapInput) Decision { return Allow() }
func (NoopEngine) BeforeFrpLogin(context.Context, FrpLoginInput) Decision         { return Allow() }
func (NoopEngine) BeforeProxyCreate(context.Context, ProxyCreateInput) Decision   { return Allow() }
func (NoopEngine) OnProxyStarted(context.Context, ProxyEvent)                     {}
func (NoopEngine) OnProxyClosed(context.Context, ProxyEvent)                      {}
func (NoopEngine) OnTrafficSample(context.Context, TrafficSample) Decision        { return Allow() }
func (NoopEngine) OnSecurityEvent(context.Context, SecurityEvent) Decision        { return Allow() }

type BootstrapInput struct {
	UserID   int64
	TokenID  int64
	ClientID string
}

type FrpLoginInput struct {
	UserID   int64
	TokenID  int64
	ClientID string
	LeaseID  string
	RunID    string
}

type ProxyCreateInput struct {
	UserID     int64
	TokenID    int64
	ClientID   string
	LeaseID    string
	ProxyName  string
	ProxyType  string
	RemotePort int
	Domain     string
	Subdomain  string
}

type ProxyEvent struct {
	LeaseID    string
	ProxyName  string
	ProxyType  string
	RemotePort int
	Reason     string
}

type TrafficSample struct {
	LeaseID    string
	ProxyName  string
	RemoteAddr string
	BytesIn    int64
	BytesOut   int64
}

type SecurityEvent struct {
	Scope  string
	Target string
	Reason string
}
