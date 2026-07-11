package dpihook

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

type FlowContext struct {
	User       string            `json:"user,omitempty"`
	Metas      map[string]string `json:"metas,omitempty"`
	LeaseID    string            `json:"lease_id,omitempty"`
	ProxyName  string            `json:"proxy_name,omitempty"`
	ProxyType  string            `json:"proxy_type,omitempty"`
	LocalAddr  string            `json:"local_addr,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
}

type TrafficSample struct {
	Flow           FlowContext `json:"flow"`
	Direction      Direction   `json:"direction"`
	Payload        []byte      `json:"-"`
	PayloadLength  int         `json:"payload_length"`
	CapturedLength int         `json:"captured_length"`
	ObservedAt     time.Time   `json:"observed_at"`
}

type Action string

const (
	ActionAllow   Action = "allow"
	ActionMonitor Action = "monitor"
	ActionBlock   Action = "block"
)

type Decision struct {
	Action Action `json:"action"`
	Reason string `json:"reason,omitempty"`
}

type Inspector interface {
	InspectTCP(context.Context, TrafficSample) Decision
	InspectUDP(context.Context, TrafficSample) Decision
}

type ConnectionInfo struct {
	Protocol   string            `json:"protocol"`
	User       string            `json:"user,omitempty"`
	Metas      map[string]string `json:"metas,omitempty"`
	LeaseID    string            `json:"lease_id,omitempty"`
	ProxyName  string            `json:"proxy_name,omitempty"`
	ProxyType  string            `json:"proxy_type,omitempty"`
	LocalAddr  string            `json:"local_addr,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
}

type ConnectionObserver interface {
	IsInboundBlocked(context.Context, ConnectionInfo) bool
	RegisterTCPConnection(context.Context, ConnectionInfo, net.Conn, io.Closer) string
	UnregisterTCPConnection(string)
	ObserveUDPFlow(context.Context, ConnectionInfo)
}

var current atomic.Value

func Register(inspector Inspector) {
	current.Store(inspector)
}

func Current() Inspector {
	inspector, _ := current.Load().(Inspector)
	return inspector
}

func CurrentConnectionObserver() ConnectionObserver {
	observer, _ := current.Load().(ConnectionObserver)
	return observer
}

func Allow() Decision {
	return Decision{Action: ActionAllow}
}
