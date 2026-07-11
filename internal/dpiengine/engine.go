package dpiengine

import (
	"context"
	"time"
)

type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

type FlowContext struct {
	UserID     int64             `json:"user_id"`
	TokenID    int64             `json:"token_id"`
	ClientID   string            `json:"client_id"`
	LeaseID    string            `json:"lease_id"`
	ProxyName  string            `json:"proxy_name"`
	ProxyType  string            `json:"proxy_type"`
	RemotePort int               `json:"remote_port"`
	LocalAddr  string            `json:"local_addr,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	User       string            `json:"user,omitempty"`
	Metas      map[string]string `json:"metas,omitempty"`
}

type TrafficSample struct {
	Flow           FlowContext `json:"flow"`
	Direction      Direction   `json:"direction"`
	Payload        []byte      `json:"-"`
	PayloadLength  int         `json:"payload_length"`
	CapturedLength int         `json:"captured_length"`
	ObservedAt     time.Time   `json:"observed_at"`
}

type Finding struct {
	Detector   string  `json:"detector"`
	Protocol   string  `json:"protocol,omitempty"`
	Host       string  `json:"host,omitempty"`
	SNI        string  `json:"sni,omitempty"`
	TargetIP   string  `json:"target_ip,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Summary    string  `json:"summary,omitempty"`
}

type Result struct {
	Findings []Finding `json:"findings"`
}

type Engine interface {
	Inspect(context.Context, TrafficSample) (Result, error)
}

type NoopEngine struct{}

func (NoopEngine) Inspect(context.Context, TrafficSample) (Result, error) {
	return Result{}, nil
}
