package cluster

import (
	"encoding/json"
	"strings"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

const controlMethod = "/meowfrp.cluster.v1.NodeControl/Connect"

type Message struct {
	Type         string          `json:"type"`
	NodeID       string          `json:"node_id,omitempty"`
	Sequence     int64           `json:"sequence,omitempty"`
	Revision     int64           `json:"revision,omitempty"`
	CommandID    string          `json:"command_id,omitempty"`
	Capabilities json.RawMessage `json:"capabilities,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	SentAt       time.Time       `json:"sent_at"`
}

type IdentitySnapshot struct {
	Revision    int64                   `json:"revision"`
	Users       []SnapshotUser          `json:"users"`
	Tokens      []SnapshotToken         `json:"tokens"`
	Policies    []db.UserResourcePolicy `json:"policies"`
	Grants      []db.PortGrant          `json:"grants"`
	DPIPolicies []dpi.Policy            `json:"dpi_policies"`
	BlockedIPs  []db.BlockedInboundIP   `json:"blocked_ips"`
}

type ClientPresence struct {
	UserID      int64      `json:"user_id"`
	TokenID     int64      `json:"token_id"`
	ClientID    string     `json:"client_id"`
	FRPCRunning bool       `json:"frpc_running"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
}

type EdgeConnectionSnapshot struct {
	ID           string    `json:"id"`
	Protocol     string    `json:"protocol"`
	UserID       int64     `json:"user_id"`
	TokenID      int64     `json:"token_id"`
	ClientID     string    `json:"client_id"`
	ClientAddr   string    `json:"client_addr"`
	LeaseID      string    `json:"lease_id"`
	ProxyName    string    `json:"proxy_name"`
	ProxyType    string    `json:"proxy_type"`
	RemotePort   int       `json:"remote_port"`
	InboundAddr  string    `json:"inbound_addr"`
	InboundIP    string    `json:"inbound_ip"`
	InboundPort  int       `json:"inbound_port"`
	ServerAddr   string    `json:"server_addr"`
	OpenedAt     time.Time `json:"opened_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	CanTerminate bool      `json:"can_terminate"`
}

type EdgeTrafficSnapshot struct {
	BytesInbound    uint64    `json:"bytes_inbound"`
	BytesOutbound   uint64    `json:"bytes_outbound"`
	SamplesInbound  uint64    `json:"samples_inbound"`
	SamplesOutbound uint64    `json:"samples_outbound"`
	StartedAt       time.Time `json:"started_at"`
	CapturedAt      time.Time `json:"captured_at"`
}

type HeartbeatPayload struct {
	ClientsOnline               int                      `json:"clients_online"`
	FRPConnections              int                      `json:"frp_connections"`
	PendingEvents               int                      `json:"pending_events"`
	Clients                     []ClientPresence         `json:"clients,omitempty"`
	ReportingVersion            int                      `json:"reporting_version,omitempty"`
	ConnectionsReportingEnabled bool                     `json:"connections_reporting_enabled"`
	Connections                 []EdgeConnectionSnapshot `json:"connections,omitempty"`
	Traffic                     *EdgeTrafficSnapshot     `json:"traffic,omitempty"`
}
type HeartbeatAck struct {
	IntervalSeconds int       `json:"heartbeat_interval_seconds"`
	ServerTime      time.Time `json:"server_time"`
	ObservedAddress string    `json:"observed_address,omitempty"`
}
type EventEnvelope struct {
	EventID   string          `json:"event_id"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}
type EventBatch struct {
	Events []EventEnvelope `json:"events"`
}
type EventAck struct {
	EventIDs []string `json:"event_ids"`
}
type NodeCommand struct {
	CommandID string          `json:"command_id"`
	NodeID    string          `json:"node_id,omitempty"`
	Command   string          `json:"command"`
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt time.Time       `json:"expires_at"`
}
type CommandResult struct {
	CommandID string          `json:"command_id"`
	Status    string          `json:"status"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}
type SnapshotUser struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	BanReason string `json:"ban_reason"`
}
type SnapshotToken struct {
	ID            int64      `json:"id"`
	UserID        int64      `json:"user_id"`
	Name          string     `json:"name"`
	TokenHash     string     `json:"token_hash"`
	Status        string     `json:"status"`
	BanReason     string     `json:"ban_reason"`
	MaxProxyCount int        `json:"max_proxy_count"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error)      { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
func (jsonCodec) Name() string                       { return "json" }

func init() { encoding.RegisterCodec(jsonCodec{}) }

type controlService interface{ Connect(grpc.ServerStream) error }

var controlServiceDesc = grpc.ServiceDesc{
	ServiceName: "meowfrp.cluster.v1.NodeControl",
	HandlerType: (*controlService)(nil),
	Streams:     []grpc.StreamDesc{{StreamName: "Connect", Handler: func(srv any, stream grpc.ServerStream) error { return srv.(controlService).Connect(stream) }, ServerStreams: true, ClientStreams: true}},
}

func NormalizeControllerAddress(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	return strings.TrimSuffix(value, "/")
}
