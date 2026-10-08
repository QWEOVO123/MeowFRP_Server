package config

import "fmt"

// Zero values retain the existing FRP and mTLS defaults.
type ConnectionTuning struct {
	DisableTCPMux                bool  `json:"disable_tcp_mux"`
	TCPMuxKeepaliveSeconds       int64 `json:"tcp_mux_keepalive_seconds"`
	TCPKeepaliveSeconds          int64 `json:"tcp_keepalive_seconds"`
	MaxPoolCount                 int64 `json:"max_pool_count"`
	HeartbeatTimeoutSeconds      int64 `json:"heartbeat_timeout_seconds"`
	UserConnectionTimeoutSeconds int64 `json:"user_connection_timeout_seconds"`
	MTLSHandshakeTimeoutSeconds  int64 `json:"mtls_handshake_timeout_seconds"`
	DisableMTLSSessionTickets    bool  `json:"disable_mtls_session_tickets"`
	EnableMTLSSessionResumption  bool  `json:"enable_mtls_session_resumption"`
}

func ValidateConnectionTuning(value ConnectionTuning) error {
	for _, field := range []struct {
		name                    string
		value, minimum, maximum int64
	}{
		{"tcp_mux_keepalive_seconds", value.TCPMuxKeepaliveSeconds, 0, 3600},
		{"tcp_keepalive_seconds", value.TCPKeepaliveSeconds, -1, 86400},
		{"max_pool_count", value.MaxPoolCount, 0, 1024},
		{"heartbeat_timeout_seconds", value.HeartbeatTimeoutSeconds, -1, 3600},
		{"user_connection_timeout_seconds", value.UserConnectionTimeoutSeconds, 0, 600},
		{"mtls_handshake_timeout_seconds", value.MTLSHandshakeTimeoutSeconds, 0, 120},
	} {
		if field.value < field.minimum || field.value > field.maximum {
			return fmt.Errorf("%s must be between %d and %d", field.name, field.minimum, field.maximum)
		}
	}
	return nil
}
