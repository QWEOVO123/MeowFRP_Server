package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"frp-control-server/internal/dpi"
	"frp-control-server/internal/dpiengine"
)

type DPIEvent struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	Username   string    `json:"username"`
	TokenID    int64     `json:"token_id"`
	ClientID   string    `json:"client_id"`
	LeaseID    string    `json:"lease_id"`
	ProxyName  string    `json:"proxy_name"`
	ProxyType  string    `json:"proxy_type"`
	RemotePort int       `json:"remote_port"`
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	Direction  string    `json:"direction"`
	Detector   string    `json:"detector"`
	Protocol   string    `json:"protocol"`
	Host       string    `json:"host,omitempty"`
	SNI        string    `json:"sni,omitempty"`
	TargetIP   string    `json:"target_ip,omitempty"`
	Action     string    `json:"action"`
	Reason     string    `json:"reason"`
	Summary    string    `json:"summary"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Store) GetPolicy(ctx context.Context, flow dpiengine.FlowContext) (dpi.Policy, error) {
	if flow.UserID <= 0 && flow.LeaseID != "" {
		lease, err := s.GetRuntimeLeaseByLeaseID(ctx, flow.LeaseID)
		if err == nil {
			flow.UserID = lease.UserID
		}
	}
	if flow.UserID <= 0 {
		return dpi.DefaultPolicy(), nil
	}
	return s.GetDPIPolicy(ctx, flow.UserID)
}

func (s *Store) GetDPIPolicy(ctx context.Context, userID int64) (dpi.Policy, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT user_id, enabled, mode, enabled_detectors, block_on_any_finding,
		       allow_http, allow_tls, allow_quic, allow_encrypted_tunnel,
		       max_inspect_bytes, temporary_block_ttl_seconds, encrypted_tunnel_mode
		FROM dpi_user_policies WHERE user_id=?
	`, userID)
	return scanDPIPolicy(row)
}

func (s *Store) ListDPIPolicies(ctx context.Context) ([]dpi.Policy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_id, enabled, mode, enabled_detectors, block_on_any_finding,
		       allow_http, allow_tls, allow_quic, allow_encrypted_tunnel,
		       max_inspect_bytes, temporary_block_ttl_seconds, encrypted_tunnel_mode
		FROM dpi_user_policies ORDER BY user_id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []dpi.Policy
	for rows.Next() {
		policy, err := scanDPIPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}

func (s *Store) UpsertDPIPolicy(ctx context.Context, policy dpi.Policy) (dpi.Policy, error) {
	if policy.Mode == "" {
		policy.Mode = dpi.ModeMonitor
	}
	if len(policy.EnabledDetectors) == 0 {
		policy.EnabledDetectors = dpi.DefaultPolicy().EnabledDetectors
	}
	if policy.MaxInspectBytes <= 0 {
		policy.MaxInspectBytes = dpi.DefaultPolicy().MaxInspectBytes
	}
	if policy.TemporaryBlockTTL <= 0 {
		policy.TemporaryBlockTTL = dpi.DefaultPolicy().TemporaryBlockTTL
	}
	if policy.EncryptedTunnelMode == "" {
		policy.EncryptedTunnelMode = dpi.ModeMonitor
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dpi_user_policies(
			user_id, enabled, mode, enabled_detectors, block_on_any_finding,
			allow_http, allow_tls, allow_quic, allow_encrypted_tunnel,
			max_inspect_bytes, temporary_block_ttl_seconds, encrypted_tunnel_mode
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			enabled=VALUES(enabled),
			mode=VALUES(mode),
			enabled_detectors=VALUES(enabled_detectors),
			block_on_any_finding=VALUES(block_on_any_finding),
			allow_http=VALUES(allow_http),
			allow_tls=VALUES(allow_tls),
			allow_quic=VALUES(allow_quic),
			allow_encrypted_tunnel=VALUES(allow_encrypted_tunnel),
			max_inspect_bytes=VALUES(max_inspect_bytes),
			temporary_block_ttl_seconds=VALUES(temporary_block_ttl_seconds),
			encrypted_tunnel_mode=VALUES(encrypted_tunnel_mode),
			updated_at=CURRENT_TIMESTAMP(3)
	`, policy.UserID, policy.Enabled, policy.Mode, strings.Join(policy.EnabledDetectors, ","), policy.BlockOnAnyFinding,
		policy.AllowHTTP, policy.AllowTLS, policy.AllowQUIC, policy.AllowEncryptedTunnel,
		policy.MaxInspectBytes, policy.TemporaryBlockTTL, policy.EncryptedTunnelMode)
	if err != nil {
		return dpi.Policy{}, err
	}
	return s.GetDPIPolicy(ctx, policy.UserID)
}

func (s *Store) RecordDPIEvent(ctx context.Context, event dpi.Event) {
	if s == nil || s.db == nil {
		return
	}
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO dpi_events(
			user_id, token_id, client_id, lease_id, proxy_name, proxy_type, remote_port,
			local_addr, remote_addr, direction, detector, protocol, host, sni, target_ip, action, reason, summary
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?)
	`, event.Flow.UserID, event.Flow.TokenID, event.Flow.ClientID, event.Flow.LeaseID,
		event.Flow.ProxyName, event.Flow.ProxyType, event.Flow.RemotePort, event.Flow.LocalAddr, event.Flow.RemoteAddr, event.Direction,
		event.Finding.Detector, event.Finding.Protocol, event.Finding.Host, event.Finding.SNI,
		event.Finding.TargetIP, event.Action, event.Reason, event.Finding.Summary)
}

func (s *Store) ListDPIEvents(ctx context.Context, limit int) ([]DPIEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.user_id, COALESCE(u.username, ''), e.token_id, e.client_id, e.lease_id,
		       e.proxy_name, e.proxy_type, e.remote_port, e.local_addr, e.remote_addr,
		       e.direction, e.detector, e.protocol, COALESCE(e.host, ''), COALESCE(e.sni, ''),
		       COALESCE(e.target_ip, ''), e.action, e.reason, e.summary, e.created_at
		FROM dpi_events e
		LEFT JOIN users u ON u.id = e.user_id
		ORDER BY e.id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []DPIEvent
	for rows.Next() {
		var event DPIEvent
		if err := rows.Scan(
			&event.ID, &event.UserID, &event.Username, &event.TokenID, &event.ClientID, &event.LeaseID,
			&event.ProxyName, &event.ProxyType, &event.RemotePort, &event.LocalAddr, &event.RemoteAddr,
			&event.Direction, &event.Detector, &event.Protocol, &event.Host, &event.SNI,
			&event.TargetIP, &event.Action, &event.Reason, &event.Summary, &event.CreatedAt,
		); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) AuditDPIError(ctx context.Context, event dpi.Event, err error) {
	if err == nil {
		return
	}
	s.Audit(ctx, "system", 0, "dpi_event_error", "lease", event.Flow.LeaseID, fmt.Sprintf("%v", err))
}

type dpiPolicyScanner interface {
	Scan(dest ...any) error
}

func scanDPIPolicy(row dpiPolicyScanner) (dpi.Policy, error) {
	var policy dpi.Policy
	var detectors string
	err := row.Scan(
		&policy.UserID, &policy.Enabled, &policy.Mode, &detectors, &policy.BlockOnAnyFinding,
		&policy.AllowHTTP, &policy.AllowTLS, &policy.AllowQUIC, &policy.AllowEncryptedTunnel,
		&policy.MaxInspectBytes, &policy.TemporaryBlockTTL, &policy.EncryptedTunnelMode,
	)
	if errors.Is(err, sql.ErrNoRows) {
		policy = dpi.DefaultPolicy()
		return policy, nil
	}
	if err != nil {
		return dpi.Policy{}, err
	}
	policy.EnabledDetectors = splitCSV(detectors)
	return policy, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
